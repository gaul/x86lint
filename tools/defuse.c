/*
 * Copyright 2026 Andrew Gaul <andrew@gaul.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// defuse: block-local def-to-use distance profiler for the x86-64 code in ELF
// files.
//
// Answers with numbers the two questions a windowed x86lint check raises --
// how wide does the window have to be, and what does adjacency alone miss --
// by measuring, for each kind of definition, how far away its sole consumer
// sits, and by counting the multi-instruction redundancies no pair statistic
// can see. Distances are in instructions, so bucket d1 is an adjacent pair;
// x86lint's APX_NDD_WINDOW counts the definition itself, so window N covers
// distances up to N-1.
//
// Region discipline mirrors x86lint's: tracking resets at direct branch
// targets (side entries), at calls, at unconditional transfers, and across
// undecodable bytes and range boundaries. Conditional branches do not reset;
// a definition whose consumer lies past one is tagged xbr, since reaching it
// needs path reasoning rather than a straight-line window.
//
// Definition kinds profiled (sole-use only, definition and use in one region):
//   mov    mov r, r          -- the copies missing APX NDD would fold away
//   imm    mov r, imm        -- constants foldable into a later immediate
//   lea    lea r, [...]      -- addresses foldable into a later memory operand
//   ext    movzx/movsx/movsxd
//   load   mov r, [mem]
//   alu    add/sub/and/or/xor/shl/... with a register destination
// The consumer is classified, and a register used as a memory base or index
// counts as addr rather than as a value use: the two admit different rewrites.
//
// Multi-instruction-only categories:
//   dead   a pure definition overwritten with no use, its flag write unread
//          too -- the whole instruction is removable
//   deadv  the same, but a later instruction read the flags it set, so only
//          the value is dead (the candidate rewrite is a cmp/test, not a
//          deletion)
//   reload the same address loaded again with no intervening store, call, or
//          redefinition of its base or index
//   remat  mov r, imm of a constant still live in another register
//   cmp0   cmp r, 0 or test r, r where r's producer already set the flags,
//          with no flag writer in between. Split three ways. By consumer
//          form: test (the shape x86lint's flags_test_redundant matches),
//          test-width (the same, but naming a different width of the
//          producer's register, which that check's exact-register match
//          rejects), and cmpi (cmp r, 0, which x86lint reaches through its
//          separate CMP-zero check). By producer: logic (and/or/xor) sets CF
//          and OF to zero exactly as a test does, so those rows are removable
//          outright, while arith (add/sub/inc/dec/neg) diverges there and is
//          an upper bound -- legal only where CF and OF are dead afterward.
//          And by distance, which is what says how much the adjacent-only
//          check leaves behind.
//
// Usage: defuse [-a] [-e CAT [-n MAX]] <binary>...
//   -a  scan every byte, not just the symbol table's function ranges
//   -e  print example sites for one category (mov imm lea ext load alu dead
//       deadv reload remat cmp0)
//   -n  cap the examples printed (default 20)

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "corpus.h"

// Slot numbering and register aliasing as in tools/pairscan.c: eax and al
// occupy rax's slot, xmm0 zmm0's.
#define NSLOT 96
#define MAXREGS 12

static int reg_slot(xed_reg_enum_t r)
{
    if (r == XED_REG_INVALID) {
        return -1;
    }
    xed_reg_enum_t big = xed_get_largest_enclosing_register(r);
    if (big >= XED_REG_GPR64_FIRST && big <= XED_REG_GPR64_LAST) {
        return (int) (big - XED_REG_GPR64_FIRST);
    }
    if (big >= XED_REG_MASK_FIRST && big <= XED_REG_MASK_LAST) {
        return 32 + (int) (big - XED_REG_MASK_FIRST);
    }
    if (big >= XED_REG_ZMM_FIRST && big <= XED_REG_ZMM_LAST) {
        return 64 + (int) (big - XED_REG_ZMM_FIRST);
    }
    return -1;
}

struct slots {
    int s[MAXREGS];
    int n;
};

static void slots_add(struct slots *set, int slot)
{
    if (slot < 0) {
        return;
    }
    for (int i = 0; i < set->n; ++i) {
        if (set->s[i] == slot) {
            return;
        }
    }
    if (set->n < MAXREGS) {
        set->s[set->n++] = slot;
    }
}

// Register reads, and register writes split by width. Only a write of 32 bits
// or more replaces the whole value -- a 32-bit write zero-extends, an 8- or
// 16-bit one leaves the surrounding bits intact -- so a narrow write stops
// tracking a slot without claiming its definition was dead. Implicit operands
// count, including the memory-addressing ones that carry pop's write to RSP,
// as do the base and index of an ordinary memory operand (reads). XED reports
// the compare aliases correctly (CMP and TEST read their first operand rather
// than writing it), so no correction is needed here.
static void collect_regs(const xed_decoded_inst_t *xedd, struct slots *rd,
                         struct slots *wide, struct slots *narrow)
{
    rd->n = 0;
    wide->n = 0;
    narrow->n = 0;
    const xed_inst_t *xi = xed_decoded_inst_inst(xedd);
    unsigned nops = xed_inst_noperands(xi);
    for (unsigned i = 0; i < nops; ++i) {
        const xed_operand_t *op = xed_inst_operand(xi, i);
        xed_operand_enum_t name = xed_operand_name(op);
        if (!xed_operand_is_register(name) &&
            !xed_operand_is_memory_addressing_register(name)) {
            continue;
        }
        xed_reg_enum_t r = xed_decoded_inst_get_reg(xedd, name);
        int slot = reg_slot(r);
        if (xed_operand_read(op)) {
            slots_add(rd, slot);
        }
        if (xed_operand_written(op)) {
            slots_add(xed_get_register_width_bits64(r) >= 32 ? wide : narrow,
                slot);
        }
    }
    unsigned nmem = xed_decoded_inst_number_of_memory_operands(xedd);
    for (unsigned m = 0; m < nmem; ++m) {
        slots_add(rd, reg_slot(xed_decoded_inst_get_base_reg(xedd, m)));
        slots_add(rd, reg_slot(xed_decoded_inst_get_index_reg(xedd, m)));
    }
    // A conditional writer keeps the destination's prior value when the
    // condition fails, so it consumes the definition it appears to overwrite.
    // kill_iclass already refuses to treat it as a redefinition; recording the
    // read as well is what makes it show up as the consumer it is.
    if (corpus_conditional_write(xedd)) {
        for (int i = 0; i < wide->n; ++i) {
            slots_add(rd, wide->s[i]);
        }
        for (int i = 0; i < narrow->n; ++i) {
            slots_add(rd, narrow->s[i]);
        }
    }
}

#define FLAG_CF (1u << 0)
#define FLAG_PF (1u << 1)
#define FLAG_AF (1u << 2)
#define FLAG_ZF (1u << 3)
#define FLAG_SF (1u << 4)
#define FLAG_OF (1u << 5)

static uint32_t flag_mask(const xed_flag_set_t *fs)
{
    if (fs == NULL) {
        return 0;
    }
    uint32_t m = 0;
    if (fs->s.cf) m |= FLAG_CF;
    if (fs->s.pf) m |= FLAG_PF;
    if (fs->s.af) m |= FLAG_AF;
    if (fs->s.zf) m |= FLAG_ZF;
    if (fs->s.sf) m |= FLAG_SF;
    if (fs->s.of) m |= FLAG_OF;
    return m;
}

// Flags read, and flags unconditionally written ("undefined" included, since
// the prior value is destroyed either way). A conditional writer -- a shift
// by CL writes none for a masked count of zero -- contributes no writes, so
// an earlier flag value stays live through it, as in x86lint's
// flags_live_after.
static void collect_flags(const xed_decoded_inst_t *xedd, uint32_t *read,
                          uint32_t *written)
{
    *read = 0;
    *written = 0;
    const xed_simple_flag_t *fi = xed_decoded_inst_get_rflags_info(xedd);
    if (fi == NULL) {
        return;
    }
    *read = flag_mask(xed_simple_flag_get_read_flag_set(fi));
    if (!xed_simple_flag_get_may_write(fi)) {
        *written = flag_mask(xed_simple_flag_get_written_flag_set(fi)) |
                   flag_mask(xed_simple_flag_get_undefined_flag_set(fi));
    }
}

// ---- result table: key -> count plus a distance histogram ----

typedef struct {
    char *key;
    uint64_t n;
    uint64_t bucket[6];     // 1, 2, 3, 4-7, 8-15, 16+
} entry;

#define HASH_BITS 16
#define HASH_SIZE (1u << HASH_BITS)
static entry table[HASH_SIZE];

static int bucket_of(long d)
{
    return d <= 1 ? 0 : d == 2 ? 1 : d == 3 ? 2 : d <= 7 ? 3 : d <= 15 ? 4 : 5;
}

static size_t table_used;
static uint64_t dropped_keys;

// dist < 0 records an occurrence with no meaningful distance.
static void bump(const char *key, long dist)
{
    uint32_t h = 5381;
    for (const char *s = key; *s != '\0'; ++s) {
        h = h * 33 + (uint8_t) *s;
    }
    h &= HASH_SIZE - 1;
    for (;;) {
        if (table[h].key == NULL) {
            // Stop before the open-addressed probe can run out of empty
            // slots, which would spin. Keys are bounded by the fixed
            // kind/detail/consumer vocabulary, so this is a backstop.
            if (table_used >= HASH_SIZE / 4 * 3) {
                dropped_keys++;
                return;
            }
            table[h].key = strdup(key);
            table_used++;
            break;
        }
        if (strcmp(table[h].key, key) == 0) {
            break;
        }
        h = (h + 1) & (HASH_SIZE - 1);
    }
    table[h].n++;
    if (dist >= 0) {
        table[h].bucket[bucket_of(dist)]++;
    }
}

// ---- per-region tracking ----

typedef struct {
    bool live;
    long idx;                   // instruction index of the definition
    uint64_t addr;
    int uses;
    long first_use_idx;
    char first_use_cls[16];
    bool xbr;                   // a conditional branch sits after the def
    char kind[8];               // mov, imm, lea, ext, load, alu
    char detail[24];
    bool pure;                  // removable if the value proves dead
    uint32_t wflags;            // flags the defining instruction wrote
    bool flags_used;            // a later instruction read one of them
    char text[96];
} defrec;

typedef struct {
    bool live;
    long idx;
    int base;
    int index;
    unsigned scale;
    int64_t disp;
    unsigned size;
    xed_reg_enum_t seg;
} loadrec;

typedef struct {
    bool live;
    long idx;
    int64_t val;
    int slot;
} constrec;

static defrec defs[NSLOT];
static loadrec loads[64];
static int nloads;
static constrec consts[48];
static int nconsts;

// The most recent register-writing instruction that also set the flags: the
// producer a later cmp/test against zero would make redundant.
static int flags_producer_slot = -1;
static long flags_producer_idx;
static char flags_producer_mn[24];
static bool flags_producer_logic;
static xed_reg_enum_t flags_producer_reg;

static uint64_t total_insns;
static uint64_t total_skipped;

static const char *example_cat;
static long example_max = 20;
static long example_printed;

static void region_reset(void)
{
    memset(defs, 0, sizeof(defs));
    nloads = 0;
    nconsts = 0;
    flags_producer_slot = -1;
}

// What consumed the value, at the granularity a rewrite would care about.
static const char *use_class(const xed_decoded_inst_t *xedd, int slot)
{
    unsigned nmem = xed_decoded_inst_number_of_memory_operands(xedd);
    for (unsigned m = 0; m < nmem; ++m) {
        if (reg_slot(xed_decoded_inst_get_base_reg(xedd, m)) == slot ||
            reg_slot(xed_decoded_inst_get_index_reg(xedd, m)) == slot) {
            return "addr";
        }
    }
    switch (xed_decoded_inst_get_iclass(xedd)) {
    case XED_ICLASS_MOVZX: case XED_ICLASS_MOVSX: case XED_ICLASS_MOVSXD:
        return "extend";
    case XED_ICLASS_LEA:
        return "lea";
    case XED_ICLASS_CMP: case XED_ICLASS_TEST:
        return "cmp";
    case XED_ICLASS_ADD: case XED_ICLASS_SUB: case XED_ICLASS_ADC:
    case XED_ICLASS_SBB: case XED_ICLASS_INC: case XED_ICLASS_DEC:
    case XED_ICLASS_NEG:
        return "addsub";
    case XED_ICLASS_AND: case XED_ICLASS_OR: case XED_ICLASS_XOR:
    case XED_ICLASS_NOT:
        return "logic";
    case XED_ICLASS_SHL: case XED_ICLASS_SHR: case XED_ICLASS_SAR:
    case XED_ICLASS_ROL: case XED_ICLASS_ROR: case XED_ICLASS_SHLD:
    case XED_ICLASS_SHRD:
        return "shift";
    case XED_ICLASS_IMUL: case XED_ICLASS_MUL:
        return "mul";
    case XED_ICLASS_DIV: case XED_ICLASS_IDIV:
        return "div";
    case XED_ICLASS_MOV:
        return nmem != 0 && xed_decoded_inst_mem_written(xedd, 0) ? "store"
            : "mov";
    case XED_ICLASS_PUSH:
        return "push";
    case XED_ICLASS_XCHG:
        return "xchg";
    default:
        break;
    }
    switch (xed_decoded_inst_get_category(xedd)) {
    case XED_CATEGORY_CALL: return "call";
    case XED_CATEGORY_UNCOND_BR: return "jmp";
    case XED_CATEGORY_RET: return "ret";
    case XED_CATEGORY_COND_BR: return "cbranch";
    case XED_CATEGORY_SETCC: return "setcc";
    case XED_CATEGORY_CMOV: return "cmov";
    default: break;
    }
    if (nmem != 0) {
        return xed_decoded_inst_mem_written(xedd, 0) ? "store" : "load";
    }
    return "other";
}

// Instruction classes that unconditionally replace the whole destination
// register, so an earlier definition of it provably never reached a consumer.
// The same whitelist x86lint.c's reg_kill_iclass carries, for the same
// reasons: CMOVcc is excluded because XED models its destination as a plain
// write (r=0 w=1) though the prior value survives a not-taken move, REP-string
// writes because a zero count writes nothing, shifts and rotates because the
// SDM's count-0 pseudocode performs no write, and BSF/BSR because the
// destination is undefined for a zero source. Leaving an instruction out only
// forgoes a dead-definition count; putting a conditional one in would
// manufacture them.
static bool kill_iclass(xed_iclass_enum_t ic)
{
    switch (ic) {
    case XED_ICLASS_MOV:
    case XED_ICLASS_MOVZX:
    case XED_ICLASS_MOVSX:
    case XED_ICLASS_MOVSXD:
    case XED_ICLASS_LEA:
    case XED_ICLASS_ADD:
    case XED_ICLASS_SUB:
    case XED_ICLASS_ADC:
    case XED_ICLASS_SBB:
    case XED_ICLASS_AND:
    case XED_ICLASS_OR:
    case XED_ICLASS_XOR:
    case XED_ICLASS_NEG:
    case XED_ICLASS_NOT:
    case XED_ICLASS_INC:
    case XED_ICLASS_DEC:
    case XED_ICLASS_IMUL:
    case XED_ICLASS_MUL:
    case XED_ICLASS_POP:
    case XED_ICLASS_BSWAP:
    case XED_ICLASS_XCHG:
        return true;
    default:
        return false;
    }
}

// Close out a definition: report its sole-use distance, its multi-use status,
// or -- when an unconditional full-width redefinition arrives with no use in
// between -- that it was dead. A narrow (8- or 16-bit) write, or a wide but
// conditional one, only stops tracking: part or all of the value can survive,
// so nothing about the definition is proven.
static void finalize_def(int slot, bool redefined, const char *path,
                         const char *killer)
{
    defrec *d = &defs[slot];
    if (!d->live) {
        return;
    }
    char key[96];
    if (d->uses == 0 && d->pure && redefined) {
        bool flags_dead = d->wflags == 0 || !d->flags_used;
        snprintf(key, sizeof(key), "%s|%s|%s%s",
            flags_dead ? "dead" : "deadv", d->kind, d->detail,
            d->xbr ? "|xbr" : "");
        bump(key, -1);
        if (example_cat != NULL && example_printed < example_max &&
            strcmp(example_cat, flags_dead ? "dead" : "deadv") == 0) {
            printf("EX %s %s %#" PRIx64 ": %s ;; killed by %s\n",
                flags_dead ? "dead" : "deadv", path, d->addr, d->text, killer);
            example_printed++;
        }
    } else if (d->uses == 1) {
        snprintf(key, sizeof(key), "sole|%s|%s->%s%s", d->kind, d->detail,
            d->first_use_cls, d->xbr ? "|xbr" : "");
        bump(key, d->first_use_idx - d->idx);
    } else if (d->uses > 1) {
        snprintf(key, sizeof(key), "multi|%s|%s", d->kind, d->detail);
        bump(key, -1);
    }
    d->live = false;
}

static void start_def(int slot, long idx, uint64_t addr, const char *kind,
                      const char *detail, bool pure, uint32_t wflags,
                      const xed_decoded_inst_t *xedd)
{
    defrec *d = &defs[slot];
    memset(d, 0, sizeof(*d));
    d->live = true;
    d->idx = idx;
    d->addr = addr;
    d->pure = pure;
    d->wflags = wflags;
    snprintf(d->kind, sizeof(d->kind), "%s", kind);
    snprintf(d->detail, sizeof(d->detail), "%s", detail);
    if (example_cat != NULL &&
        !xed_format_context(XED_SYNTAX_INTEL, xedd, d->text, sizeof(d->text),
            addr, NULL, NULL)) {
        d->text[0] = '\0';
    }
}

// The instruction's destination register, when it has exactly one written
// register operand that is not also a memory destination.
static xed_reg_enum_t dest_reg(const xed_decoded_inst_t *xedd)
{
    if (xed_decoded_inst_number_of_memory_operands(xedd) != 0 &&
        xed_decoded_inst_mem_written(xedd, 0)) {
        return XED_REG_INVALID;
    }
    const xed_inst_t *xi = xed_decoded_inst_inst(xedd);
    unsigned nops = xed_inst_noperands(xi);
    xed_reg_enum_t found = XED_REG_INVALID;
    for (unsigned i = 0; i < nops; ++i) {
        const xed_operand_t *op = xed_inst_operand(xi, i);
        xed_operand_enum_t name = xed_operand_name(op);
        if (!xed_operand_is_register(name) || !xed_operand_written(op)) {
            continue;
        }
        xed_reg_enum_t r = xed_decoded_inst_get_reg(xedd, name);
        if (reg_slot(r) < 0) {
            continue;               // RFLAGS and the like
        }
        if (found != XED_REG_INVALID) {
            return XED_REG_INVALID; // more than one: not a simple definition
        }
        found = r;
    }
    return found;
}

// The ALU operations whose flag write a later cmp/test against zero could
// reuse. logic operations set CF and OF to zero exactly as a test does;
// arithmetic ones do not, so a rewrite there needs the CF/OF liveness gate
// x86lint's flags_test_redundant applies.
static bool flag_producer_iclass(xed_iclass_enum_t ic, bool *logic)
{
    switch (ic) {
    case XED_ICLASS_AND: case XED_ICLASS_OR: case XED_ICLASS_XOR:
        *logic = true;
        return true;
    case XED_ICLASS_ADD: case XED_ICLASS_SUB: case XED_ICLASS_ADC:
    case XED_ICLASS_SBB: case XED_ICLASS_INC: case XED_ICLASS_DEC:
    case XED_ICLASS_NEG:
        *logic = false;
        return true;
    default:
        return false;
    }
}

static const char *base_kind(int base_slot, xed_reg_enum_t seg,
                             xed_reg_enum_t base)
{
    if (seg == XED_REG_FS || seg == XED_REG_GS) {
        return "tls";
    }
    if (base == XED_REG_RIP || base == XED_REG_EIP) {
        return "rip";
    }
    if (base_slot == (int) (XED_REG_RSP - XED_REG_GPR64_FIRST) ||
        base_slot == (int) (XED_REG_RBP - XED_REG_GPR64_FIRST)) {
        return "stack";
    }
    return "heap";
}

static void lowercase(const char *in, char *out, size_t outsz)
{
    size_t i = 0;
    for (; in[i] != '\0' && i + 1 < outsz; ++i) {
        out[i] = (char) (in[i] >= 'A' && in[i] <= 'Z' ? in[i] - 'A' + 'a'
            : in[i]);
    }
    out[i] = '\0';
}

static void scan_range(const corpus_section *sec, uint64_t start, uint64_t end)
{
    long idx = 0;
    region_reset();

    for (uint64_t offset = start; offset < end;) {
        xed_decoded_inst_t xedd;
        corpus_decode_init(&xedd);
        if (xed_decode(&xedd, sec->code + offset, end - offset) !=
                XED_ERROR_NONE) {
            total_skipped++;
            region_reset();
            offset += 1;
            continue;
        }
        total_insns++;
        ++idx;
        uint64_t addr = sec->vaddr + offset;
        uint64_t next = offset + xed_decoded_inst_get_length(&xedd);
        if (corpus_is_target(sec->targets, offset)) {
            region_reset();
        }

        xed_iclass_enum_t ic = xed_decoded_inst_get_iclass(&xedd);
        xed_category_enum_t cat = xed_decoded_inst_get_category(&xedd);
        unsigned nmem = xed_decoded_inst_number_of_memory_operands(&xedd);
        struct slots rd, wide, narrow;
        collect_regs(&xedd, &rd, &wide, &narrow);
        uint32_t rflags, wflags;
        collect_flags(&xedd, &rflags, &wflags);

        // ---- uses ----
        for (int i = 0; i < rd.n; ++i) {
            defrec *d = &defs[rd.s[i]];
            if (!d->live) {
                continue;
            }
            d->uses++;
            if (d->uses == 1) {
                d->first_use_idx = idx;
                snprintf(d->first_use_cls, sizeof(d->first_use_cls), "%s",
                    use_class(&xedd, rd.s[i]));
                if (example_cat != NULL && example_printed < example_max &&
                    strcmp(example_cat, d->kind) == 0 && idx - d->idx > 1) {
                    char disasm[96];
                    if (!xed_format_context(XED_SYNTAX_INTEL, &xedd, disasm,
                            sizeof(disasm), addr, NULL, NULL)) {
                        disasm[0] = '\0';
                    }
                    printf("EX %s %s %#" PRIx64 ": d=%ld %s ;; %s\n", d->kind,
                        sec->path, d->addr, idx - d->idx, d->text, disasm);
                    example_printed++;
                }
            }
        }

        // A read of a definition's flags means the definition is not
        // removable even if its value turns out dead.
        if (rflags != 0) {
            for (int s = 0; s < NSLOT; ++s) {
                if (defs[s].live && (defs[s].wflags & rflags) != 0) {
                    defs[s].flags_used = true;
                }
            }
        }

        // ---- cmp r, 0 / test r, r against a producer that already set the
        // flags ----
        if (flags_producer_slot >= 0) {
            xed_reg_enum_t r0 = xed_decoded_inst_get_reg(&xedd,
                XED_OPERAND_REG0);
            const char *form = NULL;
            if (nmem == 0 && reg_slot(r0) == flags_producer_slot) {
                if (ic == XED_ICLASS_CMP &&
                    xed_decoded_inst_get_immediate_width_bits(&xedd) != 0 &&
                    xed_decoded_inst_get_unsigned_immediate(&xedd) == 0) {
                    form = "cmpi";
                } else if (ic == XED_ICLASS_TEST &&
                    xed_decoded_inst_get_reg(&xedd, XED_OPERAND_REG1) == r0) {
                    // Whether the compare names the producer's own width
                    // decides whether x86lint's adjacent check, which matches
                    // the register exactly, can see this at all.
                    form = r0 == flags_producer_reg ? "test" : "test-width";
                }
            }
            if (form != NULL) {
                char key[64];
                snprintf(key, sizeof(key), "cmp0|%s|%s|%s", form,
                    flags_producer_logic ? "logic" : "arith",
                    flags_producer_mn);
                bump(key, idx - flags_producer_idx);
                if (example_cat != NULL && example_printed < example_max &&
                    strcmp(example_cat, "cmp0") == 0) {
                    char disasm[96];
                    if (!xed_format_context(XED_SYNTAX_INTEL, &xedd, disasm,
                            sizeof(disasm), addr, NULL, NULL)) {
                        disasm[0] = '\0';
                    }
                    printf("EX cmp0 %s %#" PRIx64 ": d=%ld %s %s ;; %s\n",
                        sec->path, addr, idx - flags_producer_idx, form,
                        flags_producer_mn, disasm);
                    example_printed++;
                }
            }
        }

        // ---- redundant reload of one address ----
        bool is_call = cat == XED_CATEGORY_CALL;
        bool clobbers_memory = is_call ||
            xed_operand_values_has_lock_prefix(&xedd) ||
            (nmem != 0 && xed_decoded_inst_mem_written(&xedd, 0));
        if (clobbers_memory) {
            nloads = 0;
        } else if (ic == XED_ICLASS_MOV && nmem == 1 &&
                   xed_decoded_inst_mem_read(&xedd, 0)) {
            int bslot = reg_slot(xed_decoded_inst_get_base_reg(&xedd, 0));
            xed_reg_enum_t breg = xed_decoded_inst_get_base_reg(&xedd, 0);
            xed_reg_enum_t seg = xed_decoded_inst_get_seg_reg(&xedd, 0);
            loadrec cur = {
                .live = true,
                .idx = idx,
                .base = bslot,
                .index = reg_slot(xed_decoded_inst_get_index_reg(&xedd, 0)),
                .scale = xed_decoded_inst_get_scale(&xedd, 0),
                .disp = xed_decoded_inst_get_memory_displacement(&xedd, 0),
                .size = xed_decoded_inst_get_memory_operand_length(&xedd, 0),
                .seg = seg,
            };
            bool matched = false;
            for (int k = 0; k < nloads; ++k) {
                loadrec *l = &loads[k];
                if (!l->live || l->base != cur.base || l->index != cur.index ||
                    l->scale != cur.scale || l->disp != cur.disp ||
                    l->size != cur.size || l->seg != cur.seg) {
                    continue;
                }
                char key[64];
                snprintf(key, sizeof(key), "reload|%s|sz%u",
                    base_kind(bslot, seg, breg), cur.size);
                bump(key, idx - l->idx);
                if (example_cat != NULL && example_printed < example_max &&
                    strcmp(example_cat, "reload") == 0) {
                    char disasm[96];
                    if (!xed_format_context(XED_SYNTAX_INTEL, &xedd, disasm,
                            sizeof(disasm), addr, NULL, NULL)) {
                        disasm[0] = '\0';
                    }
                    printf("EX reload %s %#" PRIx64 ": d=%ld %s\n", sec->path,
                        addr, idx - l->idx, disasm);
                    example_printed++;
                }
                l->idx = idx;       // re-arm from the later load
                matched = true;
                break;              // records are unique per address
            }
            if (!matched && nloads < (int) (sizeof(loads) / sizeof(loads[0]))) {
                loads[nloads++] = cur;
            }
        }

        // ---- writes: close out definitions, invalidate what they keyed on --
        char killer[96];
        killer[0] = '\0';
        if (example_cat != NULL && (wide.n != 0 || narrow.n != 0) &&
            !xed_format_context(XED_SYNTAX_INTEL, &xedd, killer,
                sizeof(killer), addr, NULL, NULL)) {
            killer[0] = '\0';
        }
        bool unconditional = kill_iclass(ic);
        for (int i = 0; i < wide.n + narrow.n; ++i) {
            bool full = i < wide.n;
            int slot = full ? wide.s[i] : narrow.s[i - wide.n];
            finalize_def(slot, full && unconditional, sec->path, killer);
            for (int k = 0; k < nloads; ++k) {
                if (loads[k].live &&
                    (loads[k].base == slot || loads[k].index == slot)) {
                    loads[k].live = false;
                }
            }
            for (int k = 0; k < nconsts; ++k) {
                if (consts[k].live && consts[k].slot == slot) {
                    consts[k].live = false;
                }
            }
            if (flags_producer_slot == slot) {
                flags_producer_slot = -1;
            }
        }
        if (wflags != 0) {
            flags_producer_slot = -1;   // this instruction's flags are newer
        }

        // ---- new definitions ----
        xed_reg_enum_t dst = dest_reg(&xedd);
        int dslot = reg_slot(dst);
        if (dslot >= 0 && xed_get_register_width_bits64(dst) >= 32) {
            char mn[24];
            lowercase(xed_iclass_enum_t2str(ic), mn, sizeof(mn));
            bool src_mem = nmem != 0 && xed_decoded_inst_mem_read(&xedd, 0);
            switch (ic) {
            case XED_ICLASS_MOVZX:
            case XED_ICLASS_MOVSX:
            case XED_ICLASS_MOVSXD: {
                char detail[24];
                snprintf(detail, sizeof(detail), "%s%s", mn,
                    src_mem ? "-mem" : "");
                start_def(dslot, idx, addr, "ext", detail, !src_mem, wflags,
                    &xedd);
                break;
            }
            case XED_ICLASS_LEA:
                start_def(dslot, idx, addr, "lea", "lea", true, wflags, &xedd);
                break;
            case XED_ICLASS_MOV:
                if (src_mem) {
                    char detail[24];
                    snprintf(detail, sizeof(detail), "ld%u",
                        xed_decoded_inst_get_memory_operand_length(&xedd, 0));
                    start_def(dslot, idx, addr, "load", detail, false, wflags,
                        &xedd);
                } else if (xed_decoded_inst_get_immediate_width_bits(&xedd) !=
                           0) {
                    int64_t v = (int64_t)
                        xed_decoded_inst_get_signed_immediate(&xedd);
                    for (int k = 0; k < nconsts; ++k) {
                        if (consts[k].live && consts[k].val == v &&
                            consts[k].slot != dslot) {
                            bump("remat|movimm", idx - consts[k].idx);
                            if (example_cat != NULL &&
                                example_printed < example_max &&
                                strcmp(example_cat, "remat") == 0) {
                                printf("EX remat %s %#" PRIx64
                                    ": d=%ld #%" PRId64 "\n", sec->path, addr,
                                    idx - consts[k].idx, v);
                                example_printed++;
                            }
                            break;
                        }
                    }
                    if (nconsts <
                            (int) (sizeof(consts) / sizeof(consts[0]))) {
                        consts[nconsts++] = (constrec){ true, idx, v, dslot };
                    }
                    start_def(dslot, idx, addr, "imm", "movimm", true, wflags,
                        &xedd);
                } else {
                    start_def(dslot, idx, addr, "mov", "movrr", true, wflags,
                        &xedd);
                }
                break;
            default: {
                bool logic;
                if (!src_mem && nmem == 0 &&
                    flag_producer_iclass(ic, &logic)) {
                    start_def(dslot, idx, addr, "alu", mn, true, wflags,
                        &xedd);
                    flags_producer_slot = dslot;
                    flags_producer_idx = idx;
                    flags_producer_logic = logic;
                    flags_producer_reg = dst;
                    snprintf(flags_producer_mn, sizeof(flags_producer_mn),
                        "%s", mn);
                }
                break;
            }
            }
        }

        // ---- a conditional branch makes any later consumer path-dependent --
        if (cat == XED_CATEGORY_COND_BR) {
            for (int s = 0; s < NSLOT; ++s) {
                if (defs[s].live) {
                    defs[s].xbr = true;
                }
            }
        }

        if (is_call || cat == XED_CATEGORY_RET ||
            cat == XED_CATEGORY_UNCOND_BR || cat == XED_CATEGORY_INTERRUPT ||
            cat == XED_CATEGORY_SYSCALL) {
            region_reset();
        }
        offset = next;
    }
}

static void scan_section(const corpus_section *sec, void *ctx)
{
    (void) ctx;
    for (size_t i = 0; i < sec->nranges; ++i) {
        scan_range(sec, sec->ranges[i].start, sec->ranges[i].end);
    }
}

static void usage(const char *argv0)
{
    fprintf(stderr, "usage: %s [-a] [-e CAT [-n MAX]] <binary>...\n", argv0);
}

int main(int argc, char **argv)
{
    bool scan_all = false;
    int argi = 1;
    for (; argi < argc && argv[argi][0] == '-' && argv[argi][1] != '\0';
         ++argi) {
        if (strcmp(argv[argi], "-a") == 0) {
            scan_all = true;
        } else if (strcmp(argv[argi], "-e") == 0 && argi + 1 < argc) {
            example_cat = argv[++argi];
        } else if (strcmp(argv[argi], "-n") == 0 && argi + 1 < argc) {
            example_max = atol(argv[++argi]);
        } else {
            usage(argv[0]);
            return 2;
        }
    }
    if (argi >= argc) {
        usage(argv[0]);
        return 2;
    }

    xed_tables_init();
    xed_set_verbosity(0);

    int rc = 0;
    for (; argi < argc; ++argi) {
        if (corpus_scan_file(argv[argi], scan_all, scan_section, NULL) != 0) {
            rc = 2;
        }
    }

    size_t n = 0;
    for (size_t i = 0; i < HASH_SIZE; ++i) {
        if (table[i].key != NULL) {
            ++n;
        }
    }
    entry *flat = malloc(n * sizeof(*flat));
    if (flat == NULL) {
        fprintf(stderr, "failed to allocate %zu results\n", n);
        return 2;
    }
    size_t k = 0;
    for (size_t i = 0; i < HASH_SIZE; ++i) {
        if (table[i].key != NULL) {
            flat[k++] = table[i];
        }
    }
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = i + 1; j < n; ++j) {
            if (flat[j].n > flat[i].n) {
                entry t = flat[i];
                flat[i] = flat[j];
                flat[j] = t;
            }
        }
    }

    fprintf(stderr, "instructions=%" PRIu64 " skipped=%" PRIu64 "\n",
        total_insns, total_skipped);
    if (dropped_keys != 0) {
        fprintf(stderr, "warning: table full, %" PRIu64 " events uncounted;"
            " raise HASH_BITS\n", dropped_keys);
    }
    printf("%-52s %10s | %8s %8s %8s %8s %8s %8s\n", "pattern", "total", "d1",
        "d2", "d3", "d4-7", "d8-15", "d16+");
    for (size_t i = 0; i < n; ++i) {
        printf("%-52s %10" PRIu64 " | %8" PRIu64 " %8" PRIu64 " %8" PRIu64
            " %8" PRIu64 " %8" PRIu64 " %8" PRIu64 "\n", flat[i].key,
            flat[i].n, flat[i].bucket[0], flat[i].bucket[1],
            flat[i].bucket[2], flat[i].bucket[3], flat[i].bucket[4],
            flat[i].bucket[5]);
    }
    return rc;
}
