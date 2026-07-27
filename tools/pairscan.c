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

// pairscan: disassemble the x86-64 code in ELF files and count adjacent
// instruction pairs by normalized shape, to surface frequent patterns worth a
// new x86lint check.
//
// Normalization keeps what a peephole rewrite would key on and drops what it
// would not. Mnemonic: the iclass, with the Jcc, SETcc, and CMOVcc families
// folded to jcc/setcc/cmovcc (x86lint treats each as one family), and LOCK
// and REP kept as prefixes. Registers: collapsed to a class plus width, with
// RAX, RCX, RDX, RSP, and RBP distinct -- the accumulator has short encodings,
// CL is the shift count, RDX the widening half, and the stack registers are
// not allocatable like the rest -- so mov r64,r64 and mov a64,r64 count apart.
// Immediates: #0, #1, #-1, and #i, since several checks turn on exactly those
// values. Memory: [base+index*scale+disp] with the class of each part, the
// displacement as +0 (an encoded zero) or +i, an fs/gs segment override, and
// the access width in bytes, e.g. [r64+r64*8+i]:8. An operand the opcode
// implies rather than encodes prints in parentheses, so the accumulator short
// form reads as cmp (a32),#i and stays a shape apart from the modrm cmp
// a32,#i it could be exchanged for.
//
// Pair flags say how the two instructions are coupled:
//   dep   second reads a register the first wrote
//   waw   second overwrites a register the first wrote without reading it
//   fdep  second reads a flag the first wrote (the cmp/jcc coupling)
//   fdead first's flag write is entirely overwritten by the second, unread --
//         the gate that decides whether a flag-disturbing rewrite is legal
//
// Pairs are skipped where straight-line reasoning does not hold: when the
// second instruction is a direct branch target (a side entry reaching it
// without the first), when the first is an unconditional transfer, and across
// undecodable bytes, INT3/UD2 padding, and range boundaries. With a symbol
// table present, ranges are the function ranges, so no pair spans two
// functions (see corpus.c).
//
// Usage: pairscan [-a] [-e SUBSTR [-n MAX]] [-t TOP] <binary>...
//   -a  scan every byte, not just the symbol table's function ranges
//   -e  also print example sites for keys containing SUBSTR
//   -n  cap the examples printed (default 20)
//   -t  print only the TOP most frequent pairs (default: all)

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "corpus.h"

// Canonical architectural slot for dependency tracking: 0-31 GPRs (a write to
// eax kills rax, a read of al reads it), 32-39 mask registers, 64-95 the
// vector file, where xmm0/ymm0/zmm0 share one slot. -1 for everything a pair
// statistic should not couple on: RIP, RFLAGS (tracked separately), x87, MMX,
// and the system registers.
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

static bool slots_has(const struct slots *set, int slot)
{
    for (int i = 0; i < set->n; ++i) {
        if (set->s[i] == slot) {
            return true;
        }
    }
    return false;
}

// Register reads and writes, implicit operands included: push writes RSP and
// the next push reads it, and a pair statistic that missed that coupling would
// call the two independent. XED models the compare aliases correctly -- CMP
// and TEST mark their first operand read-only -- so no correction is needed
// here, unlike the Capstone-based armlint tools this one mirrors.
//
// Two operand kinds carry registers. The register operands (REG0..REGn) are
// the ordinary ones, and the memory-addressing operands (BASE0, INDEX, ...)
// carry the stack- and string-pointer updates: XED expresses pop's write to
// RSP as a written BASE0, not as a register operand. Neither kind lists the
// base and index of an ordinary memory operand, which the memory loop below
// adds as reads -- a read even when the memory operand itself is written.
static void collect_regs(const xed_decoded_inst_t *xedd, struct slots *rd,
                         struct slots *wr)
{
    rd->n = 0;
    wr->n = 0;
    const xed_inst_t *xi = xed_decoded_inst_inst(xedd);
    unsigned nops = xed_inst_noperands(xi);
    for (unsigned i = 0; i < nops; ++i) {
        const xed_operand_t *op = xed_inst_operand(xi, i);
        xed_operand_enum_t name = xed_operand_name(op);
        if (!xed_operand_is_register(name) &&
            !xed_operand_is_memory_addressing_register(name)) {
            continue;
        }
        int slot = reg_slot(xed_decoded_inst_get_reg(xedd, name));
        if (xed_operand_read(op)) {
            slots_add(rd, slot);
        }
        if (xed_operand_written(op)) {
            slots_add(wr, slot);
        }
    }
    unsigned nmem = xed_decoded_inst_number_of_memory_operands(xedd);
    for (unsigned m = 0; m < nmem; ++m) {
        slots_add(rd, reg_slot(xed_decoded_inst_get_base_reg(xedd, m)));
        slots_add(rd, reg_slot(xed_decoded_inst_get_index_reg(xedd, m)));
    }
    // A conditional writer keeps the destination's prior value when the
    // condition fails, so it reads what it writes; without this a copy
    // feeding a CMOVcc reads as waw, i.e. as a dead instruction.
    if (corpus_conditional_write(xedd)) {
        for (int i = 0; i < wr->n; ++i) {
            slots_add(rd, wr->s[i]);
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

// Flags read, and flags unconditionally written. "Undefined" per the SDM
// counts as written: the prior value is destroyed either way. A conditional
// writer -- a shift by CL, which writes nothing for a masked count of zero --
// is reported by XED with the same written set as an unconditional one and
// distinguished only by may_write, so its writes are dropped here and the
// earlier flag value stays live through it, matching x86lint's
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

static void reg_class(xed_reg_enum_t r, char *out, size_t outsz)
{
    if (r == XED_REG_AH || r == XED_REG_CH || r == XED_REG_DH ||
        r == XED_REG_BH) {
        snprintf(out, outsz, "rhi8");     // aliases bits 15:8, not a low byte
        return;
    }
    switch (xed_reg_class(r)) {
    case XED_REG_CLASS_GPR: {
        xed_reg_enum_t big = xed_get_largest_enclosing_register(r);
        const char *name = big == XED_REG_RAX ? "a"
            : big == XED_REG_RCX ? "c"
            : big == XED_REG_RDX ? "d"
            : big == XED_REG_RSP ? "sp"
            : big == XED_REG_RBP ? "bp" : "r";
        snprintf(out, outsz, "%s%u", name, xed_get_register_width_bits64(r));
        return;
    }
    case XED_REG_CLASS_XMM: snprintf(out, outsz, "x"); return;
    case XED_REG_CLASS_YMM: snprintf(out, outsz, "y"); return;
    case XED_REG_CLASS_ZMM: snprintf(out, outsz, "z"); return;
    case XED_REG_CLASS_MASK: snprintf(out, outsz, "k"); return;
    case XED_REG_CLASS_MMX: snprintf(out, outsz, "mm"); return;
    case XED_REG_CLASS_X87: snprintf(out, outsz, "st"); return;
    case XED_REG_CLASS_SR:
        snprintf(out, outsz, r == XED_REG_FS ? "fs"
            : r == XED_REG_GS ? "gs" : "seg");
        return;
    case XED_REG_CLASS_IP: snprintf(out, outsz, "ip"); return;
    case XED_REG_CLASS_FLAGS: snprintf(out, outsz, "flags"); return;
    default: snprintf(out, outsz, "sys"); return;
    }
}

static void imm_class(const xed_decoded_inst_t *xedd, char *out, size_t outsz)
{
    uint64_t u = xed_decoded_inst_get_unsigned_immediate(xedd);
    unsigned bits = xed_decoded_inst_get_immediate_width_bits(xedd);
    int64_t v = (int64_t) u;
    if (bits != 0 && bits < 64) {
        v = (int64_t) (u << (64 - bits)) >> (64 - bits);
    }
    snprintf(out, outsz, v == 0 ? "#0" : v == 1 ? "#1" : v == -1 ? "#-1"
        : "#i");
}

// [seg:base+index*scale+disp]:width, omitting the parts the encoding leaves
// out. An encoded zero displacement prints as +0 and a nonzero one as +i:
// x86lint has a check for each. `agen` is lea's address, which computes but
// does not access, so it carries no width.
static void mem_shape(const xed_decoded_inst_t *xedd, unsigned mi, bool agen,
                      char *out, size_t outsz)
{
    xed_reg_enum_t breg = xed_decoded_inst_get_base_reg(xedd, mi);
    xed_reg_enum_t ireg = xed_decoded_inst_get_index_reg(xedd, mi);
    xed_reg_enum_t sreg = xed_decoded_inst_get_seg_reg(xedd, mi);

    const char *seg = sreg == XED_REG_FS ? "fs:"
        : sreg == XED_REG_GS ? "gs:" : "";
    char base[16] = "", index[24] = "", disp[4] = "", width[8] = "";
    if (breg != XED_REG_INVALID) {
        reg_class(breg, base, sizeof(base));
    }
    if (ireg != XED_REG_INVALID) {
        char cls[16];
        reg_class(ireg, cls, sizeof(cls));
        snprintf(index, sizeof(index), "%s%s*%u", base[0] != '\0' ? "+" : "",
            cls, xed_decoded_inst_get_scale(xedd, mi));
    }
    if (xed_decoded_inst_get_memory_displacement_width(xedd, mi) != 0) {
        snprintf(disp, sizeof(disp), "%s%s",
            base[0] != '\0' || index[0] != '\0' ? "+" : "",
            xed_decoded_inst_get_memory_displacement(xedd, mi) == 0 ? "0"
                : "i");
    }
    // lea's address is computed, not accessed, so it carries no width.
    if (!agen) {
        snprintf(width, sizeof(width), ":%u",
            xed_decoded_inst_get_memory_operand_length(xedd, mi));
    }
    snprintf(out, outsz, "[%s%s%s%s]%s", seg, base, index, disp, width);
}

// True for the conditional-branch iclasses worth folding into one jcc token.
// XED's COND_BR category also holds JRCXZ and the LOOP family, which branch
// on a register rather than the flags and do not belong with them.
static bool is_jcc(xed_iclass_enum_t ic)
{
    switch (ic) {
    case XED_ICLASS_JRCXZ:
    case XED_ICLASS_LOOP:
    case XED_ICLASS_LOOPE:
    case XED_ICLASS_LOOPNE:
        return false;
    default:
        return true;
    }
}

static void build_token(const xed_decoded_inst_t *xedd, char *out, size_t outsz)
{
    size_t p = 0;
    if (xed_operand_values_has_lock_prefix(xedd)) {
        p += (size_t) snprintf(out + p, outsz - p, "lock ");
    }
    if (xed_operand_values_has_real_rep(xedd)) {
        p += (size_t) snprintf(out + p, outsz - p, "rep ");
    }

    xed_iclass_enum_t ic = xed_decoded_inst_get_iclass(xedd);
    xed_category_enum_t cat = xed_decoded_inst_get_category(xedd);
    if (cat == XED_CATEGORY_COND_BR && is_jcc(ic)) {
        p += (size_t) snprintf(out + p, outsz - p, "jcc");
    } else if (cat == XED_CATEGORY_SETCC) {
        p += (size_t) snprintf(out + p, outsz - p, "setcc");
    } else if (cat == XED_CATEGORY_CMOV) {
        p += (size_t) snprintf(out + p, outsz - p, "cmovcc");
    } else {
        const char *mn = xed_iclass_enum_t2str(ic);
        for (size_t i = 0; mn[i] != '\0' && p + 1 < outsz; ++i) {
            out[p++] = (char) (mn[i] >= 'A' && mn[i] <= 'Z'
                ? mn[i] - 'A' + 'a' : mn[i]);
        }
        out[p] = '\0';
    }

    const xed_inst_t *xi = xed_decoded_inst_inst(xedd);
    unsigned nops = xed_inst_noperands(xi);
    unsigned printed = 0;
    unsigned mi = 0;
    for (unsigned i = 0; i < nops && p + 24 < outsz; ++i) {
        const xed_operand_t *op = xed_inst_operand(xi, i);
        xed_operand_enum_t name = xed_operand_name(op);
        char part[48];
        if (xed_operand_is_register(name)) {
            reg_class(xed_decoded_inst_get_reg(xedd, name), part,
                sizeof(part));
        } else if (name == XED_OPERAND_MEM0 || name == XED_OPERAND_MEM1) {
            mem_shape(xedd, mi++, false, part, sizeof(part));
        } else if (name == XED_OPERAND_AGEN) {
            mem_shape(xedd, mi++, true, part, sizeof(part));
        } else if (name == XED_OPERAND_IMM0) {
            imm_class(xedd, part, sizeof(part));
        } else if (name == XED_OPERAND_IMM1) {
            snprintf(part, sizeof(part), "#i2");
        } else if (name == XED_OPERAND_RELBR) {
            snprintf(part, sizeof(part), "rel");
        } else if (name == XED_OPERAND_PTR) {
            snprintf(part, sizeof(part), "ptr");
        } else {
            continue;
        }
        // Suppressed operands are pure opcode semantics -- RFLAGS, the stack
        // pointer -- and stay out of the shape, though they still count for
        // dependencies. Implicit ones are printed in parentheses: the
        // accumulator short forms (cmp eax, imm32 as 0x3d) hold their register
        // there, and dropping it would render them as a bare "cmp #i" while
        // still, correctly, keeping them a distinct shape from the modrm
        // encoding that x86lint's implicit-register check compares them to.
        xed_operand_visibility_enum_t vis =
            xed_operand_operand_visibility(op);
        if (vis == XED_OPVIS_SUPPRESSED) {
            continue;
        }
        p += (size_t) snprintf(out + p, outsz - p,
            vis == XED_OPVIS_IMPLICIT ? "%c(%s)" : "%c%s",
            printed++ == 0 ? ' ' : ',', part);
    }
}

// Keys are long-lived and numerous (a large corpus reaches six figures of
// distinct shapes), so the table is a plain open-addressed counter sized well
// past any observed load.
#define HASH_BITS 22
#define HASH_SIZE (1u << HASH_BITS)

typedef struct {
    char *key;
    uint64_t count;
} entry;

static entry *table;
static size_t table_used;
static uint64_t dropped_keys;
static uint64_t total_pairs;
static uint64_t total_insns;
static uint64_t total_skipped;

static void bump(const char *key)
{
    uint32_t h = 5381;
    for (const char *s = key; *s != '\0'; ++s) {
        h = h * 33 + (uint8_t) *s;
    }
    h &= HASH_SIZE - 1;
    for (;;) {
        if (table[h].key == NULL) {
            // Stop before the open-addressed probe can run out of empty
            // slots, which would spin. A corpus large enough to reach this
            // gets a count on stderr rather than silent truncation.
            if (table_used >= HASH_SIZE / 4 * 3) {
                dropped_keys++;
                return;
            }
            table[h].key = strdup(key);
            table[h].count = 1;
            table_used++;
            return;
        }
        if (strcmp(table[h].key, key) == 0) {
            table[h].count++;
            return;
        }
        h = (h + 1) & (HASH_SIZE - 1);
    }
}

static const char *example_substr;
static long example_max = 20;
static long example_printed;

// Straight-line region enders: after these the next instruction is not the
// fallthrough of this one.
static bool ends_region(const xed_decoded_inst_t *xedd)
{
    switch (xed_decoded_inst_get_category(xedd)) {
    case XED_CATEGORY_UNCOND_BR:
    case XED_CATEGORY_RET:
        return true;
    default:
        break;
    }
    switch (xed_decoded_inst_get_iclass(xedd)) {
    case XED_ICLASS_UD0:
    case XED_ICLASS_UD1:
    case XED_ICLASS_UD2:
    case XED_ICLASS_INT3:
    case XED_ICLASS_HLT:
        return true;               // trap or inter-function padding
    default:
        return false;
    }
}

static void scan_range(const corpus_section *sec, uint64_t start, uint64_t end)
{
    bool have_prev = false;
    char prev_tok[192];
    char prev_text[128];
    uint64_t prev_addr = 0;
    struct slots prev_wr = { { 0 }, 0 };
    uint32_t prev_wflags = 0;

    for (uint64_t offset = start; offset < end;) {
        xed_decoded_inst_t xedd;
        corpus_decode_init(&xedd);
        if (xed_decode(&xedd, sec->code + offset, end - offset) !=
                XED_ERROR_NONE) {
            total_skipped++;
            have_prev = false;
            offset += 1;
            continue;
        }
        total_insns++;

        char tok[192];
        build_token(&xedd, tok, sizeof(tok));
        struct slots rd, wr;
        collect_regs(&xedd, &rd, &wr);
        uint32_t rflags, wflags;
        collect_flags(&xedd, &rflags, &wflags);

        // A side entry reaches this instruction without the previous one, so
        // the two are not reliably adjacent in execution.
        if (have_prev && !corpus_is_target(sec->targets, offset)) {
            bool dep = false, waw = false;
            for (int i = 0; i < prev_wr.n; ++i) {
                if (slots_has(&rd, prev_wr.s[i])) {
                    dep = true;
                }
                if (slots_has(&wr, prev_wr.s[i]) &&
                    !slots_has(&rd, prev_wr.s[i])) {
                    waw = true;
                }
            }
            bool fdep = (prev_wflags & rflags) != 0;
            bool fdead = prev_wflags != 0 && (prev_wflags & rflags) == 0 &&
                (prev_wflags & ~wflags) == 0;

            char flags[32];
            snprintf(flags, sizeof(flags), "%s%s%s%s%s",
                dep ? "dep" : "", waw ? (dep ? ",waw" : "waw") : "",
                fdep ? (dep || waw ? ",fdep" : "fdep") : "",
                fdead ? (dep || waw || fdep ? ",fdead" : "fdead") : "",
                !dep && !waw && !fdep && !fdead ? "-" : "");

            char key[440];
            snprintf(key, sizeof(key), "%s || %s || %s", prev_tok, tok, flags);
            bump(key);
            total_pairs++;

            if (example_substr != NULL && example_printed < example_max &&
                strstr(key, example_substr) != NULL) {
                char disasm[96];
                if (!xed_format_context(XED_SYNTAX_INTEL, &xedd, disasm,
                        sizeof(disasm), sec->vaddr + offset, NULL, NULL)) {
                    disasm[0] = '\0';
                }
                printf("EX %s %#" PRIx64 ": %s ;; %s\n", sec->path, prev_addr,
                    prev_text, disasm);
                example_printed++;
            }
        }

        uint64_t next = offset + xed_decoded_inst_get_length(&xedd);
        if (ends_region(&xedd)) {
            have_prev = false;
        } else {
            have_prev = true;
            memcpy(prev_tok, tok, sizeof(prev_tok));
            prev_wr = wr;
            prev_wflags = wflags;
            prev_addr = sec->vaddr + offset;
            if (example_substr != NULL &&
                !xed_format_context(XED_SYNTAX_INTEL, &xedd, prev_text,
                    sizeof(prev_text), prev_addr, NULL, NULL)) {
                prev_text[0] = '\0';
            }
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

static int cmp_entry(const void *a, const void *b)
{
    const entry *ea = a, *eb = b;
    if (ea->count != eb->count) {
        return eb->count > ea->count ? 1 : -1;
    }
    return strcmp(ea->key, eb->key);
}

static void usage(const char *argv0)
{
    fprintf(stderr,
        "usage: %s [-a] [-e SUBSTR [-n MAX]] [-t TOP] <binary>...\n", argv0);
}

int main(int argc, char **argv)
{
    bool scan_all = false;
    long top = 0;
    int argi = 1;
    for (; argi < argc && argv[argi][0] == '-' && argv[argi][1] != '\0';
         ++argi) {
        if (strcmp(argv[argi], "-a") == 0) {
            scan_all = true;
        } else if (strcmp(argv[argi], "-e") == 0 && argi + 1 < argc) {
            example_substr = argv[++argi];
        } else if (strcmp(argv[argi], "-n") == 0 && argi + 1 < argc) {
            example_max = atol(argv[++argi]);
        } else if (strcmp(argv[argi], "-t") == 0 && argi + 1 < argc) {
            top = atol(argv[++argi]);
        } else {
            usage(argv[0]);
            return 2;
        }
    }
    if (argi >= argc) {
        usage(argv[0]);
        return 2;
    }

    table = calloc(HASH_SIZE, sizeof(*table));
    if (table == NULL) {
        fprintf(stderr, "failed to allocate the pair table\n");
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
    qsort(flat, n, sizeof(*flat), cmp_entry);

    fprintf(stderr, "pairs=%" PRIu64 " distinct=%zu instructions=%" PRIu64
        " skipped=%" PRIu64 "\n", total_pairs, n, total_insns, total_skipped);
    if (dropped_keys != 0) {
        fprintf(stderr, "warning: table full, %" PRIu64 " pairs uncounted;"
            " raise HASH_BITS\n", dropped_keys);
    }
    size_t limit = top > 0 && (size_t) top < n ? (size_t) top : n;
    for (size_t i = 0; i < limit; ++i) {
        printf("%10" PRIu64 "  %s\n", flat[i].count, flat[i].key);
    }
    return rc;
}
