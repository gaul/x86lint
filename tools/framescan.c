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

// framescan: size the frame-layout counterfactual -- of the bytes a binary
// pays for 32-bit displacements on its stack-slot accesses, how many a
// frequency-aware slot order would recover.
//
// A frame slot more than 127 bytes from its base register costs a disp32
// where a nearer one costs a disp8, three bytes on every access. No
// instruction check can see this: each access is correctly encoded for the
// offset it was given, and the cost lives in a choice the compiler made once
// per function, which slot goes where. That is the same shape as the
// register census's finding (x86lint -r): a per-instruction scan sums the
// bytes, and only a whole-function view can say which of them a different
// allocation would have saved. A quick objdump pass put the disp32 bytes at
// 7.4% of /bin/go's .text and 4.0% of libLLVM's, against 0.09% of glibc's;
// register numbering costs 2.2-2.9%. This tool exists to split that sum into
// the part a reordering recovers and the part the frame's size makes
// structural, which is the question the sum alone cannot answer.
//
// What is measured. Every function is a `.symtab` range (there is no `-a`:
// without function boundaries there is no frame to reason about, and a
// stripped binary is reported as unmeasurable rather than guessed at). Each
// explicit memory operand -- LEA's address included, PUSH's and CALL's
// implicit stack operands excluded -- whose base is RSP, or RBP in a
// function that establishes a frame pointer by x86lint's own rule
// (`push rbp ; mov rbp, rsp` within the first four instructions, nothing
// having written rbp before), is a frame-slot access. Its cost is the
// displacement width XED decoded, 0, 8 or 32 bits; nothing is inferred from
// the value.
//
// A slot is identified by where it sits relative to the return address, so
// that one slot keeps one identity across the function. RSP-relative
// displacements are normalized by the depth RSP has reached in a linear
// walk -- pushes, pops, `sub`/`add rsp, imm`, `lea rsp`, `leave`, and
// `mov rsp, rbp` are tracked, and the depth resets to the function body's
// after a `ret` or `jmp`, since the next block starts at the body's depth and
// not the epilogue's. An outgoing-argument `push` therefore does not make
// `[rsp+0x20]` and `[rsp+0x18]` two slots. A function that assigns RSP from
// anything else (alloca, `and rsp` alignment) is counted as dynamic; its
// accesses are still tallied, with the depth frozen where tracking stopped.
// RBP-relative displacements need no tracking: RBP is the entry RSP minus 8.
//
// Slots then fall into three classes by position. At or above the return
// address are incoming arguments, which the ABI fixes. Between the return
// address and the frame allocation lie the pushed callee-saved registers,
// fixed by the prologue. Below that are the locals and spills, the only
// slots a layout chooses, and the only ones the counterfactual moves.
//
// The counterfactual. A disp8 reaches 128 bytes below RBP, or 128 bytes
// above RSP. For each base register in each function the tool asks: which
// set of local slots, each taking its widest access as its size (rounded up
// to a power of two, so natural alignment packs without waste; an LEA with
// no width counts as 8), fits in those 128 bytes and covers the most
// accesses? That is a 0/1 knapsack over 128 bytes of capacity, solved
// exactly. The accesses it covers would pay a disp8; the accesses that pay
// one today are known; three bytes times the difference is what reordering
// recovers in that function, never less than zero. Everything else the
// disp32 accesses pay is structural: arguments the ABI placed, saved
// registers the prologue placed, and locals that do not fit near the base
// because the frame is simply larger than the window.
//
// Where the estimate leans optimistic, and knowingly. Slots are independent,
// so two fields of one struct can be moved apart; an LEA's slot is sized at
// 8 bytes where the array behind it may be much larger; stack-passed outgoing
// arguments sit at the bottom of the frame by ABI but are not distinguishable
// from locals, so the knapsack may evict them; Go's saved frame pointer lives
// in the frame as a local does. Where it leans pessimistic: a slot keeps its
// base register, where a compiler with both could address a slot from either
// end, and a disp0 (`[rsp]`) is counted as a disp8. And it weighs accesses by
// static count, which is the only weight a binary carries. Where a build has
// said more -- a `.cold` fragment from GCC's or LLVM's hot/cold split is code
// the profile says does not run -- the tool believes it: fragments' accesses
// are tallied but weigh nothing in the counterfactual, since a layout driven
// by frequency would already have placed them last. Every one of these is a
// reason to read the result as a bound, and the first measurement in any
// direction should be checked against a dumped slot table (`-f`).
//
// Usage: framescan [-v] [-m] [-n MAX] [-f SUBSTR] [-c ADDR] <binary>...
//   -v  list the functions with the most recoverable bytes
//   -n  how many to list (default 16)
//   -c  treat every function starting below vaddr ADDR as profile-cold, like
//       a .cold fragment: tallied, not weighed. GCC's hot/cold split under
//       PGO lays the whole cold partition out first, fragments and whole
//       cold functions alike, so the end of the highest .cold fragment
//       bounds it (tools/split.py's --cold-below is the same knob)
//   -f  dump the slot table of every function whose name contains SUBSTR
//       (up to eight functions), for checking the model against objdump
//   -m  dump the first eight functions behind the "tracking miss" count: a
//       local slot paying a disp32 inside a frame the walk sized at 128
//       bytes or less, which is a contradiction the model owes an answer for

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "corpus.h"

// Bytes a disp8 reaches on the side of the base register where locals live:
// below RBP, above RSP.
#define WINDOW 128

// How many instructions into a function the frame-pointer prologue may
// begin. Mirrors FRAME_PROLOGUE_WINDOW in x86lint.c, whose measurement it
// rests on: zero misses every CET function (`endbr64` first) and Go's
// stack-growth check, and four saturates.
#define FRAME_PROLOGUE_WINDOW 4

#define TOP_MAX 64
#define TOP_DEFAULT 16
#define DUMP_MAX 8

enum base { BASE_RSP, BASE_RBP, NBASE };
static const char *const base_name[NBASE] = { "rsp", "rbp" };

enum slot_class { CLASS_LOCAL, CLASS_SAVED, CLASS_ARG, NCLASS };
static const char *const class_name[NCLASS] = {
    "locals", "saved registers", "incoming arguments"
};

// Displacement widths XED reports in 64-bit mode, indexed 0/8/32 -> 0/1/2.
enum width { W0, W8, W32, NWIDTH };

struct slot {
    bool used;
    uint8_t base;
    int64_t key;          // bytes from the return address; negative is below
    uint32_t size;        // widest access in bytes; an LEA counts as 8
    uint64_t accesses;
    uint64_t narrow;      // accesses encoded with 0 or 8 displacement bits
    uint64_t wide;        // accesses encoded with 32
    uint64_t lea;
    uint64_t site;        // vaddr of the first access, for objdump
};

struct slots {
    struct slot *v;
    size_t cap;           // zero or a power of two
    size_t n;
};

static uint64_t slot_hash(uint8_t base, int64_t key)
{
    uint64_t h = (uint64_t) key * 0x9E3779B97F4A7C15ull;
    h ^= (uint64_t) base << 61;
    return h ^ (h >> 29);
}

static bool slots_grow(struct slots *s)
{
    size_t ncap = s->cap == 0 ? 64 : s->cap * 2;
    struct slot *nv = calloc(ncap, sizeof(*nv));
    if (nv == NULL) {
        return false;
    }
    for (size_t i = 0; i < s->cap; ++i) {
        if (!s->v[i].used) {
            continue;
        }
        size_t j = slot_hash(s->v[i].base, s->v[i].key) & (ncap - 1);
        while (nv[j].used) {
            j = (j + 1) & (ncap - 1);
        }
        nv[j] = s->v[i];
    }
    free(s->v);
    s->v = nv;
    s->cap = ncap;
    return true;
}

// The slot for (base, key), inserted if absent; NULL only on allocation
// failure, which the caller counts rather than hides.
static struct slot *slot_lookup(struct slots *s, uint8_t base, int64_t key)
{
    if ((s->n + 1) * 2 > s->cap && !slots_grow(s)) {
        return NULL;
    }
    size_t j = slot_hash(base, key) & (s->cap - 1);
    while (s->v[j].used) {
        if (s->v[j].base == base && s->v[j].key == key) {
            return &s->v[j];
        }
        j = (j + 1) & (s->cap - 1);
    }
    s->v[j].used = true;
    s->v[j].base = base;
    s->v[j].key = key;
    ++s->n;
    return &s->v[j];
}

// Empty the table for the next function. A table a huge function grew is
// released rather than cleared, so the clearing cost stays proportional to
// the typical function and not the largest one seen.
static void slots_reset(struct slots *s)
{
    if (s->cap > 4096) {
        free(s->v);
        s->v = NULL;
        s->cap = 0;
    } else if (s->v != NULL) {
        memset(s->v, 0, s->cap * sizeof(*s->v));
    }
    s->n = 0;
}

static int slot_key_cmp(const void *a, const void *b)
{
    const struct slot *sa = a, *sb = b;
    if (sa->base != sb->base) {
        return sa->base < sb->base ? -1 : 1;
    }
    if (sa->key != sb->key) {
        return sa->key < sb->key ? -1 : 1;
    }
    return 0;
}

struct func {
    uint64_t vaddr;
    const char *name;
    bool fragment;        // profile-cold: a .cold fragment, or below -c
    bool cold_by_address; // ... the latter
    bool frame_pointer;
    bool dynamic;         // RSP assigned from something the walk cannot follow
    bool calls;           // not a leaf: the red zone below RSP is not its to use
    bool allocated;       // the frame allocation has happened: saved_bytes is final
    bool body_known;
    int64_t depth;        // bytes RSP sits below its value at entry
    int64_t saved_bytes;  // depth from the pushes before the frame allocation
    int64_t body_depth;   // depth at the first slot access or call
    size_t index;         // instructions seen
    bool prev_push_rbp;
    bool rbp_clobbered;
    bool prev_sub_page;   // the last instruction was `sub rsp, k * 4096`
    // A register holding where a stack-clash probe loop will leave RSP:
    // `lea r11, [rsp - N]` (or `mov r11, rsp ; sub r11, N`) before the loop,
    // `cmp rsp, r11 ; jne` at its end.
    xed_reg_enum_t probe_reg;
    int64_t probe_depth;
    uint64_t alloc_failures;
};

struct top {
    uint64_t vaddr;
    char *name;           // a copy: the mapping the symbol lives in is gone
                          // by the time the report prints
    uint64_t recoverable;
    uint64_t accesses;
    uint64_t wide;
    int64_t locals;
    size_t nslots;
};

struct totals {
    struct slots slots;
    // Scope.
    uint64_t functions, fragments, cold_functions, frame_pointer, dynamic;
    uint64_t sections_without_symbols, bytes_without_symbols;
    bool minidebug;             // the ranges came from .gnu_debugdata
    uint64_t insns, skipped, code_bytes, alloc_failures;
    // Every frame-slot access, by displacement width.
    uint64_t accesses[NWIDTH];
    uint64_t lea;
    // disp32 accesses by class, and in cold fragments.
    uint64_t wide_class[NCLASS];
    uint64_t wide_cold, accesses_cold;
    // The counterfactual.
    uint64_t recoverable, recoverable_base[NBASE], funcs_recoverable;
    uint64_t narrow_local, wide_local;     // locals in non-fragment functions
    uint64_t unfittable;                    // local slots wider than the window
    // Frame sizes: locals below the saved registers, non-fragment functions.
    uint64_t frames_none, frames_small, frames_mid, frames_large;
    uint64_t wide_local_small;              // locals paying disp32 in a frame <= WINDOW
    // Reporting.
    struct top top[TOP_MAX];
    size_t ntop;
    size_t dumped;
    size_t dumped_miss;
};

static bool verbose = false;
static bool miss_dump = false;
static size_t top_n = TOP_DEFAULT;
static const char *dump_substr = NULL;
static uint64_t cold_below = 0;

static void usage(const char *argv0)
{
    fprintf(stderr, "usage: %s [-v] [-m] [-n MAX] [-f SUBSTR] [-c ADDR]"
            " <binary>...\n", argv0);
}

// === the frame-pointer prologue, as x86lint.c judges it ===

static bool is_push_rbp(const xed_decoded_inst_t *xedd)
{
    return xed_decoded_inst_get_iclass(xedd) == XED_ICLASS_PUSH &&
        xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0) == XED_REG_RBP;
}

static bool is_mov_rbp_rsp(const xed_decoded_inst_t *xedd)
{
    return xed_decoded_inst_get_iclass(xedd) == XED_ICLASS_MOV &&
        xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0) == XED_REG_RBP &&
        xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1) == XED_REG_RSP;
}

// Whether the instruction writes `reg` (RBP or RSP) at any width, through
// any register operand, suppressed ones included.
static bool writes_reg64(const xed_decoded_inst_t *xedd, xed_reg_enum_t reg)
{
    const xed_inst_t *xi = xed_decoded_inst_inst(xedd);
    unsigned n = xed_inst_noperands(xi);
    for (unsigned i = 0; i < n; ++i) {
        const xed_operand_t *op = xed_inst_operand(xi, i);
        xed_operand_enum_t name = xed_operand_name(op);
        if (!xed_operand_is_register(name) || !xed_operand_written(op)) {
            continue;
        }
        if (xed_get_largest_enclosing_register(
                xed_decoded_inst_get_reg(xedd, name)) == reg) {
            return true;
        }
    }
    return false;
}

static void frame_pointer_step(struct func *f, const xed_decoded_inst_t *xedd)
{
    if (f->frame_pointer || f->rbp_clobbered ||
        f->index > FRAME_PROLOGUE_WINDOW) {
        return;
    }
    if (f->prev_push_rbp && is_mov_rbp_rsp(xedd)) {
        f->frame_pointer = true;
        return;
    }
    f->prev_push_rbp = f->index < FRAME_PROLOGUE_WINDOW && is_push_rbp(xedd);
    if (!f->prev_push_rbp && writes_reg64(xedd, XED_REG_RBP)) {
        f->rbp_clobbered = true;
    }
}

// === depth tracking ===

// The frame allocation is the first `sub rsp`, `and rsp` or `lea rsp`, or
// failing one of those the first slot access or call: whatever the depth is
// then came from pushes, and that is the saved-register area.
static void mark_allocated(struct func *f)
{
    if (!f->allocated) {
        f->allocated = true;
        f->saved_bytes = f->depth;
    }
}

static void mark_body(struct func *f)
{
    mark_allocated(f);
    if (!f->body_known) {
        f->body_known = true;
        f->body_depth = f->depth;
    }
}

static bool has_immediate(const xed_decoded_inst_t *xedd)
{
    return xed_decoded_inst_get_immediate_width_bits(xedd) != 0;
}

// A stack-clash probe: `or [rsp], 0` (GCC) or `mov qword [rsp], 0` touching
// the page a `sub rsp, 4096` just reached. It is not a slot, and taking it for
// one is wrong twice over: in the loop form the depth it sits at is one the
// loop passes through again, and in both forms it would fix the body's depth
// before the remainder of the frame is allocated. Only the store right after a
// page-sized `sub` qualifies, so a real zero store to `[rsp]` is still counted.
static bool is_stack_probe(const struct func *f, const xed_decoded_inst_t *xedd)
{
    xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass(xedd);
    if (!f->prev_sub_page ||
        (iclass != XED_ICLASS_OR && iclass != XED_ICLASS_MOV) ||
        xed_decoded_inst_number_of_memory_operands(xedd) != 1 ||
        !has_immediate(xedd) ||
        xed_decoded_inst_get_signed_immediate(xedd) != 0) {
        return false;
    }
    return xed_decoded_inst_get_base_reg(xedd, 0) == XED_REG_RSP &&
        xed_decoded_inst_get_index_reg(xedd, 0) == XED_REG_INVALID &&
        xed_decoded_inst_get_memory_displacement(xedd, 0) == 0 &&
        xed_decoded_inst_mem_written(xedd, 0);
}

// Apply the instruction's effect on RSP after its operands have been read.
static void depth_step(struct func *f, const xed_decoded_inst_t *xedd)
{
    xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass(xedd);
    xed_reg_enum_t reg0 = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);
    f->prev_sub_page = false;
    switch (iclass) {
    case XED_ICLASS_PUSH:
    case XED_ICLASS_PUSHF:
    case XED_ICLASS_PUSHFQ:
        f->depth += 8;
        return;
    case XED_ICLASS_POP:
    case XED_ICLASS_POPF:
    case XED_ICLASS_POPFQ:
        f->depth -= 8;
        return;
    case XED_ICLASS_SUB:
    case XED_ICLASS_ADD:
        if (reg0 == XED_REG_RSP) {
            if (!has_immediate(xedd)) {
                f->dynamic = true;
                return;
            }
            mark_allocated(f);
            int64_t imm = xed_decoded_inst_get_signed_immediate(xedd);
            f->depth += iclass == XED_ICLASS_SUB ? imm : -imm;
            f->prev_sub_page = iclass == XED_ICLASS_SUB && imm >= 4096 &&
                imm % 4096 == 0;
        } else if (reg0 != XED_REG_INVALID && reg0 == f->probe_reg &&
                   has_immediate(xedd)) {
            int64_t imm = xed_decoded_inst_get_signed_immediate(xedd);
            f->probe_depth += iclass == XED_ICLASS_SUB ? imm : -imm;
        }
        return;
    case XED_ICLASS_CMP: {
        // The probe loop's exit test: when it falls through, RSP is where
        // the register says.
        xed_reg_enum_t reg1 = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1);
        if (f->probe_reg != XED_REG_INVALID &&
            ((reg0 == XED_REG_RSP && reg1 == f->probe_reg) ||
             (reg0 == f->probe_reg && reg1 == XED_REG_RSP))) {
            f->depth = f->probe_depth;
        }
        return;
    }
    case XED_ICLASS_AND:
        if (reg0 == XED_REG_RSP) {
            mark_allocated(f);
            f->dynamic = true;
        }
        return;
    case XED_ICLASS_LEA: {
        xed_reg_enum_t base = xed_decoded_inst_get_base_reg(xedd, 0);
        int64_t disp = xed_decoded_inst_get_memory_displacement(xedd, 0);
        bool indexed = xed_decoded_inst_get_index_reg(xedd, 0) != XED_REG_INVALID;
        if (reg0 == XED_REG_RSP) {
            mark_allocated(f);
            if (indexed) {
                f->dynamic = true;
            } else if (base == XED_REG_RSP) {
                f->depth -= disp;
            } else if (base == XED_REG_RBP && f->frame_pointer) {
                f->depth = 8 - disp;
            } else {
                f->dynamic = true;
            }
        } else if (!f->body_known && reg0 != XED_REG_RBP &&
                   base == XED_REG_RSP && !indexed) {
            // Before the body, a register set to RSP minus a constant is a
            // probe loop's target (GCC), or Go's stack-growth check; neither
            // is a slot.
            f->probe_reg = reg0;
            f->probe_depth = f->depth - disp;
        }
        return;
    }
    case XED_ICLASS_MOV:
        if (reg0 == XED_REG_RSP) {
            if (xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1) ==
                    XED_REG_RBP && f->frame_pointer) {
                f->depth = 8;
            } else {
                f->dynamic = true;
            }
        } else if (!f->body_known && reg0 != XED_REG_RBP &&
                   reg0 != XED_REG_INVALID &&
                   xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1) ==
                       XED_REG_RSP) {
            f->probe_reg = reg0;
            f->probe_depth = f->depth;
        }
        return;
    case XED_ICLASS_LEAVE:
        f->depth = 0;
        return;
    case XED_ICLASS_CALL_NEAR:
    case XED_ICLASS_CALL_FAR:
        f->calls = true;
        mark_body(f);
        return;
    case XED_ICLASS_RET_NEAR:
    case XED_ICLASS_RET_FAR:
    case XED_ICLASS_JMP:
    case XED_ICLASS_JMP_FAR:
    case XED_ICLASS_UD2:
    case XED_ICLASS_HLT:
        // The next instruction begins a block control reaches from the body,
        // at the body's depth and not the epilogue's.
        if (f->body_known) {
            f->depth = f->body_depth;
        }
        return;
    default:
        if (writes_reg64(xedd, XED_REG_RSP)) {
            f->dynamic = true;
        }
        return;
    }
}

// === accesses ===

static enum width width_of(unsigned bits)
{
    return bits == 0 ? W0 : bits == 8 ? W8 : W32;
}

static void record_access(struct func *f, struct totals *t,
                          const xed_decoded_inst_t *xedd, unsigned m,
                          bool is_lea, uint64_t vaddr)
{
    xed_reg_enum_t breg = xed_decoded_inst_get_base_reg(xedd, m);
    int64_t disp = xed_decoded_inst_get_memory_displacement(xedd, m);
    uint8_t base;
    int64_t key;
    if (breg == XED_REG_RSP) {
        base = BASE_RSP;
        key = f->fragment ? disp : disp - f->depth;
    } else if (breg == XED_REG_RBP && f->frame_pointer) {
        base = BASE_RBP;
        key = disp - 8;
    } else {
        return;
    }
    // An address taken from RSP before the frame exists is not a slot: Go's
    // stack-growth check (`lea r12, [rsp - N]`) and GCC's probe-loop target
    // (`lea r11, [rsp - N]`) both compute where RSP is about to go.
    if (is_lea && !f->allocated && !f->fragment) {
        return;
    }
    // A read of an incoming argument says nothing about the frame: it may
    // precede the allocation, as hand-written assembly often arranges. Only a
    // slot below the return address proves the frame is in place.
    if (!f->fragment && key < 0) {
        mark_body(f);
    }
    enum width w = width_of(
        xed_decoded_inst_get_memory_displacement_width_bits(xedd, m));
    unsigned len = is_lea ? 0 : xed_decoded_inst_get_memory_operand_length(xedd, m);
    struct slot *s = slot_lookup(&t->slots, base, key);
    if (s == NULL) {
        ++f->alloc_failures;
        return;
    }
    if (s->accesses == 0) {
        s->site = vaddr;
    }
    ++s->accesses;
    if (w == W32) {
        ++s->wide;
    } else {
        ++s->narrow;
    }
    if (is_lea) {
        ++s->lea;
        ++t->lea;
        if (s->size == 0) {
            s->size = 8;
        }
    } else if (len > s->size) {
        s->size = len;
    }
    ++t->accesses[w];
}

static void visit(struct func *f, struct totals *t,
                  const xed_decoded_inst_t *xedd, uint64_t vaddr)
{
    if (!f->fragment) {
        frame_pointer_step(f, xedd);
    }
    bool is_lea = xed_decoded_inst_get_iclass(xedd) == XED_ICLASS_LEA;
    const xed_inst_t *xi = xed_decoded_inst_inst(xedd);
    unsigned n = f->fragment || !is_stack_probe(f, xedd)
        ? xed_inst_noperands(xi) : 0;
    for (unsigned i = 0; i < n; ++i) {
        const xed_operand_t *op = xed_inst_operand(xi, i);
        xed_operand_enum_t name = xed_operand_name(op);
        unsigned m;
        if (name == XED_OPERAND_MEM0 || name == XED_OPERAND_AGEN) {
            m = 0;
        } else if (name == XED_OPERAND_MEM1) {
            m = 1;
        } else {
            continue;
        }
        // PUSH, POP, CALL and RET address the stack through an operand the
        // disassembly does not show and no displacement byte encodes.
        if (xed_operand_operand_visibility(op) == XED_OPVIS_SUPPRESSED) {
            continue;
        }
        record_access(f, t, xedd, m, is_lea, vaddr);
    }
    if (!f->fragment) {
        depth_step(f, xedd);
    }
    ++f->index;
}

// === the counterfactual ===

static uint32_t round_pow2(uint32_t v)
{
    uint32_t p = 1;
    while (p < v) {
        p <<= 1;
    }
    return p;
}

// The most accesses any set of local slots fitting in `capacity` bytes
// covers, for one base register: a 0/1 knapsack over at most 129 capacities.
// `local` is the function's local slots, already classified.
static uint64_t best_in_window(const struct slot *const *local, size_t n,
                               uint8_t base, int capacity,
                               uint64_t *unfittable)
{
    uint64_t best[WINDOW + 1] = { 0 };
    if (capacity <= 0) {
        return 0;
    }
    for (size_t i = 0; i < n; ++i) {
        const struct slot *s = local[i];
        if (s->base != base) {
            continue;
        }
        uint32_t size = round_pow2(s->size == 0 ? 1 : s->size);
        if (size > WINDOW) {
            ++*unfittable;
            continue;
        }
        if ((int) size > capacity) {
            continue;
        }
        for (int c = capacity; c >= (int) size; --c) {
            uint64_t with = best[c - size] + s->accesses;
            if (with > best[c]) {
                best[c] = with;
            }
        }
    }
    return best[capacity];
}

// How much of a base register's disp8 window is left for locals. Above RSP
// the window is the bottom of the frame and all of it is locals. Below RBP
// the pushed callee-saved registers come first -- the saved RBP itself sits
// at [rbp], outside the window -- so a function that pushes five registers
// has 88 bytes of reach for its locals, not 128. A layout cannot move the
// pushes, so the knapsack must not count their bytes as available.
static int window_capacity(const struct func *f, uint8_t base)
{
    if (base == BASE_RSP) {
        return WINDOW;
    }
    int64_t pushed = f->saved_bytes - 8;
    if (pushed < 0) {
        pushed = 0;
    }
    return pushed >= WINDOW ? 0 : WINDOW - (int) pushed;
}

static enum slot_class classify(const struct func *f, const struct slot *s)
{
    if (s->key >= 0) {
        return CLASS_ARG;
    }
    if (s->key >= -f->saved_bytes) {
        return CLASS_SAVED;
    }
    return CLASS_LOCAL;
}

static void top_insert(struct totals *t, const struct top *entry,
                       const char *name)
{
    if (t->ntop == TOP_MAX &&
        t->top[TOP_MAX - 1].recoverable >= entry->recoverable) {
        return;
    }
    size_t i = t->ntop < TOP_MAX ? t->ntop++ : TOP_MAX - 1;
    free(t->top[i].name);
    t->top[i] = *entry;
    t->top[i].name = name != NULL ? strdup(name) : NULL;
    while (i > 0 && t->top[i - 1].recoverable < t->top[i].recoverable) {
        struct top tmp = t->top[i - 1];
        t->top[i - 1] = t->top[i];
        t->top[i] = tmp;
        --i;
    }
}

static void dump_function(const struct func *f, struct slot *flat, size_t n,
                          uint64_t recoverable)
{
    printf("\n%s at 0x%" PRIx64 ": %s%s%ssaved registers %" PRId64
           " bytes, body depth %" PRId64 ", rbp window %d bytes, recoverable %"
           PRIu64 " bytes\n",
           f->name != NULL ? f->name : "?", f->vaddr,
           f->fragment ? "cold fragment, " : "",
           f->frame_pointer ? "frame pointer, " : "",
           f->dynamic ? "dynamic stack, " : f->calls ? "" : "leaf, ",
           f->saved_bytes, f->body_depth, window_capacity(f, BASE_RBP),
           recoverable);
    printf("  %-4s %8s %-18s %5s %9s %7s %7s %5s  %s\n", "base", "key",
           "class", "size", "accesses", "disp<=8", "disp32", "lea",
           "first site");
    qsort(flat, n, sizeof(*flat), slot_key_cmp);
    for (size_t i = 0; i < n; ++i) {
        const struct slot *s = &flat[i];
        const char *cls = f->fragment ? "cold" : class_name[classify(f, s)];
        printf("  %-4s %8" PRId64 " %-18s %5" PRIu32 " %9" PRIu64
               " %7" PRIu64 " %7" PRIu64 " %5" PRIu64 "  0x%" PRIx64 "\n",
               base_name[s->base], s->key, cls, s->size, s->accesses,
               s->narrow, s->wide, s->lea, s->site);
    }
}

static void finish(struct func *f, struct totals *t)
{
    ++t->functions;
    t->alloc_failures += f->alloc_failures;
    if (f->cold_by_address) {
        ++t->cold_functions;
    } else if (f->fragment) {
        ++t->fragments;
    }
    if (!f->fragment) {
        if (f->frame_pointer) {
            ++t->frame_pointer;
        }
        if (f->dynamic) {
            ++t->dynamic;
        }
    }

    struct slots *sl = &t->slots;
    struct slot *flat = malloc((sl->n == 0 ? 1 : sl->n) * sizeof(*flat));
    const struct slot **local = malloc((sl->n == 0 ? 1 : sl->n) * sizeof(*local));
    if (flat == NULL || local == NULL) {
        ++t->alloc_failures;
        free(flat);
        free(local);
        return;
    }
    size_t n = 0, nlocal = 0;
    uint64_t accesses = 0, wide = 0, narrow_local = 0, wide_local = 0;
    uint64_t wide_local_base[NBASE] = { 0 };
    for (size_t i = 0; i < sl->cap; ++i) {
        if (!sl->v[i].used) {
            continue;
        }
        flat[n] = sl->v[i];
        struct slot *s = &flat[n++];
        accesses += s->accesses;
        wide += s->wide;
        if (f->fragment) {
            t->accesses_cold += s->accesses;
            t->wide_cold += s->wide;
            continue;
        }
        enum slot_class cls = classify(f, s);
        t->wide_class[cls] += s->wide;
        if (cls == CLASS_LOCAL) {
            local[nlocal++] = s;
            narrow_local += s->narrow;
            wide_local += s->wide;
            wide_local_base[s->base] += s->wide;
        }
    }

    uint64_t recoverable = 0;
    if (!f->fragment) {
        t->narrow_local += narrow_local;
        t->wide_local += wide_local;
        int64_t locals = f->body_known ? f->body_depth - f->saved_bytes : 0;
        if (locals < 0) {
            // The body was marked before the pushes: a shrink-wrapped leaf
            // spilling into the red zone ahead of its prologue.
            locals = 0;
        }
        // A disp32 on a local the frame's own extent puts within reach of
        // its base is a contradiction: above RSP the reach is the locals,
        // below RBP the locals plus the pushes in front of them.
        // A dynamic stack is excused: its RSP-relative keys are frozen
        // where the walk lost RSP, and its depth is not the frame's. A leaf
        // reaches 128 bytes further: GCC gives a leaf's locals the red zone
        // below RSP with no `sub rsp` at all, so its frame extends past
        // what it allocated.
        uint64_t miss = 0;
        int64_t reach = locals + (f->calls ? 0 : WINDOW);
        if (!f->dynamic) {
            if (reach <= WINDOW) {
                miss += wide_local_base[BASE_RSP];
            }
            if (reach + (f->saved_bytes - 8) <= WINDOW) {
                miss += wide_local_base[BASE_RBP];
            }
        }
        t->wide_local_small += miss;
        if (miss_dump && miss != 0 && t->dumped_miss < DUMP_MAX) {
            ++t->dumped_miss;
            dump_function(f, flat, n, 0);
        }
        if (locals <= 0) {
            ++t->frames_none;
        } else if (locals <= WINDOW) {
            ++t->frames_small;
        } else if (locals <= 1024) {
            ++t->frames_mid;
        } else {
            ++t->frames_large;
        }
        for (uint8_t b = 0; b < NBASE; ++b) {
            uint64_t now = 0;
            for (size_t i = 0; i < nlocal; ++i) {
                if (local[i]->base == b) {
                    now += local[i]->narrow;
                }
            }
            uint64_t best = best_in_window(local, nlocal, b,
                                           window_capacity(f, b),
                                           &t->unfittable);
            if (best > now) {
                uint64_t r = 3 * (best - now);
                recoverable += r;
                t->recoverable_base[b] += r;
            }
        }
        t->recoverable += recoverable;
        if (recoverable != 0) {
            ++t->funcs_recoverable;
            struct top entry = {
                .vaddr = f->vaddr, .recoverable = recoverable,
                .accesses = accesses, .wide = wide, .locals = locals,
                .nslots = n,
            };
            top_insert(t, &entry, f->name);
        }
    }

    if (dump_substr != NULL && t->dumped < DUMP_MAX && f->name != NULL &&
        strstr(f->name, dump_substr) != NULL) {
        ++t->dumped;
        dump_function(f, flat, n, recoverable);
    }
    free(flat);
    free(local);
}

// === the walk ===

static void scan_section(const corpus_section *sec, void *ctx)
{
    struct totals *t = ctx;
    if (!sec->by_symbol) {
        ++t->sections_without_symbols;
        t->bytes_without_symbols += sec->size;
        return;
    }
    if (sec->minidebug) {
        t->minidebug = true;
    }
    for (size_t r = 0; r < sec->nranges; ++r) {
        const corpus_range *range = &sec->ranges[r];
        bool named_cold = range->name != NULL &&
            strstr(range->name, ".cold") != NULL;
        bool below = cold_below != 0 && sec->vaddr + range->start < cold_below;
        struct func f = {
            .vaddr = sec->vaddr + range->start,
            .name = range->name,
            .fragment = named_cold || below,
            .cold_by_address = below && !named_cold,
        };
        slots_reset(&t->slots);
        t->code_bytes += range->end - range->start;
        for (size_t off = range->start; off < range->end;) {
            xed_decoded_inst_t xedd;
            corpus_decode_init(&xedd);
            if (xed_decode(&xedd, sec->code + off, range->end - off) !=
                    XED_ERROR_NONE) {
                ++off;
                ++t->skipped;
                continue;
            }
            ++t->insns;
            visit(&f, t, &xedd, sec->vaddr + off);
            off += xed_decoded_inst_get_length(&xedd);
        }
        finish(&f, t);
    }
}

static double pct(uint64_t part, uint64_t whole)
{
    return whole == 0 ? 0.0 : 100.0 * (double) part / (double) whole;
}

static void report(const char *path, const struct totals *t)
{
    uint64_t all = t->accesses[W0] + t->accesses[W8] + t->accesses[W32];
    uint64_t extra = 3 * t->accesses[W32];
    printf("framescan: %s\n", path);
    if (t->sections_without_symbols != 0) {
        printf("  %" PRIu64 " executable section%s (%" PRIu64 " bytes) without"
               " .symtab function ranges: not measured, a frame needs a"
               " function\n", t->sections_without_symbols,
               t->sections_without_symbols == 1 ? "" : "s",
               t->bytes_without_symbols);
    }
    if (t->functions == 0) {
        return;
    }
    printf("  functions %" PRIu64 " (frame pointer %" PRIu64 ", dynamic stack %"
           PRIu64 ", cold fragments %" PRIu64,
           t->functions, t->frame_pointer, t->dynamic, t->fragments);
    if (cold_below != 0) {
        printf(", functions below 0x%" PRIx64 " %" PRIu64, cold_below,
               t->cold_functions);
    }
    printf(")%s; instructions %" PRIu64 ", undecodable bytes %" PRIu64 "\n",
           t->minidebug ? ", ranges from .gnu_debugdata" : "", t->insns,
           t->skipped);
    printf("  frame-slot accesses %" PRIu64 ": disp0 %" PRIu64 " (%.1f%%),"
           " disp8 %" PRIu64 " (%.1f%%), disp32 %" PRIu64 " (%.1f%%);"
           " %" PRIu64 " LEA\n",
           all, t->accesses[W0], pct(t->accesses[W0], all), t->accesses[W8],
           pct(t->accesses[W8], all), t->accesses[W32],
           pct(t->accesses[W32], all), t->lea);
    printf("  disp32 costs %" PRIu64 " bytes over disp8 (%.2f%% of %" PRIu64
           " code bytes)\n", extra, pct(extra, t->code_bytes), t->code_bytes);
    printf("  disp32 accesses by slot: locals %" PRIu64 ", saved registers %"
           PRIu64 " (fixed by the prologue), incoming arguments %" PRIu64
           " (fixed by the ABI), in cold fragments %" PRIu64
           " (profile-cold, not weighed)\n",
           t->wide_class[CLASS_LOCAL], t->wide_class[CLASS_SAVED],
           t->wide_class[CLASS_ARG], t->wide_cold);
    uint64_t local_extra = 3 * t->wide_local;
    printf("  counterfactual, local slots reordered by access count within each"
           " base's %d-byte disp8 window (less the pushes, below rbp):\n",
           WINDOW);
    printf("    recoverable %" PRIu64 " bytes (%.1f%% of the disp32 cost, %.1f%%"
           " of the locals' share) in %" PRIu64 " functions; rsp %" PRIu64
           ", rbp %" PRIu64 "\n",
           t->recoverable, pct(t->recoverable, extra),
           pct(t->recoverable, local_extra), t->funcs_recoverable,
           t->recoverable_base[BASE_RSP], t->recoverable_base[BASE_RBP]);
    printf("    structural %" PRIu64 " bytes: locals that do not fit %" PRIu64
           ", saved registers %" PRIu64 ", incoming arguments %" PRIu64
           ", cold fragments %" PRIu64 "\n",
           extra - t->recoverable,
           local_extra > t->recoverable ? local_extra - t->recoverable : 0,
           3 * t->wide_class[CLASS_SAVED], 3 * t->wide_class[CLASS_ARG],
           3 * t->wide_cold);
    printf("  local frame bytes: none %" PRIu64 ", 1-%d %" PRIu64 ", %d-1024 %"
           PRIu64 ", over 1024 %" PRIu64 "; disp32 local accesses in frames of"
           " %d bytes or less: %" PRIu64 " (a tracking miss if not zero);"
           " local slots wider than the window: %" PRIu64 "\n",
           t->frames_none, WINDOW, t->frames_small, WINDOW + 1, t->frames_mid,
           t->frames_large, WINDOW, t->wide_local_small, t->unfittable);
    if (t->alloc_failures != 0) {
        printf("  warning: %" PRIu64 " allocation failures; counts are low\n",
               t->alloc_failures);
    }
    if (verbose && t->ntop != 0) {
        printf("  functions with the most recoverable bytes:\n");
        size_t n = t->ntop < top_n ? t->ntop : top_n;
        for (size_t i = 0; i < n; ++i) {
            const struct top *e = &t->top[i];
            printf("    %8" PRIu64 " bytes  0x%-10" PRIx64 " %s  (locals %"
                   PRId64 " bytes, %zu slots, %" PRIu64 " accesses, %" PRIu64
                   " disp32)\n", e->recoverable, e->vaddr,
                   e->name != NULL ? e->name : "?", e->locals, e->nslots,
                   e->accesses, e->wide);
        }
    }
}

int main(int argc, char **argv)
{
    int argi = 1;
    for (; argi < argc && argv[argi][0] == '-' && argv[argi][1] != '\0';
         ++argi) {
        if (strcmp(argv[argi], "-v") == 0) {
            verbose = true;
        } else if (strcmp(argv[argi], "-m") == 0) {
            miss_dump = true;
        } else if (strcmp(argv[argi], "-n") == 0 && argi + 1 < argc) {
            long n = atol(argv[++argi]);
            top_n = n < 1 ? 1 : n > TOP_MAX ? TOP_MAX : (size_t) n;
        } else if (strcmp(argv[argi], "-f") == 0 && argi + 1 < argc) {
            dump_substr = argv[++argi];
        } else if (strcmp(argv[argi], "-c") == 0 && argi + 1 < argc) {
            cold_below = strtoull(argv[++argi], NULL, 0);
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
        struct totals t;
        memset(&t, 0, sizeof(t));
        if (corpus_scan_file(argv[argi], false, scan_section, &t) != 0) {
            rc = 2;
        } else {
            report(argv[argi], &t);
        }
        free(t.slots.v);
        for (size_t i = 0; i < t.ntop; ++i) {
            free(t.top[i].name);
        }
    }
    return rc;
}
