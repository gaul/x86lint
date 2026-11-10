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

// shapescan: size a named candidate with the rewrite's own conditions
// applied, and say what refused the rest.
//
// pairscan ranks every adjacent pair by a normalized shape to discover what
// is frequent; defuse profiles how far a value's use sits from its
// definition. Neither asks whether a specific rewrite is actually available
// at a site, and that is the question a TODO row turns on. Measuring it ad
// hoc is what this tool exists to stop. The 2026-09 armlint port was sized
// four times with throwaway scripts and was wrong four times:
//
//     LOCK CMPXCHG fetch-op loop      614 shape  ->      19 findings
//     vector memory-operand fold    9,279 shape  ->     583 findings
//     GPR load into a vector move     470 shape  ->      12 findings
//     adjacent zero stores         ~6,000 pairs  ->  20,870 runs
//
// Three overstated the rewrite because a condition went unapplied; the
// fourth counted the wrong unit. A fifth estimate ran the other way, high,
// because its liveness model was a regular expression over disassembly where
// the check uses inst_reads_reg64.
//
// Two decisions follow from that, and they are the whole design.
//
// **A candidate is a draft check, not a description of one.** Every
// candidate above needed operand-role matching, register-family comparison
// across widths, branch-displacement arithmetic, memory-operand
// decomposition, encodability decided by re-encoding through XED, or a
// forward liveness walk. None of that is expressible as a pattern language
// short of a real one, so candidates are C predicates with the same shape as
// x86lint's window checks -- which is why this file includes x86lint.c and
// calls the shipped ones directly. A candidate that earns its place is then
// moved into x86lint.c rather than reimplemented, and a shipped one keeps
// being measured by the code that realizes it.
//
// This is also why the counts here are the driver's and not an
// approximation of them: the same masking of non-function bytes, the same
// branch-target prepass, the same decode loop and resync. A shipped
// candidate must report exactly what x86lint reports, which is this tool's
// own regression test.
//
// **A count without a reason is what went wrong before.** Each candidate
// reports three things: how often the pattern matched at all, how often the
// rewrite was available, and which gate refused the difference. The middle
// number is the finding count; the third is what makes it mean something.
// "9,298 sites become 583" is a fact to be puzzled over; "6,670 of them read
// the loaded register again, because a vector constant lives in a register
// precisely when it is reused" is the answer, and only the breakdown says it.
//
// Usage: shapescan [-a] [-e NAME] [-n MAX] <binary>...
//   -a  scan every byte, not just the symbol table's function ranges
//   -e  print example sites for the candidate whose name contains NAME
//       (an empty NAME matches every candidate)
//   -n  cap the examples printed, per candidate and file (default 8)

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// For the shipped window checks and the gates they call, all of which are
// static: reimplementing them here is exactly the error the tool exists to
// prevent, and widening the public header for internal helpers would be a
// worse trade than one include in one tool.
#include "../x86lint.c"

#include "corpus.h"

#define MAX_REASONS 8

struct tally {
    unsigned long shape;        // the pattern matched
    unsigned long realized;     // and every gate passed
    struct {
        const char *why;        // interned: the gate's own literal
        unsigned long n;
    } refused[MAX_REASONS];
    size_t nrefused;
};

static void tally_refusal(struct tally *t, const char *why)
{
    for (size_t i = 0; i < t->nrefused; ++i) {
        if (t->refused[i].why == why) {
            ++t->refused[i].n;
            return;
        }
    }
    if (t->nrefused < MAX_REASONS) {
        t->refused[t->nrefused].why = why;
        t->refused[t->nrefused].n = 1;
        ++t->nrefused;
    }
}

// A window candidate, called once per decoded instruction with that
// instruction as the window's head. Returns true when the rewrite is
// available; leaves *why untouched when the pattern did not match and sets
// it to the refusing gate's name when it did.
typedef bool (*window_fn)(const uint8_t *inst, size_t len,
                          const uint8_t *targets, size_t offset, size_t next,
                          const xed_decoded_inst_t *xedd, const char **why);

// A run candidate owns its own iteration, for a pattern whose length is not
// fixed. See zero_store_runs.
typedef void (*run_fn)(const uint8_t *inst, size_t len,
                       const uint8_t *targets, struct tally *t,
                       const char *path, uint64_t vaddr,
                       const char *example, long *left);

struct candidate {
    const char *name;
    const char *rewrite;
    window_fn window;
    run_fn run;
};

// === window candidates: the shipped checks, measured as themselves ===

static bool w_vecop(const uint8_t *inst, size_t len, const uint8_t *targets,
                    size_t offset, size_t next, const xed_decoded_inst_t *d,
                    const char **why)
{
    (void) offset;
    return load_foldable_into_vecop(inst, len, targets, next, d, why);
}

static bool w_vec_transfer(const uint8_t *inst, size_t len,
                           const uint8_t *targets, size_t offset, size_t next,
                           const xed_decoded_inst_t *d, const char **why)
{
    (void) offset;
    return load_foldable_into_vec_transfer(inst, len, targets, next, d, why);
}

static bool w_cas(const uint8_t *inst, size_t len, const uint8_t *targets,
                  size_t offset, size_t next, const xed_decoded_inst_t *d,
                  const char **why)
{
    return cas_fetch_op_loop(inst, len, targets, offset, next, d, why);
}

// === window candidates: TODO rows not yet shipped ===
//
// Each is written as the check it would become -- match the pattern, then
// call x86lint's own gates -- so that promoting one is a move. Where a row
// carries a figure from an earlier throwaway script, that figure is named
// here, and a divergence is a disagreement to explain rather than a silent
// correction.

// The explicit register operand at `name`, or XED_REG_INVALID.
static xed_reg_enum_t explicit_reg(const xed_decoded_inst_t *d,
                                   xed_operand_enum_t name)
{
    const xed_inst_t *xi = xed_decoded_inst_inst(d);
    for (unsigned i = 0; i < xed_inst_noperands(xi); ++i) {
        const xed_operand_t *op = xed_inst_operand(xi, i);
        if (xed_operand_name(op) == name &&
            xed_operand_operand_visibility(op) == XED_OPVIS_EXPLICIT &&
            xed_operand_is_register(name)) {
            return xed_decoded_inst_get_reg(d, name);
        }
    }
    return XED_REG_INVALID;
}

// Decode the instruction at `off`, or report failure.
static bool decode_at(const uint8_t *inst, size_t len, size_t off,
                      xed_decoded_inst_t *out)
{
    if (off >= len) {
        return false;
    }
    decode_init(out);
    return xed_decode(out, inst + off, len - off) == XED_ERROR_NONE;
}

// A register-only CMP or TEST whose flags die unread writes nothing at all,
// so it is deletable outright (armlint's check_dead_compare, 315 findings on
// /bin/ls). A memory operand is excluded rather than gated: deleting the
// access removes a fault that may be the point, which is what go's
// `test BYTE PTR [rax], al` nil check is. Measured at 291 in libxul.
// Now shipped; measured through the check itself and the gate the dispatcher
// applies to it, so this row is a regression test on the realized count rather
// than an estimate of it. The table checks return true when there is nothing
// to report, so the sense inverts.
static bool c_dead_compare(const uint8_t *inst, size_t len,
                           const uint8_t *targets, size_t offset, size_t next,
                           const xed_decoded_inst_t *d, const char **why)
{
    (void) targets; (void) offset;
    if (check_dead_compare(d)) {
        return false;
    }
    if (flags_live_after(inst, len, next, FLAG_ARITH)) {
        REFUSE("the flags are live afterward");
    }
    return true;
}

// Now shipped; measured through the check itself. The table checks return
// true when there is nothing to report, so the sense inverts.
static bool c_cmov_self(const uint8_t *inst, size_t len,
                        const uint8_t *targets, size_t offset, size_t next,
                        const xed_decoded_inst_t *d, const char **why)
{
    (void) inst; (void) len; (void) targets; (void) offset; (void) next;
    (void) why;
    return !check_cmov_self(d);
}

// A vector logical or arithmetic instruction naming one register as both
// sources: AND/OR give the operand back, SUB and the signed-compare give
// zero. PXOR and XORPS are excluded, being the canonical zero idioms this
// would otherwise report as findings against themselves.
static bool c_vec_self_op(const uint8_t *inst, size_t len,
                          const uint8_t *targets, size_t offset, size_t next,
                          const xed_decoded_inst_t *d, const char **why)
{
    (void) inst; (void) len; (void) targets; (void) offset; (void) next;
    (void) why;
    switch (xed_decoded_inst_get_iclass(d)) {
    case XED_ICLASS_PAND:  case XED_ICLASS_POR:
    case XED_ICLASS_ANDPS: case XED_ICLASS_ANDPD:
    case XED_ICLASS_ORPS:  case XED_ICLASS_ORPD:
    case XED_ICLASS_PSUBB: case XED_ICLASS_PSUBW:
    case XED_ICLASS_PSUBD: case XED_ICLASS_PSUBQ:
    case XED_ICLASS_PCMPGTB: case XED_ICLASS_PCMPGTW:
    case XED_ICLASS_PCMPGTD:
    // SUBPS and SUBPD are deliberately absent: x - x is +0.0 only for a
    // finite x, and NaN for an infinity or a NaN, so the floating-point
    // self-subtract is not a zeroing idiom and rewriting it to XORPS would
    // change the result. All three of libxul's sites were that spelling.
        break;
    default:
        return false;
    }
    if (xed_decoded_inst_number_of_memory_operands(d) != 0) {
        return false;
    }
    // Legacy two-operand: destination and source are one register. VEX
    // three-operand: the two sources are, and the destination is free.
    xed_reg_enum_t a = explicit_reg(d, XED_OPERAND_REG1);
    xed_reg_enum_t b = explicit_reg(d, XED_OPERAND_REG2);
    if (b != XED_REG_INVALID) {
        return a != XED_REG_INVALID && a == b;
    }
    return a != XED_REG_INVALID && a == explicit_reg(d, XED_OPERAND_REG0);
}

// Now shipped; measured through the check itself.
static bool c_lane0_extract(const uint8_t *inst, size_t len,
                            const uint8_t *targets, size_t offset, size_t next,
                            const xed_decoded_inst_t *d, const char **why)
{
    (void) inst; (void) len; (void) targets; (void) offset; (void) next;
    (void) why;
    return !check_lane0_extract(d);
}

// AND of a 64-bit register with 0xffffffff keeps exactly the low half, which
// a 32-bit register copy does in two bytes. AND writes the flags and MOV
// does not, so they must be dead.
static bool c_and_lo32(const uint8_t *inst, size_t len,
                       const uint8_t *targets, size_t offset, size_t next,
                       const xed_decoded_inst_t *d, const char **why)
{
    (void) targets; (void) offset;
    if (xed_decoded_inst_get_iclass(d) != XED_ICLASS_AND ||
        xed_decoded_inst_number_of_memory_operands(d) != 0 ||
        xed_decoded_inst_get_operand_width(d) != 64 ||
        !xed_operand_values_has_immediate(
            xed_decoded_inst_operands_const(d)) ||
        (uint64_t) xed_decoded_inst_get_unsigned_immediate(d) != 0xffffffffu ||
        explicit_reg(d, XED_OPERAND_REG0) == XED_REG_INVALID) {
        return false;
    }
    if (flags_live_after(inst, len, next, FLAG_ARITH)) {
        REFUSE("the flags are live afterward");
    }
    return true;
}

// Now shipped; measured through the check itself like the three above.
static bool c_branch_to_next(const uint8_t *inst, size_t len,
                             const uint8_t *targets, size_t offset,
                             size_t next, const xed_decoded_inst_t *d,
                             const char **why)
{
    (void) inst; (void) len; (void) targets; (void) offset; (void) next;
    (void) why;
    return !check_branch_to_next(d);
}

// Now shipped; measured through the check itself.
static bool c_neg_add(const uint8_t *inst, size_t len, const uint8_t *targets,
                      size_t offset, size_t next, const xed_decoded_inst_t *d,
                      const char **why)
{
    (void) offset;
    return neg_foldable_into_add_sub(inst, len, targets, next, d, why);
}

// A shift count materialized into CL and used once is an immediate count.
// The two forms mask the count identically and write the same flags, so the
// only condition is that RCX dies with the MOV.
static bool c_mov_cl_shift(const uint8_t *inst, size_t len,
                           const uint8_t *targets, size_t offset, size_t next,
                           const xed_decoded_inst_t *d, const char **why)
{
    (void) offset;
    if (xed_decoded_inst_get_iclass(d) != XED_ICLASS_MOV ||
        xed_decoded_inst_number_of_memory_operands(d) != 0 ||
        !xed_operand_values_has_immediate(
            xed_decoded_inst_operands_const(d))) {
        return false;
    }
    xed_reg_enum_t dest = explicit_reg(d, XED_OPERAND_REG0);
    if (dest == XED_REG_INVALID ||
        xed_get_largest_enclosing_register(dest) != XED_REG_RCX) {
        return false;
    }
    xed_decoded_inst_t use;
    if (!decode_at(inst, len, next, &use)) {
        return false;
    }
    switch (xed_decoded_inst_get_iclass(&use)) {
    case XED_ICLASS_SHL: case XED_ICLASS_SHR: case XED_ICLASS_SAR:
    case XED_ICLASS_ROL: case XED_ICLASS_ROR:
        break;
    default:
        return false;
    }
    bool by_cl = false;
    const xed_inst_t *xi = xed_decoded_inst_inst(&use);
    for (unsigned i = 0; i < xed_inst_noperands(xi); ++i) {
        const xed_operand_t *op = xed_inst_operand(xi, i);
        xed_operand_enum_t nm = xed_operand_name(op);
        by_cl |= xed_operand_is_register(nm) &&
            xed_decoded_inst_get_reg(&use, nm) == XED_REG_CL;
    }
    if (!by_cl) {
        return false;
    }
    size_t after = next + xed_decoded_inst_get_length(&use);
    if (branch_target_in(targets, next, after)) {
        REFUSE("a branch targets the consumer");
    }
    if (reg_live_after(inst, len, after, XED_REG_RCX)) {
        REFUSE("RCX is live afterward");
    }
    return true;
}

// SHL by one to three then an ADD of the result is an address computation:
// `lea rD, [rD + rX*2^k]`. The scale field only reaches eight, so a larger
// count has no LEA form at all and is not matched.
static bool c_shl_add_lea(const uint8_t *inst, size_t len,
                          const uint8_t *targets, size_t offset, size_t next,
                          const xed_decoded_inst_t *d, const char **why)
{
    (void) offset;
    if (xed_decoded_inst_get_iclass(d) != XED_ICLASS_SHL ||
        xed_decoded_inst_number_of_memory_operands(d) != 0 ||
        !xed_operand_values_has_immediate(
            xed_decoded_inst_operands_const(d))) {
        return false;
    }
    uint64_t k = xed_decoded_inst_get_unsigned_immediate(d);
    xed_reg_enum_t shifted = explicit_reg(d, XED_OPERAND_REG0);
    if (k < 1 || k > 3 || shifted == XED_REG_INVALID) {
        return false;
    }
    xed_decoded_inst_t use;
    if (!decode_at(inst, len, next, &use)) {
        return false;
    }
    if (xed_decoded_inst_get_iclass(&use) != XED_ICLASS_ADD ||
        xed_decoded_inst_number_of_memory_operands(&use) != 0 ||
        explicit_reg(&use, XED_OPERAND_REG1) != shifted) {
        return false;
    }
    xed_reg_enum_t dest = explicit_reg(&use, XED_OPERAND_REG0);
    if (dest == XED_REG_INVALID || dest == shifted ||
        xed_decoded_inst_get_operand_width(&use) !=
            xed_decoded_inst_get_operand_width(d)) {
        return false;
    }
    size_t after = next + xed_decoded_inst_get_length(&use);
    if (branch_target_in(targets, next, after)) {
        REFUSE("a branch targets the consumer");
    }
    if (flags_live_after(inst, len, after, FLAG_ARITH)) {
        REFUSE("the flags are live afterward");
    }
    if (reg_live_after(inst, len, after,
            xed_get_largest_enclosing_register(shifted))) {
        REFUSE("the shifted value is live afterward");
    }
    return true;
}

// A widening sign-extension feeding an integer-to-float conversion is the
// 32-bit conversion, which sign-extends its own source.
static bool c_movsxd_cvt(const uint8_t *inst, size_t len,
                         const uint8_t *targets, size_t offset, size_t next,
                         const xed_decoded_inst_t *d, const char **why)
{
    (void) offset;
    if (xed_decoded_inst_get_iclass(d) != XED_ICLASS_MOVSXD ||
        xed_decoded_inst_number_of_memory_operands(d) != 0) {
        return false;
    }
    xed_reg_enum_t widened = explicit_reg(d, XED_OPERAND_REG0);
    if (widened == XED_REG_INVALID) {
        return false;
    }
    xed_decoded_inst_t use;
    if (!decode_at(inst, len, next, &use)) {
        return false;
    }
    switch (xed_decoded_inst_get_iclass(&use)) {
    case XED_ICLASS_CVTSI2SD: case XED_ICLASS_CVTSI2SS:
    case XED_ICLASS_VCVTSI2SD: case XED_ICLASS_VCVTSI2SS:
        break;
    default:
        return false;
    }
    bool reads = false;
    const xed_inst_t *xi = xed_decoded_inst_inst(&use);
    for (unsigned i = 0; i < xed_inst_noperands(xi); ++i) {
        const xed_operand_t *op = xed_inst_operand(xi, i);
        xed_operand_enum_t nm = xed_operand_name(op);
        reads |= xed_operand_is_register(nm) && xed_operand_read(op) &&
            xed_decoded_inst_get_reg(&use, nm) == widened;
    }
    if (!reads) {
        return false;
    }
    size_t after = next + xed_decoded_inst_get_length(&use);
    if (branch_target_in(targets, next, after)) {
        REFUSE("a branch targets the consumer");
    }
    if (reg_live_after(inst, len, after,
            xed_get_largest_enclosing_register(widened))) {
        REFUSE("the widened value is live afterward");
    }
    return true;
}

// Now shipped; measured through the check itself.
static bool c_redundant_zext(const uint8_t *inst, size_t len,
                             const uint8_t *targets, size_t offset,
                             size_t next, const xed_decoded_inst_t *d,
                             const char **why)
{
    (void) offset;
    return redundant_zero_extension(inst, len, targets, next, d, why);
}

// Now shipped, gated on the target axis (#28); measured through the check
// itself. The tool passes the properties of the core where the rewrite is
// available, since under the conservative default it correctly reports none.
static bool c_bitscan_default(const uint8_t *inst, size_t len,
                              const uint8_t *targets, size_t offset,
                              size_t next, const xed_decoded_inst_t *d,
                              const char **why)
{
    (void) targets; (void) offset; (void) why;
    return bitscan_default_dead(inst, len, next, d);
}

// A second plain load of an address the block already loaded, with nothing
// between that could have changed it. The heap, global and TLS halves of
// this shape select for the unsound case -- a load surviving -O2 CSE is one
// the source forbade merging, an atomic or a volatile the bytes cannot show
// -- so only a frame slot is a candidate, which is what #29 records.
static bool c_stack_reload(const uint8_t *inst, size_t len,
                           const uint8_t *targets, size_t offset, size_t next,
                           const xed_decoded_inst_t *d, const char **why)
{
    (void) targets; (void) offset;
    if (xed_decoded_inst_get_iclass(d) != XED_ICLASS_MOV ||
        xed_decoded_inst_number_of_memory_operands(d) != 1 ||
        xed_decoded_inst_mem_written(d, 0) ||
        xed_decoded_inst_get_seg_reg(d, 0) != XED_REG_INVALID) {
        return false;
    }
    xed_reg_enum_t base = xed_decoded_inst_get_base_reg(d, 0);
    xed_reg_enum_t index = xed_decoded_inst_get_index_reg(d, 0);
    int64_t disp = xed_decoded_inst_get_memory_displacement(d, 0);
    unsigned width = xed_decoded_inst_get_memory_operand_length(d, 0);
    xed_reg_enum_t first_dest = explicit_reg(d, XED_OPERAND_REG0);
    if (index != XED_REG_INVALID || width == 0 ||
        first_dest == XED_REG_INVALID) {
        return false;
    }
    bool value_gone = false;

    // Walk forward for the twin, stopping at anything that could change
    // either the address or the value.
    const int WINDOW = 8;
    size_t off = next;
    for (int step = 0; step < WINDOW; ++step) {
        xed_decoded_inst_t x;
        if (!decode_at(inst, len, off, &x)) {
            return false;
        }
        size_t x_next = off + xed_decoded_inst_get_length(&x);
        if (xed_decoded_inst_get_iclass(&x) == XED_ICLASS_MOV &&
            xed_decoded_inst_number_of_memory_operands(&x) == 1 &&
            !xed_decoded_inst_mem_written(&x, 0) &&
            xed_decoded_inst_get_base_reg(&x, 0) == base &&
            xed_decoded_inst_get_index_reg(&x, 0) == XED_REG_INVALID &&
            xed_decoded_inst_get_memory_displacement(&x, 0) == disp &&
            xed_decoded_inst_get_memory_operand_length(&x, 0) == width) {
            if (base != XED_REG_RBP && base != XED_REG_RSP) {
                REFUSE("not a thread-private frame slot");
            }
            // Same destination: the reload is a duplicate and is simply
            // deleted. A different one needs a copy, so the first value has
            // to still be there -- where it is not, #29 calls the site
            // register allocation rather than a peephole.
            if (explicit_reg(&x, XED_OPERAND_REG0) != first_dest &&
                value_gone) {
                REFUSE("the first value was overwritten");
            }
            return true;
        }
        xed_category_enum_t cat = xed_decoded_inst_get_category(&x);
        if (cat == XED_CATEGORY_CALL || cat == XED_CATEGORY_RET ||
            cat == XED_CATEGORY_UNCOND_BR || cat == XED_CATEGORY_COND_BR ||
            cat == XED_CATEGORY_INTERRUPT) {
            return false;
        }
        if (xed_decoded_inst_number_of_memory_operands(&x) > 0 &&
            xed_decoded_inst_mem_written(&x, 0)) {
            return false;               // a store may alias
        }
        // A write to the base moves the address out from under the twin; a
        // write to the first destination takes the value the copy would use.
        const xed_inst_t *xi = xed_decoded_inst_inst(&x);
        for (unsigned i = 0; i < xed_inst_noperands(xi); ++i) {
            const xed_operand_t *op = xed_inst_operand(xi, i);
            xed_operand_enum_t nm = xed_operand_name(op);
            if (!xed_operand_is_register(nm) || !xed_operand_written(op)) {
                continue;
            }
            xed_reg_enum_t w = xed_get_largest_enclosing_register(
                xed_decoded_inst_get_reg(&x, nm));
            if (w == xed_get_largest_enclosing_register(base)) {
                return false;
            }
            if (w == xed_get_largest_enclosing_register(first_dest)) {
                value_gone = true;
            }
        }
        off = x_next;
    }
    return false;
}

// === run candidate: a constant already live in another register ===
//
// Now shipped as two findings, and driven here through the very same state
// machine: const_remat_step judges one instruction and folds it into the
// map, so the tool and the linter cannot disagree about what a register
// holds. A duplicate of this walk is exactly what produced a false positive
// on glibc -- `mov edx, 0xffffffff` leaves 0x00000000ffffffff where
// `mov rdx, -1` leaves all ones, and reading the raw immediate for both made
// them compare equal.
static void remat_constant_any(const uint8_t *inst, size_t len,
                               const uint8_t *targets, struct tally *t,
                               const char *path, uint64_t vaddr,
                               const char *example, long *left)
{
    struct const_map map;
    memset(&map, 0, sizeof(map));

    for (size_t offset = 0; offset < len;) {
        xed_decoded_inst_t xedd;
        decode_init(&xedd);
        if (xed_decode(&xedd, inst + offset, len - offset) != XED_ERROR_NONE) {
            memset(&map, 0, sizeof(map));
            offset += 1;
            continue;
        }
        size_t next = offset + xed_decoded_inst_get_length(&xedd);
        switch (const_remat_step(&map, targets, offset, next, &xedd)) {
        case CONST_DEAD:
            ++t->shape;
            tally_refusal(t, "the destination already holds it");
            break;
        case CONST_COPYABLE:
            ++t->shape;
            ++t->realized;
            if (example != NULL && *left > 0) {
                char text[128];
                xed_format_context(XED_SYNTAX_INTEL, &xedd, text,
                    sizeof(text), vaddr + offset, NULL, NULL);
                printf("  [constant already in a register] %s+0x%" PRIx64
                    ": %s\n", path, vaddr + offset, text);
                --*left;
            }
            break;
        case CONST_NONE:
            break;
        }
        offset = next;
    }
}

// === run candidate: adjacent immediate-zero stores (issue #30) ===

// Decode one `mov <width> PTR [base+index*scale+disp], 0` and report the
// address it writes. Anything else ends the run.
static bool zero_store(const xed_decoded_inst_t *x, xed_reg_enum_t *base,
                       xed_reg_enum_t *index, unsigned *scale,
                       int64_t *disp, unsigned *width)
{
    if (xed_decoded_inst_get_iclass(x) != XED_ICLASS_MOV ||
        xed_decoded_inst_number_of_memory_operands(x) != 1 ||
        !xed_decoded_inst_mem_written(x, 0) ||
        !xed_operand_values_has_immediate(
            xed_decoded_inst_operands_const(x)) ||
        xed_decoded_inst_get_unsigned_immediate(x) != 0) {
        return false;
    }
    *base = xed_decoded_inst_get_base_reg(x, 0);
    *index = xed_decoded_inst_get_index_reg(x, 0);
    *scale = xed_decoded_inst_get_scale(x, 0);
    *disp = xed_decoded_inst_get_memory_displacement(x, 0);
    *width = xed_decoded_inst_get_memory_operand_length(x, 0);
    return *width != 0;
}

// Maximal runs of immediate-zero stores covering a contiguous byte range off
// one base, in either direction and at mixed widths. Counting runs rather
// than pairs is the correction issue #30 records: an eight-store run is one
// opportunity and not seven, and pairing by matching width misses every
// mixed-width run.
//
// "Realized" is the conservative arm alone -- merge up to eight bytes with
// `MOV QWORD PTR, 0` and never allocate a register -- since the wider merge
// wants a zeroed vector register the surrounding code may not have.
// The fewest immediate stores that cover `span` contiguous bytes, which is
// what a run has to beat to be worth reporting. A store covers 1, 2, 4 or 8
// bytes and nothing between, so a span is covered by writing one store per set
// bit of its length: popcount(span), since x86 permits the unaligned pieces.
// That is the whole arithmetic, and getting it wrong is what made this
// candidate look fifteen times larger than it is -- an eight-byte store over a
// five-byte span would clobber three bytes the original never wrote, so five
// bytes costs two stores however they are spelled, and a run of two is already
// optimal. Beyond eight bytes the remainder rule would be
// span / 8 + popcount(span % 8), but those runs are refused for wanting a zero
// vector register.
static int min_stores_for_span(int64_t span)
{
    int n = 0;
    for (int64_t b = span; b != 0; b >>= 1) {
        n += (int) (b & 1);
    }
    return n;
}

static void zero_store_runs(const uint8_t *inst, size_t len,
                            const uint8_t *targets, struct tally *t,
                            const char *path, uint64_t vaddr,
                            const char *example, long *left)
{
    size_t n = 0, run_start = 0;
    xed_reg_enum_t rbase = XED_REG_INVALID, rindex = XED_REG_INVALID;
    unsigned rscale = 0;
    int64_t lo = 0, hi = 0;
    bool side_entry = false;

    for (size_t offset = 0; offset <= len;) {
        xed_decoded_inst_t xedd;
        bool ok = false;
        xed_reg_enum_t base = XED_REG_INVALID, index = XED_REG_INVALID;
        unsigned scale = 0, width = 0;
        int64_t disp = 0;
        size_t next = offset;

        if (offset < len) {
            decode_init(&xedd);
            if (xed_decode(&xedd, inst + offset, len - offset) ==
                    XED_ERROR_NONE) {
                next = offset + xed_decoded_inst_get_length(&xedd);
                ok = zero_store(&xedd, &base, &index, &scale, &disp, &width);
            } else {
                next = offset + 1;
            }
        }

        bool extends = ok && n > 0 && base == rbase && index == rindex &&
            scale == rscale && (disp == hi || disp + (int64_t) width == lo);
        if (extends) {
            if (disp == hi) {
                hi = disp + (int64_t) width;
            } else {
                lo = disp;
            }
            ++n;
            side_entry |= branch_target_in(targets, offset, next);
        } else {
            if (n >= 2) {          // close the run
                ++t->shape;
                int64_t span = hi - lo;
                if (side_entry) {
                    tally_refusal(t, "a branch enters the run");
                } else if (span <= 2) {
                    tally_refusal(t,
                        "a 2-byte span would need an LCP imm16");
                } else if (span > 8) {
                    tally_refusal(t,
                        "over 8 bytes: needs a zero vector register");
                } else if (n <= min_stores_for_span(span)) {
                    tally_refusal(t,
                        "the run is already the shortest cover of its span");
                } else {
                    ++t->realized;
                    if (example != NULL && *left > 0) {
                        printf("  [adjacent zero-store run] %s+0x%" PRIx64
                            ": %zu zero stores, %" PRId64 " bytes\n", path,
                            vaddr + run_start, n, span);
                        --*left;
                    }
                }
            }
            if (ok) {
                n = 1; run_start = offset; rbase = base; rindex = index;
                rscale = scale; lo = disp; hi = disp + (int64_t) width;
                side_entry = branch_target_in(targets, offset, next);
            } else {
                n = 0;
            }
        }
        if (offset >= len) {
            break;
        }
        offset = next;
    }
}

// === window candidates: the 2026-09-27 four-toolchain sweep ===
//
// Surfaced by pairscan over libxul (GCC C++ + rustc), the Fedora
// libLLVM/libclang-cpp (clang 22, LLD), librustc_driver and uutils coreutils
// (rustc 1.97 / LLVM 22). Each is written against the gates a shipped check would
// use, so the realized count is the finding count and the refusals say where
// the shape went.

// Direct relative branch target of `d` (whose bytes end at `next`), or -1 when
// the branch is indirect or the target leaves the section.
static int64_t direct_target(const xed_decoded_inst_t *d, size_t next,
                             size_t len)
{
    if (xed_decoded_inst_get_branch_displacement_width(d) == 0) {
        return -1;
    }
    int64_t t = (int64_t) next + xed_decoded_inst_get_branch_displacement(d);
    if (t < 0 || (uint64_t) t >= (uint64_t) len) {
        return -1;
    }
    return t;
}

// A Jcc proper: the condition-code family, not the RCX-reading JRCXZ/LOOP.
static bool is_jcc(const xed_decoded_inst_t *d)
{
    if (xed_decoded_inst_get_category(d) != XED_CATEGORY_COND_BR) {
        return false;
    }
    switch (xed_decoded_inst_get_iclass(d)) {
    case XED_ICLASS_JRCXZ: case XED_ICLASS_JECXZ: case XED_ICLASS_JCXZ:
    case XED_ICLASS_LOOP: case XED_ICLASS_LOOPE: case XED_ICLASS_LOOPNE:
        return false;
    default:
        return true;
    }
}

static bool is_direct_jmp(const xed_decoded_inst_t *d)
{
    return xed_decoded_inst_get_iclass(d) == XED_ICLASS_JMP &&
        xed_decoded_inst_get_branch_displacement_width(d) != 0;
}

static bool is_ret(const xed_decoded_inst_t *d)
{
    return xed_decoded_inst_get_category(d) == XED_CATEGORY_RET &&
        !xed_operand_values_has_immediate(xed_decoded_inst_operands_const(d));
}

static bool fits_rel8(int64_t disp)
{
    return disp >= -128 && disp <= 127;
}

// A flag walk that, like reg_live_after_branch, follows both successors of a
// conditional branch at `offset`; anything else is the plain walk.
static bool flags_live_after_branch(const uint8_t *inst, size_t len,
                                    size_t offset, uint32_t concerns)
{
    xed_decoded_inst_t j;
    if (decode_at(inst, len, offset, &j) && is_jcc(&j)) {
        size_t fall = offset + xed_decoded_inst_get_length(&j);
        int64_t t = direct_target(&j, fall, len);
        if (t < 0) {
            return true;
        }
        return flags_live_after(inst, len, fall, concerns) ||
            flags_live_after(inst, len, (size_t) t, concerns);
    }
    return flags_live_after(inst, len, offset, concerns);
}

// 1. A direct branch whose target is itself an unconditional direct jump:
// retarget the first to where the second goes. One taken branch fewer on
// every traversal and no register or flag is involved; the only gate is that
// the new displacement still fits the branch's current width.
static bool c_branch_chain(const uint8_t *inst, size_t len,
                           const uint8_t *targets, size_t offset, size_t next,
                           const xed_decoded_inst_t *d, const char **why)
{
    (void) targets;
    if (!is_direct_jmp(d) && !is_jcc(d)) {
        return false;
    }
    int64_t t = direct_target(d, next, len);
    xed_decoded_inst_t hop;
    if (t < 0 || !decode_at(inst, len, (size_t) t, &hop) ||
        !is_direct_jmp(&hop)) {
        return false;
    }
    int64_t t2 = direct_target(&hop, (size_t) t +
        xed_decoded_inst_get_length(&hop), len);
    if (t2 < 0) {
        REFUSE("the second hop leaves the section");
    }
    if ((size_t) t2 == offset) {
        REFUSE("a two-jump loop");
    }
    if (xed_decoded_inst_get_branch_displacement_width(d) == 1 &&
        !fits_rel8(t2 - (int64_t) next)) {
        REFUSE("the retargeted rel8 branch would need rel32");
    }
    return true;
}

// 2. `Jcc L1 ; JMP L2 ; L1:` -- the conditional branch hops over the jump.
// Inverting the condition to `JNcc L2` deletes the jump. Gated on nothing
// entering the jump from elsewhere and on the inverted branch still reaching.
static bool c_jcc_over_jmp(const uint8_t *inst, size_t len,
                           const uint8_t *targets, size_t offset, size_t next,
                           const xed_decoded_inst_t *d, const char **why)
{
    (void) offset;
    if (!is_jcc(d)) {
        return false;
    }
    xed_decoded_inst_t jmp;
    if (!decode_at(inst, len, next, &jmp) || !is_direct_jmp(&jmp)) {
        return false;
    }
    size_t after_jmp = next + xed_decoded_inst_get_length(&jmp);
    int64_t t = direct_target(d, next, len);
    if (t < 0 || (size_t) t != after_jmp) {
        return false;
    }
    int64_t t2 = direct_target(&jmp, after_jmp, len);
    if (t2 < 0) {
        REFUSE("the jump leaves the section");
    }
    if (branch_target_in(targets, next, after_jmp)) {
        REFUSE("a branch targets the jump");
    }
    // The inverted branch replaces both instructions: rel8 if it reaches,
    // else the 6-byte rel32 form, which still wins unless both originals
    // were rel8 (2 + 2 bytes).
    if (!fits_rel8(t2 - (int64_t) next) &&
        xed_decoded_inst_get_length(d) + xed_decoded_inst_get_length(&jmp) < 6) {
        REFUSE("a rel32 inversion would outgrow the rel8 pair");
    }
    return true;
}

// 3. `JMP L` where L is a bare RET: a RET in place is one byte for two or
// five, and the return predictor sees the return where it happens. No gate:
// the jump is replaced in place, so a branch onto it still works.
static bool c_jmp_to_ret(const uint8_t *inst, size_t len,
                         const uint8_t *targets, size_t offset, size_t next,
                         const xed_decoded_inst_t *d, const char **why)
{
    (void) targets; (void) offset; (void) why;
    if (!is_direct_jmp(d)) {
        return false;
    }
    int64_t t = direct_target(d, next, len);
    xed_decoded_inst_t x;
    return t >= 0 && decode_at(inst, len, (size_t) t, &x) && is_ret(&x);
}

// 4. `JMP L` where L is a short epilogue -- POPs and an ADD RSP, then RET.
// Duplicating it in place of the jump removes a taken branch; it is a size
// win or neutral only while the epilogue is no longer than the jump.
static bool c_jmp_to_epilogue(const uint8_t *inst, size_t len,
                              const uint8_t *targets, size_t offset,
                              size_t next, const xed_decoded_inst_t *d,
                              const char **why)
{
    (void) targets; (void) offset;
    if (!is_direct_jmp(d)) {
        return false;
    }
    int64_t t = direct_target(d, next, len);
    if (t < 0) {
        return false;
    }
    size_t off = (size_t) t, bytes = 0;
    for (int n = 0; n < 6; ++n) {
        xed_decoded_inst_t x;
        if (!decode_at(inst, len, off, &x)) {
            return false;
        }
        bytes += xed_decoded_inst_get_length(&x);
        if (is_ret(&x)) {
            if (n == 0) {
                return false;           // the bare-RET candidate's
            }
            if (bytes > xed_decoded_inst_get_length(d)) {
                REFUSE("the epilogue is longer than the jump");
            }
            return true;
        }
        xed_iclass_enum_t ic = xed_decoded_inst_get_iclass(&x);
        if (ic == XED_ICLASS_POP && explicit_reg(&x, XED_OPERAND_REG0) !=
                XED_REG_INVALID) {
            // fine
        } else if ((ic == XED_ICLASS_ADD || ic == XED_ICLASS_LEAVE) &&
                   (ic == XED_ICLASS_LEAVE ||
                    explicit_reg(&x, XED_OPERAND_REG0) == XED_REG_RSP)) {
            // fine
        } else {
            return false;
        }
        off += xed_decoded_inst_get_length(&x);
    }
    return false;
}

// 5. `MOV RSP, RBP ; POP RBP` is LEAVE by definition: one byte for four. The
// `ADD RSP, imm ; POP RBP` spelling is LEAVE only when RBP was set from RSP
// before exactly that allocation, which needs the prologue; counted, refused.
static bool c_leave(const uint8_t *inst, size_t len, const uint8_t *targets,
                    size_t offset, size_t next, const xed_decoded_inst_t *d,
                    const char **why)
{
    (void) targets; (void) offset;
    xed_iclass_enum_t ic = xed_decoded_inst_get_iclass(d);
    if (xed_decoded_inst_number_of_memory_operands(d) != 0 ||
        explicit_reg(d, XED_OPERAND_REG0) != XED_REG_RSP) {
        return false;
    }
    bool exact;
    if (ic == XED_ICLASS_MOV && explicit_reg(d, XED_OPERAND_REG1) == XED_REG_RBP) {
        exact = true;
    } else if (ic == XED_ICLASS_ADD && xed_operand_values_has_immediate(
                   xed_decoded_inst_operands_const(d))) {
        exact = false;
    } else {
        return false;
    }
    xed_decoded_inst_t pop;
    if (!decode_at(inst, len, next, &pop) ||
        xed_decoded_inst_get_iclass(&pop) != XED_ICLASS_POP ||
        explicit_reg(&pop, XED_OPERAND_REG0) != XED_REG_RBP) {
        return false;
    }
    if (!exact) {
        REFUSE("ADD form: the frame relation needs the prologue");
    }
    return true;
}

// 6. A slot-sized stack adjustment. `SUB RSP, 8` is `PUSH RAX` (one byte for
// four) while the flags are dead; `ADD RSP, 8` before an epilogue's POPs and
// RET is `POP RCX`, RCX being no return register. LLVM emits the push/pop
// forms (X86FrameLowering::emitSPUpdate); GCC does not.
static bool slot_adjust(const uint8_t *inst, size_t len, size_t next,
                        const xed_decoded_inst_t *d, const char **why,
                        xed_iclass_enum_t want)
{
    xed_iclass_enum_t ic = xed_decoded_inst_get_iclass(d);
    if (ic != want ||
        xed_decoded_inst_number_of_memory_operands(d) != 0 ||
        explicit_reg(d, XED_OPERAND_REG0) != XED_REG_RSP ||
        !xed_operand_values_has_immediate(
            xed_decoded_inst_operands_const(d)) ||
        xed_decoded_inst_get_signed_immediate(d) != 8) {
        return false;
    }
    if (ic == XED_ICLASS_SUB) {
        if (flags_live_after(inst, len, next, FLAG_ARITH)) {
            REFUSE("the flags are live afterward");
        }
        return true;
    }
    size_t off = next;
    for (int n = 0; n < 8; ++n) {
        xed_decoded_inst_t x;
        if (!decode_at(inst, len, off, &x)) {
            REFUSE("undecodable epilogue");
        }
        if (is_ret(&x)) {
            return true;
        }
        if (xed_decoded_inst_get_iclass(&x) == XED_ICLASS_POP) {
            off += xed_decoded_inst_get_length(&x);
            continue;
        }
        if (xed_decoded_inst_get_category(&x) == XED_CATEGORY_UNCOND_BR) {
            REFUSE("a tail call follows: RCX may carry an argument");
        }
        REFUSE("not followed by POPs and RET");
    }
    REFUSE("not followed by POPs and RET");
}

static bool c_slot_sub(const uint8_t *inst, size_t len, const uint8_t *targets,
                       size_t offset, size_t next, const xed_decoded_inst_t *d,
                       const char **why)
{
    (void) targets; (void) offset;
    return slot_adjust(inst, len, next, d, why, XED_ICLASS_SUB);
}

static bool c_slot_add(const uint8_t *inst, size_t len, const uint8_t *targets,
                       size_t offset, size_t next, const xed_decoded_inst_t *d,
                       const char **why)
{
    (void) targets; (void) offset;
    return slot_adjust(inst, len, next, d, why, XED_ICLASS_ADD);
}

static bool cc_is_zero_test(xed_iclass_enum_t ic)
{
    switch (ic) {
    case XED_ICLASS_JZ: case XED_ICLASS_JNZ:
    case XED_ICLASS_SETZ: case XED_ICLASS_SETNZ:
    case XED_ICLASS_CMOVZ: case XED_ICLASS_CMOVNZ:
        return true;
    default:
        return false;
    }
}

static bool cc_is_unsigned(xed_iclass_enum_t ic)
{
    switch (ic) {
    case XED_ICLASS_JB: case XED_ICLASS_JNB: case XED_ICLASS_JBE:
    case XED_ICLASS_JNBE:
    case XED_ICLASS_SETB: case XED_ICLASS_SETNB: case XED_ICLASS_SETBE:
    case XED_ICLASS_SETNBE:
    case XED_ICLASS_CMOVB: case XED_ICLASS_CMOVNB: case XED_ICLASS_CMOVBE:
    case XED_ICLASS_CMOVNBE:
        return true;
    default:
        return cc_is_zero_test(ic);
    }
}

// 7. `PMOVMSKB r32, xmm ; TEST r32, r32 ; JZ/JNZ` is `PTEST xmm, xmm ; JZ/JNZ`
// (SSE4.1): ZF is set exactly when the vector is all zero, so the mask never
// needs to exist. PTEST clears SF/PF/OF and sets CF where TEST does the
// reverse, so those must be dead on both paths, and the mask register too.
static bool c_ptest(const uint8_t *inst, size_t len, const uint8_t *targets,
                    size_t offset, size_t next, const xed_decoded_inst_t *d,
                    const char **why)
{
    (void) targets; (void) offset;
    xed_iclass_enum_t ic = xed_decoded_inst_get_iclass(d);
    if (ic != XED_ICLASS_PMOVMSKB && ic != XED_ICLASS_VPMOVMSKB) {
        return false;
    }
    xed_reg_enum_t mask = explicit_reg(d, XED_OPERAND_REG0);
    xed_reg_enum_t vec = explicit_reg(d, XED_OPERAND_REG1);
    if (mask == XED_REG_INVALID || vec == XED_REG_INVALID ||
        xed_reg_class(vec) == XED_REG_CLASS_MMX) {
        return false;
    }
    xed_decoded_inst_t test;
    if (!decode_at(inst, len, next, &test) ||
        xed_decoded_inst_get_iclass(&test) != XED_ICLASS_TEST ||
        xed_decoded_inst_number_of_memory_operands(&test) != 0 ||
        explicit_reg(&test, XED_OPERAND_REG0) != mask ||
        explicit_reg(&test, XED_OPERAND_REG1) != mask) {
        return false;
    }
    size_t after_test = next + xed_decoded_inst_get_length(&test);
    xed_decoded_inst_t use;
    if (!decode_at(inst, len, after_test, &use)) {
        return false;
    }
    if (branch_target_in(targets, next, after_test)) {
        REFUSE("a branch targets the test");
    }
    if (!cc_is_zero_test(xed_decoded_inst_get_iclass(&use))) {
        REFUSE("the consumer reads a flag PTEST sets differently");
    }
    if (reg_live_after_branch(inst, len, after_test,
            xed_get_largest_enclosing_register(mask))) {
        REFUSE("the mask is live afterward");
    }
    size_t after_use = after_test + xed_decoded_inst_get_length(&use);
    bool live = is_jcc(&use)
        ? flags_live_after_branch(inst, len, after_test,
              FLAG_CF | FLAG_SF | FLAG_PF | FLAG_OF)
        : flags_live_after(inst, len, after_use,
              FLAG_CF | FLAG_SF | FLAG_PF | FLAG_OF);
    if (live) {
        REFUSE("CF/SF/PF/OF are live afterward");
    }
    return true;
}

// 8. `MOV rD, rS ; SHR/SHL rD, n` followed by a consumer that discards the
// bits a rotate would bring in is `RORX rD, rS, n'` (BMI2): non-destructive,
// so the copy goes, and flag-silent, which the masking AND makes moot.
static bool c_rorx(const uint8_t *inst, size_t len, const uint8_t *targets,
                   size_t offset, size_t next, const xed_decoded_inst_t *d,
                   const char **why)
{
    (void) targets; (void) offset;
    if (xed_decoded_inst_get_iclass(d) != XED_ICLASS_MOV ||
        xed_decoded_inst_number_of_memory_operands(d) != 0) {
        return false;
    }
    xed_reg_enum_t dst = explicit_reg(d, XED_OPERAND_REG0);
    xed_reg_enum_t src = explicit_reg(d, XED_OPERAND_REG1);
    unsigned w = xed_decoded_inst_get_operand_width(d);
    if (dst == XED_REG_INVALID || src == XED_REG_INVALID ||
        xed_reg_class(dst) != XED_REG_CLASS_GPR || (w != 32 && w != 64)) {
        return false;
    }
    xed_decoded_inst_t sh;
    if (!decode_at(inst, len, next, &sh)) {
        return false;
    }
    xed_iclass_enum_t sic = xed_decoded_inst_get_iclass(&sh);
    if ((sic != XED_ICLASS_SHR && sic != XED_ICLASS_SHL) ||
        xed_decoded_inst_number_of_memory_operands(&sh) != 0 ||
        !xed_operand_values_has_immediate(
            xed_decoded_inst_operands_const(&sh)) ||
        explicit_reg(&sh, XED_OPERAND_REG0) != dst ||
        xed_decoded_inst_get_operand_width(&sh) != w) {
        return false;
    }
    uint64_t n = xed_decoded_inst_get_unsigned_immediate(&sh) & (w - 1);
    if (n == 0) {
        return false;
    }
    size_t after_sh = next + xed_decoded_inst_get_length(&sh);
    if (branch_target_in(targets, next, after_sh)) {
        REFUSE("a branch targets the shift");
    }
    xed_decoded_inst_t use;
    if (!decode_at(inst, len, after_sh, &use)) {
        return false;
    }
    xed_iclass_enum_t uic = xed_decoded_inst_get_iclass(&use);
    if (uic == XED_ICLASS_AND &&
        xed_decoded_inst_number_of_memory_operands(&use) == 0 &&
        explicit_reg(&use, XED_OPERAND_REG0) == dst &&
        xed_operand_values_has_immediate(
            xed_decoded_inst_operands_const(&use))) {
        int64_t m = xed_decoded_inst_get_signed_immediate(&use);
        if (m < 0) {
            REFUSE("the mask keeps rotated-in bits");
        }
        uint64_t um = (uint64_t) m;
        bool ok = sic == XED_ICLASS_SHR
            ? (w - n >= 63 || um < ((uint64_t) 1 << (w - n)))
            : ((um & (((uint64_t) 1 << n) - 1)) == 0);
        if (!ok) {
            REFUSE("the mask keeps rotated-in bits");
        }
        return true;                    // AND rewrites every flag anyway
    }
    if (uic == XED_ICLASS_MOVZX && sic == XED_ICLASS_SHR &&
        xed_decoded_inst_number_of_memory_operands(&use) == 0) {
        xed_reg_enum_t s = explicit_reg(&use, XED_OPERAND_REG1);
        unsigned sw = s == XED_REG_INVALID ? 0 :
            xed_get_register_width_bits64(s);
        if (s == XED_REG_INVALID || xed_get_largest_enclosing_register(s) !=
                xed_get_largest_enclosing_register(dst) || sw == 0 ||
            n > w - sw) {
            REFUSE("the mask keeps rotated-in bits");
        }
        if (flags_live_after(inst, len, after_sh, FLAG_ARITH)) {
            REFUSE("the shift's flags are live");
        }
        return true;
    }
    REFUSE("no masking consumer follows");
}

// 9. `MOVZX r32, r8 ; CMP r32, imm8u` (or TEST r32, r32) feeding an equality
// or unsigned condition is `CMP r8, imm8` (TEST r8, r8): the extension exists
// only to widen an operand the byte form compares identically. The extended
// register must die with the consumer. With a memory source it is
// `CMP BYTE PTR [mem], imm8`, the arm "load foldable into compare" does not
// reach because its producer is a plain MOV.
static bool movzx_cmp(const uint8_t *inst, size_t len, const uint8_t *targets,
                      size_t next, const xed_decoded_inst_t *d,
                      const char **why, bool want_mem)
{
    if (xed_decoded_inst_get_iclass(d) != XED_ICLASS_MOVZX ||
        (xed_decoded_inst_number_of_memory_operands(d) != 0) != want_mem) {
        return false;
    }
    xed_reg_enum_t dst = explicit_reg(d, XED_OPERAND_REG0);
    if (dst == XED_REG_INVALID) {
        return false;
    }
    unsigned srcw = want_mem ? xed_decoded_inst_get_memory_operand_length(d, 0) * 8
        : (explicit_reg(d, XED_OPERAND_REG1) == XED_REG_INVALID ? 0 :
           xed_get_register_width_bits64(explicit_reg(d, XED_OPERAND_REG1)));
    if (srcw != 8) {
        return false;
    }
    xed_decoded_inst_t cmp;
    if (!decode_at(inst, len, next, &cmp)) {
        return false;
    }
    xed_iclass_enum_t cic = xed_decoded_inst_get_iclass(&cmp);
    bool is_test;
    if (cic == XED_ICLASS_CMP &&
        xed_decoded_inst_number_of_memory_operands(&cmp) == 0 &&
        explicit_reg(&cmp, XED_OPERAND_REG0) == dst &&
        xed_operand_values_has_immediate(
            xed_decoded_inst_operands_const(&cmp))) {
        int64_t v = xed_decoded_inst_get_signed_immediate(&cmp);
        if (v < 0 || v > 255) {
            return false;
        }
        is_test = false;
    } else if (cic == XED_ICLASS_TEST &&
               xed_decoded_inst_number_of_memory_operands(&cmp) == 0 &&
               explicit_reg(&cmp, XED_OPERAND_REG0) == dst &&
               explicit_reg(&cmp, XED_OPERAND_REG1) == dst) {
        is_test = true;
    } else {
        return false;
    }
    size_t after_cmp = next + xed_decoded_inst_get_length(&cmp);
    if (branch_target_in(targets, next, after_cmp)) {
        REFUSE("a branch targets the compare");
    }
    xed_decoded_inst_t use;
    if (!decode_at(inst, len, after_cmp, &use)) {
        return false;
    }
    xed_iclass_enum_t uic = xed_decoded_inst_get_iclass(&use);
    if (!(is_test ? cc_is_zero_test(uic) : cc_is_unsigned(uic))) {
        REFUSE("a signed condition (or no condition) reads the compare");
    }
    xed_reg_enum_t dst64 = xed_get_largest_enclosing_register(dst);
    bool live = is_jcc(&use)
        ? reg_live_after_branch(inst, len, after_cmp, dst64)
        : reg_live_after(inst, len, after_cmp +
              xed_decoded_inst_get_length(&use), dst64);
    if (live) {
        REFUSE("the extended value is live afterward");
    }
    return true;
}

static bool c_movzx_cmp_reg(const uint8_t *inst, size_t len,
                            const uint8_t *targets, size_t offset,
                            size_t next, const xed_decoded_inst_t *d,
                            const char **why)
{
    (void) offset;
    return movzx_cmp(inst, len, targets, next, d, why, false);
}

static bool c_movzx_cmp_mem(const uint8_t *inst, size_t len,
                            const uint8_t *targets, size_t offset,
                            size_t next, const xed_decoded_inst_t *d,
                            const char **why)
{
    (void) offset;
    return movzx_cmp(inst, len, targets, next, d, why, true);
}

// 10. `CALL f ; RET` -- a call in tail position that was not made a jump.
// Counted as a shape; the bytes cannot show what refused the sibcall (a
// landing pad in the LSDA, stack-argument mismatch).
static bool c_call_ret(const uint8_t *inst, size_t len,
                       const uint8_t *targets, size_t offset, size_t next,
                       const xed_decoded_inst_t *d, const char **why)
{
    (void) targets; (void) offset;
    if (xed_decoded_inst_get_category(d) != XED_CATEGORY_CALL ||
        xed_decoded_inst_get_branch_displacement_width(d) == 0) {
        return false;
    }
    xed_decoded_inst_t x;
    if (!decode_at(inst, len, next, &x)) {
        return false;
    }
    if (is_ret(&x)) {
        return true;
    }
    if (xed_decoded_inst_get_iclass(&x) == XED_ICLASS_POP) {
        xed_decoded_inst_t y;
        if (decode_at(inst, len, next + xed_decoded_inst_get_length(&x), &y) &&
            is_ret(&y)) {
            REFUSE("one POP intervenes (POP ; JMP f)");
        }
    }
    return false;
}

// A frame-slot MOV: base RSP or RBP, no index. Returns the GPR moved and
// fills the slot's address; `store` says which direction.
static xed_reg_enum_t frame_slot_mov(const xed_decoded_inst_t *x, bool store,
                                     xed_reg_enum_t *base, int64_t *disp,
                                     unsigned *width)
{
    xed_iclass_enum_t ic = xed_decoded_inst_get_iclass(x);
    bool vec = ic == XED_ICLASS_MOVUPS || ic == XED_ICLASS_MOVAPS ||
        ic == XED_ICLASS_MOVDQU || ic == XED_ICLASS_MOVDQA;
    if ((ic != XED_ICLASS_MOV && !vec) ||
        xed_decoded_inst_number_of_memory_operands(x) != 1 ||
        xed_decoded_inst_mem_written(x, 0) != store ||
        xed_decoded_inst_get_index_reg(x, 0) != XED_REG_INVALID ||
        xed_decoded_inst_get_seg_reg(x, 0) != XED_REG_INVALID) {
        return XED_REG_INVALID;
    }
    xed_reg_enum_t b = xed_decoded_inst_get_base_reg(x, 0);
    if (b != XED_REG_RSP && b != XED_REG_RBP) {
        return XED_REG_INVALID;
    }
    xed_reg_enum_t r = explicit_reg(x, XED_OPERAND_REG0);
    if (r == XED_REG_INVALID || (ic == XED_ICLASS_MOV &&
            xed_reg_class(r) != XED_REG_CLASS_GPR)) {
        return XED_REG_INVALID;
    }
    *base = b;
    *disp = xed_decoded_inst_get_memory_displacement(x, 0);
    *width = xed_decoded_inst_get_memory_operand_length(x, 0);
    return r;
}

// 11. A store to a frame slot followed at once by a load of the identical
// slot: the value is still in the store's source register, so the load is a
// register copy, or nothing when it targets that register (#29's sibling
// shape; the "Forward a spill slot to the reload of it" LLVM change).
static bool c_store_reload(const uint8_t *inst, size_t len,
                           const uint8_t *targets, size_t offset, size_t next,
                           const xed_decoded_inst_t *d, const char **why)
{
    (void) offset;
    xed_reg_enum_t b1, b2; int64_t d1, d2; unsigned w1, w2;
    xed_reg_enum_t src = frame_slot_mov(d, true, &b1, &d1, &w1);
    if (src == XED_REG_INVALID) {
        return false;
    }
    xed_decoded_inst_t ld;
    if (!decode_at(inst, len, next, &ld)) {
        return false;
    }
    xed_reg_enum_t dst = frame_slot_mov(&ld, false, &b2, &d2, &w2);
    if (dst == XED_REG_INVALID || b1 != b2 || d1 != d2 || w1 != w2) {
        return false;
    }
    if (branch_target_in(targets, next, next + xed_decoded_inst_get_length(&ld))) {
        REFUSE("a branch targets the reload");
    }
    if (dst != src) {
        REFUSE("into another register (a copy, not a deletion)");
    }
    return true;
}

// 12. A frame slot loaded into a register that is immediately stored to
// another frame slot and then dies: an aggregate copied stack-to-stack
// through a register. No instruction-level rewrite exists; this is the
// advisory class "copy the compiler failed to elide", sized so the LLVM
// question (memcpy/move elision, Rust in particular) has a number.
static bool c_stack_copy(const uint8_t *inst, size_t len,
                         const uint8_t *targets, size_t offset, size_t next,
                         const xed_decoded_inst_t *d, const char **why)
{
    (void) offset;
    xed_reg_enum_t b1, b2; int64_t d1, d2; unsigned w1, w2;
    xed_reg_enum_t r = frame_slot_mov(d, false, &b1, &d1, &w1);
    if (r == XED_REG_INVALID) {
        return false;
    }
    xed_decoded_inst_t st;
    if (!decode_at(inst, len, next, &st)) {
        return false;
    }
    if (frame_slot_mov(&st, true, &b2, &d2, &w2) != r || w1 != w2) {
        return false;
    }
    size_t after = next + xed_decoded_inst_get_length(&st);
    if (branch_target_in(targets, next, after)) {
        REFUSE("a branch targets the store");
    }
    if (xed_reg_class(r) != XED_REG_CLASS_GPR) {
        REFUSE("vector copy (liveness not modeled)");
    }
    if (reg_live_after_branch(inst, len, after,
            xed_get_largest_enclosing_register(r))) {
        REFUSE("the register is live afterward (load and spill)");
    }
    return true;
}

static const struct candidate candidates[] = {
    { "CAS loop foldable into LOCK op", "LOCK OR/AND/XOR",
      w_cas, NULL },
    { "load foldable into vector op", "fold the load into the SIMD operand",
      w_vecop, NULL },
    { "load foldable into vector transfer", "MOVD/CVTSI2SD xmm, [mem]",
      w_vec_transfer, NULL },
    { "adjacent zero-store run (#30)", "one wider store",
      NULL, zero_store_runs },
    { "constant already in a register", "MOV rD, rS",
      NULL, remat_constant_any },
    { "dead compare", "delete the CMP/TEST", c_dead_compare, NULL },

    // TODO rows, not yet shipped. The figure in the comment on each
    // predicate is what an earlier throwaway script reported, where there
    // was one.
    { "same-register CMOVcc", "remove", c_cmov_self, NULL },
    { "vector self-op identity", "MOVAPS, or the zero idiom",
      c_vec_self_op, NULL },
    { "lane-0 extract", "MOVD/MOVQ/MOVSS", c_lane0_extract, NULL },
    { "AND r64, 0xffffffff", "MOV r32, r32", c_and_lo32, NULL },
    { "branch to the next instruction", "delete", c_branch_to_next, NULL },
    { "NEG folded into ADD/SUB", "SUB/ADD of the original", c_neg_add, NULL },
    { "MOV into CL before a shift", "an immediate count",
      c_mov_cl_shift, NULL },
    { "SHL + ADD foldable to LEA", "LEA rD, [rD + rX*2^k]",
      c_shl_add_lea, NULL },
    { "MOVSXD before CVTSI2SD/SS", "the 32-bit conversion",
      c_movsxd_cvt, NULL },
    { "redundant zero-extension by threshold", "drop the extension",
      c_redundant_zext, NULL },
    { "bit-scan defensive default (#28)", "delete the MOV, Skylake+ only",
      c_bitscan_default, NULL },
    { "reloaded frame slot (#29)", "reuse the first value",
      c_stack_reload, NULL },

    // 2026-09-27 four-toolchain sweep (libxul, libLLVM, libclang-cpp,
    // librustc_driver, uutils coreutils). See "Four-toolchain corpus" in
    // TODO.md for the figures and the reading of each.
    { "branch to a jump (chain)", "retarget to the final destination",
      c_branch_chain, NULL },
    { "Jcc over a JMP", "invert the condition, delete the jump",
      c_jcc_over_jmp, NULL },
    { "jump to a RET", "RET in place", c_jmp_to_ret, NULL },
    { "jump to a short epilogue", "duplicate the epilogue in place",
      c_jmp_to_epilogue, NULL },
    { "epilogue foldable into LEAVE", "LEAVE", c_leave, NULL },
    { "slot-sized SUB RSP", "PUSH RAX", c_slot_sub, NULL },
    { "slot-sized ADD RSP before POPs and RET", "POP RCX", c_slot_add, NULL },
    { "missing PTEST (-m sse4.1)", "PTEST xmm, xmm", c_ptest, NULL },
    { "missing RORX (-m bmi2)", "RORX rD, rS, n", c_rorx, NULL },
    { "MOVZX feeding a narrow-safe compare", "CMP r8, imm8",
      c_movzx_cmp_reg, NULL },
    { "MOVZX load feeding a compare", "CMP BYTE PTR [mem], imm8",
      c_movzx_cmp_mem, NULL },
    { "CALL then RET (sibcall miss)", "JMP f", c_call_ret, NULL },
    { "frame slot stored then reloaded (#29)", "delete the reload",
      c_store_reload, NULL },
    { "stack-to-stack copy through a register", "advisory: elide the copy",
      c_stack_copy, NULL },
};

#define NCAND (sizeof(candidates) / sizeof(candidates[0]))

struct file_result {
    const char *path;
    unsigned long instructions;
    struct tally t[NCAND];
};

struct scan_ctx {
    struct file_result *fr;
    const char *example;        // candidate name substring, or NULL
    long left[NCAND];           // examples still to print, per candidate
};

// Mirror the driver's own scan over one section: mask the bytes outside the
// function ranges the way main.c does, collect branch targets over exactly
// those bytes, then walk instructions with the same decode and resync. A
// shipped candidate must come out equal to what x86lint reports, and it only
// does if the corpus is identical byte for byte.
static void scan_section(const corpus_section *sec, void *vctx)
{
    struct scan_ctx *ctx = vctx;
    uint8_t *buf = malloc(sec->size);
    if (buf == NULL) {
        return;
    }
    memset(buf, 0xCC, sec->size);       // INT3, as the driver's mask uses
    for (size_t r = 0; r < sec->nranges; ++r) {
        memcpy(buf + sec->ranges[r].start, sec->code + sec->ranges[r].start,
            sec->ranges[r].end - sec->ranges[r].start);
    }
    uint8_t *backward = NULL;
    uint8_t *targets = collect_branch_targets(buf, sec->size, &backward,
        NULL);

    for (size_t i = 0; i < NCAND; ++i) {
        if (candidates[i].run == NULL) {
            continue;
        }
        bool want = ctx->example != NULL &&
            strstr(candidates[i].name, ctx->example) != NULL;
        candidates[i].run(buf, sec->size, targets, &ctx->fr->t[i], sec->path,
            sec->vaddr, want ? ctx->example : NULL, &ctx->left[i]);
    }

    for (size_t offset = 0; offset < sec->size;) {
        xed_decoded_inst_t xedd;
        decode_init(&xedd);
        if (xed_decode(&xedd, buf + offset, sec->size - offset) !=
                XED_ERROR_NONE) {
            offset += 1;
            continue;
        }
        ++ctx->fr->instructions;
        size_t next = offset + xed_decoded_inst_get_length(&xedd);

        for (size_t i = 0; i < NCAND; ++i) {
            if (candidates[i].window == NULL) {
                continue;
            }
            const char *why = NULL;
            bool hit = candidates[i].window(buf, sec->size, targets, offset,
                next, &xedd, &why);
            if (!hit && why == NULL) {
                continue;               // the pattern did not match
            }
            ++ctx->fr->t[i].shape;
            if (hit) {
                ++ctx->fr->t[i].realized;
                if (ctx->example != NULL && ctx->left[i] > 0 &&
                    strstr(candidates[i].name, ctx->example) != NULL) {
                    char text[128];
                    xed_format_context(XED_SYNTAX_INTEL, &xedd, text,
                        sizeof(text), sec->vaddr + offset, NULL, NULL);
                    printf("  [%s] %s+0x%" PRIx64 ": %s\n",
                        candidates[i].name, sec->path, sec->vaddr + offset,
                        text);
                    --ctx->left[i];
                }
            } else {
                tally_refusal(&ctx->fr->t[i], why);
            }
        }
        offset = next;
    }
    free(targets);
    free(backward);
    free(buf);
}

static void report(const struct file_result *fr, size_t nfr)
{
    const int w = 56;
    printf("%-*s", w, "instructions scanned");
    for (size_t f = 0; f < nfr; ++f) {
        printf("%12lu", fr[f].instructions);
    }
    printf("%12s\n", "TOTAL");

    for (size_t i = 0; i < NCAND; ++i) {
        unsigned long shape = 0, real = 0;
        for (size_t f = 0; f < nfr; ++f) {
            shape += fr[f].t[i].shape;
            real += fr[f].t[i].realized;
        }
        printf("\n%s\n  -> %s\n", candidates[i].name, candidates[i].rewrite);
        printf("  %-*s", w - 2, "shape");
        for (size_t f = 0; f < nfr; ++f) {
            printf("%12lu", fr[f].t[i].shape);
        }
        printf("%12lu\n", shape);
        printf("  %-*s", w - 2, "realized");
        for (size_t f = 0; f < nfr; ++f) {
            printf("%12lu", fr[f].t[i].realized);
        }
        printf("%12lu\n", real);

        // Refusal reasons, unioned across files so every column lines up.
        const char *seen[MAX_REASONS * 4];
        size_t nseen = 0;
        for (size_t f = 0; f < nfr; ++f) {
            for (size_t r = 0; r < fr[f].t[i].nrefused; ++r) {
                const char *why = fr[f].t[i].refused[r].why;
                bool dup = false;
                for (size_t s = 0; s < nseen; ++s) {
                    dup |= seen[s] == why;
                }
                if (!dup && nseen < sizeof(seen) / sizeof(seen[0])) {
                    seen[nseen++] = why;
                }
            }
        }
        for (size_t s = 0; s < nseen; ++s) {
            char label[64];
            snprintf(label, sizeof(label), "refused: %s", seen[s]);
            printf("  %-*s", w - 2, label);
            unsigned long tot = 0;
            for (size_t f = 0; f < nfr; ++f) {
                unsigned long n = 0;
                for (size_t r = 0; r < fr[f].t[i].nrefused; ++r) {
                    if (fr[f].t[i].refused[r].why == seen[s]) {
                        n = fr[f].t[i].refused[r].n;
                    }
                }
                printf("%12lu", n);
                tot += n;
            }
            printf("%12lu\n", tot);
        }
    }
}

static void usage(const char *argv0)
{
    fprintf(stderr, "usage: %s [-a] [-e NAME] [-n MAX] <binary>...\n", argv0);
}

int main(int argc, char **argv)
{
    bool scan_all = false;
    const char *example = NULL;
    long nexamples = 8;
    int argi = 1;
    for (; argi < argc && argv[argi][0] == '-' && argv[argi][1] != '\0';
         ++argi) {
        if (strcmp(argv[argi], "-a") == 0) {
            scan_all = true;
        } else if (strcmp(argv[argi], "-e") == 0 && argi + 1 < argc) {
            example = argv[++argi];
        } else if (strcmp(argv[argi], "-n") == 0 && argi + 1 < argc) {
            nexamples = atol(argv[++argi]);
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

    size_t nfr = (size_t) (argc - argi);
    struct file_result *fr = calloc(nfr, sizeof(*fr));
    if (fr == NULL) {
        fprintf(stderr, "failed to allocate results\n");
        return 2;
    }

    int rc = 0;
    for (size_t f = 0; f < nfr; ++f) {
        fr[f].path = argv[argi + (int) f];
        struct scan_ctx ctx = { &fr[f], example, { 0 } };
        for (size_t i = 0; i < NCAND; ++i) {
            ctx.left[i] = nexamples;
        }
        if (corpus_scan_file(fr[f].path, scan_all, scan_section, &ctx) != 0) {
            rc = 2;
        }
    }

    if (example == NULL) {
        report(fr, nfr);
    }
    free(fr);
    return rc;
}
