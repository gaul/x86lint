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
//   -n  cap the examples printed (default 8)

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
static bool c_dead_compare(const uint8_t *inst, size_t len,
                           const uint8_t *targets, size_t offset, size_t next,
                           const xed_decoded_inst_t *d, const char **why)
{
    (void) targets; (void) offset;
    xed_iclass_enum_t ic = xed_decoded_inst_get_iclass(d);
    if ((ic != XED_ICLASS_CMP && ic != XED_ICLASS_TEST) ||
        xed_decoded_inst_number_of_memory_operands(d) != 0) {
        return false;
    }
    if (flags_live_after(inst, len, next, FLAG_ARITH)) {
        REFUSE("the flags are live afterward");
    }
    return true;
}

// CMOVcc with one register named twice moves a value onto itself. The 8-,
// 16- and 64-bit forms are pure no-ops; the 32-bit form writes its
// destination zero-extended whether or not the condition holds, so it is one
// only while bits 63:32 are dead.
static bool c_cmov_self(const uint8_t *inst, size_t len,
                        const uint8_t *targets, size_t offset, size_t next,
                        const xed_decoded_inst_t *d, const char **why)
{
    (void) targets; (void) offset;
    if (xed_decoded_inst_get_category(d) != XED_CATEGORY_CMOV) {
        return false;
    }
    xed_reg_enum_t r0 = explicit_reg(d, XED_OPERAND_REG0);
    xed_reg_enum_t r1 = explicit_reg(d, XED_OPERAND_REG1);
    if (r0 == XED_REG_INVALID || r0 != r1) {
        return false;
    }
    if (xed_decoded_inst_get_operand_width(d) == 32 &&
        reg_upper32_live_after(inst, len, next,
            xed_get_largest_enclosing_register(r0))) {
        REFUSE("the zero-extension is live");
    }
    return true;
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
    case XED_ICLASS_SUBPS: case XED_ICLASS_SUBPD:
    case XED_ICLASS_PCMPGTB: case XED_ICLASS_PCMPGTW:
    case XED_ICLASS_PCMPGTD:
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

// Extracting lane 0 is a plain cross-file move: PEXTRD/Q with an index of
// zero is MOVD/MOVQ, and EXTRACTPS with one is MOVD or MOVSS, each a shorter
// encoding on an older feature level.
static bool c_lane0_extract(const uint8_t *inst, size_t len,
                            const uint8_t *targets, size_t offset, size_t next,
                            const xed_decoded_inst_t *d, const char **why)
{
    (void) inst; (void) len; (void) targets; (void) offset; (void) next;
    (void) why;
    switch (xed_decoded_inst_get_iclass(d)) {
    case XED_ICLASS_PEXTRD:  case XED_ICLASS_PEXTRQ:
    case XED_ICLASS_VPEXTRD: case XED_ICLASS_VPEXTRQ:
    case XED_ICLASS_EXTRACTPS: case XED_ICLASS_VEXTRACTPS:
        break;
    default:
        return false;
    }
    return xed_operand_values_has_immediate(
               xed_decoded_inst_operands_const(d)) &&
           xed_decoded_inst_get_unsigned_immediate(d) == 0;
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

// NEG then an ADD of the negated value is a SUB of the original, and the
// mirror. The negation's register dies with it, and the flags must too: CF
// after `add rD, -X` is an unsigned carry where after `sub rD, X` it is a
// borrow, so the two disagree on exactly that bit.
static bool c_neg_add(const uint8_t *inst, size_t len, const uint8_t *targets,
                      size_t offset, size_t next, const xed_decoded_inst_t *d,
                      const char **why)
{
    (void) offset;
    if (xed_decoded_inst_get_iclass(d) != XED_ICLASS_NEG ||
        xed_decoded_inst_number_of_memory_operands(d) != 0) {
        return false;
    }
    xed_reg_enum_t negated = explicit_reg(d, XED_OPERAND_REG0);
    if (negated == XED_REG_INVALID) {
        return false;
    }
    xed_decoded_inst_t use;
    if (!decode_at(inst, len, next, &use)) {
        return false;
    }
    xed_iclass_enum_t uic = xed_decoded_inst_get_iclass(&use);
    if ((uic != XED_ICLASS_ADD && uic != XED_ICLASS_SUB) ||
        xed_decoded_inst_number_of_memory_operands(&use) != 0 ||
        explicit_reg(&use, XED_OPERAND_REG1) != negated) {
        return false;
    }
    xed_reg_enum_t dest = explicit_reg(&use, XED_OPERAND_REG0);
    if (dest == XED_REG_INVALID || dest == negated) {
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
            xed_get_largest_enclosing_register(negated))) {
        REFUSE("the negated value is live afterward");
    }
    return true;
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

// A producer's zero guarantee: bits [*from, *upto) of the destination are
// known zero. armlint tracks only the lower bound, because on AArch64 a
// W-form write zeroes the upper half and the guarantee always reaches the
// top of the register. x86 has no such rule -- an 8- or 16-bit write merges
// -- so the upper bound has to be carried too, and leaving it out is a false
// positive this tool caught on its own first run: `setz al` guarantees bits
// 7:1 are zero and says nothing whatever about 63:8, so it cannot make the
// `movzx eax, al` after it redundant. That shape is the shipped "suboptimal
// SETcc zero-extension" and not this one.
static void zero_guarantee(const xed_decoded_inst_t *d, unsigned *from,
                           unsigned *upto)
{
    *from = 64;
    xed_reg_enum_t dest = explicit_reg(d, XED_OPERAND_REG0);
    if (dest == XED_REG_INVALID) {
        *upto = 0;
        return;
    }
    // A 32-bit write zero-extends, so its guarantee reaches bit 64.
    unsigned w = xed_get_register_width_bits64(dest);
    *upto = w == 32 ? 64 : w;

    bool has_imm = xed_operand_values_has_immediate(
        xed_decoded_inst_operands_const(d));
    uint64_t imm = xed_decoded_inst_get_unsigned_immediate(d);
    switch (xed_decoded_inst_get_iclass(d)) {
    case XED_ICLASS_SHR:
        if (has_imm) {
            unsigned n = (unsigned) (imm & (w == 64 ? 63u : 31u));
            *from = n < w ? w - n : 0;
        }
        break;
    case XED_ICLASS_AND:
        if (has_imm) {
            unsigned bits = 0;
            while (imm != 0) { imm >>= 1; ++bits; }
            *from = bits;
        }
        break;
    // MOVZX and MOVSX producers are deliberately absent: an extension
    // after an extension is the shipped "redundant re-extension" check, and
    // counting them here re-reports covered ground. Measured, that is most
    // of the shape -- with them the row read 285 on libxul against that
    // check's own 254 -- so what is left below is the generalization alone.
    default:
        if (xed_decoded_inst_get_category(d) == XED_CATEGORY_SETCC) {
            *from = 1;              // 0 or 1, within AL alone
        }
        break;
    }
}

// A zero-extension that re-establishes bits a producer already zeroed. The
// shipped "redundant re-extension" owns extension-after-extension; this is
// armlint's generalization to any producer with a known threshold, which
// adds `shr eax, 24 ; movzx eax, al` and `setz al ; and al, 1`. Redundant
// when the producer's guarantee starts at or below where the consumer
// clears AND reaches at least as high as the consumer writes.
static bool c_redundant_zext(const uint8_t *inst, size_t len,
                             const uint8_t *targets, size_t offset,
                             size_t next, const xed_decoded_inst_t *d,
                             const char **why)
{
    (void) offset;
    unsigned from = 0, upto = 0;
    zero_guarantee(d, &from, &upto);
    xed_reg_enum_t produced = explicit_reg(d, XED_OPERAND_REG0);
    if (from >= 64 || produced == XED_REG_INVALID ||
        xed_decoded_inst_number_of_memory_operands(d) > 1) {
        return false;
    }
    xed_decoded_inst_t use;
    if (!decode_at(inst, len, next, &use)) {
        return false;
    }
    if (xed_decoded_inst_number_of_memory_operands(&use) != 0) {
        return false;
    }
    // The consumer must clear bits [c, c_upto) in place on the same register.
    unsigned c = 64, c_upto = 0;
    xed_reg_enum_t cdest = explicit_reg(&use, XED_OPERAND_REG0);
    xed_reg_enum_t csrc = explicit_reg(&use, XED_OPERAND_REG1);
    if (cdest == XED_REG_INVALID) {
        return false;
    }
    unsigned cw = xed_get_register_width_bits64(cdest);
    c_upto = cw == 32 ? 64 : cw;
    xed_iclass_enum_t uic = xed_decoded_inst_get_iclass(&use);
    if (uic == XED_ICLASS_MOVZX) {
        if (csrc == XED_REG_INVALID) {
            return false;
        }
        c = xed_get_register_width_bits64(csrc);
    } else if (uic == XED_ICLASS_AND &&
               xed_operand_values_has_immediate(
                   xed_decoded_inst_operands_const(&use))) {
        uint64_t m = xed_decoded_inst_get_unsigned_immediate(&use);
        if (m == 0 || (m & (m + 1)) != 0) {
            return false;               // not a run of low bits
        }
        c = 0;
        while (m != 0) { m >>= 1; ++c; }
        csrc = cdest;
    } else {
        return false;
    }
    xed_reg_enum_t parent = xed_get_largest_enclosing_register(produced);
    if (c >= 64 || c < from || upto < c_upto ||
        xed_get_largest_enclosing_register(cdest) != parent ||
        xed_get_largest_enclosing_register(csrc) != parent) {
        return false;
    }
    size_t after = next + xed_decoded_inst_get_length(&use);
    if (branch_target_in(targets, next, after)) {
        REFUSE("a branch targets the consumer");
    }
    if (uic == XED_ICLASS_AND &&
        flags_live_after(inst, len, after, FLAG_ARITH)) {
        REFUSE("the flags are live afterward");
    }
    return true;
}

// `mov r, <operand size>` before TZCNT or LZCNT provides the zero-source
// answer those instructions already define, so the MOV is dead -- but the
// same MOV is the false-dependency break they need through Broadwell, which
// is why this is blocked on a target axis (#28) rather than on a proof.
static bool c_bitscan_default(const uint8_t *inst, size_t len,
                              const uint8_t *targets, size_t offset,
                              size_t next, const xed_decoded_inst_t *d,
                              const char **why)
{
    (void) targets; (void) offset; (void) why;
    if (xed_decoded_inst_get_iclass(d) != XED_ICLASS_MOV ||
        xed_decoded_inst_number_of_memory_operands(d) != 0 ||
        !xed_operand_values_has_immediate(
            xed_decoded_inst_operands_const(d))) {
        return false;
    }
    xed_reg_enum_t dest = explicit_reg(d, XED_OPERAND_REG0);
    uint64_t imm = xed_decoded_inst_get_unsigned_immediate(d);
    if (dest == XED_REG_INVALID) {
        return false;
    }
    xed_decoded_inst_t use;
    if (!decode_at(inst, len, next, &use)) {
        return false;
    }
    xed_iclass_enum_t uic = xed_decoded_inst_get_iclass(&use);
    if (uic != XED_ICLASS_TZCNT && uic != XED_ICLASS_LZCNT) {
        return false;
    }
    unsigned w = xed_decoded_inst_get_operand_width(&use);
    return imm == w &&
        xed_get_largest_enclosing_register(
            explicit_reg(&use, XED_OPERAND_REG0)) ==
        xed_get_largest_enclosing_register(dest);
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
                } else {
                    ++t->realized;
                    if (example != NULL && *left > 0) {
                        printf("  %s+0x%" PRIx64 ": %zu zero stores, %"
                            PRId64 " bytes\n", path, vaddr + run_start, n,
                            span);
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

static const struct candidate candidates[] = {
    { "CAS loop foldable into LOCK op", "LOCK OR/AND/XOR",
      w_cas, NULL },
    { "load foldable into vector op", "fold the load into the SIMD operand",
      w_vecop, NULL },
    { "load foldable into vector transfer", "MOVD/CVTSI2SD xmm, [mem]",
      w_vec_transfer, NULL },
    { "adjacent zero-store run (#30)", "one wider store",
      NULL, zero_store_runs },

    // TODO rows, not yet shipped. The figure in the comment on each
    // predicate is what an earlier throwaway script reported, where there
    // was one.
    { "dead compare", "delete the CMP/TEST", c_dead_compare, NULL },
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
    long left;                  // examples still to print
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
    uint8_t *targets = collect_branch_targets(buf, sec->size);

    for (size_t i = 0; i < NCAND; ++i) {
        if (candidates[i].run == NULL) {
            continue;
        }
        bool want = ctx->example != NULL &&
            strstr(candidates[i].name, ctx->example) != NULL;
        candidates[i].run(buf, sec->size, targets, &ctx->fr->t[i], sec->path,
            sec->vaddr, want ? ctx->example : NULL, &ctx->left);
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
                if (ctx->example != NULL && ctx->left > 0 &&
                    strstr(candidates[i].name, ctx->example) != NULL) {
                    char text[128];
                    xed_format_context(XED_SYNTAX_INTEL, &xedd, text,
                        sizeof(text), sec->vaddr + offset, NULL, NULL);
                    printf("  %s+0x%" PRIx64 ": %s\n", sec->path,
                        sec->vaddr + offset, text);
                    --ctx->left;
                }
            } else {
                tally_refusal(&ctx->fr->t[i], why);
            }
        }
        offset = next;
    }
    free(targets);
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
        struct scan_ctx ctx = { &fr[f], example, nexamples };
        if (corpus_scan_file(fr[f].path, scan_all, scan_section, &ctx) != 0) {
            rc = 2;
        }
        nexamples = ctx.left;
    }

    if (example == NULL) {
        report(fr, nfr);
    }
    free(fr);
    return rc;
}
