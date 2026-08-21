/*
 * Copyright 2018 Andrew Gaul <andrew@gaul.org>
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

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "xed/xed-interface.h"
#include "x86lint.h"

// Every decode in this file must agree on machine mode AND input chip: the
// branch-target prepass and the scan proper rely on seeing identical
// instruction boundaries, and the liveness walks must read the same stream
// the sweep decoded. XED_CHIP_ALL decodes every instruction XED knows; the
// chip-less default instead maps chip-gated encodings onto their legacy
// aliases -- F3 0F BD read as BSR under a stray REP prefix rather than
// LZCNT -- misattributing iclass, category, and flag behavior.
static void decode_init(xed_decoded_inst_t *xedd)
{
    xed_decoded_inst_zero(xedd);
    xed_decoded_inst_set_mode(xedd, XED_MACHINE_MODE_LONG_64,
                              XED_ADDRESS_WIDTH_64b);
    xed_decoded_inst_set_input_chip(xedd, XED_CHIP_ALL);
}

// TODO: handle 10-15 byte NOPs
bool check_suboptimal_nops(const uint8_t *inst, size_t len)
{
    int prev_nop = 0;

    for (size_t i = 0; i < len; ) {
        xed_decoded_inst_t xedd;
        decode_init(&xedd);
        xed_error_enum_t err = xed_decode(&xedd, inst + i, len - i);
        if (err != XED_ERROR_NONE) {
            // An undecodable byte ends the NOP run; it is not itself a
            // finding (executable sections routinely embed data, so a
            // NOP followed by data is normal padding, not a suboptimal
            // sequence). A real finding requires two successfully
            // decoded adjacent NOPs, reported inside the loop.
            break;
        }

        // TODO: call xed_operand_values_is_nop?
        int iclass = xed_decoded_inst_get_iclass(&xedd);
        bool cur_nop = iclass >= XED_ICLASS_NOP && iclass <= XED_ICLASS_NOP9;
        // XED classifies PAUSE (F3 90) and ENDBR32/ENDBR64 (F3 0F 1E FB/FA)
        // as NOP because they have no architectural effect, but they exist
        // as spin-loop hints and CET indirect-branch markers respectively
        // and are not interchangeable with padding NOPs.
        if (cur_nop && xed_operand_values_has_rep_prefix(xed_decoded_inst_operands_const(&xedd))) {
            cur_nop = false;
        }
        if (!cur_nop) {
            break;
        }
        // Flag only when the combined run could fit in a single multi-byte
        // NOP from the standard greedy set (NOP/NOP2..NOP9, capped at 9
        // bytes). Compilers also emit NOPs longer than 9 bytes via redundant
        // prefixes for alignment padding; combining around those would not
        // reduce byte count or instruction count.
        int cur_len = xed_decoded_inst_get_length(&xedd);
        if (prev_nop > 0 && prev_nop + cur_len <= 9) {
            return false;
        }

        prev_nop = cur_len;
        i += cur_len;
    }

    return true;
}

// TODO: consider valid uses of oversized immediate to avoid explicit no-op padding
bool check_oversized_immediate(const xed_decoded_inst_t *xedd)
{
    if (!xed_operand_values_has_immediate(xed_decoded_inst_operands_const(xedd))) {
        return true;
    }

    int iclass = xed_decoded_inst_get_iclass(xedd);

    switch (iclass) {
    case XED_ICLASS_ADC:
    case XED_ICLASS_ADD:
    case XED_ICLASS_AND:
    case XED_ICLASS_CMP:
    case XED_ICLASS_IMUL:
    case XED_ICLASS_MOV:
    case XED_ICLASS_OR:
    case XED_ICLASS_PUSH:
    case XED_ICLASS_SBB:
    case XED_ICLASS_SUB:
    case XED_ICLASS_XOR:
        break;
    default:
        return true;
    }

    int64_t imm = (int64_t) xed_decoded_inst_get_unsigned_immediate(xedd);

    switch (xed_decoded_inst_get_immediate_width_bits(xedd)) {
    case 8:
        return true;
    case 16:
        // The same shrink at 16-bit operand size: 66 81 /r iw -> 66 83 /r ib
        // saves a byte when the value fits a sign-extended imm8 (push imm16
        // -> 66 6A ib and imul -> 66 6B /r ib likewise; MOV has no such
        // form). AX is excluded: its 66 05 iw accumulator form is already 4
        // bytes, exactly tying the imm8 form -- the imm16 twin of
        // check_cmp_zero's AL rule -- and the 5-byte modrm encoding of an
        // AX-immediate op is check_implicit_register's finding.
        if (iclass != XED_ICLASS_MOV &&
            xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0) != XED_REG_AX) {
            int16_t i16 = (int16_t) imm;
            if (i16 >= INT8_MIN && i16 <= INT8_MAX) {
                return false;
            }
        }
        return true;
    case 32:
        if (iclass != XED_ICLASS_MOV) {
            // Treat the raw imm32 as signed: 0xffffffff is -1, equivalent
            // to sign-extending imm8=0xff. Otherwise XED's uint64 cast
            // would put negative-as-imm32 values out of INT8 range and
            // we would miss the shorter encoding.
            int32_t i32 = (int32_t) imm;
            if (i32 >= INT8_MIN && i32 <= INT8_MAX) {
                return false;
            }
        }
        break;
    case 64:
        // mov r/m64, imm32 (7 bytes) sign-extends, so it covers signed
        // [INT32_MIN, INT32_MAX]. mov r32, imm32 (5 bytes) zero-extends
        // to r64 via the EAX-write rule, so it covers unsigned
        // [0, UINT32_MAX]. Either shorter form replaces the 10-byte
        // movabs encoding.
        if ((imm >= INT32_MIN && imm <= INT32_MAX) ||
            (uint64_t) imm <= UINT32_MAX) {
            return false;
        }
        break;
    default:
        assert(0 && "unexpected immediate width");
        return true;
    }
    return true;
}

// TEST has no sign-extended imm8 form (F7 /0 takes a full imm16/32), so
// testing a low bit of a wide register drags a 2-4 byte immediate along:
//   test eax, 1   a9 01000000      (5 bytes)
//   test ebx, 1   f7 c3 01000000   (6 bytes)
// The byte-register form performs the identical AND on the bits that
// matter and is at least two bytes shorter for every register:
//   test al, 1    a8 01            (2 bytes)
//   test bl, 1    f6 c3 01         (3 bytes)
//   test sil, 1   40 f6 c6 01      (4 bytes, REX for the uniform byte reg)
//
// Restricted to effective masks within the low *seven* bits so the
// substitution is flag-exact and needs no liveness gate (essential: TEST
// is nearly always followed by a Jcc, where the conservative liveness
// walk would suppress a gated finding):
//   * ZF: the mask confines the result to the low byte, so zero-ness is
//     the same at either width.
//   * PF: defined from the least-significant result byte, identical.
//   * SF: 0 in both forms -- the wide result's top bit is clear because
//     the mask's is, and bit 7 of the narrow result is clear because the
//     mask's bit 7 is.
//   * CF/OF: cleared by TEST at any width; AF undefined at any width.
// A mask touching bit 7 (0x80-0xff) would make the narrow form compute SF
// from a live bit; rather than gate on FLAG_SF -- which the following
// branch would almost always suppress -- such masks are left unflagged.
// Masks confined to bits 8-15 (the test ah, imm rewrite) additionally
// change PF and only encode for the legacy A/B/C/D registers; also
// skipped.
//
// Memory operands are skipped: narrowing changes the access width, which
// is observable on MMIO (cf. check_add_sub_zero). The 64-bit form's imm32
// sign-extends, so a negative mask has high bits set and fails the
// low-seven-bits test naturally.
bool check_oversized_test_immediate(const xed_decoded_inst_t *xedd)
{
    if (xed_decoded_inst_get_iclass(xedd) != XED_ICLASS_TEST) {
        return true;
    }
    if (!xed_operand_values_has_immediate(xed_decoded_inst_operands_const(xedd))) {
        return true;
    }
    if (xed_decoded_inst_number_of_memory_operands(xedd) > 0) {
        return true;
    }
    if (xed_decoded_inst_get_immediate_width_bits(xedd) < 16) {
        return true;
    }

    unsigned width = xed_decoded_inst_get_operand_width(xedd);
    uint64_t opmask = (width >= 64) ? UINT64_MAX : (((uint64_t) 1 << width) - 1);
    uint64_t eff = (uint64_t) (int64_t) xed_decoded_inst_get_signed_immediate(xedd) & opmask;

    return (eff & ~(uint64_t) 0x7f) != 0;
}

// test reg, -1 ANDs the register with an all-ones mask, which changes nothing:
// test reg, reg computes reg & reg = reg and sets identical flags in fewer
// bytes.
//   test eax, -1   a9 ffffffff        (5 bytes)   ->   test eax, eax   85 c0     (2 bytes)
//   test rbx, -1   48 f7 c3 ffffffff  (7 bytes)   ->   test rbx, rbx   48 85 db  (3 bytes)
// The all-ones immediate is matched at the effective operand width, so the
// 64-bit form's sign-extended imm32 counts too (cf. check_xor_to_not). This is
// the full-width complement of check_oversized_test_immediate, which narrows
// masks confined to the low seven bits to the byte-register form instead.
//
// Flag-exact, so no liveness gate (cf. check_cmp_zero, check_add_sub_zero):
// test reg, -1 and test reg, reg both leave the register untouched, clear
// CF/OF, and set ZF/SF/PF from reg (AF undefined in both).
//
// AL is excluded: test al, -1 via the a8 ib accumulator opcode is already 2
// bytes, tying test al, al; its modrm form is check_implicit_register's finding
// (cf. check_xor_to_not, check_cmp_zero). Memory operands are excluded: there
// is no test [mem], [mem] form to shrink to.
bool check_test_minus_one(const xed_decoded_inst_t *xedd)
{
    if (xed_decoded_inst_get_iclass(xedd) != XED_ICLASS_TEST) {
        return true;
    }
    if (!xed_operand_values_has_immediate(xed_decoded_inst_operands_const(xedd))) {
        return true;
    }
    if (xed_decoded_inst_number_of_memory_operands(xedd) > 0) {
        return true;
    }
    if (xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0) == XED_REG_AL) {
        return true;
    }

    unsigned width = xed_decoded_inst_get_operand_width(xedd);
    uint64_t opmask = (width >= 64) ? UINT64_MAX : (((uint64_t) 1 << width) - 1);
    uint64_t eff = (uint64_t) (int64_t) xed_decoded_inst_get_signed_immediate(xedd) & opmask;

    return eff != opmask;
}

// Check for ADD REG, 128 and SUB REG, 128, which need an imm32 (128 is one
// past the +127 ceiling of a sign-extended imm8) and so encode in 5-6 bytes,
// when the negated-operation form fits in 3:
//   add reg, 128   05 80000000   ->   sub reg, -128   83 e8 80
//   sub reg, 128   2d 80000000   ->   add reg, -128   83 c0 80
// 128 is the only such value: any other immediate either already fits a
// sign-extended imm8 or its negation does not either.
//
// False positive if surrounding code reads CF: ADD sets CF on unsigned
// overflow, SUB sets CF on borrow, so a subsequent JC/JNC/ADC/SBB diverges.
// The dispatcher gates this on FLAG_CF.
bool check_oversized_add_sub_128(const xed_decoded_inst_t *xedd)
{
    if (!xed_operand_values_has_immediate(xed_decoded_inst_operands_const(xedd))) {
        return true;
    }

    switch (xed_decoded_inst_get_iclass(xedd)) {
    case XED_ICLASS_ADD:
    case XED_ICLASS_SUB:
        break;
    default:
        return true;
    }

    int64_t imm = (int64_t) xed_decoded_inst_get_unsigned_immediate(xedd);

    switch (xed_decoded_inst_get_immediate_width_bits(xedd)) {
    case 8:
    case 16:
        return true;
    case 32:
    case 64:
        if (imm == 128) {
            return false;
        }
        break;
    default:
        assert(0 && "unexpected immediate width");
        return true;
    }
    return true;
}

// A 66 operand-size prefix on an instruction whose immediate it narrows to
// 16 bits changes the instruction's length relative to the same opcode
// without the prefix -- a "length-changing prefix". Intel's pre-decoder
// speculates instruction lengths without consulting prefixes and re-walks
// the bytes when the guess proves wrong, costing ~3 cycles per visit on big
// cores through the Skylake era (Intel optimization manual, "Length-Changing
// Prefixes"; mov dx, 0x1234 is the manual's own example):
//
//   add cx, 0x1234   66 81 c1 34 12
//
// Advisory, like missing LOCK: the clean fix -- a 32-bit operation -- writes
// bits 16-31 of the destination, and nothing here tracks upper-16 liveness,
// so no rewrite is claimed. Register and memory forms alike stall (the cost
// is in pre-decode, before operands matter).
//
// The match is an iclass whitelist of exactly the ALU/MOV/PUSH/TEST forms
// whose imm16 exists only under the prefix, so an instruction with a FIXED
// 16-bit immediate that no prefix modulates -- ret 0x1234, enter -- cannot
// match. Mandatory-66 SSE never carries an imm16 (every SSE immediate is a
// byte), closing that side twice over. The sign-extended imm8 forms are imm8
// at any operand size -- no length change, not matched -- and a 66-prefixed
// imm16 whose value would fit that imm8 form is already the oversized-
// immediate finding, whose narrowing removes the LCP by itself; assemblers
// emit the imm8 form to begin with, so the overlap is hand-encoded-only and
// either finding's fix resolves both.
bool check_lcp_imm16(const xed_decoded_inst_t *xedd)
{
    switch (xed_decoded_inst_get_iclass(xedd)) {
    case XED_ICLASS_ADC:
    case XED_ICLASS_ADD:
    case XED_ICLASS_AND:
    case XED_ICLASS_CMP:
    case XED_ICLASS_IMUL:
    case XED_ICLASS_MOV:
    case XED_ICLASS_OR:
    case XED_ICLASS_PUSH:
    case XED_ICLASS_SBB:
    case XED_ICLASS_SUB:
    case XED_ICLASS_TEST:
    case XED_ICLASS_XOR:
        break;
    default:
        return true;
    }
    if (xed_decoded_inst_get_immediate_width_bits(xedd) != 16) {
        return true;
    }
    // The whitelisted iclasses reach an imm16 only through the prefix, but
    // keep the direct test so a decode surprise fails toward no finding.
    return !xed_operand_values_has_operand_size_prefix(
        xed_decoded_inst_operands_const(xedd));
}

// True if this register requires a REX prefix when used as a memory base
// or index. In 64-bit mode all 64-bit GPRs are valid base/index registers
// without any REX prefix; only R8-R15 require REX.B/X to encode.
static bool check_rex_addressing_register(xed_reg_enum_t reg)
{
    switch (reg) {
    case XED_REG_R8:
    case XED_REG_R9:
    case XED_REG_R10:
    case XED_REG_R11:
    case XED_REG_R12:
    case XED_REG_R13:
    case XED_REG_R14:
    case XED_REG_R15:

    case XED_REG_R8D:
    case XED_REG_R9D:
    case XED_REG_R10D:
    case XED_REG_R11D:
    case XED_REG_R12D:
    case XED_REG_R13D:
    case XED_REG_R14D:
    case XED_REG_R15D:
        return true;

    default:
        return false;
    }
}

static bool check_rex_register(xed_reg_enum_t reg)
{
    switch (reg) {
    case XED_REG_R8B:
    case XED_REG_R9B:
    case XED_REG_R10B:
    case XED_REG_R11B:
    case XED_REG_R12B:
    case XED_REG_R13B:
    case XED_REG_R14B:
    case XED_REG_R15B:

    case XED_REG_R8W:
    case XED_REG_R9W:
    case XED_REG_R10W:
    case XED_REG_R11W:
    case XED_REG_R12W:
    case XED_REG_R13W:
    case XED_REG_R14W:
    case XED_REG_R15W:

    case XED_REG_R8D:
    case XED_REG_R9D:
    case XED_REG_R10D:
    case XED_REG_R11D:
    case XED_REG_R12D:
    case XED_REG_R13D:
    case XED_REG_R14D:
    case XED_REG_R15D:

    case XED_REG_R8:
    case XED_REG_R9:
    case XED_REG_R10:
    case XED_REG_R11:
    case XED_REG_R12:
    case XED_REG_R13:
    case XED_REG_R14:
    case XED_REG_R15:

    case XED_REG_SPL:
    case XED_REG_BPL:
    case XED_REG_SIL:
    case XED_REG_DIL:

    case XED_REG_RAX:
    case XED_REG_RCX:
    case XED_REG_RDX:
    case XED_REG_RBX:
    case XED_REG_RSP:
    case XED_REG_RBP:
    case XED_REG_RSI:
    case XED_REG_RDI:
        return true;

    default:
        return false;
    }
}

/**
 * A REX prefix must be encoded when:
 *
 * * using 64-bit operand size and the instruction does not default to 64-bit operand size; or
 * * using one of the extended registers (R8 to R15, XMM8 to XMM15, YMM8 to YMM15, CR8 to CR15 and DR8 to DR15); or
 * * using one of the uniform byte registers SPL, BPL, SIL or DIL.
 */
bool check_unneeded_rex(const xed_decoded_inst_t *xedd)
{
    // Nothing to flag without a REX prefix. xed3_operand_get_rex is used
    // here (and xed3_operand_get_rex{r,x,b} below) because XED's public
    // xed_operand_values_* surface only exposes has_rexw_prefix; bare-REX
    // presence and the individual R/X/B bits have no public accessor.
    if (!xed3_operand_get_rex(xedd)) {
        return true;
    }

    // Instructions where REX.W has no effect (default 64-bit operand size).
    // REX is still needed if R/X/B are required to address an extended
    // register operand (e.g. call r12, jmp [r13]).
    // These iclasses must be checked before the register-operand scan
    // below, which would otherwise trip on implicit RSP or RCX.
    switch (xed_decoded_inst_get_iclass(xedd)) {
    case XED_ICLASS_CALL_NEAR:
    case XED_ICLASS_ENTER:
    case XED_ICLASS_JB:
    case XED_ICLASS_JBE:
    case XED_ICLASS_JL:
    case XED_ICLASS_JLE:
    case XED_ICLASS_JNB:
    case XED_ICLASS_JNBE:
    case XED_ICLASS_JNL:
    case XED_ICLASS_JNLE:
    case XED_ICLASS_JNO:
    case XED_ICLASS_JNP:
    case XED_ICLASS_JNS:
    case XED_ICLASS_JNZ:
    case XED_ICLASS_JO:
    case XED_ICLASS_JP:
    case XED_ICLASS_JS:
    case XED_ICLASS_JZ:
    case XED_ICLASS_JCXZ:
    case XED_ICLASS_JECXZ:
    case XED_ICLASS_JRCXZ:
    case XED_ICLASS_JMP:
    case XED_ICLASS_LEAVE:
    case XED_ICLASS_LGDT:
    case XED_ICLASS_LIDT:
    case XED_ICLASS_LLDT:
    case XED_ICLASS_LOOP:
    case XED_ICLASS_LOOPE:
    case XED_ICLASS_LOOPNE:
    case XED_ICLASS_LTR:
    case XED_ICLASS_MOV_CR:
    case XED_ICLASS_MOV_DR:
    case XED_ICLASS_POP:
    case XED_ICLASS_POPFQ:
    case XED_ICLASS_PUSH:
    case XED_ICLASS_PUSHFQ:
    case XED_ICLASS_RET_NEAR:
        if (xed3_operand_get_rexr(xedd) == 0 &&
            xed3_operand_get_rexx(xedd) == 0 &&
            xed3_operand_get_rexb(xedd) == 0) {
            return false;
        }
        return true;
    case XED_ICLASS_XOR: {
        // The same-register zero-idiom xor reg, reg with REX.W can shrink
        // to the 32-bit form (which zero-extends). Different registers
        // operate on full 64 bits; substituting the 32-bit form would
        // change semantics by clearing the upper half. Also requires no
        // other REX bits, since REX.R/X/B encode R8-R15.
        xed_reg_enum_t r0 = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);
        xed_reg_enum_t r1 = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1);
        if (xed_operand_values_has_rexw_prefix(xed_decoded_inst_operands_const(xedd)) &&
            xed3_operand_get_rexr(xedd) == 0 &&
            xed3_operand_get_rexx(xedd) == 0 &&
            xed3_operand_get_rexb(xedd) == 0 &&
            r0 != XED_REG_INVALID && r0 == r1) {
            return false;
        }
        break;
    }
    case XED_ICLASS_MOVZX: {
        // movzx r64, r/m8 and movzx r64, r/m16 zero-extend the source through
        // bit 63; the movzx r32 form produces the identical 64-bit value via
        // the 32-bit-write zero-extension rule, so REX.W is redundant. (movsx
        // is *not* equivalent: its r32 form sign-extends to 32 then
        // zero-extends, leaving bits 32-63 clear rather than sign-filled --
        // so MOVSX/MOVSXD keep REX.W and fall through to the scan below.)
        //
        // As with the xor idiom, only flag when dropping REX.W removes the
        // whole REX byte: REX.R/X/B == 0 rules out an extended destination
        // (REX.R), extended byte/word source (REX.B), or extended memory
        // base/index (REX.X/B), and a SPL/BPL/SIL/DIL source still needs a
        // bare REX to select the uniform byte register.
        xed_reg_enum_t src = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1);
        if (xed_operand_values_has_rexw_prefix(xed_decoded_inst_operands_const(xedd)) &&
            xed3_operand_get_rexr(xedd) == 0 &&
            xed3_operand_get_rexx(xedd) == 0 &&
            xed3_operand_get_rexb(xedd) == 0 &&
            src != XED_REG_SPL && src != XED_REG_BPL &&
            src != XED_REG_SIL && src != XED_REG_DIL) {
            return false;
        }
        break;
    }
    default:
        break;
    }

    for (int i = 0; i < xed_decoded_inst_number_of_memory_operands(xedd); ++i) {
        if (check_rex_addressing_register(xed_decoded_inst_get_base_reg(xedd, i)) ||
            check_rex_addressing_register(xed_decoded_inst_get_index_reg(xedd, i))) {
            return true;
        }
    }
    if (check_rex_register(xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0)) ||
        check_rex_register(xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1))) {
        return true;
    }

    // Bare 0x40 prefix with no W/R/X/B bits set carries no information.
    if (!xed_operand_values_has_rexw_prefix(xed_decoded_inst_operands_const(xedd)) &&
        xed3_operand_get_rexr(xedd) == 0 &&
        xed3_operand_get_rexx(xedd) == 0 &&
        xed3_operand_get_rexb(xedd) == 0) {
        return false;
    }
    return true;
}

bool check_cmp_zero(const xed_decoded_inst_t *xedd)
{
    if (!xed_operand_values_has_immediate(xed_decoded_inst_operands_const(xedd))) {
        return true;
    }

    // do not consider comparisons of zero to memory
    if (xed_decoded_inst_number_of_memory_operands(xedd) > 0) {
        return true;
    }

    if (xed_decoded_inst_get_iclass(xedd) != XED_ICLASS_CMP) {
        return true;
    }

    // Skip cmp al, 0: its 1-byte-opcode accumulator form (3C 00) is already
    // 2 bytes, exactly tying test al, al, so substituting test never yields
    // smaller code. AL is the only register with both a 1-byte CMP opcode
    // and a 1-byte immediate; every other register and width has a
    // cmp reg, 0 encoding at least one byte larger than test reg, reg.
    if (xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0) == XED_REG_AL) {
        return true;
    }

    return xed_decoded_inst_get_unsigned_immediate(xedd) != 0;
}

// TODO: could have false positives for sequences preserving flags
bool check_mov_zero(const xed_decoded_inst_t *xedd)
{
    switch (xed_decoded_inst_get_iclass(xedd)) {
    case XED_ICLASS_MOV:
        break;
    default:
        return true;
    }

    // do not consider stores of zero to memory
    if (xed_decoded_inst_number_of_memory_operands(xedd) > 0) {
        return true;
    }

    if (!xed_operand_values_has_immediate(xed_decoded_inst_operands_const(xedd))) {
        return true;
    }

    switch (xed_decoded_inst_get_immediate_width_bits(xedd)) {
    case 0:
    case 8:
    case 16:
        break;
    case 32: {
        int64_t imm = (int64_t) xed_decoded_inst_get_unsigned_immediate(xedd);
        if (imm == 0) {
            return false;
        }
        break;
    }
    case 64:
        break;
    default:
        assert(0 && "unexpected immediate width");
        return true;
    }

    return true;
}

// Some instructions implicitly specify EAX register without needing ModRM byte.
bool check_implicit_register(const xed_decoded_inst_t *xedd)
{
    switch (xed_decoded_inst_get_iclass(xedd)) {
    case XED_ICLASS_ADC:
    case XED_ICLASS_ADD:
    case XED_ICLASS_AND:
    case XED_ICLASS_CMP:
    case XED_ICLASS_OR:
    case XED_ICLASS_SBB:
    case XED_ICLASS_SUB:
    case XED_ICLASS_TEST:
    case XED_ICLASS_XOR:
        break;
    default:
        return true;
    }

    if (!xed_operand_values_has_modrm_byte(xedd)) {
        return true;
    }

    xed_reg_enum_t reg = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);

    if (!xed_operand_values_has_immediate(xed_decoded_inst_operands_const(xedd))) {
        return true;
    }

    switch (xed_decoded_inst_get_immediate_width_bits(xedd)) {
    case 8:
        if (reg == XED_REG_AL) {
            return false;
        }
        break;
    case 16:
        if (reg == XED_REG_AX) {
            return false;
        }
        break;
    case 32:
        if (reg == XED_REG_EAX || reg == XED_REG_RAX) {
            return false;
        }
        break;
    case 0:
    default:
        break;
    }

    return true;
}

bool check_implicit_immediate(const xed_decoded_inst_t *xedd)
{
    xed_uint64_t imm = xed_decoded_inst_get_unsigned_immediate(xedd);
    if (imm != 1) {
        return true;
    }
    switch (xed_decoded_inst_get_iform_enum(xedd)) {
    case XED_IFORM_RCL_GPRv_IMMb:
    case XED_IFORM_RCR_GPRv_IMMb:
    case XED_IFORM_ROL_GPRv_IMMb:
    case XED_IFORM_ROR_GPRv_IMMb:
    //case XED_IFORM_SAL_GPRv_IMMb:
    case XED_IFORM_SAR_GPRv_IMMb:
    //case XED_IFORM_SHL_GPRv_IMMb:
    case XED_IFORM_SHR_GPRv_IMMb:
        return false;
    default:
        break;
    }
    return true;
}

// AND DST, IMM can be replaced by MOVZBL / MOVZWL when the mask keeps a low
// byte or word and zeros everything above it -- e.g. and eax, 0xff -> movzx
// eax, al. Both replacements produce a register zero-extended through bit 63,
// so the substitution is valid only when:
//
//   * the destination is a register (movzx cannot target memory); and
//   * the AND writes a 32- or 64-bit register, so the write itself clears
//     bits up to 63 (an 8-/16-bit AND preserves the upper register bytes,
//     which movzx would instead zero); and
//   * the *effective* mask -- the immediate sign-extended and truncated to
//     the operand width -- is exactly 0xff or 0xffff.
//
// Matching the effective mask rather than the raw immediate byte separates a
// genuine low-byte mask (and eax, 0xff, encoded with an imm32) from a
// sign-extended all-ones no-op (and eax, sx(0xff) = 0xffffffff, encoded
// 83 e0 ff): only the former reduces to movzbl. The all-ones mask is a value
// no-op with no zero-extending win, so it is check_and_minus_one's finding
// (-> test reg, reg) instead.
//
// False positive if surrounding code reads ZF/SF/PF: AND sets them based on
// the masked result and clears CF/OF; MOVZX does not touch flags. A
// subsequent JZ/JS/JP would diverge, so the dispatcher gates this on
// FLAG_ARITH.
bool check_and_strength_reduce(const xed_decoded_inst_t *xedd)
{
    if (xed_decoded_inst_get_iclass(xedd) != XED_ICLASS_AND) {
        return true;
    }
    if (!xed_operand_values_has_immediate(xed_decoded_inst_operands_const(xedd))) {
        return true;
    }
    if (xed_decoded_inst_number_of_memory_operands(xedd) > 0) {
        return true;
    }

    unsigned width = xed_decoded_inst_get_operand_width(xedd);
    if (width != 32 && width != 64) {
        return true;
    }

    uint64_t opmask = (width == 64) ? UINT64_MAX : (((uint64_t) 1 << width) - 1);
    uint64_t eff = (uint64_t) (int64_t) xed_decoded_inst_get_signed_immediate(xedd) & opmask;

    if (eff == 0xff || eff == 0xffff) {
        return false;
    }
    return true;
}

// and reg, -1 keeps every bit (the mask is all ones), so it changes only the
// flags -- and test reg, reg reproduces those exactly (CF=OF=0, ZF/SF/PF from
// reg, AF undefined in both) in fewer bytes:
//   and eax, -1   83 e0 ff      (3 bytes)   ->   test eax, eax   85 c0     (2 bytes)
//   and rax, -1   48 83 e0 ff   (4 bytes)   ->   test rax, rax   48 85 c0  (3 bytes)
// The all-ones immediate is matched at the effective operand width (cf.
// check_xor_to_not, check_test_minus_one). Flag-exact, so no flag-liveness
// gate: this is the flag-preserving counterpart to check_and_strength_reduce's
// former all-ones -> mov reg, reg (FLAG_ARITH-gated, so it vanished exactly
// when a downstream reader made the finding worth acting on). What test does
// drop is the 32-bit form's write: and eax, -1 zero-extends bits 63:32 where
// test writes nothing -- GCC emits exactly this shape as a fused
// zero-extend-and-test, branching and then reading the full register -- so the
// dispatcher gates that form on upper-32 liveness (reg0_upper32_concern, cf.
// check_mov_self). The other widths are value-identical and fire
// unconditionally. The wider all-ones masks and reg is full width already
// leave nothing for movzx/mov to shorten, so this is their only finding.
//
// AL is excluded: and al, -1 via the 24 ib accumulator opcode is already 2
// bytes, tying test al, al; its modrm form is check_implicit_register's
// finding. Memory is excluded: there is no test [mem], [mem], and a masked
// store may be intentional.
bool check_and_minus_one(const xed_decoded_inst_t *xedd)
{
    if (xed_decoded_inst_get_iclass(xedd) != XED_ICLASS_AND) {
        return true;
    }
    if (!xed_operand_values_has_immediate(xed_decoded_inst_operands_const(xedd))) {
        return true;
    }
    if (xed_decoded_inst_number_of_memory_operands(xedd) > 0) {
        return true;
    }
    if (xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0) == XED_REG_AL) {
        return true;
    }

    unsigned width = xed_decoded_inst_get_operand_width(xedd);
    uint64_t opmask = (width >= 64) ? UINT64_MAX : (((uint64_t) 1 << width) - 1);
    uint64_t eff = (uint64_t) (int64_t) xed_decoded_inst_get_signed_immediate(xedd) & opmask;

    return eff != opmask;
}

// xor r/m, -1 flips every bit, which is not r/m, one byte shorter in every
// encoding:
//   xor eax, -1   83 f0 ff      (3 bytes)   ->   not eax   f7 d0      (2 bytes)
//   xor rax, -1   48 83 f0 ff   (4 bytes)   ->   not rax   48 f7 d0   (3 bytes)
// The all-ones immediate is matched at the effective operand width, so the
// sign-extended imm8/imm32 encodings count too (cf. check_and_strength_reduce).
//
// False positive if surrounding code reads any arithmetic flag: XOR sets
// CF/OF/SF/ZF/PF (AF undefined); NOT writes none. The dispatcher gates this
// on FLAG_ARITH.
//
// AL is excluded: xor al, -1 via the 34 ib accumulator opcode is already 2
// bytes, tying not al; its modrm form is check_implicit_register's finding
// (cf. check_cmp_zero). Memory destinations are included: not [mem] performs
// the same-width read-modify-write at the same address, and the locked forms
// decode to the distinct XOR_LOCK iclass (cf. check_inc_dec).
bool check_xor_to_not(const xed_decoded_inst_t *xedd)
{
    if (xed_decoded_inst_get_iclass(xedd) != XED_ICLASS_XOR) {
        return true;
    }
    if (!xed_operand_values_has_immediate(xed_decoded_inst_operands_const(xedd))) {
        return true;
    }
    if (xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0) == XED_REG_AL) {
        return true;
    }

    unsigned width = xed_decoded_inst_get_operand_width(xedd);
    uint64_t opmask = (width >= 64) ? UINT64_MAX : (((uint64_t) 1 << width) - 1);
    uint64_t eff = (uint64_t) (int64_t) xed_decoded_inst_get_signed_immediate(xedd) & opmask;

    return eff != opmask;
}


bool check_superfluous_lock_prefix(const xed_decoded_inst_t *xedd)
{
    bool has_lock = xed_operand_values_has_lock_prefix(xed_decoded_inst_operands_const(xedd));

    switch (xed_decoded_inst_get_iclass(xedd)) {
    case XED_ICLASS_XCHG:
        return !has_lock;
    default:
        return true;
    }
}

// gcc through version 7 emitted rep ret (F3 C3) for generic tuning: AMD
// K8/K10 branch predictors mispredicted a one-byte RET that was a branch
// target or followed a Jcc, and the ignored F3 prefix was AMD's recommended
// two-byte spelling (Agner Fog's microarchitecture guide). Every core
// ignores the prefix -- the workaround depended on exactly that -- and the
// predictor quirk is gone since Bulldozer and Zen, so the byte is pure
// waste: dropping it is value- and flag-identical, unconditional. Only F3 is
// matched; F2 C3 was MPX's bnd ret, which carried real bounds semantics on
// MPX silicon. (A future re-definition of F3 C3, cf. F3 90 becoming PAUSE,
// is the same accepted residual as the other prefix-dropping checks.)
bool check_rep_ret(const xed_decoded_inst_t *xedd)
{
    if (xed_decoded_inst_get_iclass(xedd) != XED_ICLASS_RET_NEAR) {
        return true;
    }
    return !xed_operand_values_has_rep_prefix(
        xed_decoded_inst_operands_const(xedd));
}

// The NOTRACK prefix (3E) on an indirect near CALL or JMP exempts that one
// transfer from CET indirect-branch tracking: the CPU will not require an
// ENDBR64 landing pad at the target (Intel SDM vol. 1, Control-flow
// Enforcement Technology chapter). Compilers emit it for exactly one shape
// -- register-form JMPs through read-only switch tables, whose basic-block
// targets legitimately lack pads (all 447 NOTRACK branches across bash,
// libc, ld.so, and libcrypto on Fedora 44 are that shape) -- so indirect
// JMPs are not matched. A NOTRACK call reaches compiler output only through
// an explicit __attribute__((nocf_check)) function-pointer type, otherwise
// hand-written assembly: a deliberately untracked forward edge in an
// otherwise enforced binary, exactly where a CFI bypass hides. Unlike the
// optimization checks this finding is a security review flag, not a rewrite
// -- deleting the prefix makes the call tracked, which #CP-faults if the
// target really lacks a pad. Direct and far calls need no gate here: XED's
// cet_no_track is already false for them (their 3E is an ignored legacy
// segment override with no CET meaning).
bool check_notrack_call(const xed_decoded_inst_t *xedd)
{
    if (xed_decoded_inst_get_iclass(xedd) != XED_ICLASS_CALL_NEAR) {
        return true;
    }
    return !xed_operand_values_cet_no_track(
        xed_decoded_inst_operands_const(xedd));
}

// xchg between a word/dword/qword accumulator (AX/EAX/RAX) and another
// register has a one-byte 90+r form; the modrm form (87 /r) is one byte
// longer:
//   xchg eax, ecx   87 c8   (2 bytes)
//   xchg ecx, eax   91      (1 byte)
//
// Excluded:
//   - memory operands: there is no 90+r form for xchg r/m, r (and a
//     memory xchg carries an implicit LOCK, so it is never a bare move).
//   - 8-bit xchg (AL): 90+r is word-size and up, so xchg al, r8 has no
//     short form.
//   - xchg acc, acc (same register): the 90+r encoding would be 0x90,
//     which is NOP and -- unlike xchg eax, eax via 87 c0 -- does not
//     zero-extend the accumulator into its 64-bit register.
bool check_xchg_accumulator(const xed_decoded_inst_t *xedd)
{
    if (xed_decoded_inst_get_iclass(xedd) != XED_ICLASS_XCHG) {
        return true;
    }
    if (xed_decoded_inst_number_of_memory_operands(xedd) > 0) {
        return true;
    }
    // The 90+r short form carries no modrm byte; only the 87 /r form does.
    if (!xed_operand_values_has_modrm_byte(xedd)) {
        return true;
    }

    xed_reg_enum_t r0 = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);
    xed_reg_enum_t r1 = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1);
    if (r0 == r1) {
        return true;
    }

    bool accumulator =
        r0 == XED_REG_AX || r0 == XED_REG_EAX || r0 == XED_REG_RAX ||
        r1 == XED_REG_AX || r1 == XED_REG_EAX || r1 == XED_REG_RAX;
    return !accumulator;
}

// IMUL r, r, imm by a small constant can be strength-reduced to a LEA or SHL,
// which on most uarches have shorter latency and avoid the multiplier --
// and the degenerate multipliers, JIT constant-folding residue, need no
// multiply at all.
//
//   * imm in {2,3,5,9}: dst = src*{2,3,5,9} is lea [src + src*{1,2,4,8}],
//     valid for any destination register.
//   * imm a power of two >= 4: dst = src << log2(imm), i.e. shl by the shift
//     amount. The single-LEA form would be [src*scale], which needs an
//     absolute disp32 (SIB base=101) and whose scale maxes at 8, so it is
//     never shorter; SHL requires the destination and source to coincide, and
//     a different-register imul r, r2, 2^k is left alone. (imm 2 stays a LEA:
//     lea [src+src] serves any destination, unlike shl.)
//   * imm 0: the product is always zero -- xor dst, dst, shorter and
//     dependency-free. A zero product cannot overflow, so imul leaves
//     CF=OF=0 exactly as xor does; the shared CF/OF gate below is merely
//     conservative here.
//   * imm 1: the product is the source -- mov dst, src, or nothing at all
//     when they coincide. The bare removal is the one rewrite here that
//     drops a register write, so its 32-bit form loses the zero-extension
//     into bits 63:32; imul_identity_upper_concern gates exactly that form
//     on upper-32 liveness (cf. check_mov_self).
//   * imm -1 with dst == src: negation in place -- neg dst, one byte
//     shorter. neg's OF (set only for the minimum value) matches imul's
//     overflow condition exactly; its CF = (src != 0) does diverge, covered
//     by the CF/OF gate. A different-register imul r, r2, -1 (3 bytes) beats
//     mov + neg (4) and stays.
//
// The multiplier is matched at the effective operand width, so the 32-bit
// imul eax, eax, 0x80000000 (2^31 mod 2^32 = shl eax, 31) is caught while the
// 64-bit imul rax, rax, 0x80000000 -- whose imm32 sign-extends to -2^31, not a
// power of two -- is not. A power of two 2^k confined to the width has
// k < width, so the shl count is never masked.
//
// Memory-source IMUL (IMUL r, [m], imm) is not flagged: for the strength
// reductions the replacement would need a separate load first, and for the
// degenerate multipliers it would drop the load -- a memory read that may be
// intentional (cf. check_add_sub_zero's MMIO note).
//
// False positive if surrounding code reads CF or OF: IMUL sets both on
// signed overflow, which none of the replacements reproduces in general (see
// the per-constant notes above). SF/ZF/PF go from SDM-undefined to defined,
// destroyed either way. The dispatcher gates on FLAG_CF | FLAG_OF.
bool check_imul_to_lea(const xed_decoded_inst_t *xedd)
{
    if (xed_decoded_inst_get_iclass(xedd) != XED_ICLASS_IMUL) {
        return true;
    }
    if (!xed_operand_values_has_immediate(xed_decoded_inst_operands_const(xedd))) {
        return true;
    }
    if (xed_decoded_inst_number_of_memory_operands(xedd) > 0) {
        return true;
    }

    unsigned width = xed_decoded_inst_get_operand_width(xedd);
    uint64_t opmask = (width >= 64) ? UINT64_MAX : (((uint64_t) 1 << width) - 1);
    uint64_t eff = (uint64_t) (int64_t) xed_decoded_inst_get_signed_immediate(xedd) & opmask;

    xed_reg_enum_t dst = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);
    xed_reg_enum_t src = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1);
    bool in_place = dst != XED_REG_INVALID && dst == src;

    // Degenerate multipliers: 0 -> xor, 1 -> mov or removal, -1 -> neg
    // (in place only; the different-register form is already minimal).
    if (eff == 0 || eff == 1 || (eff == opmask && in_place)) {
        return false;
    }

    switch (eff) {
    case 2: case 3: case 5: case 9:
        return false;
    default:
        break;
    }

    // A power of two >= 4 reduces to SHL, but only when the destination and
    // source coincide (there is no shorter LEA form).
    if (eff >= 4 && (eff & (eff - 1)) == 0) {
        return !in_place;
    }

    return true;
}

// lea dst, [base] with no index and a zero displacement computes exactly the
// base register, so it is mov dst, base. MOV issues on more execution ports
// and skips the address-generation unit, and for an RBP/R13 or RSP/R12 base
// the lea is even a byte longer (a disp8=0 or SIB byte is forced). Both
// instructions leave the flags untouched, so the rewrite is always valid.
//
// Restricted to a base whose width matches the destination: a mixed
// operand/address size (lea rax, [ebx] or lea eax, [rbx]) would need a mov
// of a different width and is left alone. A RIP-relative lea computes a
// PC-relative address rather than a register copy and is excluded; so is a
// pure index form (lea rax, [rcx*2]), which is not a bare base.
bool check_lea_to_mov(const xed_decoded_inst_t *xedd)
{
    if (xed_decoded_inst_get_iclass(xedd) != XED_ICLASS_LEA) {
        return true;
    }
    if (xed_decoded_inst_get_index_reg(xedd, 0) != XED_REG_INVALID) {
        return true;
    }
    if (xed_decoded_inst_get_memory_displacement(xedd, 0) != 0) {
        return true;
    }

    xed_reg_enum_t base = xed_decoded_inst_get_base_reg(xedd, 0);
    if (base == XED_REG_INVALID ||
        base == XED_REG_RIP || base == XED_REG_EIP) {
        return true;
    }

    xed_reg_enum_t dst = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);
    if (xed_get_register_width_bits64(dst) !=
        xed_get_register_width_bits64(base)) {
        return true;
    }

    return false;
}

// lea dst, [reg + reg2] with unit scale and no displacement adds two registers;
// when dst is one of those two registers the add is in place, so add dst, other
// computes the same value a byte shorter (no SIB byte) and on more execution
// ports. lea leaves the flags untouched while add writes them, so the dispatcher
// gates this on FLAG_ARITH (cf. check_lea_to_mov, the no-index [base] case, and
// check_mov_zero's mov reg, 0 -> xor). When dst matches neither address register
// (lea eax, [rcx + rdx]) the lea is a genuine three-operand add that add cannot
// express, and is kept.
//
// The registers are compared by enclosing register, so a mixed operand/address
// size folds too: lea eax, [rax + rcx] is add eax, ecx because low-width
// arithmetic is closed (the low W bits of base + index equal the sum of their
// low W bits). A scale (lea rax, [rax + rcx*2]) or a displacement is not a plain
// two-register add and is excluded, as is the pure base or RIP-relative form
// (no index), which check_lea_to_mov owns.
bool check_lea_to_add(const xed_decoded_inst_t *xedd)
{
    if (xed_decoded_inst_get_iclass(xedd) != XED_ICLASS_LEA) {
        return true;
    }

    xed_reg_enum_t base = xed_decoded_inst_get_base_reg(xedd, 0);
    xed_reg_enum_t index = xed_decoded_inst_get_index_reg(xedd, 0);
    if (base == XED_REG_INVALID || index == XED_REG_INVALID ||
        xed_decoded_inst_get_scale(xedd, 0) != 1 ||
        xed_decoded_inst_get_memory_displacement(xedd, 0) != 0) {
        return true;
    }

    // The destination must be one of the two address registers, so the add is
    // in place rather than a three-operand sum.
    xed_reg_enum_t dst = xed_get_largest_enclosing_register(
        xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0));
    if (dst != xed_get_largest_enclosing_register(base) &&
        dst != xed_get_largest_enclosing_register(index)) {
        return true;
    }

    return false;
}

// lea r64 and lea r32 compute the same effective address and store the same
// low 32 bits of it -- the destination width only selects how much of the
// address survives: the 64-bit form stores its upper half into bits 32-63,
// the 32-bit form zeroes them. (Under a 32-bit address override the two agree
// in all 64 bits -- the 32-bit address zero-extends either way -- so the gate
// below is merely sufficient there.) When bits 32-63 of the destination are
// dead the forms are interchangeable and the narrow one is shorter by exactly
// the REX.W byte, so flag only when W is the sole REX payload: an extended
// register in any slot (destination, base, or index) keeps the prefix and the
// narrowed form would be the same length. LEA has no byte-register operand,
// so no other REX dependence exists. The dispatcher gates the finding on the
// upper half being dead (lea_width_upper_concern) WITHOUT the backward
// zero-extension escape (reg_zx_escape stays false in the checks table): this
// rewrite still writes the register, so a predecessor's zeroing of the
// destination is overwritten either way and proves nothing about the
// address's upper half.
bool check_oversized_lea_width(const xed_decoded_inst_t *xedd)
{
    if (xed_decoded_inst_get_iclass(xedd) != XED_ICLASS_LEA) {
        return true;
    }
    if (xed_decoded_inst_get_operand_width(xedd) != 64) {
        return true;
    }
    if (xed3_operand_get_rexr(xedd) != 0 ||
        xed3_operand_get_rexx(xedd) != 0 ||
        xed3_operand_get_rexb(xedd) != 0) {
        return true;
    }
    return false;
}

// shl reg, 1 doubles the register exactly as add reg, reg does, with
// IDENTICAL flags: CF receives the shifted-out MSB either way (add's carry
// out is that same bit); OF -- defined for a 1-bit shift -- is
// MSB(result) XOR CF for the shift and in-sign XOR out-sign for the add, the
// same two bits of the same values; SF/ZF/PF derive from the same result.
// (AF: undefined for the shift, defined for the add -- unobservable in 64-bit
// mode either way.) The add matches the D0/D1 encodings byte for byte
//   shl eax, 1   d1 e0   ->   add eax, eax   01 c0
// while issuing on roughly twice the execution ports (p0156 vs p06 on recent
// Intel, similarly on AMD), and beats the C0/C1 imm8 encodings of a 1-count
// shift by a byte besides. Value- and flag-exact at every width, 8-bit
// included, so the rewrite is unconditional -- it fires even into a
// following CF reader.
//
// Only SHL qualifies: shr/sar and the rotates by 1 have no two-operand ALU
// twin. Memory destinations are excluded -- there is no add [mem], [mem] --
// and so is the CL form, whose runtime count is not statically 1; its count
// register CL rides in REG1, which the ONE and IMMb register forms never
// populate with CL. (check_implicit_immediate deliberately leaves SHL's
// C1 -> D1 narrowing disabled; this finding subsumes it with the stronger
// rewrite.)
bool check_shl_one(const xed_decoded_inst_t *xedd)
{
    if (xed_decoded_inst_get_iclass(xedd) != XED_ICLASS_SHL) {
        return true;
    }
    if (xed_decoded_inst_number_of_memory_operands(xedd) > 0) {
        return true;
    }
    if (xed_reg_class(xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0)) !=
            XED_REG_CLASS_GPR) {
        return true;
    }
    // shl reg, cl carries the count register as REG1.
    if (xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1) == XED_REG_CL) {
        return true;
    }
    // The D0/D1 forms encode the 1 implicitly; the C0/C1 forms carry an imm8
    // that must be exactly 1.
    if (xed_operand_values_has_immediate(xed_decoded_inst_operands_const(xedd)) &&
        xed_decoded_inst_get_unsigned_immediate(xedd) != 1) {
        return true;
    }
    return false;
}

// SHL/SHR/SAR with a CL count on a 32/64-bit register have flagless BMI2
// equivalents: shlx/shrx/sarx take the count in any register and write no
// flags at all, where the legacy CL forms update CF/OF/SF/ZF/PF (for a
// nonzero count) and cost flag-merge uops on Intel cores. The dispatcher
// runs this check only when the caller enabled BMI2 (-m bmi2) and applies
// two gates:
//   * every arithmetic flag must be dead -- the legacy form writes them all
//     for a nonzero count and preserves them at count 0, the BMI2 form never
//     writes them, so equal flag state needs them unread either way;
//   * for 32-bit forms, the destination's upper 32 bits must be dead
//     (reg0_upper32_concern): the SDM's count-0 pseudocode skips the
//     destination write, so the legacy shift may preserve those bits where
//     shlx always zero-extends -- the same weaker-guarantee reading as
//     check_shift_zero, whose comment records that measured hardware
//     zero-extends anyway.
// Memory destinations are excluded (the BMI2 forms have none), as are 8- and
// 16-bit widths (no BMI2 form exists).
bool check_missing_shlx(const xed_decoded_inst_t *xedd)
{
    switch (xed_decoded_inst_get_iclass(xedd)) {
    case XED_ICLASS_SHL:
    case XED_ICLASS_SHR:
    case XED_ICLASS_SAR:
        break;
    default:
        return true;
    }
    if (xed_decoded_inst_number_of_memory_operands(xedd) > 0) {
        return true;
    }
    unsigned width = xed_decoded_inst_get_operand_width(xedd);
    if (width != 32 && width != 64) {
        return true;
    }
    if (xed_reg_class(xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0)) !=
            XED_REG_CLASS_GPR) {
        return true;
    }
    // The CL-count forms carry the count register as REG1 (cf.
    // check_shl_one); the by-1 and imm8 forms do not.
    return xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1) != XED_REG_CL;
}

// Shift and rotate instructions with an immediate count of 0 are value- and
// flag-preserving: the destination keeps its value and per the Intel SDM the
// flags are explicitly "not affected" when the count is 0. Removal is still
// not unconditional for the 32-bit register forms: the SDM's count-0
// pseudocode skips the destination write, but measured hardware (AMD Zen 5)
// performs it anyway, zero-extending bits 63:32 -- so the dispatcher gates
// those on upper-32 liveness (reg0_upper32_concern, cf. check_mov_self).
// The other register widths change no state under either reading and fire
// unconditionally. The CL-register form cannot be checked statically.
//
// Memory destinations are excluded: removing shl dword [rdi], 0 deletes a
// memory ACCESS, which is architecturally observable in itself -- the RMW
// form loads its operand even at count 0 (the pseudocode's tempDEST <- DEST
// precedes the count loop), requires a writable mapping and can fault, has
// read and write side effects on MMIO regardless of the value, and its
// non-atomic write-back can overwrite a racing store. Whether the store
// cycle fires at count 0 is not architecturally settled (cf. CMPXCHG, whose
// destination is documented to receive a write cycle regardless of the
// comparison), and no forward walk can prove any of this dead. This is the
// same standard the rest of the tool holds: no other finding suggests a
// rewrite that changes the set of memory accesses. In practice the excluded
// form is data, not code: every memory-destination count-0 shift in a
// 2,583-binary /bin sweep was a GHC info table decoding as instructions
// (c0 00 00 = rol byte [rax], 0), while every genuine finding was a
// register form.
bool check_shift_zero(const xed_decoded_inst_t *xedd)
{
    switch (xed_decoded_inst_get_iclass(xedd)) {
    case XED_ICLASS_RCL:
    case XED_ICLASS_RCR:
    case XED_ICLASS_ROL:
    case XED_ICLASS_ROR:
    case XED_ICLASS_SAR:
    case XED_ICLASS_SHL:
    case XED_ICLASS_SHLD:
    case XED_ICLASS_SHR:
    case XED_ICLASS_SHRD:
        break;
    default:
        return true;
    }

    if (xed_decoded_inst_number_of_memory_operands(xedd) != 0) {
        return true;
    }

    if (!xed_operand_values_has_immediate(xed_decoded_inst_operands_const(xedd))) {
        return true;
    }

    return xed_decoded_inst_get_unsigned_immediate(xedd) != 0;
}

// movapd, movdqa, movupd, and movdqu are pure 128-bit copies that differ
// from movaps/movups only in their mandatory 66/F3 prefix, which costs a
// byte:
//   movdqa xmm1, xmm2   66 0f 6f ca   ->   movaps xmm1, xmm2   0f 28 ca
//   movdqu xmm0, [rsi]  f3 0f 6f 06   ->   movups xmm0, [rsi]  0f 10 06
// The aligned forms (movapd/movdqa) map to movaps, keeping the
// #GP-on-misalignment behavior; the unaligned forms (movupd/movdqu) map to
// movups. Register, load, and store directions all carry the same saving,
// and none of these touch flags, so the rewrite is unconditional.
//
// Only the legacy SSE encodings qualify: the VEX and EVEX forms decode to
// distinct V* iclasses (VMOVDQA, VMOVDQA64, ...) and fold the 66/F3
// selector into the prefix's pp field, so vmovaps saves nothing over
// vmovdqa (and the EVEX forms add masking semantics besides).
//
// Bypass-delay caveat (cf. check_sub_self's uarch note): Nehalem-era cores
// charged a penalty when *computation* ops crossed the int/FP domains, but
// plain moves and loads/stores are domain-agnostic on every relevant core;
// clang canonicalizes all of these to movaps/movups unconditionally.
bool check_sse_mov_opcode(const xed_decoded_inst_t *xedd)
{
    switch (xed_decoded_inst_get_iclass(xedd)) {
    case XED_ICLASS_MOVAPD:
    case XED_ICLASS_MOVDQA:
    case XED_ICLASS_MOVDQU:
    case XED_ICLASS_MOVUPD:
        return false;
    default:
        return true;
    }
}

// The self-XOR zeroing idiom spelled pxor xmm, xmm (66 0F EF, 4 bytes) or
// xorpd xmm, xmm (66 0F 57, 4 bytes) is xorps xmm, xmm (0F 57, 3 bytes) with
// a wasted 66 prefix: XOR is typeless -- the mnemonic suffix only picks the
// execution domain, not the result -- and the self forms all write 128 zero
// bits, leave the upper YMM/ZMM bits and the flags alone, and raise no
// exceptions. Every recent core (Intel since Sandy Bridge, AMD since
// Bulldozer) recognizes all three as rename-time zeroing idioms: no uop
// executes, so the integer-versus-float domain folklore that made compilers
// prefer pxor cannot apply. Only the self form is flagged: a data XOR really
// executes, and routing it through the float domain between integer
// consumers can cost bypass latency on older cores -- bytes for arguable
// cycles is not this tool's trade. Legacy SSE only, which the iclass test
// gives for free (VEX/EVEX decode as VPXOR/VPXORD/VXORPD, and under VEX the
// 66 moves into the pp field, making vpxor and vxorps the same length). The
// prefixless MMX form of pxor shares the iclass and has no xorps twin, so
// the destination must be an XMM register.
bool check_sse_zero_idiom(const xed_decoded_inst_t *xedd)
{
    xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass(xedd);
    if (iclass != XED_ICLASS_PXOR && iclass != XED_ICLASS_XORPD) {
        return true;
    }
    xed_reg_enum_t dst = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);
    if (dst != xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1)) {
        return true;
    }
    return xed_reg_class(dst) != XED_REG_CLASS_XMM;
}

// AVX-512 renamed the integer copy and bitwise iclasses with element-size
// suffixes (the suffix only matters under an opmask, which the caller has
// already ruled out); map them back to their VEX ancestors. Every other
// iclass is shared between VEX and EVEX (VADDPS, VPADDD, ...) or is
// EVEX-only (VPTERNLOGD, ...), for which the VEX re-encode below simply
// fails.
static xed_iclass_enum_t evex_vex_equivalent_iclass(xed_iclass_enum_t ic)
{
    switch (ic) {
    case XED_ICLASS_VMOVDQA32:
    case XED_ICLASS_VMOVDQA64: return XED_ICLASS_VMOVDQA;
    case XED_ICLASS_VMOVDQU8:
    case XED_ICLASS_VMOVDQU16:
    case XED_ICLASS_VMOVDQU32:
    case XED_ICLASS_VMOVDQU64: return XED_ICLASS_VMOVDQU;
    case XED_ICLASS_VPANDD:
    case XED_ICLASS_VPANDQ:    return XED_ICLASS_VPAND;
    case XED_ICLASS_VPANDND:
    case XED_ICLASS_VPANDNQ:   return XED_ICLASS_VPANDN;
    case XED_ICLASS_VPORD:
    case XED_ICLASS_VPORQ:     return XED_ICLASS_VPOR;
    case XED_ICLASS_VPXORD:
    case XED_ICLASS_VPXORQ:    return XED_ICLASS_VPXOR;
    default:                   return ic;
    }
}

// An EVEX prefix is four bytes where VEX needs two or three, so an EVEX
// instruction that uses no EVEX-only feature usually has a shorter VEX
// encoding (GNU as performs this exact demotion at -O1):
//   vmovdqa64 ymm1, ymm2   62 f1 fd 28 6f ca   ->   vmovdqa ymm1, ymm2   c5 fd 6f ca
//
// EVEX-only features that block demotion: an opmask, embedded broadcast,
// embedded rounding / SAE (XED reports these via the roundc/sae operands;
// the rebuild below would silently drop the override), 512-bit vector
// length, and xmm16-31/ymm16-31 operands.
//
// Rather than hand-maintain a which-iclass-has-a-VEX-form table, rebuild
// the instruction as a fresh encoder request (high-level xed_inst API,
// EVEX-renamed iclasses mapped back to their VEX ancestors) and let
// xed_encode answer: given a plain request, this XED's encoder prefers
// VEX patterns, fails on EVEX-only iclasses, and fails on registers VEX
// cannot address -- each failure is a conservative pass. The k0 operand
// that EVEX templates list explicitly is skipped during the rebuild, or
// it would steer pattern matching back to EVEX.
//
// Flag only a strictly shorter re-encode: EVEX compresses disp8 by the
// tuple factor, so a one-byte scaled displacement can need disp32 under
// VEX, making the EVEX form the shorter one -- the length comparison
// settles that per instruction. Length is also why the displacement is
// re-narrowed here (0 / disp8 / disp32, disp32 for RIP-relative) instead
// of copied: the decoded width of a scaled disp8 does not round-trip.
bool check_oversized_evex(const xed_decoded_inst_t *xedd)
{
    if (xed3_operand_get_vexvalid(xedd) != 2) {
        return true;
    }
    if (xed3_operand_get_mask(xedd) != 0 ||
        xed3_operand_get_bcast(xedd) != 0 ||
        xed3_operand_get_roundc(xedd) != 0 ||
        xed3_operand_get_sae(xedd) != 0 ||
        xed3_operand_get_vl(xedd) >= 2) {
        return true;
    }

    xed_state_t dstate;
    dstate.mmode = XED_MACHINE_MODE_LONG_64;
    dstate.stack_addr_width = XED_ADDRESS_WIDTH_64b;

    xed_encoder_operand_t ops[4];
    unsigned nops = 0;

    const xed_inst_t *xi = xed_decoded_inst_inst(xedd);
    for (unsigned i = 0; i < xed_inst_noperands(xi); ++i) {
        const xed_operand_t *op = xed_inst_operand(xi, i);
        if (xed_operand_operand_visibility(op) != XED_OPVIS_EXPLICIT) {
            continue;
        }
        xed_operand_enum_t name = xed_operand_name(op);
        if (nops >= sizeof(ops) / sizeof(ops[0])) {
            return true;
        }
        switch (name) {
        case XED_OPERAND_REG0:
        case XED_OPERAND_REG1:
        case XED_OPERAND_REG2:
        case XED_OPERAND_REG3: {
            xed_reg_enum_t reg = xed_decoded_inst_get_reg(xedd, name);
            if (reg >= XED_REG_K0 && reg <= XED_REG_K7) {
                continue;  // unmasked k0, not a VEX operand
            }
            ops[nops++] = xed_reg(reg);
            break;
        }
        case XED_OPERAND_MEM0: {
            xed_int64_t disp = xed_decoded_inst_get_memory_displacement(xedd, 0);
            xed_reg_enum_t base = xed_decoded_inst_get_base_reg(xedd, 0);
            unsigned disp_bits;
            if (base == XED_REG_RIP || base == XED_REG_EIP) {
                disp_bits = 32;
            } else if (disp == 0 &&
                       base != XED_REG_RBP && base != XED_REG_R13 &&
                       base != XED_REG_EBP && base != XED_REG_R13D) {
                disp_bits = 0;
            } else if (disp >= INT8_MIN && disp <= INT8_MAX) {
                disp_bits = 8;
            } else {
                disp_bits = 32;
            }
            ops[nops++] = xed_mem_bisd(base,
                xed_decoded_inst_get_index_reg(xedd, 0),
                xed_decoded_inst_get_scale(xedd, 0),
                xed_disp(disp, disp_bits),
                xed_decoded_inst_get_memory_operand_length(xedd, 0) * 8);
            break;
        }
        case XED_OPERAND_IMM0:
            ops[nops++] = xed_imm0(xed_decoded_inst_get_unsigned_immediate(xedd),
                xed_decoded_inst_get_immediate_width_bits(xedd));
            break;
        default:
            return true;
        }
    }

    xed_encoder_instruction_t enc;
    xed_inst(&enc, dstate,
        evex_vex_equivalent_iclass(xed_decoded_inst_get_iclass(xedd)),
        0, nops, ops);

    xed_encoder_request_t req;
    xed_encoder_request_zero_set_mode(&req, &dstate);
    if (!xed_convert_to_encoder_request(&req, &enc)) {
        return true;
    }
    uint8_t out[XED_MAX_INSTRUCTION_BYTES];
    unsigned int olen = 0;
    if (xed_encode(&req, out, sizeof(out), &olen) != XED_ERROR_NONE) {
        return true;
    }
    if (olen >= xed_decoded_inst_get_length(xedd)) {
        return true;
    }

    // A shorter encoding is only an opportunity if the target can run it, and
    // for a few families the VEX form is not the older encoding of the same
    // feature but a *later* extension carrying its own CPUID bit. EVEX
    // VPMADD52LUQ is AVX512_IFMA, shipped from Cannon Lake; the VEX spelling
    // XED encodes for it is AVX_IFMA, which arrived years later on parts that
    // dropped AVX-512 -- so the rewrite would fault on precisely the CPUs the
    // original code targets. AVX512_VNNI against AVX_VNNI and AVX512_BF16
    // against AVX_NE_CONVERT divide the same way. Decode what was just
    // encoded and let XED name the feature rather than inferring it from the
    // iclass: an unrecognized encoding, like any other uncertainty here,
    // suppresses the finding.
    xed_decoded_inst_t reenc;
    decode_init(&reenc);
    if (xed_decode(&reenc, out, olen) != XED_ERROR_NONE) {
        return true;
    }
    switch (xed_decoded_inst_get_isa_set(&reenc)) {
    case XED_ISA_SET_AVX_IFMA:
    case XED_ISA_SET_AVX_NE_CONVERT:
    case XED_ISA_SET_AVX_VNNI:
    case XED_ISA_SET_AVX_VNNI_INT8:
    case XED_ISA_SET_AVX_VNNI_INT16:
        return true;
    default:
        return false;
    }
}

// A VEX instruction has a compact two-byte prefix (C5) and a long three-byte
// prefix (C4). The two-byte form can encode only opcode map 1 (0F) with
// VEX.W == 0 and no REX.B/REX.X operand extension; opcode maps 0F38/0F3A,
// VEX.W == 1, or an r8-r15 base/index/rm operand each force the three-byte
// form. An instruction that satisfies the two-byte constraints yet is encoded
// with C4 wastes one byte:
//   vmovdqa ymm1, ymm2   c4 e1 7d 6f ca   ->   c5 fd 6f ca
// GNU as emits the two-byte form; naive hand-rolled encoders and some JITs do
// not. This is the VEX analogue of check_oversized_evex.
//
// Unlike the EVEX demotion, the rule here is exact and needs no re-encode:
// VEX.R (the one extension the two-byte form still carries) and the vvvv/pp/L
// fields encode identically either way, so {map 1, W 0, no B/X} is precisely
// the set of two-byte-encodable VEX instructions. The prefix selects operands
// only -- no semantics ride on its length -- so the shrink is value- and
// flag-identical and unconditional.
//
// The current prefix length is the nominal opcode's offset minus the legacy
// prefixes ahead of it (a segment or address-size override may precede VEX):
// 3 is the three-byte C4 form, 2 the already-minimal C5.
bool check_oversized_vex(const xed_decoded_inst_t *xedd)
{
    // vexvalid: 0=legacy, 1=VEX, 2=EVEX (cf. check_oversized_displacement).
    if (xed3_operand_get_vexvalid(xedd) != 1) {
        return true;
    }
    if (xed3_operand_get_map(xedd) != 1 ||
        xed_operand_values_has_rexw_prefix(xed_decoded_inst_operands_const(xedd)) ||
        xed3_operand_get_rexb(xedd) != 0 ||
        xed3_operand_get_rexx(xedd) != 0) {
        return true;
    }
    return (xed3_operand_get_pos_nominal_opcode(xedd) -
            xed3_operand_get_nprefixes(xedd)) != 3;
}

// sub reg, reg zeros the register at the same size as xor reg, reg, but
// xor is the portable dependency-breaking idiom. Mainstream cores (Intel
// Sandy Bridge onward, AMD) recognize both xor reg, reg and sub reg, reg
// at register rename as zeroing idioms that break the dependency on the
// prior value, but some low-power cores -- e.g. Intel Silvermont/Atom --
// special-case only xor, leaving sub reg, reg with a false dependency on
// its old value. xor is never worse, so prefer it.
//
// Flag-safe, so no liveness gating: sub reg, reg and xor reg, reg both
// produce 0 with CF=OF=0, ZF=1, SF=0, PF=1 identically (only AF differs,
// and AF is unobservable in x86-64).
bool check_sub_self(const xed_decoded_inst_t *xedd)
{
    if (xed_decoded_inst_get_iclass(xedd) != XED_ICLASS_SUB) {
        return true;
    }
    xed_reg_enum_t r0 = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);
    xed_reg_enum_t r1 = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1);
    return !(r0 != XED_REG_INVALID && r0 == r1);
}

// or reg, reg and and reg, reg with both operands the same register leave the
// value unchanged (x|x == x and x&x == x); they exist only to set flags, the
// role test reg, reg fills. All three are two bytes and set CF=OF=0 with
// ZF/SF/PF per the value (AF is undefined in every case), so test is
// flag-equivalent -- but, unlike or/and, it does not write the destination,
// avoiding a redundant register write and matching the canonical idiom. (The
// memory forms cannot have both operands the same register, so the r0 == r1
// test excludes them, as in check_sub_self.)
//
// Not flag-gated (cf. check_add_sub_zero): test reproduces the flags, so the
// rewrite holds whether or not they are live, and when they are dead the
// instruction can be removed outright. It is register-gated: the 32-bit form
// zero-extends into the upper 64 bits where test writes nothing, so the
// dispatcher suppresses it while those bits may be live (reg0_upper32_concern,
// cf. check_mov_self). The common shape -- a 32-bit load or ALU result tested
// right where it is produced -- still fires via the already-zero-extended
// escape (writes_zero_extended_32).
bool check_or_and_self(const xed_decoded_inst_t *xedd)
{
    switch (xed_decoded_inst_get_iclass(xedd)) {
    case XED_ICLASS_AND:
    case XED_ICLASS_OR:
        break;
    default:
        return true;
    }
    xed_reg_enum_t r0 = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);
    xed_reg_enum_t r1 = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1);
    return !(r0 != XED_REG_INVALID && r0 == r1);
}

// movsxd rax, eax (48 63 c0, 3 bytes) sign-extends EAX into RAX. The
// CDQE / cltq instruction (48 98, 2 bytes) does the same. The analogous
// narrower steps -- movsx eax, ax -> cwde and movsx ax, al -> cbw -- are a
// distinct iclass (MOVSX, not MOVSXD) and are handled by check_unneeded_movsx.
bool check_unneeded_movsxd(const xed_decoded_inst_t *xedd)
{
    if (xed_decoded_inst_get_iclass(xedd) != XED_ICLASS_MOVSXD) {
        return true;
    }

    xed_reg_enum_t r0 = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);
    xed_reg_enum_t r1 = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1);
    return !(r0 == XED_REG_RAX && r1 == XED_REG_EAX);
}

// movsx eax, ax (0f bf c0, 3 bytes) sign-extends AX into EAX; cwde (98, 1
// byte) does the same. movsx ax, al (66 0f be c0, 4 bytes) sign-extends AL
// into AX; cbw (66 98, 2 bytes) does the same. Both are accumulator-only --
// the operands must be exactly the AX<-AL or EAX<-AX step. The AX<-... and
// RAX<-... widenings have no one-instruction form (cdqe covers only RAX<-EAX,
// which is the MOVSXD case above), and a memory or non-accumulator source
// fails the exact-register match. Sign-extension sets no flags, so the
// rewrite is unconditional.
bool check_unneeded_movsx(const xed_decoded_inst_t *xedd)
{
    if (xed_decoded_inst_get_iclass(xedd) != XED_ICLASS_MOVSX) {
        return true;
    }

    xed_reg_enum_t r0 = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);
    xed_reg_enum_t r1 = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1);
    if (r0 == XED_REG_EAX && r1 == XED_REG_AX) {    // -> cwde
        return false;
    }
    if (r0 == XED_REG_AX && r1 == XED_REG_AL) {     // -> cbw
        return false;
    }
    return true;
}

// A zero displacement encoded as disp8 or disp32 wastes bytes that could
// be elided. disp32=0 can always shrink to disp8=0 (saves 3 bytes); a
// disp8=0 can often be omitted entirely (saves 1 byte). Exceptions:
//   - RBP/R13 (or EBP/R13D) base with no SIB: mod=00 rm=101 means
//     RIP-relative in 64-bit (or absolute disp32 in 32-bit), so a
//     disp8=0 is required to encode [rbp].
//   - RIP-relative addressing always uses disp32.
//   - Absolute disp32 addressing (no base register, 64-bit mode) always
//     uses disp32.
bool check_unneeded_zero_displacement(const xed_decoded_inst_t *xedd)
{
    if (xed_decoded_inst_number_of_memory_operands(xedd) == 0) {
        return true;
    }

    // Multi-byte NOPs (NOP_MEMv_0F1F and friends) use [rax+disp=0] forms
    // deliberately as length padding; the displacement is part of how
    // they reach 4, 5, 7, 8, 9 bytes. The suboptimal-NOPs check handles
    // their actual concern.
    int iclass = xed_decoded_inst_get_iclass(xedd);
    if (iclass >= XED_ICLASS_NOP && iclass <= XED_ICLASS_NOP9) {
        return true;
    }

    unsigned width = xed_decoded_inst_get_memory_displacement_width_bits(xedd, 0);
    if (width == 0) {
        return true;
    }

    if (xed_decoded_inst_get_memory_displacement(xedd, 0) != 0) {
        return true;
    }

    xed_reg_enum_t base = xed_decoded_inst_get_base_reg(xedd, 0);

    if (base == XED_REG_RIP || base == XED_REG_EIP) {
        return true;
    }
    if (base == XED_REG_INVALID) {
        return true;
    }

    if (width == 32) {
        return false;
    }

    // width == 8: a disp8=0 is required for RBP/R13 (or EBP/R13D in
    // 32-bit address mode) to disambiguate from the no-base encoding.
    switch (base) {
    case XED_REG_RBP:
    case XED_REG_R13:
    case XED_REG_EBP:
    case XED_REG_R13D:
        return true;
    default:
        return false;
    }
}

// A nonzero displacement encoded as disp32 wastes three bytes when its value
// fits in a signed disp8:
//   mov eax, [rbx+0x10]   8b 83 10000000   (disp32, 6 bytes)
//   mov eax, [rbx+0x10]   8b 43 10         (disp8,  3 bytes)
// XED returns the displacement sign-extended, so a disp32 of 0xfffffff0 reads
// back as -16 and still fits. The zero case is left to
// check_unneeded_zero_displacement (which can elide it entirely, not merely
// narrow it); this check handles only nonzero displacements.
//
// Cannot narrow:
//   - RIP-relative addressing: disp32 is the only form.
//   - Absolute / no-base addressing (SIB base=101 with no base register):
//     disp32 is mandatory in 64-bit mode.
//   - EVEX-encoded instructions: disp8 is compressed (disp8*N, where N
//     comes from the tuple type and vector length -- 64 for a full
//     512-bit operand), so a disp32 narrows only when its value is an
//     exact multiple of N. [rax+16] on a zmm access has no disp8 form at
//     all. Rather than reproduce XED's tuple-type tables to compute N,
//     skip EVEX entirely; compilers already emit compressed disp8
//     whenever the offset divides evenly, so a small EVEX disp32 in real
//     code is almost always there because it cannot compress.
// Any real base register supports a disp8 -- including RBP/R13, which merely
// require *at least* a disp8 -- so no base-specific exclusion is needed in the
// narrowing direction. Multi-byte NOPs are skipped: their displacement width
// is deliberate length padding (cf. check_unneeded_zero_displacement).
bool check_oversized_displacement(const xed_decoded_inst_t *xedd)
{
    if (xed_decoded_inst_number_of_memory_operands(xedd) == 0) {
        return true;
    }

    int iclass = xed_decoded_inst_get_iclass(xedd);
    if (iclass >= XED_ICLASS_NOP && iclass <= XED_ICLASS_NOP9) {
        return true;
    }

    if (xed_decoded_inst_get_memory_displacement_width_bits(xedd, 0) != 32) {
        return true;
    }

    // vexvalid: 0=legacy, 1=VEX, 2=EVEX (no public named constants). The
    // compressed-disp8 form itself never reaches this check: XED reports
    // its decompressed displacement with a widened width, failing the
    // ==32 test above.
    if (xed3_operand_get_vexvalid(xedd) == 2) {
        return true;
    }

    xed_int64_t disp = xed_decoded_inst_get_memory_displacement(xedd, 0);
    if (disp == 0 || disp < INT8_MIN || disp > INT8_MAX) {
        return true;
    }

    xed_reg_enum_t base = xed_decoded_inst_get_base_reg(xedd, 0);
    if (base == XED_REG_RIP || base == XED_REG_EIP) {
        return true;
    }
    if (base == XED_REG_INVALID) {
        return true;
    }

    return false;
}

// modrm with rm=100 in 32-/64-bit addressing means "a SIB byte follows."
// This is required when the base register's three-bit encoding overlaps
// the SIB marker (RSP/R12, or ESP/R12D in 32-bit address mode), when
// there is an index register, or for absolute disp32 addressing in
// 64-bit mode (the special SIB.base=101 + no-index form). For other
// single-register bases the SIB is redundant -- the same effective
// address can be encoded with just modrm, saving one byte.
bool check_unneeded_sib(const xed_decoded_inst_t *xedd)
{
    if (!xed_operand_values_has_sib_byte(xed_decoded_inst_operands_const(xedd))) {
        return true;
    }

    if (xed_decoded_inst_number_of_memory_operands(xedd) == 0) {
        return true;
    }

    if (xed_decoded_inst_get_index_reg(xedd, 0) != XED_REG_INVALID) {
        return true;
    }

    xed_reg_enum_t base = xed_decoded_inst_get_base_reg(xedd, 0);
    if (base == XED_REG_INVALID) {
        return true;
    }

    switch (base) {
    case XED_REG_RSP:
    case XED_REG_R12:
    case XED_REG_ESP:
    case XED_REG_R12D:
        return true;
    default:
        return false;
    }
}

// MOV r/m, imm with a register destination has two encodings: the c6/c7
// opcode with a modrm byte, and the b0/b8 +r form where the destination
// register is encoded in the low 3 bits of the opcode (no modrm). The +r
// form is one byte shorter for 8/16/32-bit operands. For 64-bit operand
// size the C7 modrm form (48 c7 c0 imm32, 7 bytes) sign-extends imm32;
// when the value is non-negative the result matches what the 5-byte b8+r
// form produces via the EAX-write zero-extension rule, so the 32-bit form
// replaces it. A negative imm32 needs the C7 form (the only alternative
// is the 10-byte movabs encoding).
bool check_mov_modrm_imm(const xed_decoded_inst_t *xedd)
{
    if (xed_decoded_inst_get_iclass(xedd) != XED_ICLASS_MOV) {
        return true;
    }
    if (xed_decoded_inst_number_of_memory_operands(xedd) > 0) {
        return true;
    }
    if (!xed_operand_values_has_immediate(xed_decoded_inst_operands_const(xedd))) {
        return true;
    }
    if (!xed_operand_values_has_modrm_byte(xedd)) {
        return true;
    }
    unsigned op_width = xed_decoded_inst_get_operand_width(xedd);
    if (op_width == 8 || op_width == 16 || op_width == 32) {
        return false;
    }
    if (op_width == 64) {
        int32_t imm = (int32_t) xed_decoded_inst_get_unsigned_immediate(xedd);
        if (imm >= 0) {
            return false;
        }
    }
    return true;
}

// add reg, 0 and sub reg, 0 leave the register unchanged but set flags as
// a side effect (CF/OF cleared, ZF/SF/PF reflect the register's value).
// They can be removed when the flags are unused, or otherwise replaced by
// test reg, reg, which is 1-3 bytes shorter. test reg, reg reproduces the
// flags exactly (CF=OF=0, ZF/SF/PF per the value; only the unobservable AF
// differs), so the substitution is valid even when the flags are live --
// hence the dispatcher entry carries no flag concern and the finding fires
// regardless of downstream flag liveness. It does carry a register concern:
// the 32-bit forms zero-extend bits 63:32 where test (or removal) leaves
// them, so those are gated on upper-32 liveness (reg0_upper32_concern, cf.
// check_mov_self).
//
// AL is excluded: add al, 0 already fits in 2 bytes via the 04 ib
// accumulator opcode, exactly tying test al, al, so substituting test
// saves nothing (cf. check_cmp_zero). Memory operands are excluded too:
// those touches may be intentional (cache-line warm, MMIO trigger).
bool check_add_sub_zero(const xed_decoded_inst_t *xedd)
{
    switch (xed_decoded_inst_get_iclass(xedd)) {
    case XED_ICLASS_ADD:
    case XED_ICLASS_SUB:
        break;
    default:
        return true;
    }

    if (xed_decoded_inst_number_of_memory_operands(xedd) > 0) {
        return true;
    }

    if (!xed_operand_values_has_immediate(xed_decoded_inst_operands_const(xedd))) {
        return true;
    }

    if (xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0) == XED_REG_AL) {
        return true;
    }

    return xed_decoded_inst_get_unsigned_immediate(xedd) != 0;
}

// or reg, 0 and xor reg, 0 leave the register unchanged (reg | 0 == reg,
// reg ^ 0 == reg) but set flags as a side effect, exactly like add reg, 0:
// CF/OF cleared, ZF/SF/PF from the register's value. They can be removed when
// the flags are unused, or replaced by test reg, reg, which is 1-3 bytes
// shorter and reproduces the flags exactly (only the unobservable AF differs),
// so the finding fires regardless of downstream flag liveness (cf.
// check_add_sub_zero, whose incidental 32-bit zero-extension caveat applies
// here identically).
//
// AL is excluded: or al, 0 / xor al, 0 already fit in 2 bytes via the 0c/34 ib
// accumulator opcodes, exactly tying test al, al (cf. check_add_sub_zero,
// check_cmp_zero). Memory operands are excluded too: the access may be
// intentional (cache-line warm, MMIO trigger), and there is no
// test [mem], [mem] form besides.
bool check_or_xor_zero(const xed_decoded_inst_t *xedd)
{
    switch (xed_decoded_inst_get_iclass(xedd)) {
    case XED_ICLASS_OR:
    case XED_ICLASS_XOR:
        break;
    default:
        return true;
    }

    if (xed_decoded_inst_number_of_memory_operands(xedd) > 0) {
        return true;
    }

    if (!xed_operand_values_has_immediate(xed_decoded_inst_operands_const(xedd))) {
        return true;
    }

    if (xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0) == XED_REG_AL) {
        return true;
    }

    return xed_decoded_inst_get_unsigned_immediate(xedd) != 0;
}

// and reg, 0 forces the register to zero, which xor reg, reg does in fewer
// bytes and -- unlike mov reg, 0 -- with identical flags: both clear CF/OF and
// set ZF=1, SF=0, PF=1 (AF undefined in both), and both zero the full register
// (the 32-bit forms zero-extend alike). The rewrite is thus value- and
// flag-identical and unconditional, so it carries no flag concern (cf.
// check_mov_zero, gated only because MOV writes no flags). A zero immediate is
// zero at every width, so no effective-mask computation is needed.
//
// AL is excluded: and al, 0 via the 24 ib accumulator opcode is already 2
// bytes, tying xor al, al; its modrm form is check_implicit_register's finding
// (cf. check_add_sub_zero). Memory operands are excluded: a store of zero may
// be intentional, and xor cannot target memory. A nonzero mask (including the
// all-ones no-op and the low-byte masks) is check_and_strength_reduce's
// concern, not this one.
bool check_and_zero(const xed_decoded_inst_t *xedd)
{
    if (xed_decoded_inst_get_iclass(xedd) != XED_ICLASS_AND) {
        return true;
    }

    if (xed_decoded_inst_number_of_memory_operands(xedd) > 0) {
        return true;
    }

    if (!xed_operand_values_has_immediate(xed_decoded_inst_operands_const(xedd))) {
        return true;
    }

    if (xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0) == XED_REG_AL) {
        return true;
    }

    return xed_decoded_inst_get_unsigned_immediate(xedd) != 0;
}

// add r/m, 1 and sub r/m, 1 (and their -1 counterparts) encode as inc /
// dec, which drops the imm8 byte for every destination, addressing mode,
// and operand width:
//   add eax, 1                83 c0 01      ->   inc eax                ff c0
//   sub eax, 1                83 e8 01      ->   dec eax                ff c8
//   sub dword [rbx+0x10], 1   83 6b 10 01   ->   dec dword [rbx+0x10]   ff 4b 10
// (There is no shorter form in 64-bit mode: the 1-byte 40+r inc/dec opcodes
// were reclaimed as the REX prefixes, so inc/dec take the 2-byte ff /r form.)
//
// inc/dec produce the identical result, so SF/ZF/AF/PF/OF match add/sub by
// one exactly; the only difference is that inc/dec leave CF unchanged whereas
// add/sub write it. The rewrite is therefore valid only when CF is dead
// downstream, so the dispatcher gates this check on FLAG_CF (cf.
// check_oversized_add_sub_128, whose ADD<->SUB flip likewise perturbs only CF).
//
// Caveat (not a correctness issue, so not encoded here): because inc/dec
// write only part of the flags, a later reader of the full flags register can
// hit a partial-flags merge stall on pre-Sandy-Bridge Intel, which is why
// some compilers still emit add/sub by one. On current cores the merge is
// cheap and the byte saving is a clean win.
//
// AL is excluded: add al, 1 already fits in 2 bytes via the 04 ib
// accumulator opcode, exactly tying inc al, so the rewrite saves nothing (cf.
// check_add_sub_zero, check_cmp_zero). Memory destinations are included --
// neither form is atomic without LOCK, and inc/dec perform the same-width
// read-modify-write at the same address, so even MMIO behavior is identical.
// The locked forms never reach here: they decode to the distinct
// ADD_LOCK/SUB_LOCK iclasses (and inc/dec accept a LOCK prefix anyway).
bool check_inc_dec(const xed_decoded_inst_t *xedd)
{
    switch (xed_decoded_inst_get_iclass(xedd)) {
    case XED_ICLASS_ADD:
    case XED_ICLASS_SUB:
        break;
    default:
        return true;
    }

    if (!xed_operand_values_has_immediate(xed_decoded_inst_operands_const(xedd))) {
        return true;
    }

    int32_t imm = (int32_t) xed_decoded_inst_get_signed_immediate(xedd);
    if (imm != 1 && imm != -1) {
        return true;
    }

    if (xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0) == XED_REG_AL) {
        return true;
    }

    return false;
}

// mov reg, reg with both operands the same register is a no-op in the 8-, 16-,
// and 64-bit forms -- pure waste, flagged outright.
//
// The 32-bit form mov r32, r32 is not pure waste: it zero-extends into the
// upper 32 bits of the enclosing 64-bit register (any write of a 32-bit
// register clears bits 63-32). Removing it is sound only when that
// zero-extension is dead -- those upper bits are redefined before any reader --
// which the dispatcher decides with reg_upper32_live_after via the entry's
// reg_concern hook (reg0_upper32_concern). So this returns a finding for
// every same-register mov; the 32-bit case is then gated on upper-bit liveness,
// while the 8/16/64-bit cases -- with no upper bits to disturb -- fire
// unconditionally.
//
// The r0 == r1 test also excludes the memory forms (mov [mem], reg has a single
// register operand, so r1 is INVALID) and different-register copies.
bool check_mov_self(const xed_decoded_inst_t *xedd)
{
    if (xed_decoded_inst_get_iclass(xedd) != XED_ICLASS_MOV) {
        return true;
    }

    xed_reg_enum_t r0 = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);
    xed_reg_enum_t r1 = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1);
    if (r0 == XED_REG_INVALID || r0 != r1) {
        return true;
    }

    return false;
}

// Both JMP rel32 and Jcc rel32 have a 2-byte rel8 alternative when the
// target is within reach. JMP rel32 is 5 bytes vs 2; Jcc rel32 is 6 vs 2.
// Shortening shrinks the encoding, which shifts the displacement by the
// size delta -- so the rel8 fits iff (current_disp + size_delta) fits in
// int8.
bool check_oversized_branch(const xed_decoded_inst_t *xedd)
{
    int size_delta;
    switch (xed_decoded_inst_get_iclass(xedd)) {
    case XED_ICLASS_JMP:
        size_delta = 3;
        break;
    case XED_ICLASS_JB:
    case XED_ICLASS_JBE:
    case XED_ICLASS_JL:
    case XED_ICLASS_JLE:
    case XED_ICLASS_JNB:
    case XED_ICLASS_JNBE:
    case XED_ICLASS_JNL:
    case XED_ICLASS_JNLE:
    case XED_ICLASS_JNO:
    case XED_ICLASS_JNP:
    case XED_ICLASS_JNS:
    case XED_ICLASS_JNZ:
    case XED_ICLASS_JO:
    case XED_ICLASS_JP:
    case XED_ICLASS_JS:
    case XED_ICLASS_JZ:
        size_delta = 4;
        break;
    default:
        return true;
    }

    // Only the rel32 form has a shorter alternative.
    if (xed_decoded_inst_get_branch_displacement_width_bits(xedd) != 32) {
        return true;
    }

    // Computed in 64 bits: a rel32 displacement near INT32_MAX (a branch
    // spanning a ~2 GB section) would overflow the int32 sum.
    int32_t disp = (int32_t) xed_decoded_inst_get_branch_displacement(xedd);
    int64_t new_disp = (int64_t) disp + size_delta;
    return new_disp < INT8_MIN || new_disp > INT8_MAX;
}

// Bitmask of x86 arithmetic status flags. Aliased to the bit names in
// xed_flag_set_t.s; the higher-order EFLAGS bits (DF, IF, etc.) aren't
// tracked here because none of the optimizations below change them.
//
// AF is intentionally absent: the only encodable readers of AF in any
// mode are DAA/DAS/AAA/AAS, all of which were removed from 64-bit mode.
// (ADC/SBB read CF only, not AF.) So an AF-only divergence between an
// original and replacement instruction is never observable in x86-64 code.
enum {
    FLAG_CF = 1u << 0,
    FLAG_PF = 1u << 1,
    FLAG_ZF = 1u << 2,
    FLAG_SF = 1u << 3,
    FLAG_OF = 1u << 4,
    FLAG_ARITH = FLAG_CF | FLAG_PF | FLAG_ZF | FLAG_SF | FLAG_OF,
};

static uint32_t flag_set_to_mask(const xed_flag_set_t *fs)
{
    if (fs == NULL) {
        return 0;
    }
    uint32_t m = 0;
    if (fs->s.cf) m |= FLAG_CF;
    if (fs->s.pf) m |= FLAG_PF;
    if (fs->s.zf) m |= FLAG_ZF;
    if (fs->s.sf) m |= FLAG_SF;
    if (fs->s.of) m |= FLAG_OF;
    return m;
}

// Walk forward from byte `offset` in `inst` to decide whether any flag in
// `concerns` might be read by a downstream instruction before being
// overwritten. Returns true (LIVE) on yes or unknown; the caller (dispatcher
// for a flag-disturbing optimization) should suppress its finding when this
// returns true.
//
// Returns false (DEAD) only after seeing every flag in `concerns`
// unconditionally written by straight-line code, or after hitting a
// function-exit terminator (RET / IRET; neither the SysV nor Win64 ABI
// preserves flags across calls).
//
// Conservative LIVE on: decode error; any control transfer that isn't such
// a terminator -- CALL, conditional or unconditional branch, SYSCALL,
// SYSRET (sysret/sysexit return to user mode; sysexit carries the flags
// there rather than overwriting them, so they may be read), INTERRUPT;
// running out of input; reaching the lookahead bound.
//
// "Undefined" flag writes per Intel SDM count as writes -- the original
// value is destroyed either way, so the candidate optimization doesn't
// worsen things relative to the unmodified code.
//
// Conditional flag writes do NOT count: a shift/rotate by CL updates its
// flags only when the masked runtime count is nonzero, and a REP-prefixed
// string compare touches none when RCX is 0, so the prior flag value can
// flow through such an instruction to a later reader. XED folds these
// conditionally-written flags into the same written/undefined sets as
// unconditional ones and distinguishes them only by the instruction-level
// may_write marker, so the walk keeps a concern live across any may_write
// instruction.
// The walk proper, with one opt-in refinement: when `call_kills` is set, a
// CALL concludes DEAD rather than LIVE, by the same ABI argument the RET case
// rests on -- neither the SysV nor the Win64 ABI preserves flags across
// calls, so the callee (and the code resuming after it) receives them
// undefined and cannot legitimately read the caller's values. The general
// walk (the flags_live_after wrapper below, and every established caller)
// keeps the conservative reading of a call as unknown control flow;
// shift_test_redundant opts in because its motivating consumer branches
// straight to a cold-path call (rustc's panic_count::is_zero_slow_path),
// which the conservative reading would suppress wholesale.
static bool flags_live_after_ext(const uint8_t *inst, size_t len,
                                 size_t offset, uint32_t concerns,
                                 bool call_kills)
{
    const int MAX_LOOKAHEAD = 16;
    uint32_t live = concerns;

    for (int step = 0; step < MAX_LOOKAHEAD && offset < len && live != 0; ++step) {
        xed_decoded_inst_t xedd;
        decode_init(&xedd);
        if (xed_decode(&xedd, inst + offset, len - offset) != XED_ERROR_NONE) {
            return true;
        }

        xed_category_enum_t category = xed_decoded_inst_get_category(&xedd);
        if (category == XED_CATEGORY_RET) {
            return false;
        }
        if (call_kills && category == XED_CATEGORY_CALL) {
            return false;
        }
        if (category == XED_CATEGORY_CALL ||
            category == XED_CATEGORY_UNCOND_BR ||
            category == XED_CATEGORY_COND_BR ||
            category == XED_CATEGORY_SYSCALL ||
            category == XED_CATEGORY_SYSRET ||
            category == XED_CATEGORY_INTERRUPT) {
            return true;
        }

        const xed_simple_flag_t *fi = xed_decoded_inst_get_rflags_info(&xedd);
        if (fi != NULL) {
            uint32_t r = flag_set_to_mask(xed_simple_flag_get_read_flag_set(fi));
            if (r & live) {
                return true;
            }
            if (!xed_simple_flag_get_may_write(fi)) {
                uint32_t w = flag_set_to_mask(xed_simple_flag_get_written_flag_set(fi)) |
                             flag_set_to_mask(xed_simple_flag_get_undefined_flag_set(fi));
                live &= ~w;
            }
        }

        offset += xed_decoded_inst_get_length(&xedd);
    }

    return live != 0;
}

static bool flags_live_after(const uint8_t *inst, size_t len, size_t offset,
                             uint32_t concerns)
{
    return flags_live_after_ext(inst, len, offset, concerns, false);
}

// Instruction classes that unconditionally overwrite bits 32-63 of a GPR when
// they write its 32- or 64-bit form: a 64-bit write sets those bits directly, a
// 32-bit write zero-extends into them. reg_upper32_live_after uses this to
// recognize a redefinition (kill) of the upper half. The list is a deliberately
// conservative whitelist -- omitting an instruction only forgoes a DEAD
// conclusion (and thus a finding), never soundness. Excluded on purpose: CMOVcc
// and REP-string writes (conditional -- the prior value can survive a not-taken
// move or a zero REP count), shifts and rotates (the SDM's count-0 pseudocode
// performs no destination write, so the zero-extension cannot be assumed here
// -- observed hardware zero-extends even at count 0, but a kill must rest on
// the weaker guarantee), and BSF/BSR (the destination is undefined when the
// source is 0).
static bool reg_kill_iclass(xed_iclass_enum_t iclass)
{
    switch (iclass) {
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

// True when `xedd` unconditionally redefines the 64-bit GPR reg64: it writes
// the register's 32-bit form (zero-extending into bits 32-63) or its 64-bit
// form, with a defined result. Restricted to the reg_kill_iclass whitelist
// for that whitelist's reasons; omitting an instruction only forgoes the
// conclusion. The kill step of reg_upper32_live_after, shared with the
// POPCNT false-dependency suppression.
static bool redefines_reg_ge32(const xed_decoded_inst_t *xedd,
                               xed_reg_enum_t reg64)
{
    if (!reg_kill_iclass(xed_decoded_inst_get_iclass(xedd))) {
        return false;
    }
    const xed_inst_t *xi = xed_decoded_inst_inst(xedd);
    unsigned nops = xed_inst_noperands(xi);
    for (unsigned i = 0; i < nops; ++i) {
        const xed_operand_t *op = xed_inst_operand(xi, i);
        xed_operand_enum_t name = xed_operand_name(op);
        if (!xed_operand_is_register(name) || !xed_operand_written(op)) {
            continue;
        }
        xed_reg_enum_t wr = xed_decoded_inst_get_reg(xedd, name);
        if (xed_get_largest_enclosing_register(wr) == reg64 &&
            xed_get_register_width_bits64(wr) >= 32) {
            return true;
        }
    }
    return false;
}

static bool gpr_dep_mitigation(const xed_decoded_inst_t *xedd,
                               xed_reg_enum_t parent);

// Walk forward from byte `offset` to decide whether the bits of `parent` at
// or above bit `width_bits` might be read by a downstream instruction before
// being redefined. Returns true (LIVE) on yes or unknown; the dispatcher
// suppresses a finding whose rewrite would disturb those bits when this
// returns true. This is the register analogue of flags_live_after, built for
// the register questions the optimizations here raise, each naming its own
// boundary: mov r32, r32's only effect beyond identity is zero-extending
// bits 32-63, so removing it is sound exactly when those are dead
// (width_bits 32, via the reg_upper32_live_after wrapper below), and an 8-
// or 16-bit MOV rewritten to MOVZX zero-extends from its own width, sound
// exactly when everything above it is dead (the merging narrow move check).
//
// A read observes the bits when it names a form wider than the boundary --
// for the classic 32 case that is only the 64-bit name -- or serves as a
// memory base or index wider than the boundary; and below 16 a high-byte
// register read (AH/BH/CH/DH) observes bits 15:8 however narrow its own
// width. Two write shapes end the walk DEAD: the whitelisted unconditional
// 32- or 64-bit writers (redefines_reg_ge32; a 32-bit write zero-extends,
// so both redefine every bit down to bit 8), and -- below 32 only -- a
// same-register 32/64-bit XOR or SUB first, because XED records the zero
// idiom as reading its destination while the renamer-recognized result
// depends on nothing, and compilers end a value's life with exactly that
// idiom. At 32 the idiom question does not arise for the wrapper's callers
// the same way: a 64-bit self-XOR has always counted as a read there, and
// loosening tested behavior is a separate decision from parameterizing the
// walk. Ordinary reads are matched before kills, since an instruction can
// read the register and then redefine it (add rax, rbx).
//
// Conservative LIVE on: decode error; ANY control transfer, RET included (a
// register may escape as a return value or a callee-saved register, neither
// of which a linear forward walk can rule out -- unlike flags, which no ABI
// preserves across RET, so flags_live_after treats RET as DEAD); running out
// of input; reaching the lookahead bound. Reads are matched inclusively
// (conditional reads count) and kills exclusively (only the whitelisted
// unconditional writers), so every uncertainty resolves toward LIVE.
static bool reg_bits_above_live_after(const uint8_t *inst, size_t len,
                                      size_t offset, xed_reg_enum_t parent,
                                      unsigned width_bits)
{
    const int MAX_LOOKAHEAD = 16;

    for (int step = 0; step < MAX_LOOKAHEAD && offset < len; ++step) {
        xed_decoded_inst_t xedd;
        decode_init(&xedd);
        if (xed_decode(&xedd, inst + offset, len - offset) != XED_ERROR_NONE) {
            return true;
        }

        if (width_bits < 32 && gpr_dep_mitigation(&xedd, parent)) {
            return false;
        }

        const xed_inst_t *xi = xed_decoded_inst_inst(&xedd);
        unsigned nops = xed_inst_noperands(xi);
        for (unsigned i = 0; i < nops; ++i) {
            const xed_operand_t *op = xed_inst_operand(xi, i);
            xed_operand_enum_t name = xed_operand_name(op);
            if (!xed_operand_is_register(name) || !xed_operand_read(op)) {
                continue;
            }
            xed_reg_enum_t r = xed_decoded_inst_get_reg(&xedd, name);
            if (xed_get_largest_enclosing_register(r) != parent) {
                continue;
            }
            bool high8 = r == XED_REG_AH || r == XED_REG_BH ||
                         r == XED_REG_CH || r == XED_REG_DH;
            if (high8 ? width_bits < 16
                      : xed_get_register_width_bits64(r) > width_bits) {
                return true;
            }
        }
        int nmem = xed_decoded_inst_number_of_memory_operands(&xedd);
        for (int m = 0; m < nmem; ++m) {
            xed_reg_enum_t base = xed_decoded_inst_get_base_reg(&xedd, m);
            xed_reg_enum_t index = xed_decoded_inst_get_index_reg(&xedd, m);
            if ((xed_get_largest_enclosing_register(base) == parent &&
                 xed_get_register_width_bits64(base) > width_bits) ||
                (xed_get_largest_enclosing_register(index) == parent &&
                 xed_get_register_width_bits64(index) > width_bits)) {
                return true;
            }
        }

        // A transfer we cannot follow leaves the bits conservatively live.
        xed_category_enum_t category = xed_decoded_inst_get_category(&xedd);
        if (category == XED_CATEGORY_CALL ||
            category == XED_CATEGORY_RET ||
            category == XED_CATEGORY_UNCOND_BR ||
            category == XED_CATEGORY_COND_BR ||
            category == XED_CATEGORY_SYSCALL ||
            category == XED_CATEGORY_SYSRET ||
            category == XED_CATEGORY_INTERRUPT) {
            return true;
        }

        if (redefines_reg_ge32(&xedd, parent)) {
            return false;
        }

        offset += xed_decoded_inst_get_length(&xedd);
    }

    return true;
}

// The classic boundary: bits 32-63 of the 64-bit GPR reg64, where only the
// 64-bit register name reads them. See reg_bits_above_live_after.
static bool reg_upper32_live_after(const uint8_t *inst, size_t len,
                                   size_t offset, xed_reg_enum_t reg64)
{
    return reg_bits_above_live_after(inst, len, offset, reg64, 32);
}

// reg_concern hook (see struct check_entry) shared by the checks whose rewrite
// drops an incidental 32-bit identity write: removing mov eax, eax or
// shl eax, 0, or replacing add eax, 0 / or eax, eax / and eax, -1 with a
// non-writing test. Only the 32-bit register forms disturb any bits when
// rewritten -- the zero-extension into the upper 32 bits of the enclosing
// 64-bit register (measured on hardware even for the count-0 shift, whose SDM
// pseudocode suggests no write) -- so return that register for those and
// XED_REG_INVALID (ungated) otherwise: an 8-/16-bit write leaves the
// surrounding bytes untouched just as its rewrite does, and a 64-bit identity
// write changes nothing. The GPR class test is defensive: every sharing check
// now rejects memory destinations itself (check_shift_zero was the last to
// pass them through), but a shape that slipped by with no register write
// would put a suppressed non-GPR like RFLAGS in the REG0 slot, and gating on
// garbage must fail toward INVALID.
static xed_reg_enum_t reg0_upper32_concern(const xed_decoded_inst_t *xedd)
{
    if (xed_decoded_inst_get_operand_width(xedd) != 32) {
        return XED_REG_INVALID;
    }
    xed_reg_enum_t r0 = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);
    if (xed_reg_class(r0) != XED_REG_CLASS_GPR) {
        return XED_REG_INVALID;
    }
    return xed_get_largest_enclosing_register(r0);
}

// reg_concern hook for check_imul_to_lea (see struct check_entry). Of its
// rewrites, only imul reg, reg, 1 -> nothing drops a register write -- the
// lea/shl/xor/mov/neg replacements all write the destination at the original
// width -- so only that form's 32-bit zero-extension is at stake (cf.
// reg0_upper32_concern). Return the enclosing register for it and
// XED_REG_INVALID (ungated) for every other multiplier, width, or shape.
static xed_reg_enum_t imul_identity_upper_concern(const xed_decoded_inst_t *xedd)
{
    if (xed_decoded_inst_get_operand_width(xedd) != 32) {
        return XED_REG_INVALID;
    }
    xed_reg_enum_t dst = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);
    if (dst == XED_REG_INVALID ||
        dst != xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1)) {
        return XED_REG_INVALID;
    }
    uint64_t eff = (uint64_t) (int64_t)
        xed_decoded_inst_get_signed_immediate(xedd) & UINT32_MAX;
    if (eff != 1) {
        return XED_REG_INVALID;
    }
    return xed_get_largest_enclosing_register(dst);
}

// reg_concern hook for check_oversized_lea_width (see struct check_entry).
// Every shape that check flags is a 64-bit LEA, and narrowing it to a 32-bit
// destination replaces bits 32-63 of the result -- the address's upper half
// -- with zeros, so the destination register is always at stake. Unlike the
// identity family's rewrites this one still writes the register, so its table
// entry leaves reg_zx_escape false: the backward escape would be unsound.
static xed_reg_enum_t lea_width_upper_concern(const xed_decoded_inst_t *xedd)
{
    return xed_get_largest_enclosing_register(
        xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0));
}

// True when `producer` unconditionally writes the 32-bit form of the GPR reg64,
// zero-extending bits 63:32 to zero. Any 32-bit GPR write zero-extends
// architecturally; this is restricted to the unconditional, defined-result
// writers of reg_kill_iclass (excluding e.g. CMOVcc and BSF/BSR, which may
// leave the register unwritten or undefined) and to a write of exactly the
// 32-bit form -- a 64-bit write sets bits 63:32 to arbitrary values instead.
//
// The 32-bit identity ops sharing reg0_upper32_concern (mov eax, eax;
// add eax, 0; or eax, eax; and eax, -1; shl eax, 0; ...) clear exactly those
// bits, so when the immediately preceding instruction already zeroed them the
// instruction is a pure no-op -- removable whether or not the upper half is
// read downstream. That is what lets the dispatcher report the finding even
// when reg_upper32_live_after finds the bits live, the complement of the
// forward gate.
static bool writes_zero_extended_32(const xed_decoded_inst_t *producer,
                                    xed_reg_enum_t reg64)
{
    if (!reg_kill_iclass(xed_decoded_inst_get_iclass(producer))) {
        return false;
    }
    const xed_inst_t *xi = xed_decoded_inst_inst(producer);
    unsigned nops = xed_inst_noperands(xi);
    for (unsigned i = 0; i < nops; ++i) {
        const xed_operand_t *op = xed_inst_operand(xi, i);
        xed_operand_enum_t name = xed_operand_name(op);
        if (!xed_operand_is_register(name) || !xed_operand_written(op)) {
            continue;
        }
        xed_reg_enum_t wr = xed_decoded_inst_get_reg(producer, name);
        if (xed_get_largest_enclosing_register(wr) == reg64 &&
            xed_get_register_width_bits64(wr) == 32) {
            return true;
        }
    }
    return false;
}

// Backward peephole (the sub-32 sibling of writes_zero_extended_32's
// mov r32, r32 escape). An in-place movzx/movsx/movsxd re-establishing bits
// the immediately preceding extension already provided is a pure no-op:
//
//   movzx eax, byte [rsi] ; movzx eax, al   -- bits 8-63 are already zero
//   movsx rax, bl         ; movsx rax, al   -- bits 8-63 already the sign
//   movsx rcx, bl         ; movsxd rcx, ecx -- bits 32-63 already the sign
//
// The consumer must extend IN PLACE -- its register source is the low part of
// the same register the producer wrote (a high-byte source like movzx eax, ah
// reads bits the producer just cleared, not the value) -- with the SAME kind
// as the producer: a zero-extension after a sign-extension, or vice versa,
// changes bits whenever the value is negative. The producer must extend from
// the same or a narrower source, so its guarantee covers the bit the consumer
// extends from, and its established range must cover every bit the consumer
// writes:
//
//   * zero-extensions: a 32- or 64-bit destination zeroes through bit 63
//     alike (the 32-bit write zero-extends), so either serves any consumer; a
//     16-bit destination (movzx cx, al) guarantees nothing above bit 15 and
//     serves only a 16-bit consumer.
//   * sign-extensions: the 32- and 64-bit destinations DIFFER through bit 63
//     -- movsx eax, bl zeroes bits 63:32 where movsx rax, bl sign-fills them
//     -- so a 32- or 64-bit consumer needs the producer destination width to
//     match exactly; a 16-bit consumer writes only bits 8-15, which any wider
//     sign-extension already filled.
//
// A producer's own source may be memory or a high byte: only its resulting
// state matters, an extension-from-w-bits pattern either way. Neither
// instruction touches flags and every bit the consumer writes already holds
// that value, so removal needs no liveness gate -- only the dispatcher's
// direct-edge rejection, since the justification is solely the predecessor.
static bool redundant_reextension(const xed_decoded_inst_t *prev,
                                  const xed_decoded_inst_t *xedd)
{
    // Consumer: an in-place register extension of the low bits.
    xed_iclass_enum_t cic = xed_decoded_inst_get_iclass(xedd);
    bool c_sign;
    switch (cic) {
    case XED_ICLASS_MOVZX:
        c_sign = false;
        break;
    case XED_ICLASS_MOVSX:
    case XED_ICLASS_MOVSXD:
        c_sign = true;
        break;
    default:
        return false;
    }
    if (xed_decoded_inst_number_of_memory_operands(xedd) != 0) {
        return false;
    }
    xed_reg_enum_t c_dst = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);
    xed_reg_enum_t c_src = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1);
    if (c_src == XED_REG_AH || c_src == XED_REG_CH ||
        c_src == XED_REG_DH || c_src == XED_REG_BH) {
        return false;
    }
    xed_reg_enum_t family = xed_get_largest_enclosing_register(c_dst);
    if (xed_get_largest_enclosing_register(c_src) != family) {
        return false;
    }

    // Producer: an extension of the same register with the same kind.
    bool p_sign;
    switch (xed_decoded_inst_get_iclass(prev)) {
    case XED_ICLASS_MOVZX:
        p_sign = false;
        break;
    case XED_ICLASS_MOVSX:
    case XED_ICLASS_MOVSXD:
        p_sign = true;
        break;
    default:
        return false;
    }
    if (p_sign != c_sign) {
        return false;
    }
    xed_reg_enum_t p_dst = xed_decoded_inst_get_reg(prev, XED_OPERAND_REG0);
    if (xed_get_largest_enclosing_register(p_dst) != family) {
        return false;
    }

    // The producer's guarantee starts at its source width, register or
    // memory.
    unsigned p_ws = xed_decoded_inst_number_of_memory_operands(prev) != 0
        ? xed_decoded_inst_get_memory_operand_length(prev, 0) * 8
        : xed_get_register_width_bits64(
              xed_decoded_inst_get_reg(prev, XED_OPERAND_REG1));
    unsigned c_ws = xed_get_register_width_bits64(c_src);
    if (p_ws == 0 || p_ws > c_ws) {
        return false;
    }

    unsigned p_wd = xed_get_register_width_bits64(p_dst);
    unsigned c_wd = xed_get_register_width_bits64(c_dst);
    if (!c_sign) {
        // Zeroes reach bit 63 from either a 32- or 64-bit destination.
        unsigned p_end = p_wd >= 32 ? 64 : p_wd;
        unsigned c_end = c_wd >= 32 ? 64 : c_wd;
        return p_end >= c_end;
    }
    // Sign fills: 16-bit consumers are covered by any wider producer; wider
    // consumers need the exact destination width.
    return c_wd == 16 ? p_wd >= 16 : p_wd == c_wd;
}

bool check_endbr64_target(const uint8_t *inst, size_t len, size_t offset)
{
    // The tracker matches the decoded instruction, not raw bytes, so decode
    // rather than memcmp the canonical F3 0F 1E FA: a redundant-prefixed
    // ENDBR64 still decodes (and lands) as ENDBR64. ENDBR32 does not
    // terminate 64-bit tracking and correctly fails the iclass test, as does
    // an offset where no instruction decodes at all -- a landing there
    // faults either way.
    if (offset >= len) {
        return false;
    }
    xed_decoded_inst_t xedd;
    decode_init(&xedd);
    if (xed_decode(&xedd, inst + offset, len - offset) != XED_ERROR_NONE) {
        return false;
    }
    return xed_decoded_inst_get_iclass(&xedd) == XED_ICLASS_ENDBR64;
}

#define X86LINT_SUMMARY_MAX 64

struct x86lint_summary {
    struct {
        const char *name;
        unsigned count;
    } entries[X86LINT_SUMMARY_MAX];
    size_t count;
    size_t instructions;   // total decoded instructions across all runs
    size_t skipped;        // undecodable bytes skipped during resync
    // Function attribution (x86lint_summary_set_functions): caller-owned
    // sorted ranges, a parallel per-function tally, findings landing in
    // no range, and the vaddr of the buffer currently being scanned
    // (set by check_instructions from its vaddr argument).
    const x86lint_func_range *funcs;
    size_t nfuncs;
    size_t *func_hits;
    size_t nofunc_hits;
    uint64_t base;
};

x86lint_summary *x86lint_summary_create(void)
{
    return calloc(1, sizeof(struct x86lint_summary));
}

void x86lint_summary_destroy(x86lint_summary *summary)
{
    if (summary != NULL) {
        free(summary->func_hits);
    }
    free(summary);
}

void x86lint_summary_set_functions(x86lint_summary *summary,
                                   const x86lint_func_range *funcs,
                                   size_t count)
{
    if (summary == NULL) {
        return;
    }
    free(summary->func_hits);
    summary->func_hits = count != 0 ? calloc(count, sizeof(size_t)) : NULL;
    if (summary->func_hits == NULL) {   // includes allocation failure:
        summary->funcs = NULL;          // attribution quietly stays off
        summary->nfuncs = 0;
        return;
    }
    summary->funcs = funcs;
    summary->nfuncs = count;
}

size_t x86lint_summary_function_findings(const x86lint_summary *summary,
                                         size_t idx)
{
    if (summary == NULL || summary->func_hits == NULL ||
        idx >= summary->nfuncs) {
        return 0;
    }
    return summary->func_hits[idx];
}

// The installed function containing vaddr, or nfuncs for none. Binary
// search over the sorted, non-overlapping ranges.
static size_t summary_func_at(const x86lint_summary *summary, uint64_t vaddr)
{
    size_t lo = 0;
    size_t hi = summary->nfuncs;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (vaddr < summary->funcs[mid].start) {
            hi = mid;
        } else if (vaddr >= summary->funcs[mid].end) {
            lo = mid + 1;
        } else {
            return mid;
        }
    }
    return summary->nfuncs;
}

size_t x86lint_summary_instructions(const x86lint_summary *summary)
{
    return summary == NULL ? 0 : summary->instructions;
}

size_t x86lint_summary_skipped(const x86lint_summary *summary)
{
    return summary == NULL ? 0 : summary->skipped;
}

// Tally one finding by its name (a stable string literal owned by the check
// table) and, when a function table is installed, by the function holding
// the finding's address. Linear scan for the by-type entry -- the table is
// tiny. Silently ignores a NULL summary and the (cannot-happen with the
// current check set) overflow.
static void summary_add(x86lint_summary *summary, const char *name,
                        size_t offset)
{
    if (summary == NULL || name == NULL) {
        return;
    }
    if (summary->func_hits != NULL) {
        size_t k = summary_func_at(summary, summary->base + offset);
        if (k < summary->nfuncs) {
            summary->func_hits[k]++;
        } else {
            summary->nofunc_hits++;
        }
    }
    for (size_t i = 0; i < summary->count; ++i) {
        if (strcmp(summary->entries[i].name, name) == 0) {
            summary->entries[i].count++;
            return;
        }
    }
    if (summary->count < X86LINT_SUMMARY_MAX) {
        summary->entries[summary->count].name = name;
        summary->entries[summary->count].count = 1;
        summary->count++;
    }
}

void x86lint_summary_print(const x86lint_summary *summary)
{
    if (summary == NULL) {
        return;
    }

    if (summary->count > 0) {
        // Order by descending count, ties broken by name for determinism.
        size_t order[X86LINT_SUMMARY_MAX];
        for (size_t i = 0; i < summary->count; ++i) {
            order[i] = i;
        }
        for (size_t i = 0; i < summary->count; ++i) {
            size_t best = i;
            for (size_t j = i + 1; j < summary->count; ++j) {
                unsigned cj = summary->entries[order[j]].count;
                unsigned cb = summary->entries[order[best]].count;
                if (cj > cb ||
                    (cj == cb && strcmp(summary->entries[order[j]].name,
                                        summary->entries[order[best]].name) < 0)) {
                    best = j;
                }
            }
            size_t tmp = order[i];
            order[i] = order[best];
            order[best] = tmp;
        }

        printf("Optimization opportunities by type:\n");
        for (size_t i = 0; i < summary->count; ++i) {
            printf("  %6u  %s\n", summary->entries[order[i]].count,
                summary->entries[order[i]].name);
        }
        printf("\n");
    }

    // The by-function companion table: the top offenders, so a whole-binary
    // count reads as "and here is where to start". Capped -- a large binary
    // spreads findings over thousands of functions -- with the tail summed
    // into a residue line, and findings outside every installed range (the
    // -a scan reaches such bytes) reported as their own honest row.
    if (summary->func_hits != NULL) {
        size_t attributed = 0;
        size_t nhit = 0;
        for (size_t i = 0; i < summary->nfuncs; ++i) {
            attributed += summary->func_hits[i];
            nhit += summary->func_hits[i] != 0;
        }
        if (attributed + summary->nofunc_hits > 0) {
            enum { TOP = 10 };
            size_t top[TOP];
            size_t ntop = 0;
            for (size_t i = 0; i < summary->nfuncs; ++i) {
                if (summary->func_hits[i] == 0) {
                    continue;
                }
                size_t j = ntop;
                while (j > 0 &&
                       summary->func_hits[top[j - 1]] <
                           summary->func_hits[i]) {
                    if (j < TOP) {
                        top[j] = top[j - 1];
                    }
                    --j;
                }
                if (j < TOP) {
                    top[j] = i;
                    if (ntop < TOP) {
                        ++ntop;
                    }
                }
            }
            printf("Optimization opportunities by function:\n");
            size_t shown = 0;
            for (size_t i = 0; i < ntop; ++i) {
                printf("  %6zu  %s\n", summary->func_hits[top[i]],
                    summary->funcs[top[i]].name);
                shown += summary->func_hits[top[i]];
            }
            if (nhit > ntop) {
                printf("  %6zu  in %zu more functions\n",
                    attributed - shown, nhit - ntop);
            }
            if (summary->nofunc_hits > 0) {
                printf("  %6zu  outside every function range\n",
                    summary->nofunc_hits);
            }
            printf("\n");
        }
    }

    // Undecodable bytes mean the section interleaves data with code (common in
    // Go binaries and jump tables); report them so incomplete coverage is not
    // mistaken for a clean scan.
    if (summary->skipped > 0) {
        printf("%zu undecodable byte%s skipped (data in code section?)\n\n",
            summary->skipped, summary->skipped == 1 ? "" : "s");
    }
}

#define CENSUS_SAMPLES 4

struct x86lint_census {
    size_t counts[XED_ISA_SET_LAST];
    // First few sites per isa-set, so a handful of hits can be checked in a
    // disassembler: a real AVX2 loop and a jump table misdecoded as VEX
    // bytes both count, and only the address tells them apart.
    uint64_t samples[XED_ISA_SET_LAST][CENSUS_SAMPLES];
    uint8_t nsamples[XED_ISA_SET_LAST];
    size_t instructions;
    size_t skipped;
    // The x87 annotation (see enum x86lint_x87_kind in the header). Only
    // the "other" bucket keeps samples: control/env and 80-bit sites are
    // expected in ordinary binaries, but bare-stack arithmetic is what a
    // reader chases to judge whether x87 was intended.
    size_t x87[3];
    uint64_t x87_other_samples[CENSUS_SAMPLES];
    uint8_t x87_other_nsamples;
    // Code evidence (see x86lint_census_set_evidence): borrowed sorted
    // ranges, and per-set / x87-family tallies of the hits outside all
    // of them.
    const x86lint_evidence_range *evidence;
    size_t nevidence;
    size_t unevidenced[XED_ISA_SET_LAST];
    size_t x87_unevidenced;
};

void x86lint_census_set_evidence(x86lint_census *census,
                                 const x86lint_evidence_range *ranges,
                                 size_t count)
{
    if (census == NULL) {
        return;
    }
    census->evidence = ranges;
    census->nevidence = count;
}

static bool evidence_contains(const x86lint_census *census, uint64_t vaddr)
{
    size_t lo = 0;
    size_t hi = census->nevidence;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (vaddr < census->evidence[mid].start) {
            hi = mid;
        } else if (vaddr >= census->evidence[mid].end) {
            lo = mid + 1;
        } else {
            return true;
        }
    }
    return false;
}

x86lint_census *x86lint_census_create(void)
{
    return calloc(1, sizeof(struct x86lint_census));
}

void x86lint_census_destroy(x86lint_census *census)
{
    free(census);
}

size_t x86lint_census_instructions(const x86lint_census *census)
{
    return census == NULL ? 0 : census->instructions;
}

size_t x86lint_census_skipped(const x86lint_census *census)
{
    return census == NULL ? 0 : census->skipped;
}

// Which psABI micro-architecture level an isa-set belongs to: 2..4 for
// x86-64-v2..v4, 1 for baseline x86-64, 0 for a real extension outside the
// levels (AES-NI, SHA, ADX, CET, RTM, the post-v4 AVX-512 families, APX,
// ...). The level definitions are the psABI's, as implemented by GCC's
// -march=x86-64-v2/v3/v4.
static int isa_set_level(xed_isa_set_enum_t s)
{
    // x86-64-v4 adds AVX-512 F/BW/CD/DQ/VL. XED splits each of those CPUID
    // features into per-width isa-sets (AVX512F_128/_256/_512/_SCALAR, the
    // mask-register ops as AVX512F_KOPW, ...), so match the family by name
    // prefix. The 128/256-bit forms are the AVX512VL-gated encodings, still
    // v4 because the level includes VL. The underscore keeps non-level
    // families out: AVX512_VNNI_128, AVX512_FP16_512 do not match.
    const char *name = xed_isa_set_enum_t2str(s);
    if (strncmp(name, "AVX512F_", 8) == 0 ||
        strncmp(name, "AVX512BW_", 9) == 0 ||
        strncmp(name, "AVX512CD_", 9) == 0 ||
        strncmp(name, "AVX512DQ_", 9) == 0) {
        return 4;
    }

    switch ((int) s) {
    // x86-64-v2: CMPXCHG16B, LAHF-SAHF, POPCNT, SSE3, SSSE3, SSE4.1
    // (XED's SSE4), SSE4.2. SSE3X87 is FISTTP, gated on the SSE3 CPUID bit.
    case XED_ISA_SET_SSE3:
    case XED_ISA_SET_SSE3X87:
    case XED_ISA_SET_SSSE3:
    case XED_ISA_SET_SSSE3MMX:
    case XED_ISA_SET_SSE4:
    case XED_ISA_SET_SSE42:
    case XED_ISA_SET_POPCNT:
    case XED_ISA_SET_CMPXCHG16B:
    case XED_ISA_SET_LAHF:
        return 2;
    // x86-64-v3: AVX, AVX2, BMI1, BMI2, F16C, FMA, LZCNT, MOVBE, XSAVE.
    // XSAVEC/XSAVEOPT/XSAVES are separate CPUID bits outside the level, and
    // AVXAES/AVX_GFNI are VEX forms gated on the AES/GFNI bits, not on AVX
    // alone: all fall through to 0.
    case XED_ISA_SET_AVX:
    case XED_ISA_SET_AVX2:
    case XED_ISA_SET_AVX2GATHER:
    case XED_ISA_SET_BMI1:
    case XED_ISA_SET_BMI2:
    case XED_ISA_SET_F16C:
    case XED_ISA_SET_FMA:
    case XED_ISA_SET_LZCNT:
    case XED_ISA_SET_MOVBE:
    case XED_ISA_SET_XSAVE:
        return 3;
    // Baseline x86-64: the legacy integer sets through P6, x87/MMX/SSE/SSE2
    // and their support instructions, and long mode itself.
    case XED_ISA_SET_I86:
    case XED_ISA_SET_I186:
    case XED_ISA_SET_I286REAL:
    case XED_ISA_SET_I286PROTECTED:
    case XED_ISA_SET_I386:
    case XED_ISA_SET_I486:
    case XED_ISA_SET_I486REAL:
    case XED_ISA_SET_PENTIUMREAL:
    case XED_ISA_SET_PENTIUMMMX:
    case XED_ISA_SET_PPRO:
    case XED_ISA_SET_PPRO_UD0_LONG:
    case XED_ISA_SET_PPRO_UD0_SHORT:
    case XED_ISA_SET_CMOV:
    case XED_ISA_SET_FCMOV:
    case XED_ISA_SET_FCOMI:
    case XED_ISA_SET_X87:
    case XED_ISA_SET_SSE:
    case XED_ISA_SET_SSE2:
    case XED_ISA_SET_SSE2MMX:
    case XED_ISA_SET_SSEMXCSR:
    case XED_ISA_SET_SSE_PREFETCH:
    case XED_ISA_SET_FXSAVE:
    case XED_ISA_SET_FXSAVE64:
    case XED_ISA_SET_PAUSE:
    case XED_ISA_SET_FAT_NOP:
    case XED_ISA_SET_PREFETCH_NOP:
    case XED_ISA_SET_CLFSH:
    case XED_ISA_SET_LONGMODE:
    case XED_ISA_SET_SEP:
        return 1;
    default:
        return 0;
    }
}

// Display name for an isa-set: XED calls SSE4.1 "SSE4" and SSE4.2 "SSE42";
// spell those out. With `fold` set, collapse the per-width v4 sets into
// their CPUID feature (AVX512F_512 -> AVX512F) so a level line reads as
// features rather than encoding widths.
static void census_display_name(xed_isa_set_enum_t s, bool fold, char *out,
                                size_t outlen)
{
    const char *name = xed_isa_set_enum_t2str(s);
    if (s == XED_ISA_SET_SSE4) {
        name = "SSE4.1";
    } else if (s == XED_ISA_SET_SSE42) {
        name = "SSE4.2";
    }
    snprintf(out, outlen, "%s", name);
    if (fold && isa_set_level(s) == 4) {
        char *underscore = strchr(out + strlen("AVX512"), '_');
        if (underscore != NULL) {
            *underscore = '\0';
        }
    }
}

// The x87 family for the census annotation: the legacy stack FPU proper,
// its P6-era conditional forms, and SSE3's FISTTP (an x87 instruction
// gated on the SSE3 CPUID bit -- it converts from st(0), so its presence
// is x87-usage evidence even though the ladder counts it at v2).
static bool isa_set_is_x87(xed_isa_set_enum_t s)
{
    return s == XED_ISA_SET_X87 || s == XED_ISA_SET_FCMOV ||
        s == XED_ISA_SET_FCOMI || s == XED_ISA_SET_SSE3X87;
}

// Split one x87-family instruction for the annotation. Per-instruction
// facts only -- intent is judged per binary (see the header comment on
// enum x86lint_x87_kind).
static enum x86lint_x87_kind x87_kind(const xed_decoded_inst_t *xedd)
{
    switch (xed_decoded_inst_get_iclass(xedd)) {
    case XED_ICLASS_FLDCW:
    case XED_ICLASS_FNSTCW:
    case XED_ICLASS_FNSTSW:
    case XED_ICLASS_FNCLEX:
    case XED_ICLASS_FNINIT:
    case XED_ICLASS_FWAIT:
    case XED_ICLASS_FLDENV:
    case XED_ICLASS_FNSTENV:
    case XED_ICLASS_FNSAVE:
    case XED_ICLASS_FRSTOR:
        return X86LINT_X87_CONTROL;
    default:
        break;
    }
    unsigned n = xed_decoded_inst_number_of_memory_operands(xedd);
    for (unsigned i = 0; i < n; ++i) {
        if (xed_decoded_inst_get_memory_operand_length(xedd, i) == 10) {
            return X86LINT_X87_EIGHTY_BIT;
        }
    }
    return X86LINT_X87_OTHER;
}

void x86lint_census_scan(x86lint_census *census, const uint8_t *inst,
                         size_t len, uint64_t vaddr)
{
    if (census == NULL) {
        return;
    }
    for (size_t i = 0; i < len; ) {
        xed_decoded_inst_t xedd;
        decode_init(&xedd);
        if (xed_decode(&xedd, inst + i, len - i) != XED_ERROR_NONE) {
            ++i;
            ++census->skipped;
            continue;
        }
        xed_isa_set_enum_t s = xed_decoded_inst_get_isa_set(&xedd);
        if ((int) s >= 0 && s < XED_ISA_SET_LAST) {
            census->counts[s]++;
            if (census->nsamples[s] < CENSUS_SAMPLES) {
                census->samples[s][census->nsamples[s]++] = vaddr + i;
            }
            bool unevidenced = census->nevidence != 0 &&
                !evidence_contains(census, vaddr + i);
            if (unevidenced) {
                census->unevidenced[s]++;
            }
            if (isa_set_is_x87(s)) {
                enum x86lint_x87_kind kind = x87_kind(&xedd);
                census->x87[kind]++;
                if (unevidenced) {
                    census->x87_unevidenced++;
                }
                if (kind == X86LINT_X87_OTHER &&
                    census->x87_other_nsamples < CENSUS_SAMPLES) {
                    census->x87_other_samples[census->x87_other_nsamples++] =
                        vaddr + i;
                }
            }
        }
        census->instructions++;
        i += xed_decoded_inst_get_length(&xedd);
    }
}

size_t x86lint_census_level_unevidenced(const x86lint_census *census,
                                        int level)
{
    if (census == NULL) {
        return 0;
    }
    size_t total = 0;
    for (int s = 0; s < XED_ISA_SET_LAST; ++s) {
        if (census->unevidenced[s] != 0 &&
            isa_set_level((xed_isa_set_enum_t) s) == level) {
            total += census->unevidenced[s];
        }
    }
    return total;
}

size_t x86lint_census_x87_count(const x86lint_census *census,
                                enum x86lint_x87_kind kind)
{
    if (census == NULL || (int) kind < 0 || (int) kind > X86LINT_X87_OTHER) {
        return 0;
    }
    return census->x87[kind];
}

size_t x86lint_census_level_count(const x86lint_census *census, int level)
{
    if (census == NULL) {
        return 0;
    }
    size_t total = 0;
    for (int s = 0; s < XED_ISA_SET_LAST; ++s) {
        if (census->counts[s] != 0 &&
            isa_set_level((xed_isa_set_enum_t) s) == level) {
            total += census->counts[s];
        }
    }
    return total;
}

int x86lint_census_highest_level(const x86lint_census *census)
{
    int highest = 1;
    if (census == NULL) {
        return highest;
    }
    for (int s = 0; s < XED_ISA_SET_LAST; ++s) {
        int level = isa_set_level((xed_isa_set_enum_t) s);
        if (census->counts[s] != 0 && level > highest) {
            highest = level;
        }
    }
    return highest;
}

// One "  <label>: FAM (n), FAM (n), ..." line for a level, families by
// descending count with ties broken by name, "none" when the level is
// unused. Zero counts are printed as "none" rather than omitted so two
// census runs diff line-for-line. With evidence installed, a family
// with hits outside all of it prints as "FAM (n, u unevidenced)".
static void census_print_level(const x86lint_census *census, int level,
                               const char *label)
{
    struct {
        char name[32];
        size_t count;
        size_t unev;
    } fams[XED_ISA_SET_LAST];
    size_t nfams = 0;

    for (int s = 0; s < XED_ISA_SET_LAST; ++s) {
        if (census->counts[s] == 0 ||
            isa_set_level((xed_isa_set_enum_t) s) != level) {
            continue;
        }
        char name[32];
        census_display_name((xed_isa_set_enum_t) s, true, name, sizeof(name));
        size_t k = 0;
        while (k < nfams && strcmp(fams[k].name, name) != 0) {
            ++k;
        }
        if (k == nfams) {
            snprintf(fams[k].name, sizeof(fams[k].name), "%s", name);
            fams[k].count = 0;
            fams[k].unev = 0;
            ++nfams;
        }
        fams[k].count += census->counts[s];
        fams[k].unev += census->unevidenced[s];
    }

    printf("  %s: ", label);
    if (nfams == 0) {
        printf("none\n");
        return;
    }
    for (size_t i = 0; i < nfams; ++i) {
        size_t best = i;
        for (size_t j = i + 1; j < nfams; ++j) {
            if (fams[j].count > fams[best].count ||
                (fams[j].count == fams[best].count &&
                 strcmp(fams[j].name, fams[best].name) < 0)) {
                best = j;
            }
        }
        if (best != i) {
            char tname[32];
            memcpy(tname, fams[i].name, sizeof(tname));
            memcpy(fams[i].name, fams[best].name, sizeof(fams[i].name));
            memcpy(fams[best].name, tname, sizeof(tname));
            size_t tcount = fams[i].count;
            fams[i].count = fams[best].count;
            fams[best].count = tcount;
            size_t tunev = fams[i].unev;
            fams[i].unev = fams[best].unev;
            fams[best].unev = tunev;
        }
        printf("%s%s (%zu", i == 0 ? "" : ", ", fams[i].name,
            fams[i].count);
        if (fams[i].unev != 0) {
            printf(", %zu unevidenced", fams[i].unev);
        }
        printf(")");
    }
    printf("\n");
}

void x86lint_census_print(const x86lint_census *census, bool verbose)
{
    if (census == NULL) {
        return;
    }

    printf("ISA census: %zu instructions, %zu undecodable bytes skipped\n",
        census->instructions, census->skipped);
    printf("  baseline x86-64 (v1): %zu",
        x86lint_census_level_count(census, 1));
    size_t base_unev = x86lint_census_level_unevidenced(census, 1);
    if (base_unev != 0) {
        printf(" (%zu unevidenced)", base_unev);
    }
    printf("\n");
    census_print_level(census, 2, "x86-64-v2");
    census_print_level(census, 3, "x86-64-v3");
    census_print_level(census, 4, "x86-64-v4");
    census_print_level(census, 0, "outside the psABI levels");

    // Cross-cutting annotation, not a level: these instructions are also
    // counted above (x87 is baseline; FISTTP is v2). "other" beside 80-bit
    // traffic reads as long-double implementation; "other" with zero
    // 80-bit operands cannot be long double and points at -mfpmath=387
    // leakage or ported 32-bit assembly.
    size_t x87_total = census->x87[X86LINT_X87_CONTROL] +
        census->x87[X86LINT_X87_EIGHTY_BIT] + census->x87[X86LINT_X87_OTHER];
    if (x87_total == 0) {
        printf("  x87 legacy FP: none\n");
    } else {
        printf("  x87 legacy FP: %zu (control/env %zu, 80-bit operands %zu, "
            "other %zu", x87_total, census->x87[X86LINT_X87_CONTROL],
            census->x87[X86LINT_X87_EIGHTY_BIT],
            census->x87[X86LINT_X87_OTHER]);
        if (census->x87_unevidenced != 0) {
            printf("; %zu unevidenced", census->x87_unevidenced);
        }
        printf(")\n");
    }

    int highest = x86lint_census_highest_level(census);
    if (highest > 1) {
        printf("  highest psABI level: x86-64-v%d\n", highest);
    } else {
        printf("  highest psABI level: baseline x86-64 (v1)\n");
    }

    if (!verbose) {
        return;
    }
    // Sample addresses per non-baseline set, unfolded (the exact XED
    // isa-set names the width of each hit), so a suspicious tally can be
    // checked at a disassembler prompt.
    for (int s = 0; s < XED_ISA_SET_LAST; ++s) {
        if (census->counts[s] == 0 ||
            isa_set_level((xed_isa_set_enum_t) s) == 1) {
            continue;
        }
        char name[32];
        census_display_name((xed_isa_set_enum_t) s, false, name,
            sizeof(name));
        printf("    %s at", name);
        for (uint8_t k = 0; k < census->nsamples[s]; ++k) {
            printf("%s 0x%" PRIx64, k == 0 ? "" : ",",
                census->samples[s][k]);
        }
        if (census->counts[s] > census->nsamples[s]) {
            printf(" (+%zu more)",
                census->counts[s] - census->nsamples[s]);
        }
        printf("\n");
    }
    // The x87 "other" sites are the ones a reader chases to judge intent;
    // the level-1 sample suppression above would otherwise hide them.
    if (census->x87_other_nsamples > 0) {
        printf("    x87 other at");
        for (uint8_t k = 0; k < census->x87_other_nsamples; ++k) {
            printf("%s 0x%" PRIx64, k == 0 ? "" : ",",
                census->x87_other_samples[k]);
        }
        if (census->x87[X86LINT_X87_OTHER] > census->x87_other_nsamples) {
            printf(" (+%zu more)",
                census->x87[X86LINT_X87_OTHER] - census->x87_other_nsamples);
        }
        printf("\n");
    }
}

// In verbose mode print a finding as a one-line summary -- the offending
// instruction disassembled at its address, suffixed with the containing
// function when the summary carries a table -- followed by the raw
// encoding indented beneath it. Non-verbose runs print nothing per
// finding; the caller's summary is the whole report.
static void report_finding(const x86lint_summary *summary, const char *name,
                           size_t offset, bool verbose,
                           const xed_decoded_inst_t *xedd, const uint8_t *bytes)
{
    if (!verbose) {
        return;
    }

    char disasm[96];
    if (!xed_format_context(XED_SYNTAX_INTEL, xedd, disasm, sizeof(disasm),
                            offset, NULL, NULL)) {
        disasm[0] = '\0';
    }
    printf("%s at offset: 0x%zx", name, offset);
    if (summary != NULL && summary->func_hits != NULL) {
        uint64_t vaddr = summary->base + offset;
        size_t k = summary_func_at(summary, vaddr);
        if (k < summary->nfuncs) {
            printf(" (%s+0x%lx)", summary->funcs[k].name,
                (unsigned long) (vaddr - summary->funcs[k].start));
        }
    }
    printf(": %s\n", disasm);

    printf("  ");
    int insn_len = xed_decoded_inst_get_length(xedd);
    for (int i = 0; i < insn_len; ++i) {
        printf("%s%02x", i == 0 ? "" : " ", bytes[i]);
    }
    printf("\n\n");
}

struct check_entry {
    bool (*fn)(const xed_decoded_inst_t *);
    const char *name;
    // Status flags that the suggested replacement would either no longer
    // produce or compute differently from the original instruction. The
    // dispatcher suppresses the finding when any of these flags might be
    // read downstream before being overwritten. 0 for checks with no flag
    // soundness concern.
    uint32_t flag_concerns;
    // Optional hook for a rewrite that changes only the upper 32 bits of a
    // register (the 32-bit zero-extension). Given the decoded instruction it
    // returns the 64-bit GPR whose bits 32-63 are at stake, or XED_REG_INVALID
    // for none; the dispatcher then suppresses the finding when
    // reg_upper32_live_after reports those bits live. NULL for checks with no
    // such concern.
    xed_reg_enum_t (*reg_concern)(const xed_decoded_inst_t *);
    // Whether writes_zero_extended_32's backward escape may override a live
    // reg_concern verdict: when the immediately preceding instruction already
    // zeroed the register's bits 32-63, the identity family's rewrite --
    // DELETING the instruction -- makes the deletion state-preserving, so the
    // finding stands even with those bits live downstream. True for exactly
    // those checks. It must stay false for a rewrite that still writes the
    // register (lea r64 -> lea r32 swaps the address's upper half for zeros):
    // there the predecessor's zeros are overwritten either way and prove
    // nothing.
    bool reg_zx_escape;
    // Instruction-set extensions (enum x86lint_extensions bits) the suggested
    // replacement requires. The dispatcher skips the row unless the caller
    // enabled every one of them: on a target not known to support the
    // extension the finding would not be actionable. 0 (the default) for the
    // baseline checks, whose replacements any x86-64 CPU executes.
    uint32_t ext_required;
};

// check_suboptimal_nops is not in the table: it takes the raw byte stream
// (not a decoded instruction) and reports a 2-instruction window.
static const struct check_entry checks[] = {
    {check_oversized_immediate,        "oversized immediate",             0},
    {check_oversized_test_immediate,   "oversized TEST immediate",        0},
    {check_test_minus_one,             "redundant TEST immediate",        0},
    {check_oversized_add_sub_128,      "oversized ADD/SUB 128",           FLAG_CF},
    {check_lcp_imm16,                  "length-changing prefix stall",    0},
    {check_unneeded_rex,               "unneeded REX prefix",             0},
    {check_cmp_zero,                   "suboptimal CMP zero",             0},
    {check_mov_zero,                   "suboptimal MOV zero",             FLAG_ARITH},
    {check_implicit_register,          "unneeded explicit register",      0},
    {check_implicit_immediate,         "unneeded explicit immediate",     0},
    {check_and_strength_reduce,        "suboptimal AND immediate",        FLAG_ARITH},
    {check_and_minus_one,              "redundant AND immediate",         0, reg0_upper32_concern, true},
    {check_and_zero,                   "suboptimal AND zero",             0},
    {check_xor_to_not,                 "suboptimal XOR immediate",        FLAG_ARITH},
    {check_superfluous_lock_prefix,    "unneeded LOCK prefix",            0},
    {check_rep_ret,                    "unneeded REP prefix on RET",      0},
    {check_notrack_call,               "IBT-bypassing NOTRACK call",      0},
    {check_xchg_accumulator,           "oversized XCHG encoding",         0},
    {check_oversized_branch,           "oversized branch displacement",   0},
    {check_mov_self,                   "redundant MOV reg, reg",          0, reg0_upper32_concern, true},
    {check_add_sub_zero,               "redundant ADD/SUB zero",          0, reg0_upper32_concern, true},
    {check_or_xor_zero,                "redundant OR/XOR zero",           0, reg0_upper32_concern, true},
    {check_inc_dec,                    "oversized ADD/SUB one",           FLAG_CF},
    {check_mov_modrm_imm,              "oversized MOV encoding",          0},
    {check_unneeded_sib,               "unneeded SIB byte",               0},
    {check_unneeded_zero_displacement, "unneeded zero displacement",      0},
    {check_oversized_displacement,     "oversized displacement",          0},
    {check_unneeded_movsxd,            "unneeded MOVSXD",                 0},
    {check_unneeded_movsx,             "unneeded MOVSX",                  0},
    {check_sub_self,                   "suboptimal SUB reg, reg",         0},
    {check_or_and_self,                "suboptimal OR/AND reg, reg",      0, reg0_upper32_concern, true},
    {check_imul_to_lea,                "suboptimal IMUL constant",        FLAG_CF | FLAG_OF, imul_identity_upper_concern, true},
    {check_lea_to_mov,                 "suboptimal LEA",                  0},
    {check_lea_to_add,                 "suboptimal LEA",                  FLAG_ARITH},
    {check_oversized_lea_width,        "oversized LEA width",             0, lea_width_upper_concern},
    {check_shift_zero,                 "redundant shift/rotate by zero",  0, reg0_upper32_concern, true},
    {check_shl_one,                    "suboptimal SHL one",              0},
    {check_missing_shlx,               "missing SHLX/SHRX/SARX",          FLAG_ARITH, reg0_upper32_concern, false, X86LINT_EXT_BMI2},
    {check_sse_mov_opcode,             "suboptimal SSE MOV opcode",       0},
    {check_sse_zero_idiom,             "suboptimal SSE zero idiom",       0},
    {check_oversized_evex,             "oversized EVEX encoding",         0},
    {check_oversized_vex,              "oversized VEX encoding",          0},
};

// Multi-instruction peephole (the first analysis to span two instructions,
// hence the raw-stream signature rather than a check_entry). A flag-setting ALU
// that writes a register -- ADD/SUB/ADC/SBB/AND/OR/XOR/INC/DEC/NEG -- sets
// SF/ZF/PF from the value it stores, so an immediately following test reg, reg
// on that same register recomputes flags the ALU already produced. The test is
// dead: a downstream Jcc/SETcc/CMOVcc can read the ALU's flags directly.
//
//   dec ecx ; test ecx, ecx ; ...     ->   dec ecx ; ...
//   and eax, ebx ; test eax, eax ; je ->   and eax, ebx ; je
//
// `producer` is the already-decoded instruction ending at `test_offset`; on a
// match the redundant test is decoded into *test_out and the function returns
// true, leaving the caller to report at test_offset (the removable
// instruction).
//
// Soundness. test reg, reg sets SF/ZF/PF from reg and clears CF and OF (AF is
// undefined and unobservable in 64-bit mode). Because the ALU wrote reg, its
// SF/ZF/PF equal the test's exactly -- so the test's register must match the
// ALU's destination at the same width; add eax, ..; test rax, rax would read SF
// at bit 63 rather than bit 31 and is rejected. The only possible divergence is
// CF/OF:
//   * AND/OR/XOR clear CF and OF just as test does, so the test is a pure
//     duplicate: removing it changes nothing and the finding is unconditional
//     (it fires even through a following flag-reading branch).
//   * ADD/SUB/ADC/SBB/NEG write CF/OF from the arithmetic, and INC/DEC write OF
//     while leaving CF untouched; either way CF/OF may differ from the test's
//     zeroes. Dropping the test then exposes the ALU's CF/OF downstream, so the
//     finding is gated on flags_live_after showing CF and OF dead past the test
//     (a following jb, seto, or adc keeps it). That walk is conservative at any
//     branch, so an arithmetic producer whose test feeds a Jcc is left
//     unflagged -- only its straight-line and RET cases fire.
//
// Only test reg, reg is matched. cmp reg, 0 sets the same flags but is already
// check_cmp_zero's finding (rewritten to test reg, reg), after which this check
// catches the residue -- the two compose rather than double-report. Shifts and
// rotates are excluded from the producer set (a masked or CL count of zero
// leaves the flags untouched, so the test would not be redundant), as are IMUL,
// MUL, and the bit-scan ops, which leave SF/ZF/PF undefined.
// Bitmap of direct branch targets, one bit per byte offset of the scanned
// buffer: the target of every decoded jmp/jcc/call/loop with a relative
// displacement that lands inside the buffer. Built by a first pass walking the
// same decode-and-resync sweep as the scan proper (so it sees the identical
// instruction boundaries) and consulted by the multi-instruction peepholes:
// their rewrite replaces a WINDOW of instructions, which is sound only if
// control cannot enter the window's interior -- an incoming edge executes just
// the tail. The canonical trap is the scan loop
//
//   mov rbx, rax ; L: add rbx, 1 ; cmp byte [rbx], '-' ; je L
//
// where folding mov+add into lea rbx, [rax + 1] turns the loop increment into
// a per-iteration reset (observed in /usr/bin/bash and /usr/bin/git; four of
// the first five real-binary mov+add-imm findings were this shape). An edge to
// the window HEAD is harmless -- it executes the whole pattern, which the
// rewrite reproduces -- so only interior offsets suppress. Edges the sweep
// cannot see -- indirect branches, jump tables, entries from another section --
// remain a documented residual risk of operating on raw bytes (README,
// "Linear sweep with resync").
static uint8_t *collect_branch_targets(const uint8_t *inst, size_t len)
{
    uint8_t *targets = calloc((len + 7) / 8, 1);
    if (targets == NULL) {
        return NULL;    // branch_target_in treats this as every-offset-hit
    }

    for (size_t offset = 0; offset < len;) {
        xed_decoded_inst_t xedd;
        decode_init(&xedd);
        if (xed_decode(&xedd, inst + offset, len - offset) != XED_ERROR_NONE) {
            offset += 1;    // resync exactly as the scan proper does
            continue;
        }
        size_t next = offset + xed_decoded_inst_get_length(&xedd);
        // A nonzero branch-displacement width marks every direct relative
        // transfer (jmp/jcc rel8/rel32, call rel32, loop/jrcxz); indirect
        // forms carry none.
        if (xed_decoded_inst_get_branch_displacement_width_bits(&xedd) != 0) {
            int64_t target = (int64_t) next +
                xed_decoded_inst_get_branch_displacement(&xedd);
            if (target >= 0 && (uint64_t) target < (uint64_t) len) {
                targets[target >> 3] |= (uint8_t) (1u << (target & 7));
            }
        }
        offset = next;
    }
    return targets;
}

// True when any collected direct branch target lands in [lo, hi) -- for a
// multi-instruction window, the offsets after its head. Conservatively true
// when the map failed to allocate.
static bool branch_target_in(const uint8_t *targets, size_t lo, size_t hi)
{
    if (targets == NULL) {
        return true;
    }
    for (size_t t = lo; t < hi; ++t) {
        if (targets[t >> 3] & (1u << (t & 7))) {
            return true;
        }
    }
    return false;
}

// An instruction the redundant-TEST fold may look through on its way to the
// test. Both halves of the pattern have to survive it: the flags the producer
// left, and the value the test would read.
//
// So it must write no flag -- a write, "undefined" per the SDM, or a
// conditional one (a shift by CL writes none for a masked count of zero, but
// may), all replace what the producer set, leaving the test no longer a
// duplicate of it -- and must not write the tested register at any width. It
// must not transfer control either, since the fold reasons about one
// straight-line path.
//
// Reading either is fine, and is where this parts company with
// apx_ndd_gap_independent, which rejects any mention of its destination: an
// instruction that reads the flags reads the producer's both before and after
// the test is dropped, and one that reads the register (a store spilling it,
// say) leaves the value the test would have seen. Neither can tell the
// difference, and both are common enough between a compare and its branch to
// be worth looking through -- a store sits in one of the go sites this
// window was measured on.
static bool flags_gap_transparent(const xed_decoded_inst_t *gap,
                                  xed_reg_enum_t dest_enc)
{
    xed_category_enum_t category = xed_decoded_inst_get_category(gap);
    if (category == XED_CATEGORY_CALL ||
        category == XED_CATEGORY_RET ||
        category == XED_CATEGORY_UNCOND_BR ||
        category == XED_CATEGORY_COND_BR ||
        category == XED_CATEGORY_SYSCALL ||
        category == XED_CATEGORY_SYSRET ||
        category == XED_CATEGORY_INTERRUPT) {
        return false;
    }

    const xed_simple_flag_t *fi = xed_decoded_inst_get_rflags_info(gap);
    if (fi != NULL &&
        (flag_set_to_mask(xed_simple_flag_get_written_flag_set(fi)) |
         flag_set_to_mask(xed_simple_flag_get_undefined_flag_set(fi))) != 0) {
        return false;
    }

    const xed_inst_t *xi = xed_decoded_inst_inst(gap);
    unsigned nops = xed_inst_noperands(xi);
    for (unsigned i = 0; i < nops; ++i) {
        const xed_operand_t *operand = xed_inst_operand(xi, i);
        xed_operand_enum_t name = xed_operand_name(operand);
        // The memory-addressing names carry the stack-pointer updates, which
        // XED reports nowhere else: push writes RSP through BASE0.
        if ((!xed_operand_is_register(name) &&
             !xed_operand_is_memory_addressing_register(name)) ||
            !xed_operand_written(operand)) {
            continue;
        }
        if (xed_get_largest_enclosing_register(
                xed_decoded_inst_get_reg(gap, name)) == dest_enc) {
            return false;
        }
    }
    return true;
}

static bool flags_test_redundant(const uint8_t *inst, size_t len,
                                 const uint8_t *branch_targets,
                                 size_t after_producer,
                                 const xed_decoded_inst_t *producer,
                                 xed_decoded_inst_t *test_out,
                                 size_t *test_offset_out)
{
    uint32_t divergent;
    switch (xed_decoded_inst_get_iclass(producer)) {
    case XED_ICLASS_AND:
    case XED_ICLASS_OR:
    case XED_ICLASS_XOR:
        divergent = 0;
        break;
    case XED_ICLASS_ADD:
    case XED_ICLASS_SUB:
    case XED_ICLASS_ADC:
    case XED_ICLASS_SBB:
    case XED_ICLASS_NEG:
    case XED_ICLASS_INC:
    case XED_ICLASS_DEC:
        divergent = FLAG_CF | FLAG_OF;
        break;
    default:
        return false;
    }

    // The ALU's destination must be a register (skip add [mem], reg and the
    // like): the written register operand, which for these iclasses is the
    // first operand when it is not memory. A memory-destination form has no
    // written GPR at all and would otherwise leave the suppressed RFLAGS
    // operand in `dest`, so the class test is what rejects it.
    xed_reg_enum_t dest = XED_REG_INVALID;
    const xed_inst_t *xi = xed_decoded_inst_inst(producer);
    unsigned nops = xed_inst_noperands(xi);
    for (unsigned i = 0; i < nops; ++i) {
        const xed_operand_t *op = xed_inst_operand(xi, i);
        xed_operand_enum_t name = xed_operand_name(op);
        if (xed_operand_is_register(name) && xed_operand_written(op)) {
            dest = xed_decoded_inst_get_reg(producer, name);
            break;
        }
    }
    if (dest == XED_REG_INVALID || xed_reg_class(dest) != XED_REG_CLASS_GPR) {
        return false;
    }
    xed_reg_enum_t dest_enc = xed_get_largest_enclosing_register(dest);

    // test dest, dest, found within the shared window. The register must match
    // the producer's exactly, not merely enclose it: and eax, ebx clears bits
    // 63:32, so test rax, rax reads a sign bit the narrower test never sees.
    size_t cur = after_producer;
    for (int slot = 0; slot < APX_NDD_WINDOW - 1; ++slot) {
        if (cur >= len) {
            return false;
        }
        decode_init(test_out);
        if (xed_decode(test_out, inst + cur, len - cur) != XED_ERROR_NONE) {
            return false;
        }
        size_t after = cur + xed_decoded_inst_get_length(test_out);

        if (xed_decoded_inst_get_iclass(test_out) != XED_ICLASS_TEST ||
            xed_decoded_inst_number_of_memory_operands(test_out) > 0 ||
            xed_decoded_inst_get_reg(test_out, XED_OPERAND_REG0) != dest ||
            xed_decoded_inst_get_reg(test_out, XED_OPERAND_REG1) != dest) {
            // Not the test: an instruction the fold may look through if it
            // leaves the flags and the tested value alone.
            if (!flags_gap_transparent(test_out, dest_enc)) {
                return false;
            }
            cur = after;
            continue;
        }

        // An incoming direct edge onto any looked-through instruction or onto
        // the test reaches it without the producer, whose flags the rewrite
        // relies on; dropping the test would break that path.
        if (branch_target_in(branch_targets, after_producer, after)) {
            return false;
        }

        // Arithmetic producers diverge from the test on CF/OF; suppress while
        // either might still be read past the test.
        if (divergent != 0 && flags_live_after(inst, len, after, divergent)) {
            return false;
        }
        *test_offset_out = cur;
        return true;
    }
    return false;
}

// Multi-instruction peephole, the shift sibling of flags_test_redundant. A
// SHL/SHR/SAR of a register whose count is statically nonzero -- an immediate
// whose masked value (& 63 for 64-bit operands, & 31 otherwise) is not zero,
// or the by-one D0/D1 forms -- sets SF/ZF/PF from its result exactly as
// test reg, reg on that register would, so the test recomputes flags the
// shift already produced:
//
//   shl rax, 1 ; test rax, rax ; jne L   ->   shl rax, 1 ; jne L
//
// The general fold excludes shifts because a CL or masked-to-zero count
// writes no flags (see flags_test_redundant); a statically nonzero count
// closes exactly that hole. The SDM defines SF/ZF/PF "according to the
// result" for every nonzero masked count (oversized counts included), so
// those three duplicate the test's unconditionally. The divergence is CF/OF:
// the test clears both where the shift leaves CF = the last bit shifted out
// (undefined for oversized counts) and OF defined only for count 1 -- so, as
// with the arithmetic producers, CF and OF must be dead past the test.
//
// Unlike the arithmetic producers, the dominant real-world consumer is a
// branch: rustc/LLVM emit shl rax, 1 ; test rax, rax ; jne for libstd's
// panic-counter check (x & ~(1 << 63)) == 0 -- X86ISelDAGToDAG's
// immediate-TEST shrink builds the SHL behind the shl-to-add pattern's back,
// and LLVM's compare peephole refuses shift counts 1-3 to keep the SHL
// convertible to LEA, leaving hundreds of dead tests in ordinary Rust
// binaries. The straight-line CF/OF walk is conservative at any branch, so
// that consumer gets the cmp_one_branch_foldable treatment instead: when the
// instruction after the test is a Jcc reading neither CF nor OF (JZ/JNZ,
// JS/JNS, JP/JNP), both successors are walked (an out-of-buffer target is
// conservatively rejected). Any other follower takes the straight-line walk.
// Every walk here uses the call-kills reading (flags_live_after_ext): flags
// do not survive a call in either ABI -- the argument the walk's RET case
// already rests on -- and the panic-counter branch targets the cold-path
// call directly, so the conservative reading would suppress the very shape
// this fold exists for.
// No guard is needed against an edge onto the Jcc itself: the Jcc is not
// rewritten, and a path that jumps straight to it never executed the test,
// so its flags arrive unchanged either way.
//
// Register destinations only (the CL form carries CL in REG1 and is not
// statically nonzero, cf. check_shl_one; a memory destination produces no
// register for the test to read). Rotates are no producers -- ROL/ROR write
// only CF/OF, never SF/ZF/PF -- and SHLD/SHRD are left out: an oversized
// count leaves their result undefined, not merely their CF. The test must
// match the shift's register at its exact width, may sit past
// flags_gap_transparent instructions within the shared window, and no direct
// edge may enter between producer and test. Reported at the test, the
// removable instruction. Composes with check_shl_one: shl reg, 1 ->
// add reg, reg preserves every flag this fold reasons about, so both
// rewrites apply together (add rax, rax ; jne).
static bool shift_test_redundant(const uint8_t *inst, size_t len,
                                 const uint8_t *branch_targets,
                                 size_t after_producer,
                                 const xed_decoded_inst_t *producer,
                                 xed_decoded_inst_t *test_out,
                                 size_t *test_offset_out)
{
    switch (xed_decoded_inst_get_iclass(producer)) {
    case XED_ICLASS_SHL:
    case XED_ICLASS_SHR:
    case XED_ICLASS_SAR:
        break;
    default:
        return false;
    }
    if (xed_decoded_inst_number_of_memory_operands(producer) > 0) {
        return false;
    }
    xed_reg_enum_t dest = xed_decoded_inst_get_reg(producer, XED_OPERAND_REG0);
    if (xed_reg_class(dest) != XED_REG_CLASS_GPR) {
        return false;
    }
    // The CL-count form carries the count register as REG1 (cf.
    // check_shl_one); its runtime count may mask to zero, writing no flags.
    if (xed_decoded_inst_get_reg(producer, XED_OPERAND_REG1) == XED_REG_CL) {
        return false;
    }
    // The D0/D1 forms encode a count of 1 implicitly; the C0/C1 forms carry
    // an imm8 the hardware masks to 6 bits for 64-bit operands and 5
    // otherwise. Only a nonzero masked count writes SF/ZF/PF.
    uint64_t count = 1;
    if (xed_operand_values_has_immediate(
            xed_decoded_inst_operands_const(producer))) {
        count = xed_decoded_inst_get_unsigned_immediate(producer);
    }
    unsigned width = xed_decoded_inst_get_operand_width(producer);
    if ((count & (width == 64 ? 63 : 31)) == 0) {
        return false;
    }
    xed_reg_enum_t dest_enc = xed_get_largest_enclosing_register(dest);

    // test dest, dest within the shared window, past transparent gaps --
    // exactly as in flags_test_redundant.
    size_t cur = after_producer;
    for (int slot = 0; slot < APX_NDD_WINDOW - 1; ++slot) {
        if (cur >= len) {
            return false;
        }
        decode_init(test_out);
        if (xed_decode(test_out, inst + cur, len - cur) != XED_ERROR_NONE) {
            return false;
        }
        size_t after = cur + xed_decoded_inst_get_length(test_out);

        if (xed_decoded_inst_get_iclass(test_out) != XED_ICLASS_TEST ||
            xed_decoded_inst_number_of_memory_operands(test_out) > 0 ||
            xed_decoded_inst_get_reg(test_out, XED_OPERAND_REG0) != dest ||
            xed_decoded_inst_get_reg(test_out, XED_OPERAND_REG1) != dest) {
            if (!flags_gap_transparent(test_out, dest_enc)) {
                return false;
            }
            cur = after;
            continue;
        }

        // An incoming direct edge past the producer reaches the test without
        // the shift's flags.
        if (branch_target_in(branch_targets, after_producer, after)) {
            return false;
        }

        // CF/OF diverge and must be dead past the test. A directly following
        // Jcc that reads neither gets the both-successors walk (cf.
        // cmp_one_branch_foldable); anything else the straight-line walk,
        // conservative at branches. All three walks use the call-kills
        // reading: flags do not survive a call in either ABI, and the
        // motivating consumer branches straight to a cold-path call.
        if (after < len) {
            xed_decoded_inst_t jcc;
            decode_init(&jcc);
            if (xed_decode(&jcc, inst + after, len - after) ==
                    XED_ERROR_NONE) {
                switch (xed_decoded_inst_get_iclass(&jcc)) {
                case XED_ICLASS_JZ:
                case XED_ICLASS_JNZ:
                case XED_ICLASS_JS:
                case XED_ICLASS_JNS:
                case XED_ICLASS_JP:
                case XED_ICLASS_JNP: {
                    size_t fall = after + xed_decoded_inst_get_length(&jcc);
                    if (flags_live_after_ext(inst, len, fall,
                                             FLAG_CF | FLAG_OF, true)) {
                        return false;
                    }
                    int64_t target = (int64_t) fall +
                        xed_decoded_inst_get_branch_displacement(&jcc);
                    if (target < 0 || (uint64_t) target >= (uint64_t) len ||
                        flags_live_after_ext(inst, len, (size_t) target,
                                             FLAG_CF | FLAG_OF, true)) {
                        return false;
                    }
                    *test_offset_out = cur;
                    return true;
                }
                default:
                    break;
                }
            }
        }
        if (flags_live_after_ext(inst, len, after, FLAG_CF | FLAG_OF, true)) {
            return false;
        }
        *test_offset_out = cur;
        return true;
    }
    return false;
}

// The full-register analogue of reg_upper32_live_after: walk forward from
// `offset` to decide whether the 64-bit GPR `reg64` is live -- read in whole or
// in part before being fully overwritten. Returns true (LIVE) on yes or
// unknown; a caller proving a value dead before dropping the instruction that
// produced it suppresses its finding when this returns true. Where
// reg_upper32_live_after counts only reads of the 64-bit name (which alone
// observe bits 63:32), this counts a read of any sub-register (al/ax/eax/rax),
// since the whole value is at stake.
//
// Returns false (DEAD) only on an unconditional 32- or 64-bit write
// (reg_kill_iclass) with no intervening read: such a write replaces the entire
// value (a 32-bit write zero-extends). 8- and 16-bit writes leave the upper bits
// intact and are not kills. Conservative LIVE on decode error, any control
// transfer (RET included -- the value may escape as a return or callee-saved
// register), running out of input, or the lookahead bound.
static bool reg_live_after(const uint8_t *inst, size_t len, size_t offset,
                           xed_reg_enum_t reg64)
{
    const int MAX_LOOKAHEAD = 16;

    for (int step = 0; step < MAX_LOOKAHEAD && offset < len; ++step) {
        xed_decoded_inst_t xedd;
        decode_init(&xedd);
        if (xed_decode(&xedd, inst + offset, len - offset) != XED_ERROR_NONE) {
            return true;
        }

        // A read of any sub-register of reg64 -- an explicit or implicit
        // operand, or a memory base or index -- observes part of the value.
        const xed_inst_t *xi = xed_decoded_inst_inst(&xedd);
        unsigned nops = xed_inst_noperands(xi);
        for (unsigned i = 0; i < nops; ++i) {
            const xed_operand_t *op = xed_inst_operand(xi, i);
            xed_operand_enum_t name = xed_operand_name(op);
            if (xed_operand_is_register(name) && xed_operand_read(op) &&
                xed_get_largest_enclosing_register(
                    xed_decoded_inst_get_reg(&xedd, name)) == reg64) {
                return true;
            }
        }
        int nmem = xed_decoded_inst_number_of_memory_operands(&xedd);
        for (int m = 0; m < nmem; ++m) {
            xed_reg_enum_t b = xed_decoded_inst_get_base_reg(&xedd, m);
            xed_reg_enum_t x = xed_decoded_inst_get_index_reg(&xedd, m);
            if ((b != XED_REG_INVALID &&
                 xed_get_largest_enclosing_register(b) == reg64) ||
                (x != XED_REG_INVALID &&
                 xed_get_largest_enclosing_register(x) == reg64)) {
                return true;
            }
        }

        xed_category_enum_t category = xed_decoded_inst_get_category(&xedd);
        if (category == XED_CATEGORY_CALL ||
            category == XED_CATEGORY_RET ||
            category == XED_CATEGORY_UNCOND_BR ||
            category == XED_CATEGORY_COND_BR ||
            category == XED_CATEGORY_SYSCALL ||
            category == XED_CATEGORY_SYSRET ||
            category == XED_CATEGORY_INTERRUPT) {
            return true;
        }

        // An unconditional 32- or 64-bit write replaces the whole value: DEAD.
        if (reg_kill_iclass(xed_decoded_inst_get_iclass(&xedd))) {
            for (unsigned i = 0; i < nops; ++i) {
                const xed_operand_t *op = xed_inst_operand(xi, i);
                xed_operand_enum_t name = xed_operand_name(op);
                if (!xed_operand_is_register(name) || !xed_operand_written(op)) {
                    continue;
                }
                xed_reg_enum_t wr = xed_decoded_inst_get_reg(&xedd, name);
                if (xed_get_largest_enclosing_register(wr) == reg64 &&
                    xed_get_register_width_bits64(wr) >= 32) {
                    return false;
                }
            }
        }

        offset += xed_decoded_inst_get_length(&xedd);
    }

    return true;
}

// Multi-instruction peephole. lea reg, [addr] materializes an address in reg; if
// the next instruction uses reg as the base of its one memory operand and reg is
// dead afterward, the address arithmetic folds into that operand's own
// base + index*scale + disp form and the lea disappears -- x86's rich addressing
// does, for free in the consumer's AGU, the math the lea did:
//
//   lea rax, [rdi + rsi*4] ; mov ecx, [rax]      -> mov ecx, [rdi + rsi*4]
//   lea rax, [rdi + rsi*4] ; mov ecx, [rax + 8]  -> mov ecx, [rdi + rsi*4 + 8]
//   lea rax, [rbx + 8]     ; mov rax, [rax]       -> mov rax, [rbx + 8]
//
// `lea` is the already-decoded instruction ending at `consumer_offset`; the
// function returns true when the pair folds, and the caller reports against the
// lea (the removable instruction). A simple lea reg, [base] also draws
// check_lea_to_mov's separate "suboptimal LEA" finding.
//
// Encodability. The fold substitutes the lea's base_L + index_L*scale_L + disp_L
// for reg in the consumer's base + index*scale + disp, so the result must still
// fit one base, one index*scale, and one disp32: at most one of the lea and the
// consumer may carry an index (two would need two index slots), and
// disp_L + disp_M must stay within signed 32 bits. RIP-relative and 32-bit-
// address forms don't compose into a downstream 64-bit base and are rejected.
//
// Soundness. Removing the lea drops reg's definition, so reg must be dead once
// the consumer stops referencing it. reg must therefore appear in the consumer
// ONLY as the memory base -- never as the index, and never read as a data
// operand (the add rax, [rax] accumulator case, where reg stays live after the
// base folds away). Its value is then dead if the consumer fully overwrites reg
// (mov rax, [rax]) or, failing that, if reg_live_after shows it dead past the
// consumer (mov ecx, [rax] with rax unused after). Within one instruction the
// base is read before the destination is written, so aliasing such as
// lea rax, [rbx] ; mov rbx, [rax] -> mov rbx, [rbx] stays correct. A non-default
// segment on the consumer is skipped as a needless complication.
static bool lea_foldable_into_memop(const uint8_t *inst, size_t len,
                                    const uint8_t *branch_targets,
                                    size_t consumer_offset,
                                    const xed_decoded_inst_t *lea)
{
    if (xed_decoded_inst_get_iclass(lea) != XED_ICLASS_LEA) {
        return false;
    }

    // The address register we hope to eliminate must be a 64-bit GPR so it can
    // serve as a memory base downstream.
    xed_reg_enum_t dest = xed_decoded_inst_get_reg(lea, XED_OPERAND_REG0);
    if (xed_reg_class(dest) != XED_REG_CLASS_GPR ||
        xed_get_register_width_bits64(dest) != 64) {
        return false;
    }

    // The lea's address components must be 64-bit GPRs or absent; RIP-relative
    // (register class IP) and 32-bit-address (GPR32) forms fail this test.
    xed_reg_enum_t base_l = xed_decoded_inst_get_base_reg(lea, 0);
    xed_reg_enum_t index_l = xed_decoded_inst_get_index_reg(lea, 0);
    if (base_l != XED_REG_INVALID &&
        (xed_reg_class(base_l) != XED_REG_CLASS_GPR ||
         xed_get_register_width_bits64(base_l) != 64)) {
        return false;
    }
    if (index_l != XED_REG_INVALID &&
        (xed_reg_class(index_l) != XED_REG_CLASS_GPR ||
         xed_get_register_width_bits64(index_l) != 64)) {
        return false;
    }

    // Decode the consumer; it must have exactly one memory operand based on
    // dest, with dest not also its index and no fs/gs override.
    if (consumer_offset >= len) {
        return false;
    }
    xed_decoded_inst_t consumer;
    decode_init(&consumer);
    if (xed_decode(&consumer, inst + consumer_offset, len - consumer_offset) !=
            XED_ERROR_NONE) {
        return false;
    }
    if (xed_decoded_inst_number_of_memory_operands(&consumer) != 1 ||
        xed_decoded_inst_get_base_reg(&consumer, 0) != dest ||
        xed_decoded_inst_get_index_reg(&consumer, 0) == dest) {
        return false;
    }
    xed_reg_enum_t seg = xed_decoded_inst_get_seg_reg(&consumer, 0);
    if (seg == XED_REG_FS || seg == XED_REG_GS) {
        return false;
    }

    // An incoming direct edge onto the consumer reaches it without the lea;
    // folding the address into it would break that path.
    if (branch_target_in(branch_targets, consumer_offset,
            consumer_offset + xed_decoded_inst_get_length(&consumer))) {
        return false;
    }

    // A control-transfer consumer (jmp/call through [dest]) does not fall
    // through to the linear next instruction, so the deadness walk below would
    // read the wrong bytes; leave those alone.
    xed_category_enum_t cat = xed_decoded_inst_get_category(&consumer);
    if (cat == XED_CATEGORY_CALL || cat == XED_CATEGORY_RET ||
        cat == XED_CATEGORY_UNCOND_BR || cat == XED_CATEGORY_COND_BR ||
        cat == XED_CATEGORY_SYSCALL || cat == XED_CATEGORY_SYSRET ||
        cat == XED_CATEGORY_INTERRUPT) {
        return false;
    }

    // At most one index between the two, and the displacements sum within 32
    // signed bits.
    if (index_l != XED_REG_INVALID &&
        xed_decoded_inst_get_index_reg(&consumer, 0) != XED_REG_INVALID) {
        return false;
    }
    int64_t disp = xed_decoded_inst_get_memory_displacement(lea, 0) +
                   xed_decoded_inst_get_memory_displacement(&consumer, 0);
    if (disp < INT32_MIN || disp > INT32_MAX) {
        return false;
    }

    // dest must appear only as the base: never read as a data operand (else it
    // stays live after the base folds away). Note whether the consumer fully
    // overwrites it.
    const xed_inst_t *xi = xed_decoded_inst_inst(&consumer);
    unsigned nops = xed_inst_noperands(xi);
    bool writes_dest = false;
    for (unsigned i = 0; i < nops; ++i) {
        const xed_operand_t *op = xed_inst_operand(xi, i);
        xed_operand_enum_t name = xed_operand_name(op);
        if (!xed_operand_is_register(name) ||
            xed_get_largest_enclosing_register(
                xed_decoded_inst_get_reg(&consumer, name)) != dest) {
            continue;
        }
        if (xed_operand_read(op)) {
            return false;
        }
        if (xed_operand_written(op) &&
            xed_get_register_width_bits64(
                xed_decoded_inst_get_reg(&consumer, name)) >= 32) {
            writes_dest = true;
        }
    }

    // dest's address value must be dead after the fold: overwritten by the
    // consumer, or unread downstream.
    if (writes_dest) {
        return true;
    }
    size_t after = consumer_offset + xed_decoded_inst_get_length(&consumer);
    return !reg_live_after(inst, len, after, dest);
}

// Multi-instruction peephole. mov reg, imm loads a constant; when the next
// instruction uses reg as the source operand of an add/sub/adc/sbb/and/or/xor/
// cmp/test/mov and reg is dead afterward, the constant folds into that
// instruction's own immediate field and the mov disappears:
//
//   mov ecx, 5  ; add eax, ecx  -> add eax, 5
//   mov ecx, 5  ; cmp eax, ecx  -> cmp eax, 5
//   mov rcx, -1 ; and rax, rcx  -> and rax, -1
//
// `mov_const` is the already-decoded producer ending at `consumer_offset`; on a
// match the function returns true and the caller reports against the mov, the
// removable instruction.
//
// Soundness. The immediate form of each of these ops computes the identical
// result and flags as the register form -- only the source encoding differs --
// so there is no value or flag concern beyond reg's own liveness. reg must
// appear in the consumer only as the folded source (XED presents operands in
// Intel order, so that is operand 1, read-only) and nowhere else -- not the
// destination or first source, not a memory base or index -- so removing the mov
// erases its every use. The constant must encode as the consumer's immediate:
// below 64 bits the same-width field holds any value, while a 64-bit non-mov op
// sign-extends an imm32, so a movabs source (a full imm64) folds only when its
// value fits signed 32 bits -- a sign-extended-imm32 source always does, and mov
// itself can spell any width via movabs. imm == 0 is skipped: folding it yields
// an add reg, 0 / and reg, 0 that other checks own. reg is finally required dead
// past the consumer (reg_live_after), since the fold drops its definition.
static bool mov_const_foldable(const uint8_t *inst, size_t len,
                               const uint8_t *branch_targets,
                               size_t consumer_offset,
                               const xed_decoded_inst_t *mov_const)
{
    if (xed_decoded_inst_get_iclass(mov_const) != XED_ICLASS_MOV ||
        xed_decoded_inst_number_of_memory_operands(mov_const) > 0 ||
        !xed_operand_values_has_immediate(
            xed_decoded_inst_operands_const(mov_const))) {
        return false;
    }
    xed_reg_enum_t reg = xed_decoded_inst_get_reg(mov_const, XED_OPERAND_REG0);
    if (xed_reg_class(reg) != XED_REG_CLASS_GPR ||
        xed_decoded_inst_get_unsigned_immediate(mov_const) == 0) {
        return false;
    }

    if (consumer_offset >= len) {
        return false;
    }
    xed_decoded_inst_t consumer;
    decode_init(&consumer);
    if (xed_decode(&consumer, inst + consumer_offset, len - consumer_offset) !=
            XED_ERROR_NONE) {
        return false;
    }
    xed_iclass_enum_t cic = xed_decoded_inst_get_iclass(&consumer);
    switch (cic) {
    case XED_ICLASS_ADD:
    case XED_ICLASS_SUB:
    case XED_ICLASS_ADC:
    case XED_ICLASS_SBB:
    case XED_ICLASS_AND:
    case XED_ICLASS_OR:
    case XED_ICLASS_XOR:
    case XED_ICLASS_CMP:
    case XED_ICLASS_TEST:
    case XED_ICLASS_MOV:
        break;
    default:
        return false;
    }

    // An incoming direct edge onto the consumer reaches it without the mov;
    // folding the constant into it would break that path.
    if (branch_target_in(branch_targets, consumer_offset,
            consumer_offset + xed_decoded_inst_get_length(&consumer))) {
        return false;
    }

    // The folded source is operand 1 (Intel order: op0 is the destination or
    // first source, op1 the second source), which must be the read-only
    // register reg.
    const xed_inst_t *xi = xed_decoded_inst_inst(&consumer);
    unsigned nops = xed_inst_noperands(xi);
    if (nops < 2) {
        return false;
    }
    const xed_operand_t *src = xed_inst_operand(xi, 1);
    xed_operand_enum_t src_name = xed_operand_name(src);
    if (!xed_operand_is_register(src_name) || xed_operand_written(src) ||
        xed_decoded_inst_get_reg(&consumer, src_name) != reg) {
        return false;
    }

    // reg must appear nowhere else -- not the kept operand, not a memory base or
    // index -- so the fold erases its only use.
    xed_reg_enum_t reg_enc = xed_get_largest_enclosing_register(reg);
    for (unsigned i = 0; i < nops; ++i) {
        if (i == 1) {
            continue;
        }
        const xed_operand_t *op = xed_inst_operand(xi, i);
        xed_operand_enum_t name = xed_operand_name(op);
        if (xed_operand_is_register(name) &&
            xed_get_largest_enclosing_register(
                xed_decoded_inst_get_reg(&consumer, name)) == reg_enc) {
            return false;
        }
    }
    int nmem = xed_decoded_inst_number_of_memory_operands(&consumer);
    for (int m = 0; m < nmem; ++m) {
        xed_reg_enum_t b = xed_decoded_inst_get_base_reg(&consumer, m);
        xed_reg_enum_t x = xed_decoded_inst_get_index_reg(&consumer, m);
        if ((b != XED_REG_INVALID &&
             xed_get_largest_enclosing_register(b) == reg_enc) ||
            (x != XED_REG_INVALID &&
             xed_get_largest_enclosing_register(x) == reg_enc)) {
            return false;
        }
    }

    // A 64-bit consumer sign-extends an imm32; a full imm64 constant (movabs,
    // immediate width 64) folds only when it fits that -- EXCEPT a mov to a
    // register, whose imm64 movabs form holds any value. A mov to memory takes
    // only imm32 like every other memory form, so an imm64 constant does not
    // fold into it. (get_signed_immediate truncates a 64-bit immediate, so read
    // it unsigned and range-check.)
    bool reg_dest_mov = cic == XED_ICLASS_MOV &&
        xed_decoded_inst_number_of_memory_operands(&consumer) == 0;
    if (xed_decoded_inst_get_operand_width(&consumer) == 64 && !reg_dest_mov &&
        xed_decoded_inst_get_immediate_width_bits(mov_const) == 64) {
        int64_t v = (int64_t) xed_decoded_inst_get_unsigned_immediate(mov_const);
        if (v < INT32_MIN || v > INT32_MAX) {
            return false;
        }
    }

    // reg's constant value must be dead after the fold.
    size_t after = consumer_offset + xed_decoded_inst_get_length(&consumer);
    return !reg_live_after(inst, len, after, reg_enc);
}

// Multi-instruction peephole. A narrow load followed by a sign- or zero-
// extension of the loaded register is a single extending load; the separate mov
// disappears, and with it a partial-register write that can stall a later
// full-register read:
//
//   mov al, [rsi]  ; movzx eax, al   -> movzx eax, byte [rsi]
//   mov ax, [rsi]  ; movsx eax, ax   -> movsx eax, word [rsi]
//   mov ebx, [rsi] ; movsxd rbx, ebx -> movsxd rbx, [rsi]
//
// `load` is the already-decoded producer ending at `ext_offset`; on a match the
// function returns true and the caller reports against the load, the removable
// instruction.
//
// Soundness needs no liveness scan. The extension must widen the loaded register
// IN PLACE -- its register source is exactly the load's destination and its own
// destination is the same register family -- so the extension's full-width write
// overwrites the load's narrow write (and any prior upper bits). The register
// therefore ends identical whether or not the load runs, and the memory is read
// once at the same width and address either way (MMIO-safe). The in-place
// requirement is essential: mov al, [rsi] ; movzx ecx, al writes ECX, leaving
// RAX's low byte unset once the load is dropped, so it does not fold. The exact
// source match also keeps the fold correct when the loaded register addresses
// the load (mov al, [rax] ; movzx eax, al): with the mov gone the extension
// reads [rax] at rax's pre-mov value, the very address the mov used.
static bool load_foldable_into_extend(const uint8_t *inst, size_t len,
                                      const uint8_t *branch_targets,
                                      size_t ext_offset,
                                      const xed_decoded_inst_t *load)
{
    // Producer: mov reg, [mem] -- a GPR loaded from a single memory source at
    // 8/16/32 bits (64 has nothing to extend into).
    if (xed_decoded_inst_get_iclass(load) != XED_ICLASS_MOV ||
        xed_decoded_inst_number_of_memory_operands(load) != 1 ||
        !xed_decoded_inst_mem_read(load, 0) ||
        xed_decoded_inst_mem_written(load, 0)) {
        return false;
    }
    xed_reg_enum_t dest = xed_decoded_inst_get_reg(load, XED_OPERAND_REG0);
    if (xed_reg_class(dest) != XED_REG_CLASS_GPR) {
        return false;
    }
    unsigned w = xed_get_register_width_bits64(dest);
    if (w != 8 && w != 16 && w != 32) {
        return false;
    }

    // Consumer: movzx/movsx/movsxd whose register source is exactly dest and
    // whose destination is the same register family (an in-place widening).
    if (ext_offset >= len) {
        return false;
    }
    xed_decoded_inst_t ext;
    decode_init(&ext);
    if (xed_decode(&ext, inst + ext_offset, len - ext_offset) !=
            XED_ERROR_NONE) {
        return false;
    }
    switch (xed_decoded_inst_get_iclass(&ext)) {
    case XED_ICLASS_MOVZX:
    case XED_ICLASS_MOVSX:
    case XED_ICLASS_MOVSXD:
        break;
    default:
        return false;
    }
    if (xed_decoded_inst_number_of_memory_operands(&ext) != 0 ||
        xed_decoded_inst_get_reg(&ext, XED_OPERAND_REG1) != dest) {
        return false;
    }
    // An incoming direct edge onto the extension reaches it without the load;
    // folding the load into it would break that path.
    if (branch_target_in(branch_targets, ext_offset,
            ext_offset + xed_decoded_inst_get_length(&ext))) {
        return false;
    }
    return xed_get_largest_enclosing_register(
               xed_decoded_inst_get_reg(&ext, XED_OPERAND_REG0)) ==
           xed_get_largest_enclosing_register(dest);
}

// Window support for the copy folds below -- mov_add_foldable_to_lea and
// the APX NDD fold share this proof and the APX_NDD_WINDOW bound: may the
// scan look through `gap` -- is it provably independent of deleting the
// copy? Deleting the
// mov changes exactly two things: the copy's register no longer holds the
// source's value while `gap` runs, and the op reads the source at its own
// position rather than the mov's. So `gap` must not touch the copy's
// register in any width or role (a read would see the stale value; a
// write means the op consumes gap's result, not the copy -- and a partial
// write like shr cl, 5 under mov ecx, eax is a write), must not write the
// source, and must not transfer control (a call conservatively does all
// of the above, and any branch changes which code runs between the two).
// Everything else is independent: flag reads and writes (the mov is
// flag-transparent, so deleting it moves nothing relative to any flag
// producer or consumer), loads, and stores -- even to memory the op then
// loads, which both shapes read at the op's own position. Register
// operands are walked through XED's full template, implicit and
// suppressed ones included (cdqe writes rax without naming it), plus the
// memory base and index registers, which are reads; every comparison is
// by largest enclosing register, so aliases at any width count.
// Pseudo-registers (RFLAGS, RIP, STACKPUSH) never equal a GPR family and
// pass through.
static bool apx_ndd_gap_independent(const xed_decoded_inst_t *gap,
                                    xed_reg_enum_t dst_enc,
                                    xed_reg_enum_t src_enc)
{
    xed_category_enum_t category = xed_decoded_inst_get_category(gap);
    if (category == XED_CATEGORY_CALL ||
        category == XED_CATEGORY_RET ||
        category == XED_CATEGORY_UNCOND_BR ||
        category == XED_CATEGORY_COND_BR ||
        category == XED_CATEGORY_SYSCALL ||
        category == XED_CATEGORY_SYSRET ||
        category == XED_CATEGORY_INTERRUPT) {
        return false;
    }

    const xed_inst_t *xi = xed_decoded_inst_inst(gap);
    unsigned nops = xed_inst_noperands(xi);
    for (unsigned i = 0; i < nops; ++i) {
        const xed_operand_t *operand = xed_inst_operand(xi, i);
        xed_operand_enum_t name = xed_operand_name(operand);
        if (!xed_operand_is_register(name)) {
            continue;
        }
        xed_reg_enum_t enc = xed_get_largest_enclosing_register(
            xed_decoded_inst_get_reg(gap, name));
        if (enc == dst_enc ||
            (enc == src_enc && xed_operand_written(operand))) {
            return false;
        }
    }
    int nmem = xed_decoded_inst_number_of_memory_operands(gap);
    for (int m = 0; m < nmem; ++m) {
        if (xed_get_largest_enclosing_register(
                xed_decoded_inst_get_base_reg(gap, m)) == dst_enc ||
            xed_get_largest_enclosing_register(
                xed_decoded_inst_get_index_reg(gap, m)) == dst_enc) {
            return false;
        }
    }
    return true;
}

// Multi-instruction peephole. mov dest, srcA followed by an add into dest
// computes srcA + addend into dest; lea does the same in one instruction --
// the non-destructive three-operand add -- saving the mov. The addend may be a
// register or an immediate (inc/dec are add/sub by an implied 1):
//
//   mov edx, esi ; add edx, edi  ->  lea edx, [rsi + rdi]
//   mov edx, esi ; add edx, 5    ->  lea edx, [rsi + 5]
//   mov rdx, rsi ; sub rdx, 8    ->  lea rdx, [rsi - 8]
//   mov edx, esi ; inc edx       ->  lea edx, [rsi + 1]
//
// `mov_rr` is the already-decoded producer ending at `add_offset`; on a match
// the function returns true and the caller reports against the mov, the start of
// the pair.
//
// The consumer need not be adjacent: the search shares the APX NDD fold's
// window (APX_NDD_WINDOW, x86lint.h) and its independence proof -- each
// instruction looked through must neither touch dest in any width or role,
// nor write srcA, whose value the lea reads later than the mov captured
// it, nor transfer control (see apx_ndd_gap_independent above). A direct
// branch onto any looked-through instruction or onto the consumer reaches
// code that expects the copy done, so the widened span suppresses it.
// Sharing the window keeps the division of labor with the APX NDD fold
// exact at every distance: that check claims these pairs while the flags
// live, this one while they die.
//
// Soundness. lea reproduces the sum but writes no flags, so the finding is
// suppressed while any flag the consumer writes may be read: every arithmetic
// flag for add/sub, and every one but CF for inc/dec, which -- exactly like
// lea -- leave CF untouched (so a following adc gates the sub 1 form but not
// the dec form). srcA must differ from dest (srcA == dest makes the mov a
// self-move, check_mov_self's finding), and a register addend must too:
// add dest, dest would double the value the mov just wrote, which the fold,
// reading dest's pre-mov value, would get wrong. dest, srcA, and the addend
// share a width from the mov and its consumer; the lea addresses through the
// enclosing 64-bit registers, exact because low-width arithmetic is closed (a
// 32- or 16-bit pair folds too). An immediate addend becomes the lea
// displacement, negated for sub/dec: a 16/32-bit lea truncates the address to
// the destination width, so any immediate folds mod 2^w, while a 64-bit pair
// uses the displacement at full value and must fit signed 32 bits --
// everything but sub rdx, INT32_MIN, whose negation disp32 cannot hold.
// add/sub dest, 0 is left to check_add_sub_zero: the mov alone already
// computes the result (cf. mov_const_foldable's imm == 0 skip). The
// unencodable forms are excluded: an 8-bit pair, since LEA has no byte-width
// destination (8D encodes r16/r32/r64 only), and [rsp + rsp], since RSP is
// not a legal SIB index (a lone RSP base with a displacement encodes fine).
static bool mov_add_foldable_to_lea(const uint8_t *inst, size_t len,
                                    const uint8_t *branch_targets,
                                    size_t add_offset,
                                    const xed_decoded_inst_t *mov_rr)
{
    // Producer: mov dest, srcA -- register to register.
    if (xed_decoded_inst_get_iclass(mov_rr) != XED_ICLASS_MOV ||
        xed_decoded_inst_number_of_memory_operands(mov_rr) != 0 ||
        xed_operand_values_has_immediate(
            xed_decoded_inst_operands_const(mov_rr))) {
        return false;
    }
    xed_reg_enum_t dest = xed_decoded_inst_get_reg(mov_rr, XED_OPERAND_REG0);
    xed_reg_enum_t src_a = xed_decoded_inst_get_reg(mov_rr, XED_OPERAND_REG1);
    if (xed_reg_class(dest) != XED_REG_CLASS_GPR ||
        xed_reg_class(src_a) != XED_REG_CLASS_GPR) {
        return false;
    }
    // LEA has no byte-width destination, so an 8-bit pair (mov al, bl ;
    // add al, cl) has no single-LEA rewrite. dest's width is the pair's:
    // the add's destination must match it exactly below.
    if (xed_get_register_width_bits64(dest) == 8) {
        return false;
    }
    xed_reg_enum_t dest_enc = xed_get_largest_enclosing_register(dest);
    if (xed_get_largest_enclosing_register(src_a) == dest_enc) {
        return false;
    }

    // Consumer: an add into the same dest -- add dest, srcB, add/sub dest,
    // imm, or inc/dec dest (add/sub by an implied 1) -- found within the
    // shared window.
    xed_reg_enum_t src_a_enc = xed_get_largest_enclosing_register(src_a);
    size_t cur = add_offset;
    for (int slot = 0; slot < APX_NDD_WINDOW - 1; ++slot) {
        if (cur >= len) {
            return false;
        }
        xed_decoded_inst_t add;
        decode_init(&add);
        if (xed_decode(&add, inst + cur, len - cur) != XED_ERROR_NONE) {
            return false;
        }
        size_t after = cur + xed_decoded_inst_get_length(&add);

        xed_iclass_enum_t cic = xed_decoded_inst_get_iclass(&add);
        uint32_t divergent;
        switch (cic) {
        case XED_ICLASS_ADD:
        case XED_ICLASS_SUB:
            divergent = FLAG_ARITH;
            break;
        case XED_ICLASS_INC:
        case XED_ICLASS_DEC:
            // inc/dec leave CF untouched exactly as lea does, so only the
            // flags they do write can diverge.
            divergent = FLAG_ARITH & ~FLAG_CF;
            break;
        default:
            divergent = 0;
            break;
        }
        if (divergent == 0 ||
            xed_decoded_inst_number_of_memory_operands(&add) != 0 ||
            xed_decoded_inst_get_reg(&add, XED_OPERAND_REG0) != dest) {
            // Not the consumer: an instruction the fold may look through if
            // it proves independence; otherwise -- it touches dest, writes
            // srcA, or transfers control -- there is no fold.
            if (!apx_ndd_gap_independent(&add, dest_enc, src_a_enc)) {
                return false;
            }
            cur = after;
            continue;
        }

        // An incoming direct edge onto any looked-through instruction or
        // onto the consumer reaches it without the mov -- the canonical
        // scan loop enters at its increment (mov rbx, rax ; L: add rbx, 1 ;
        // ... ; je L), where the fold would turn the increment into a
        // per-iteration reset. Suppress.
        if (branch_target_in(branch_targets, add_offset, after)) {
            return false;
        }

        if (cic == XED_ICLASS_ADD &&
            !xed_operand_values_has_immediate(
                xed_decoded_inst_operands_const(&add))) {
            // Register addend: add dest, srcB -> lea dest, [srcA + srcB].
            xed_reg_enum_t src_b = xed_decoded_inst_get_reg(&add,
                XED_OPERAND_REG1);
            if (xed_reg_class(src_b) != XED_REG_CLASS_GPR ||
                xed_get_largest_enclosing_register(src_b) == dest_enc) {
                return false;
            }
            // [rsp + rsp] cannot be encoded: RSP is not a legal SIB index.
            if (src_a_enc == XED_REG_RSP &&
                xed_get_largest_enclosing_register(src_b) == XED_REG_RSP) {
                return false;
            }
        } else {
            // Immediate addend: add/sub dest, imm or inc/dec dest ->
            // lea dest, [srcA + disp], the displacement negated for
            // sub/dec.
            int64_t disp;
            if (cic == XED_ICLASS_INC) {
                disp = 1;
            } else if (cic == XED_ICLASS_DEC) {
                disp = -1;
            } else {
                if (!xed_operand_values_has_immediate(
                        xed_decoded_inst_operands_const(&add))) {
                    // sub dest, srcB: lea cannot subtract a register.
                    return false;
                }
                int64_t imm = xed_decoded_inst_get_signed_immediate(&add);
                if (imm == 0) {
                    return false;   // the add/sub is check_add_sub_zero's
                }
                disp = (cic == XED_ICLASS_SUB) ? -imm : imm;
            }
            // A 16/32-bit lea truncates the address to the destination
            // width, so any immediate folds mod 2^w; a 64-bit pair uses the
            // displacement at full value, which must fit disp32 --
            // everything but the negation of sub rdx, INT32_MIN.
            if (xed_get_register_width_bits64(dest) == 64 &&
                (disp < INT32_MIN || disp > INT32_MAX)) {
                return false;
            }
        }

        // lea writes no flags; suppress while any flag the consumer sets
        // diverges -- i.e. may be read before being overwritten.
        return !flags_live_after(inst, len, after, divergent);
    }
    return false;
}

// Multi-instruction peephole. shl reg, k followed by sar reg, k on the same
// register shifts the low m = width - k bits to the top and arithmetic-shifts
// them back: it sign-extends the low m bits in place. When m is a register
// boundary -- 8, 16, or 32 -- a single movsx (movsxd for the 32 -> 64 case)
// computes the same value at half the bytes, replacing a two-shift dependency
// chain with one uop; shr instead of sar is the zero-extending twin, a movzx
// (for 32 -> 64: mov reg32, reg32, whose write zero-extends):
//
//   shl eax, 24 ; sar eax, 24   ->   movsx eax, al
//   shl rax, 32 ; sar rax, 32   ->   movsxd rax, eax
//   shl eax, 24 ; shr eax, 24   ->   movzx eax, al
//
// `shl` is the already-decoded producer ending at `sar_offset`; on a match the
// function returns true and the caller reports against the shl, the head of
// the pair.
//
// Soundness. The replacement writes the same register at the same width (the
// 32-bit forms zero-extend the enclosing register alike), so no register gate
// is needed, and it reads the same low m bits the pair read. But movsx/movzx
// write no flags where the second shift set CF and SF/ZF/PF from the result
// (OF is undefined at these counts, AF always), so the finding is gated on
// the arithmetic flags being dead past the pair -- and, like every
// multi-instruction window, on no direct edge entering at the second shift.
// Both counts must be exactly width - m with m in {8, 16, 32}: every count in
// that set is below the hardware's 5/6-bit count mask, so the raw immediate
// is the effective count (an over-encoded count that masks into range is left
// unmatched, a false negative only). A mismatched or off-boundary count
// computes something movsx cannot. Only the immediate forms match (a CL count
// is not statically knowable, cf. check_shift_zero) and only register
// destinations: a memory pair would need a load-extend-store rewrite with a
// different access pattern.
static bool shift_pair_foldable_to_extend(const uint8_t *inst, size_t len,
                                          const uint8_t *branch_targets,
                                          size_t sar_offset,
                                          const xed_decoded_inst_t *shl)
{
    if (xed_decoded_inst_get_iclass(shl) != XED_ICLASS_SHL ||
        xed_decoded_inst_number_of_memory_operands(shl) != 0 ||
        !xed_operand_values_has_immediate(
            xed_decoded_inst_operands_const(shl))) {
        return false;
    }
    xed_reg_enum_t reg = xed_decoded_inst_get_reg(shl, XED_OPERAND_REG0);
    if (xed_reg_class(reg) != XED_REG_CLASS_GPR) {
        return false;
    }
    unsigned width = xed_get_register_width_bits64(reg);
    uint64_t count = xed_decoded_inst_get_unsigned_immediate(shl);
    if (count == 0 || count >= width) {
        return false;
    }
    unsigned m = width - (unsigned) count;
    if (m != 8 && m != 16 && m != 32) {
        return false;
    }

    // Consumer: sar (sign) or shr (zero) of the same register by the same
    // count.
    if (sar_offset >= len) {
        return false;
    }
    xed_decoded_inst_t sar;
    decode_init(&sar);
    if (xed_decode(&sar, inst + sar_offset, len - sar_offset) !=
            XED_ERROR_NONE) {
        return false;
    }
    xed_iclass_enum_t cic = xed_decoded_inst_get_iclass(&sar);
    if (cic != XED_ICLASS_SAR && cic != XED_ICLASS_SHR) {
        return false;
    }
    if (xed_decoded_inst_number_of_memory_operands(&sar) != 0 ||
        xed_decoded_inst_get_reg(&sar, XED_OPERAND_REG0) != reg ||
        !xed_operand_values_has_immediate(
            xed_decoded_inst_operands_const(&sar)) ||
        xed_decoded_inst_get_unsigned_immediate(&sar) != count) {
        return false;
    }

    // An incoming direct edge onto the second shift reaches it without the
    // first; the fold would break that path.
    size_t after = sar_offset + xed_decoded_inst_get_length(&sar);
    if (branch_target_in(branch_targets, sar_offset, after)) {
        return false;
    }

    // movsx/movzx write no flags; the second shift's must be dead.
    return !flags_live_after(inst, len, after, FLAG_ARITH);
}

// Multi-instruction peephole. cmp reg, 1 followed by jb or jae branches on the
// unsigned comparison against 1 -- but unsigned "< 1" is exactly "== 0" and
// ">= 1" is "!= 0", conditions test reg, reg answers one byte shorter (two for
// an imm32-encoded cmp; the re-spelled branch is the same length):
//
//   cmp eax, 1 ; jb L    ->   test eax, eax ; jz L
//   cmp rcx, 1 ; jae L   ->   test rcx, rcx ; jnz L
//
// `cmp` is the already-decoded instruction ending at `jcc_offset`; on a match
// the function returns true and the caller reports against the cmp, the head
// of the pair. This is check_cmp_zero's conditional sibling: cmp reg, 0 is
// flag-exact under test and needs no gate, while cmp reg, 1 preserves only the
// branch DECISION, not the flags.
//
// Soundness. jb reads CF = (reg < 1 unsigned) = (reg == 0); after
// test reg, reg, jz reads ZF = (reg == 0): the taken/fall-through decision is
// identical for every value of reg, with no assumption about how reg was
// produced (jae/jnz likewise, negated). What changes is the residual flags
// past the branch: cmp leaves ZF = (reg == 1), CF from the borrow, and
// SF/OF/PF/AF from reg - 1, where test leaves CF = OF = 0 and ZF/SF/PF from
// reg. So every arithmetic flag must be dead on BOTH successors, each scanned
// with flags_live_after exactly as in redundant_test_after_setcc (an
// out-of-buffer target is conservatively rejected). An incoming direct edge
// onto the branch arrives expecting jb-on-CF semantics the rewritten jz does
// not reproduce, so the window guard rejects it; an edge onto the cmp executes
// the whole rewritten pair and is fine. Only jb/jae qualify: ja and jbe fold
// ZF into the condition (a comparison against 2), and the signed conditions
// answer a different question.
//
// AL is excluded: cmp al, 1 via the 3c ib accumulator opcode is already 2
// bytes, tying test al, al (cf. check_cmp_zero; its modrm form is
// check_implicit_register's finding). Memory operands are excluded: there is
// no test [mem], [mem] to shrink to (also as in check_cmp_zero). The
// immediate is matched at the effective operand width.
static bool cmp_one_branch_foldable(const uint8_t *inst, size_t len,
                                    const uint8_t *branch_targets,
                                    size_t jcc_offset,
                                    const xed_decoded_inst_t *cmp)
{
    if (xed_decoded_inst_get_iclass(cmp) != XED_ICLASS_CMP ||
        xed_decoded_inst_number_of_memory_operands(cmp) > 0 ||
        !xed_operand_values_has_immediate(
            xed_decoded_inst_operands_const(cmp))) {
        return false;
    }
    if (xed_decoded_inst_get_reg(cmp, XED_OPERAND_REG0) == XED_REG_AL) {
        return false;
    }

    unsigned width = xed_decoded_inst_get_operand_width(cmp);
    uint64_t opmask = (width >= 64) ? UINT64_MAX : (((uint64_t) 1 << width) - 1);
    uint64_t eff = (uint64_t) (int64_t)
        xed_decoded_inst_get_signed_immediate(cmp) & opmask;
    if (eff != 1) {
        return false;
    }

    // The consumer: jb (taken iff reg == 0 -> jz) or jae (-> jnz).
    if (jcc_offset >= len) {
        return false;
    }
    xed_decoded_inst_t jcc;
    decode_init(&jcc);
    if (xed_decode(&jcc, inst + jcc_offset, len - jcc_offset) !=
            XED_ERROR_NONE) {
        return false;
    }
    xed_iclass_enum_t jc = xed_decoded_inst_get_iclass(&jcc);
    if (jc != XED_ICLASS_JB && jc != XED_ICLASS_JNB) {
        return false;
    }

    // An incoming direct edge onto the branch expects the jb/jae reading of
    // the cmp's flags, which the rewritten jz/jnz does not reproduce.
    size_t fall = jcc_offset + xed_decoded_inst_get_length(&jcc);
    if (branch_target_in(branch_targets, jcc_offset, fall)) {
        return false;
    }

    // The residual flags differ in every arithmetic flag; both successors
    // must have them dead (cf. redundant_test_after_setcc).
    if (flags_live_after(inst, len, fall, FLAG_ARITH)) {
        return false;
    }
    int64_t target = (int64_t) fall +
        xed_decoded_inst_get_branch_displacement(&jcc);
    if (target < 0 || (uint64_t) target >= (uint64_t) len) {
        return false;
    }
    return !flags_live_after(inst, len, (size_t) target, FLAG_ARITH);
}

// Multi-instruction peephole (three instructions). setcc X ; test X, X ; je/jne
// materializes a condition into a byte register and then branches on that
// register -- but SETcc writes no flags, so the flags the branch needs are the
// ones the preceding compare already left in place. The intervening test merely
// recomputes ZF = (X == 0), the negated condition those flags still hold, so the
// test is redundant: branch on the flags directly.
//
//   setb r11b ; test r11b, r11b ; je L   ->   setb r11b ; jae L
//   setz al   ; test al, al     ; jne L  ->   setz al   ; jnz L
//
// (The setcc stays when X is live and is dropped when X is dead; either way the
// test goes.) `setcc` is the already-decoded instruction ending at
// `test_offset`; on a match the function returns true and the caller reports
// against the setcc, the head of the sequence.
//
// Soundness. je/jne read ZF alone. After test X, X, ZF = (X == 0) = (cc false),
// so je L is j(not cc) and jne L is j(cc) -- exactly the branch the compare
// flags support. setcc preserves those flags and nothing sits between the two,
// so branching on them reproduces the control flow for ANY prior flags value; no
// assumption about the compare is needed. The one state the rewrite changes is
// the flags left live PAST the branch: test leaves ZF set with CF/OF cleared and
// SF/PF from X, whereas the compare's flags now flow through instead. These can
// differ in any arithmetic flag, so every one must be dead on BOTH successors --
// the fall-through and the taken target. A direct je/jne's target is a known
// offset (read from the displacement, not assumed), so both are scanned with
// flags_live_after; a target outside the section is unscannable and
// conservatively rejected. Register liveness does not gate the finding: X is
// untouched by the rewrite, so the sequence is suboptimal whether or not X is
// live. Only exact-width test X, X matches (REG0 == REG1 == the setcc's byte
// register); a wider test eax, eax after setcc al would depend on the upper bits
// of X, which this three-instruction window cannot show are zero. Only je (JZ)
// and jne (JNZ) match: after test X, X they read ZF alone, where the negation is
// exact; the other conditions fold in the always-clear SF/OF/CF and are skipped.
static bool redundant_test_after_setcc(const uint8_t *inst, size_t len,
                                       const uint8_t *branch_targets,
                                       size_t test_offset,
                                       const xed_decoded_inst_t *setcc)
{
    if (xed_decoded_inst_get_category(setcc) != XED_CATEGORY_SETCC) {
        return false;
    }
    xed_reg_enum_t x = xed_decoded_inst_get_reg(setcc, XED_OPERAND_REG0);
    if (xed_reg_class(x) != XED_REG_CLASS_GPR) {
        return false;   // setcc to memory has no register destination
    }

    // test X, X.
    if (test_offset >= len) {
        return false;
    }
    xed_decoded_inst_t test;
    decode_init(&test);
    if (xed_decode(&test, inst + test_offset, len - test_offset) !=
            XED_ERROR_NONE ||
        xed_decoded_inst_get_iclass(&test) != XED_ICLASS_TEST ||
        xed_decoded_inst_number_of_memory_operands(&test) > 0 ||
        xed_decoded_inst_get_reg(&test, XED_OPERAND_REG0) != x ||
        xed_decoded_inst_get_reg(&test, XED_OPERAND_REG1) != x) {
        return false;
    }

    // je (JZ) or jne (JNZ).
    size_t jcc_offset = test_offset + xed_decoded_inst_get_length(&test);
    if (jcc_offset >= len) {
        return false;
    }
    xed_decoded_inst_t jcc;
    decode_init(&jcc);
    if (xed_decode(&jcc, inst + jcc_offset, len - jcc_offset) !=
            XED_ERROR_NONE) {
        return false;
    }
    xed_iclass_enum_t jc = xed_decoded_inst_get_iclass(&jcc);
    if (jc != XED_ICLASS_JZ && jc != XED_ICLASS_JNZ) {
        return false;
    }

    // An incoming direct edge onto the test or the branch reaches them without
    // the setcc; dropping the test and flipping the branch's condition would
    // break such a path (it arrives expecting the original je/jne on X).
    size_t fall = jcc_offset + xed_decoded_inst_get_length(&jcc);
    if (branch_target_in(branch_targets, test_offset, fall)) {
        return false;
    }

    // Dropping the test replaces its residual flags with the compare's on both
    // successors, so every arithmetic flag must be dead on each: the
    // fall-through and the taken target.
    if (flags_live_after(inst, len, fall, FLAG_ARITH)) {
        return false;
    }
    int64_t target = (int64_t) fall +
        xed_decoded_inst_get_branch_displacement(&jcc);
    if (target < 0 || (uint64_t) target >= (uint64_t) len) {
        return false;
    }
    return !flags_live_after(inst, len, (size_t) target, FLAG_ARITH);
}

// Multi-instruction peephole (advisory). setcc into a byte register
// immediately widened into its own 32/64-bit parent builds a boolean the
// long way around:
//
//   setz al ; movzx eax, al
//
// Intel's preferred form zeroes the register ahead of the flag-setting
// instruction -- xor eax, eax ; cmp ... ; setz al -- dropping the movzx and
// the partial-register merge it exists to paper over: the setcc's byte write
// merges into the stale parent, and the movzx spends a uop re-reading that
// merge (Intel optimization manual, the SETcc dependency-breaking
// recommendation).
//
// Advisory, unlike the window rewrites above: the xor belongs upstream of
// the flag-setting instruction, outside this window, where a peephole can
// prove neither the register free nor the xor's flag clobber dead. The
// sequence is reported as suboptimal with no verified replacement --
// missing LOCK's precedent -- so no liveness gate applies. Under -m apx
// the same match stops being advisory: the zero-upper setcc (EVEX ND=1)
// writes the 0/1 result zero-extended to 64 bits itself, reading the same
// condition flags, so the dispatcher reports the pair as the exact
// missing-SETZU fold instead. Matched tightly so each finding is the real
// idiom:
//
//   * low-byte setcc destination only: under the xor form the result lives
//     in the low byte, so a high-byte destination (setz ah) is a different
//     value position;
//   * movzx destination of 32 or 64 bits, which zero to bit 63 alike (the
//     32-bit write zero-extends) -- exactly the state the xor form
//     establishes; a 16-bit movzx (movzx ax, al) leaves bits 16-63 the xor
//     form would zero;
//   * the same register only (movzx eax, al): extending into a different
//     register is a real move, not a widening idiom;
//   * no incoming direct edge onto the movzx: that path's byte was set by
//     something other than this setcc, and zeroing upstream of the setcc
//     proves nothing for it.
//
// `setcc` is the already-decoded instruction ending at `movzx_offset`; on a
// match the movzx is decoded into *movzx_out and the caller reports at
// movzx_offset, the instruction the preferred form removes.
static bool setcc_movzx_zero_extend(const uint8_t *inst, size_t len,
                                    const uint8_t *branch_targets,
                                    size_t movzx_offset,
                                    const xed_decoded_inst_t *setcc,
                                    xed_decoded_inst_t *movzx_out)
{
    if (xed_decoded_inst_get_category(setcc) != XED_CATEGORY_SETCC) {
        return false;
    }
    xed_reg_enum_t byte_reg = xed_decoded_inst_get_reg(setcc, XED_OPERAND_REG0);
    if (xed_reg_class(byte_reg) != XED_REG_CLASS_GPR) {
        return false;   // setcc to memory has no register destination
    }
    switch (byte_reg) {
    case XED_REG_AH:
    case XED_REG_CH:
    case XED_REG_DH:
    case XED_REG_BH:
        return false;
    default:
        break;
    }

    // movzx (r32|r64), byte_reg into the same enclosing register.
    if (movzx_offset >= len) {
        return false;
    }
    decode_init(movzx_out);
    if (xed_decode(movzx_out, inst + movzx_offset, len - movzx_offset) !=
            XED_ERROR_NONE ||
        xed_decoded_inst_get_iclass(movzx_out) != XED_ICLASS_MOVZX ||
        xed_decoded_inst_number_of_memory_operands(movzx_out) > 0 ||
        xed_decoded_inst_get_reg(movzx_out, XED_OPERAND_REG1) != byte_reg) {
        return false;
    }
    unsigned width = xed_decoded_inst_get_operand_width(movzx_out);
    if (width != 32 && width != 64) {
        return false;
    }
    xed_reg_enum_t dst = xed_decoded_inst_get_reg(movzx_out, XED_OPERAND_REG0);
    if (xed_get_largest_enclosing_register(dst) !=
            xed_get_largest_enclosing_register(byte_reg)) {
        return false;
    }

    return !branch_target_in(branch_targets, movzx_offset,
        movzx_offset + xed_decoded_inst_get_length(movzx_out));
}

// Multi-instruction peephole (BMI1): NOT feeding a register AND of the same
// destination,
//
//   not eax ; and eax, ecx   ->   andn eax, eax, ecx
//
// ANDN computes ~src1 & src2 in one instruction, reading src1's original
// value, so the pair collapses exactly: both forms write only the
// destination, and a 32-bit write zero-extends either way. The flag delta is
// Multi-instruction peephole. SETcc writes 0 or 1, so exclusive-oring it with
// 1 inverts a boolean the complementary condition code produces outright:
//
//   setz al ; xor al, 1  ->  setnz al
//
// The XOR disappears. Every condition code has a complement, so the rewrite
// always exists and the check need not enumerate them; the finding is
// reported at the SETcc, where the replacement lands.
//
// Soundness. SETcc writes no flags and the XOR writes all the arithmetic ones,
// so dropping it leaves whatever the compare feeding the SETcc set, and the
// finding is gated on those being dead past the pair. The destination must be
// the same byte register in both, matched exactly: `setz al ; xor eax, 1`
// inverts the same bit but writes eax, zero-extending into bits 63:8 where
// setnz al leaves them alone, and proving those dead is a separate question
// from the one this check answers. Memory destinations are excluded for the
// same reason the pair is required to be adjacent -- see below.
//
// Adjacency. Unlike the other window peepholes here this one does not scan:
// the pair is a single emitted idiom, and a gap could neither read the
// destination (it would observe the value before inversion, which the rewrite
// inverts earlier) nor write it, which leaves almost nothing a gap could be.
// The measured population is adjacent.
static bool setcc_xor_one_invertible(const uint8_t *inst, size_t len,
                                     const uint8_t *branch_targets,
                                     size_t xor_offset,
                                     const xed_decoded_inst_t *setcc,
                                     xed_decoded_inst_t *xor_out)
{
    if (xed_decoded_inst_get_category(setcc) != XED_CATEGORY_SETCC ||
        xed_decoded_inst_number_of_memory_operands(setcc) != 0) {
        return false;
    }
    xed_reg_enum_t dest = xed_decoded_inst_get_reg(setcc, XED_OPERAND_REG0);
    if (xed_reg_class(dest) != XED_REG_CLASS_GPR ||
        xed_get_register_width_bits64(dest) != 8) {
        return false;
    }

    if (xor_offset >= len) {
        return false;
    }
    decode_init(xor_out);
    if (xed_decode(xor_out, inst + xor_offset, len - xor_offset) !=
            XED_ERROR_NONE) {
        return false;
    }
    if (xed_decoded_inst_get_iclass(xor_out) != XED_ICLASS_XOR ||
        xed_decoded_inst_number_of_memory_operands(xor_out) != 0 ||
        xed_decoded_inst_get_operand_width(xor_out) != 8 ||
        xed_decoded_inst_get_reg(xor_out, XED_OPERAND_REG0) != dest) {
        return false;
    }
    if (xed_decoded_inst_get_immediate_width_bits(xor_out) == 0 ||
        xed_decoded_inst_get_unsigned_immediate(xor_out) != 1) {
        return false;
    }

    // An incoming direct edge onto the XOR reaches it without the SETcc, so it
    // would invert whatever else arrived in the register.
    size_t after = xor_offset + xed_decoded_inst_get_length(xor_out);
    if (branch_target_in(branch_targets, xor_offset, after)) {
        return false;
    }
    return !flags_live_after(inst, len, after, FLAG_ARITH);
}

// PF alone -- both clear CF/OF and set SF/ZF from the same result, but AND
// defines PF where ANDN leaves it undefined -- so the fold is suppressed
// while PF may be read downstream (AF is untracked, and both leave it
// undefined anyway).
//
// Not matched:
//   * immediate masks (and eax, 0xf): ANDN has no immediate form, so the
//     mask would need its own register and instruction -- no fold;
//   * a different AND destination (not ecx ; and ebx, ecx): the original
//     leaves ~ecx behind, which the fold would not compute, and proving that
//     value dead needs register liveness this tool does not track;
//   * a same-register source (not eax ; and eax, eax): andn eax, eax, eax
//     computes ~x & x = 0 where the pair computes ~x;
//   * memory operands on either side, and 8/16-bit widths (ANDN is 32/64
//     only). The exact REG0 match also forces equal operand widths.
//
// `not_insn` is the already-decoded instruction ending at `and_offset`; the
// caller reports at the NOT, where the pair collapses to the single ANDN. A
// direct branch onto the AND reaches it without the NOT, so the fold is
// suppressed then, as in every window peephole here.
static bool not_and_foldable_to_andn(const uint8_t *inst, size_t len,
                                     const uint8_t *branch_targets,
                                     size_t and_offset,
                                     const xed_decoded_inst_t *not_insn)
{
    if (xed_decoded_inst_get_iclass(not_insn) != XED_ICLASS_NOT ||
        xed_decoded_inst_number_of_memory_operands(not_insn) > 0) {
        return false;
    }
    unsigned width = xed_decoded_inst_get_operand_width(not_insn);
    if (width != 32 && width != 64) {
        return false;
    }
    xed_reg_enum_t dst = xed_decoded_inst_get_reg(not_insn, XED_OPERAND_REG0);
    if (xed_reg_class(dst) != XED_REG_CLASS_GPR) {
        return false;
    }

    if (and_offset >= len) {
        return false;
    }
    xed_decoded_inst_t and_insn;
    decode_init(&and_insn);
    if (xed_decode(&and_insn, inst + and_offset, len - and_offset) !=
            XED_ERROR_NONE ||
        xed_decoded_inst_get_iclass(&and_insn) != XED_ICLASS_AND ||
        xed_decoded_inst_number_of_memory_operands(&and_insn) > 0 ||
        xed_decoded_inst_get_immediate_width_bits(&and_insn) != 0 ||
        xed_decoded_inst_get_reg(&and_insn, XED_OPERAND_REG0) != dst) {
        return false;
    }
    xed_reg_enum_t src = xed_decoded_inst_get_reg(&and_insn, XED_OPERAND_REG1);
    if (xed_reg_class(src) != XED_REG_CLASS_GPR || src == dst) {
        return false;
    }

    size_t after_and = and_offset + xed_decoded_inst_get_length(&and_insn);
    if (flags_live_after(inst, len, after_and, FLAG_PF)) {
        return false;
    }
    return !branch_target_in(branch_targets, and_offset, after_and);
}

// Multi-instruction peephole (BMI1): the clear-lowest-set-bit idiom spelled
// out as a decrement-and-mask,
//
//   lea edx, [rax-1] ; and edx, eax   ->   blsr edx, eax
//
// BLSR computes src & (src-1) in one instruction. The fold is exact for
// value: both forms write only the destination, and the 32-bit-destination /
// 64-bit-base mix is safe because the truncated decrement equals the 32-bit
// decrement (trunc32(rax-1) == (eax-1) mod 2^32). The flag deltas are CF --
// AND clears it, BLSR sets it to (source == 0) -- and PF, which AND defines
// and BLSR leaves undefined; SF/ZF come from the same result value in both,
// and OF is cleared by both. So the fold is suppressed while CF or PF may be
// read downstream.
//
// Not matched:
//   * any other displacement, or an index register: the address is not
//     src-1;
//   * a non-64-bit base: RIP-relative is not a register decrement, and a
//     67-prefixed 32-bit base under a 64-bit destination would zero-extend
//     where BLSR's 64-bit decrement does not;
//   * an AND whose destination is the LEA's base (lea rax's decrement
//     already destroyed the source) or whose destination is not the LEA's
//     (the original leaves rX-1 behind, which the fold would not compute);
//   * memory or immediate AND forms, and 8/16-bit widths (BLSR is 32/64
//     only; the exact REG0 match pins the AND to the LEA's width).
//
// `lea` is the already-decoded instruction ending at `and_offset`; the
// caller reports at the LEA, where the pair collapses to the single BLSR. A
// direct branch onto the AND suppresses, as in every window peephole here.
static bool lea_and_foldable_to_blsr(const uint8_t *inst, size_t len,
                                     const uint8_t *branch_targets,
                                     size_t and_offset,
                                     const xed_decoded_inst_t *lea)
{
    if (xed_decoded_inst_get_iclass(lea) != XED_ICLASS_LEA) {
        return false;
    }
    unsigned width = xed_decoded_inst_get_operand_width(lea);
    if (width != 32 && width != 64) {
        return false;
    }
    xed_reg_enum_t dst = xed_decoded_inst_get_reg(lea, XED_OPERAND_REG0);
    if (xed_reg_class(dst) != XED_REG_CLASS_GPR) {
        return false;
    }
    // The decremented register: a 64-bit GPR base (rejects RIP-relative and
    // 67-prefixed 32-bit bases), no index, displacement exactly -1.
    xed_reg_enum_t base = xed_decoded_inst_get_base_reg(lea, 0);
    if (xed_reg_class(base) != XED_REG_CLASS_GPR ||
        xed_get_register_width_bits64(base) != 64 ||
        xed_decoded_inst_get_index_reg(lea, 0) != XED_REG_INVALID ||
        xed_decoded_inst_get_memory_displacement(lea, 0) != -1) {
        return false;
    }
    if (xed_get_largest_enclosing_register(dst) == base) {
        return false;   // the LEA already destroyed the AND's source
    }

    if (and_offset >= len) {
        return false;
    }
    xed_decoded_inst_t and_insn;
    decode_init(&and_insn);
    if (xed_decode(&and_insn, inst + and_offset, len - and_offset) !=
            XED_ERROR_NONE ||
        xed_decoded_inst_get_iclass(&and_insn) != XED_ICLASS_AND ||
        xed_decoded_inst_number_of_memory_operands(&and_insn) > 0 ||
        xed_decoded_inst_get_immediate_width_bits(&and_insn) != 0 ||
        xed_decoded_inst_get_reg(&and_insn, XED_OPERAND_REG0) != dst) {
        return false;
    }
    xed_reg_enum_t src = xed_decoded_inst_get_reg(&and_insn, XED_OPERAND_REG1);
    if (xed_reg_class(src) != XED_REG_CLASS_GPR ||
        xed_get_largest_enclosing_register(src) != base) {
        return false;
    }

    size_t after_and = and_offset + xed_decoded_inst_get_length(&and_insn);
    if (flags_live_after(inst, len, after_and, FLAG_CF | FLAG_PF)) {
        return false;
    }
    return !branch_target_in(branch_targets, and_offset, after_and);
}

// Multi-instruction peephole (BMI1): the mask-through-lowest-set-bit idiom
// spelled out as a decrement-and-difference,
//
//   lea edx, [rax-1] ; xor edx, eax   ->   blsmsk edx, eax
//
// BLSMSK computes src ^ (src-1) in one instruction: BLSR's idiom with the
// AND swapped for an XOR, so the head-side rules are lea_and_foldable_to_
// blsr's verbatim (displacement exactly -1, no index, 64-bit non-RIP base,
// destination distinct from the base -- the truncated-decrement argument
// for the 32-bit-destination / 64-bit-base mix carries over unchanged). The
// flag deltas are also BLSR's: CF -- XOR clears it, BLSMSK sets it to
// (source == 0) -- and PF, which XOR defines and BLSMSK leaves undefined.
// SF comes from the same result in both, OF is cleared by both, and ZF
// agrees for free: XOR computes it from the result and BLSMSK hardwires it
// to 0, but src ^ (src-1) is never zero (a zero source yields all-ones, any
// other contains its lowest set bit). So the fold is suppressed while CF or
// PF may be read downstream.
//
// `lea` is the already-decoded instruction ending at `xor_offset`; the
// caller reports at the LEA, where the pair collapses to the single BLSMSK.
// A direct branch onto the XOR suppresses, as in every window peephole
// here.
static bool lea_xor_foldable_to_blsmsk(const uint8_t *inst, size_t len,
                                       const uint8_t *branch_targets,
                                       size_t xor_offset,
                                       const xed_decoded_inst_t *lea)
{
    if (xed_decoded_inst_get_iclass(lea) != XED_ICLASS_LEA) {
        return false;
    }
    unsigned width = xed_decoded_inst_get_operand_width(lea);
    if (width != 32 && width != 64) {
        return false;
    }
    xed_reg_enum_t dst = xed_decoded_inst_get_reg(lea, XED_OPERAND_REG0);
    if (xed_reg_class(dst) != XED_REG_CLASS_GPR) {
        return false;
    }
    // The decremented register: a 64-bit GPR base (rejects RIP-relative and
    // 67-prefixed 32-bit bases), no index, displacement exactly -1.
    xed_reg_enum_t base = xed_decoded_inst_get_base_reg(lea, 0);
    if (xed_reg_class(base) != XED_REG_CLASS_GPR ||
        xed_get_register_width_bits64(base) != 64 ||
        xed_decoded_inst_get_index_reg(lea, 0) != XED_REG_INVALID ||
        xed_decoded_inst_get_memory_displacement(lea, 0) != -1) {
        return false;
    }
    if (xed_get_largest_enclosing_register(dst) == base) {
        return false;   // the LEA already destroyed the XOR's source
    }

    if (xor_offset >= len) {
        return false;
    }
    xed_decoded_inst_t xor_insn;
    decode_init(&xor_insn);
    if (xed_decode(&xor_insn, inst + xor_offset, len - xor_offset) !=
            XED_ERROR_NONE ||
        xed_decoded_inst_get_iclass(&xor_insn) != XED_ICLASS_XOR ||
        xed_decoded_inst_number_of_memory_operands(&xor_insn) > 0 ||
        xed_decoded_inst_get_immediate_width_bits(&xor_insn) != 0 ||
        xed_decoded_inst_get_reg(&xor_insn, XED_OPERAND_REG0) != dst) {
        return false;
    }
    xed_reg_enum_t src = xed_decoded_inst_get_reg(&xor_insn, XED_OPERAND_REG1);
    if (xed_reg_class(src) != XED_REG_CLASS_GPR ||
        xed_get_largest_enclosing_register(src) != base) {
        return false;
    }

    size_t after_xor = xor_offset + xed_decoded_inst_get_length(&xor_insn);
    if (flags_live_after(inst, len, after_xor, FLAG_CF | FLAG_PF)) {
        return false;
    }
    return !branch_target_in(branch_targets, xor_offset, after_xor);
}

// Multi-instruction peephole (BMI1, three instructions): the
// isolate-lowest-set-bit idiom, which needs a copy in baseline code because
// x and -x must coexist,
//
//   mov ecx, edi ; neg ecx ; and ecx, edi   ->   blsi ecx, edi
//
// BLSI computes src & -src in one instruction, so the whole triple -- copy
// included -- collapses. The fold is exact for value: both forms write only
// the destination, with the identical result, the source register is
// preserved by both, and a 32-bit write zero-extends in all four
// instructions. The NEG's intermediate flags are unobservable: nothing sits
// between it and the AND, which rewrites every tracked flag (AF is
// untracked; NEG defines it where AND leaves it undefined). The final flag
// deltas are the family's usual pair: CF -- AND clears it, BLSI sets it to
// (source != 0) -- and PF, which AND defines and BLSI leaves undefined;
// SF/ZF come from the same result in both, and OF is cleared by both. So
// the fold is suppressed while CF or PF may be read downstream.
//
// Not matched:
//   * a copy aliasing its source (mov ecx, ecx): the NEG then destroys the
//     original, and the AND computes -x & -x = -x, not x & -x;
//   * an AND whose destination is the source register (and edi, ecx): the
//     original leaves -x behind in the copy, which the fold would not
//     compute, and proving that value dead needs register liveness this
//     tool does not track;
//   * memory or immediate forms in any slot, and 8/16-bit widths (BLSI is
//     32/64 only). The exact REG0/REG1 matches pin all three instructions
//     to one width and one register pair.
//
// `mov` is the already-decoded instruction ending at `neg_offset`; the
// caller reports at the MOV, where the triple collapses to the single
// BLSI. A direct branch onto the NEG or the AND reaches a partial idiom,
// so the fold is suppressed then, as in every window peephole here.
static bool mov_neg_and_foldable_to_blsi(const uint8_t *inst, size_t len,
                                         const uint8_t *branch_targets,
                                         size_t neg_offset,
                                         const xed_decoded_inst_t *mov)
{
    if (xed_decoded_inst_get_iclass(mov) != XED_ICLASS_MOV ||
        xed_decoded_inst_number_of_memory_operands(mov) > 0 ||
        xed_decoded_inst_get_immediate_width_bits(mov) != 0) {
        return false;
    }
    unsigned width = xed_decoded_inst_get_operand_width(mov);
    if (width != 32 && width != 64) {
        return false;
    }
    xed_reg_enum_t dst = xed_decoded_inst_get_reg(mov, XED_OPERAND_REG0);
    xed_reg_enum_t src = xed_decoded_inst_get_reg(mov, XED_OPERAND_REG1);
    if (xed_reg_class(dst) != XED_REG_CLASS_GPR ||
        xed_reg_class(src) != XED_REG_CLASS_GPR || src == dst) {
        return false;
    }

    // neg of the copy.
    if (neg_offset >= len) {
        return false;
    }
    xed_decoded_inst_t neg;
    decode_init(&neg);
    if (xed_decode(&neg, inst + neg_offset, len - neg_offset) !=
            XED_ERROR_NONE ||
        xed_decoded_inst_get_iclass(&neg) != XED_ICLASS_NEG ||
        xed_decoded_inst_number_of_memory_operands(&neg) > 0 ||
        xed_decoded_inst_get_reg(&neg, XED_OPERAND_REG0) != dst) {
        return false;
    }

    // and of the negated copy with the preserved source.
    size_t and_offset = neg_offset + xed_decoded_inst_get_length(&neg);
    if (and_offset >= len) {
        return false;
    }
    xed_decoded_inst_t and_insn;
    decode_init(&and_insn);
    if (xed_decode(&and_insn, inst + and_offset, len - and_offset) !=
            XED_ERROR_NONE ||
        xed_decoded_inst_get_iclass(&and_insn) != XED_ICLASS_AND ||
        xed_decoded_inst_number_of_memory_operands(&and_insn) > 0 ||
        xed_decoded_inst_get_immediate_width_bits(&and_insn) != 0 ||
        xed_decoded_inst_get_reg(&and_insn, XED_OPERAND_REG0) != dst ||
        xed_decoded_inst_get_reg(&and_insn, XED_OPERAND_REG1) != src) {
        return false;
    }

    size_t after_and = and_offset + xed_decoded_inst_get_length(&and_insn);
    if (flags_live_after(inst, len, after_and, FLAG_CF | FLAG_PF)) {
        return false;
    }
    return !branch_target_in(branch_targets, neg_offset, after_and);
}

// The ADD/SUB/INC/DEC division of labor with mov_add_foldable_to_lea,
// seen from that fold's side: it claims a register-headed pair only
// while every flag the op writes is dead after it (lea writes none), so
// this fold takes the exact complement -- the same walk saying LIVE,
// where the NDD form, flag-identical to the legacy op, is the only
// rewrite -- and exactly one of the two claims any pair. A zero
// immediate degenerates the pair (redundant ADD/SUB zero's finding);
// neither fold claims it, matching the LEA fold's own rejection.
static bool apx_ndd_lea_complement(const uint8_t *inst, size_t len,
                                   size_t after,
                                   const xed_decoded_inst_t *op,
                                   uint32_t divergent)
{
    if (xed_decoded_inst_get_immediate_width_bits(op) != 0 &&
        xed_decoded_inst_get_signed_immediate(op) == 0) {
        return false;
    }
    return flags_live_after(inst, len, after, divergent);
}

// The consumer side of the APX NDD fold: does the op at [`after` -
// its length, `after`) destructively consume the copy sitting in `dst`
// (family `dst_enc`; the mov's width `width`) in a shape whose EVEX NDD
// promotion is exact? `load_head` selects the mov rY, [mem] variant,
// whose division of labor differs: ADD, SUB, INC, and DEC belong here
// unconditionally (the LEA fold's head is register-to-register), and the
// op itself may not touch memory -- the head's load is the one memory
// operand an NDD form encodes. The matched-op inventory and every
// rejection are mov_op_foldable_to_apx_ndd's story below; factored out
// so the window scan can try each slot in turn.
static bool apx_ndd_op_consumes_copy(const uint8_t *inst, size_t len,
                                     size_t after,
                                     const xed_decoded_inst_t *op,
                                     xed_reg_enum_t dst,
                                     xed_reg_enum_t dst_enc,
                                     unsigned width, bool load_head)
{
    if (xed_decoded_inst_get_reg(op, XED_OPERAND_REG0) != dst) {
        return false;
    }
    if (load_head && xed_decoded_inst_number_of_memory_operands(op) > 0) {
        return false;
    }

    bool unary = false;
    bool shift = false;
    switch (xed_decoded_inst_get_iclass(op)) {
    case XED_ICLASS_ADD:
        // Register and immediate adds are lea dest, [srcA + addend]:
        // mov_add_foldable_to_lea's finding, needing no extension --
        // while the arithmetic flags die. While they live that fold is
        // suppressed and this one takes the complement. Memory sources,
        // which lea cannot load, and load heads, which its head cannot
        // see, are this fold's at any liveness.
        if (!load_head &&
            xed_decoded_inst_number_of_memory_operands(op) == 0 &&
            !apx_ndd_lea_complement(inst, len, after, op, FLAG_ARITH)) {
            return false;
        }
        break;
    case XED_ICLASS_SUB:
        // sub dest, imm is likewise lea dest, [srcA - imm], under the
        // same complement.
        if (!load_head &&
            xed_decoded_inst_get_immediate_width_bits(op) != 0 &&
            xed_decoded_inst_number_of_memory_operands(op) == 0 &&
            !apx_ndd_lea_complement(inst, len, after, op, FLAG_ARITH)) {
            return false;
        }
        break;
    case XED_ICLASS_INC:
    case XED_ICLASS_DEC:
        // The LEA fold's implied +/-1 forms, which -- like lea -- leave
        // CF untouched, so only the flags they do write divide the labor.
        if (!load_head &&
            !apx_ndd_lea_complement(inst, len, after, op,
                                    FLAG_ARITH & ~FLAG_CF)) {
            return false;
        }
        unary = true;
        break;
    case XED_ICLASS_AND:
    case XED_ICLASS_OR:
    case XED_ICLASS_XOR:
    case XED_ICLASS_ADC:
    case XED_ICLASS_SBB:
        break;
    // CMOVcc after the copy is a select -- rY = cc ? rZ : rX -- and the
    // NDD promotion is exactly a select: the reg-field operand carries
    // the untaken value, the rm or memory operand the taken one, and the
    // destination is written either way (the 32-bit forms zero-extend on
    // a false condition in both shapes, per the SDM). The condition
    // flags are read, never written, and the mov is flag-transparent, so
    // both shapes read the same flags -- even across a flag-writing
    // window gap, which both shapes read identically. Behind a load head
    // the loaded value is the untaken default, which the memory operand's
    // rm slot cannot carry -- but the inverse condition code swaps the
    // roles, and every cc has one, so the fold stands there too. A
    // memory-source cmov loads unconditionally in the legacy and the
    // promoted form alike (conditional faulting is CFCMOV, a different
    // instruction), so the access moves exactly as any other memory
    // source here.
    case XED_ICLASS_CMOVB:
    case XED_ICLASS_CMOVBE:
    case XED_ICLASS_CMOVL:
    case XED_ICLASS_CMOVLE:
    case XED_ICLASS_CMOVNB:
    case XED_ICLASS_CMOVNBE:
    case XED_ICLASS_CMOVNL:
    case XED_ICLASS_CMOVNLE:
    case XED_ICLASS_CMOVNO:
    case XED_ICLASS_CMOVNP:
    case XED_ICLASS_CMOVNS:
    case XED_ICLASS_CMOVNZ:
    case XED_ICLASS_CMOVO:
    case XED_ICLASS_CMOVP:
    case XED_ICLASS_CMOVS:
    case XED_ICLASS_CMOVZ:
        break;
    case XED_ICLASS_IMUL:
        if (xed_decoded_inst_get_iform_enum(op) != XED_IFORM_IMUL_GPRv_GPRv &&
            xed_decoded_inst_get_iform_enum(op) != XED_IFORM_IMUL_GPRv_MEMv) {
            return false;
        }
        break;
    case XED_ICLASS_NEG:
    case XED_ICLASS_NOT:
        unary = true;
        break;
    case XED_ICLASS_SHL:
    case XED_ICLASS_SHR:
    case XED_ICLASS_SAR:
    case XED_ICLASS_ROL:
    case XED_ICLASS_ROR:
        shift = true;
        break;
    default:
        return false;
    }

    if (shift) {
        if (xed_decoded_inst_get_reg(op, XED_OPERAND_REG1) == XED_REG_CL ||
            xed_decoded_inst_get_immediate_width_bits(op) == 0) {
            return false;
        }
        uint64_t count = xed_decoded_inst_get_unsigned_immediate(op);
        if ((count & (width == 64 ? 63 : 31)) == 0) {
            return false;
        }
    } else if (!unary) {
        // A register source must not alias the destination: the folded op
        // would read its stale pre-copy value. (The immediate and memory
        // forms carry RFLAGS in REG1.) The mov's own source may recur --
        // it holds the same value in both shapes.
        xed_reg_enum_t op_src = xed_decoded_inst_get_reg(op,
            XED_OPERAND_REG1);
        if (xed_reg_class(op_src) == XED_REG_CLASS_GPR &&
            xed_get_largest_enclosing_register(op_src) == dst_enc) {
            return false;
        }
    }

    if (xed_decoded_inst_number_of_memory_operands(op) > 0) {
        // A pure load: the write-back forms put their register source in
        // the REG0 slot, so this is what rejects them.
        if (!xed_decoded_inst_mem_read(op, 0) ||
            xed_decoded_inst_mem_written(op, 0)) {
            return false;
        }
        // The address is computed after the mov in the original but with
        // no copy in the folded form, so it must not read the destination.
        xed_reg_enum_t base = xed_decoded_inst_get_base_reg(op, 0);
        if (base != XED_REG_INVALID && base != XED_REG_RIP &&
            (xed_reg_class(base) != XED_REG_CLASS_GPR ||
             xed_get_register_width_bits64(base) != 64 ||
             xed_get_largest_enclosing_register(base) == dst_enc)) {
            return false;
        }
        xed_reg_enum_t index = xed_decoded_inst_get_index_reg(op, 0);
        if (index != XED_REG_INVALID &&
            (xed_reg_class(index) != XED_REG_CLASS_GPR ||
             xed_get_register_width_bits64(index) != 64 ||
             xed_get_largest_enclosing_register(index) == dst_enc)) {
            return false;
        }
    }

    return true;
}

// Multi-instruction peephole (APX): a destructive ALU op consuming a fresh
// copy,
//
//   mov ecx, edi ; sub ecx, esi     ->   sub ecx, edi, esi (EVEX NDD)
//   mov rax, [rbx] ; sub rax, rdi   ->   sub rax, [rbx], rdi
//
// APX promotes the legacy ALU group to EVEX forms with a new data
// destination: the op reads its sources and writes the copy's register
// directly, so the mov -- which exists only because the legacy form
// destroys its first source -- disappears. The copy may equally be a
// plain load: the promoted forms take one memory source in either
// operand order, so the load folds into the op the same way. That shape
// is where the population lives -- a loaded value on the left of a
// non-commutative op (rY = [mem] - rZ) has no legacy single-instruction
// form, which is why compilers emit the pair. The fold is exact with no
// liveness gate at all: each matched op's NDD form sets every flag exactly
// as its legacy twin does on the same source values (XED's APX tables
// carry identical flag records, form for form), and only the destination
// is written, with the identical result -- a 32-bit write zero-extends in
// both shapes. The one flag delta in the family is SBB's AF, which the
// legacy form defines and the NDD record leaves undefined: this tool does
// not track AF (64-bit user code cannot branch on it), and the LEA fold
// above already accepts the same drop.
//
// Matched: SUB, AND, OR, XOR, ADC, SBB, and two-operand IMUL with a
// register, immediate, or memory-load source; CMOVcc, whose promotion is
// a true select of the copy against the moved value (see the switch
// below); NEG and NOT; and
// SHL/SHR/SAR/ROL/ROR by an immediate whose masked count is nonzero --
// the SDM leaves a count-0 shift writing nothing, where the copy's value
// would survive in the original, so only a provably nonzero count keeps
// the two shapes equal (the D1 by-one forms decode as an immediate 1 and
// qualify; a zero immediate is check_shift_rotate_zero's finding anyway).
//
// Not matched:
//   * pairs LEA claims -- register and immediate ADD, immediate SUB, and
//     INC/DEC behind a register head, while every flag the op writes is
//     dead after it: mov_add_foldable_to_lea's finding, which needs no
//     extension. While those flags live, lea (which writes none) cannot
//     fold and the NDD form -- flag-identical to the legacy op -- is the
//     only rewrite, so this fold takes the exact complement of that
//     check's gate: exactly one of the two claims any pair (see
//     apx_ndd_lea_complement). Memory-source ADD, which lea cannot load,
//     and every op behind a load head (the LEA fold's head is
//     register-to-register) are this fold's at any liveness;
//   * a load head that is not a pure modrm load: the moffs absolute
//     forms have no EVEX re-encoding, and a store or read-modify-write
//     mov is not a copy. Its address may use the destination itself --
//     mov rax, [rax] reads the pre-load value in both shapes -- and an
//     op behind a load head may not carry a second memory operand,
//     which no NDD form encodes;
//   * CL-count shifts: under -m bmi2 they are the missing SHLX finding,
//     whose flagless forms are the stronger rewrite, and a runtime count
//     of 0 reaches the SDM carve-out above, where the NDD form's write
//     behavior is not something this tool has verified;
//   * an op source aliasing the destination (sub ecx, ecx after the
//     copy), or a memory source addressed through it (sub rcx, [rcx]):
//     the folded op would read the stale pre-copy value;
//   * memory destinations (and [rax], rcx -- whose register source XED
//     reports in the REG0 slot, so the write-back rejection is what stops
//     it), the one-operand widening IMUL (imul rbx fills rdx:rax and also
//     parks its operand in REG0, but consumes rax, not the copy -- the
//     iform check is what stops it), non-64-bit address registers
//     (67-prefixed, kept out conservatively as in the BLSR family), and
//     8/16-bit widths, as everywhere in this family.
//
// A register-headed consumer need not be adjacent: the search looks
// through up to APX_NDD_WINDOW - 2 intervening instructions (six at the
// default), each of which must prove itself independent of the fold --
// see apx_ndd_gap_independent. The first instruction that fails
// independence must be the consumer or there is no fold, which preserves
// every rejection above at a distance: a consumer shape that fails its
// own guards (shl rY, 0, a CL-count shift, sub rY, rY) reads or writes
// the copy and so stops the scan. Load-headed pairs are the exception:
// they must be adjacent. The fold moves the load -- and any fault it
// takes -- to the op's position, which with nothing between changes no
// value and no ordering, but across a gap would reorder the access and
// its fault against the gap's effects, where deleting a register copy
// moves nothing observable.
//
// `mov` is the already-decoded instruction ending at `op_offset`; the
// caller reports at the MOV, whose removal the finding suggests. A direct
// branch onto any looked-through instruction or onto the op reaches code
// that expects the copy done, so the fold is suppressed then, as in every
// window peephole here.
static bool mov_op_foldable_to_apx_ndd(const uint8_t *inst, size_t len,
                                       const uint8_t *branch_targets,
                                       size_t op_offset,
                                       const xed_decoded_inst_t *mov)
{
    if (xed_decoded_inst_get_iclass(mov) != XED_ICLASS_MOV ||
        xed_decoded_inst_get_immediate_width_bits(mov) != 0) {
        return false;
    }
    unsigned width = xed_decoded_inst_get_operand_width(mov);
    if (width != 32 && width != 64) {
        return false;
    }
    xed_reg_enum_t dst = xed_decoded_inst_get_reg(mov, XED_OPERAND_REG0);
    if (xed_reg_class(dst) != XED_REG_CLASS_GPR) {
        return false;
    }
    xed_reg_enum_t dst_enc = xed_get_largest_enclosing_register(dst);
    xed_reg_enum_t src_enc = XED_REG_INVALID;
    bool load_head = xed_decoded_inst_number_of_memory_operands(mov) > 0;
    if (load_head) {
        // A pure modrm load (cf. mov_bswap_foldable_to_movbe): the moffs
        // absolute forms have no EVEX re-encoding, and a store or
        // read-modify-write head is not a copy. The address may use the
        // destination itself -- both shapes compute it before any write
        // -- but 32-bit (67-prefixed) address registers are kept out
        // conservatively, as on the consumer side.
        if (xed_decoded_inst_number_of_memory_operands(mov) != 1 ||
            !xed_decoded_inst_mem_read(mov, 0) ||
            xed_decoded_inst_mem_written(mov, 0) ||
            !xed_operand_values_has_modrm_byte(
                xed_decoded_inst_operands_const(mov))) {
            return false;
        }
        xed_reg_enum_t base = xed_decoded_inst_get_base_reg(mov, 0);
        if (base != XED_REG_INVALID && base != XED_REG_RIP &&
            (xed_reg_class(base) != XED_REG_CLASS_GPR ||
             xed_get_register_width_bits64(base) != 64)) {
            return false;
        }
        xed_reg_enum_t index = xed_decoded_inst_get_index_reg(mov, 0);
        if (index != XED_REG_INVALID &&
            (xed_reg_class(index) != XED_REG_CLASS_GPR ||
             xed_get_register_width_bits64(index) != 64)) {
            return false;
        }
    } else {
        xed_reg_enum_t src = xed_decoded_inst_get_reg(mov, XED_OPERAND_REG1);
        if (xed_reg_class(src) != XED_REG_CLASS_GPR || src == dst) {
            return false;
        }
        src_enc = xed_get_largest_enclosing_register(src);
    }

    // Scan forward: each slot is either the consumer or a provably
    // independent instruction to look through, up to the window bound --
    // one slot only for a load head, whose access must not move across a
    // gap. The consumer test's exact REG0 match pins the op's width to
    // the mov's and rejects the memory-destination and shift/unary
    // memory forms, whose REG0 is not the destination register.
    int slots = load_head ? 1 : APX_NDD_WINDOW - 1;
    size_t cur = op_offset;
    for (int slot = 0; slot < slots; ++slot) {
        if (cur >= len) {
            return false;
        }
        xed_decoded_inst_t op;
        decode_init(&op);
        if (xed_decode(&op, inst + cur, len - cur) != XED_ERROR_NONE) {
            return false;
        }
        size_t after = cur + xed_decoded_inst_get_length(&op);
        if (apx_ndd_op_consumes_copy(inst, len, after, &op, dst, dst_enc,
                                     width, load_head)) {
            return !branch_target_in(branch_targets, op_offset, after);
        }
        if (!apx_ndd_gap_independent(&op, dst_enc, src_enc)) {
            return false;
        }
        cur = after;
    }
    return false;
}

// Multi-instruction peephole (MOVBE): a load immediately byte-swapped in
// place,
//
//   mov eax, [rsi] ; bswap eax   ->   movbe eax, [rsi]
//
// MOVBE performs the byte-swapping load in one instruction. The fold needs
// no gate at all: none of the three instructions writes any flag, only the
// destination register is written -- with the identical byte-reversed value
// -- and the memory operand is untouched. An address that uses the
// destination (mov rax, [rax]) reads the pre-load value in both forms, and
// a 32-bit write zero-extends in both.
//
// Not matched:
//   * the store direction (bswap rX ; mov [mem], rX): movbe [mem], rX would
//     leave rX un-swapped where the original leaves it swapped, and proving
//     the swapped value dead needs register liveness this tool does not
//     track;
//   * the moffs absolute forms (A1: mov eax, [abs64]), rejected by the
//     modrm requirement -- MOVBE is modrm-only (0F 38 F0), so a 64-bit
//     absolute address has no MOVBE encoding (and the 67-prefixed moffs
//     variant, though encodable via SIB, is the one shape where the fold
//     would grow the code);
//   * 8- and 16-bit widths: MOVBE has no 8-bit form and BSWAP of a 16-bit
//     register is SDM-undefined, so neither side of a narrow pair arises.
// Every modrm addressing mode the load can carry -- RIP-relative, SIB,
// disp32-absolute, segment overrides, r8-r15 -- MOVBE encodes identically.
//
// `mov` is the already-decoded instruction ending at `bswap_offset`; the
// caller reports at the MOV, where the pair collapses to the single MOVBE.
// A direct branch onto the BSWAP reaches it without the load, so the fold
// is suppressed then, as in every window peephole here.
static bool mov_bswap_foldable_to_movbe(const uint8_t *inst, size_t len,
                                        const uint8_t *branch_targets,
                                        size_t bswap_offset,
                                        const xed_decoded_inst_t *mov)
{
    if (xed_decoded_inst_get_iclass(mov) != XED_ICLASS_MOV ||
        xed_decoded_inst_number_of_memory_operands(mov) != 1 ||
        !xed_decoded_inst_mem_read(mov, 0) ||
        xed_decoded_inst_mem_written(mov, 0) ||
        !xed_operand_values_has_modrm_byte(
            xed_decoded_inst_operands_const(mov))) {
        return false;
    }
    unsigned width = xed_decoded_inst_get_operand_width(mov);
    if (width != 32 && width != 64) {
        return false;
    }
    xed_reg_enum_t dst = xed_decoded_inst_get_reg(mov, XED_OPERAND_REG0);
    if (xed_reg_class(dst) != XED_REG_CLASS_GPR) {
        return false;
    }

    if (bswap_offset >= len) {
        return false;
    }
    xed_decoded_inst_t bswap;
    decode_init(&bswap);
    if (xed_decode(&bswap, inst + bswap_offset, len - bswap_offset) !=
            XED_ERROR_NONE ||
        xed_decoded_inst_get_iclass(&bswap) != XED_ICLASS_BSWAP ||
        xed_decoded_inst_get_reg(&bswap, XED_OPERAND_REG0) != dst) {
        return false;
    }

    return !branch_target_in(branch_targets, bswap_offset,
        bswap_offset + xed_decoded_inst_get_length(&bswap));
}

// Single-instruction advisory with a backward suppression. POPCNT, LZCNT,
// and TZCNT treat their destination as an input on affected Intel cores --
// uops.info measures 3 cycles of latency from the destination operand,
// though no core needs the value: POPCNT on Sandy Bridge through Cascade
// Lake, LZCNT/TZCNT through Broadwell -- so a count into a stale register
// serializes behind whatever wrote it last, however unrelated:
//
//   popcnt rax, rdi   -- waits for rax's previous producer
//
// The mitigation gcc and clang emit is a zero idiom just before:
// xor eax, eax ; popcnt rax, rdi. That insertion is invisible in the
// architectural state: the count fully overwrites the destination (dst !=
// src in every flagged form, and a 32-bit write zero-extends), and all
// three unconditionally write or undefine every tracked flag -- POPCNT
// zeroes them all but ZF; LZCNT/TZCNT write CF/ZF and undefine the rest,
// which counts as destroyed here (cf. flags_live_after) -- so nothing
// downstream can see the xor's flag clobber and nothing sits between the
// two to see it either. Advisory nonetheless: adding an instruction is a
// size-for-latency trade on the affected cores, not an equivalence rewrite.
//
// BSF and BSR -- the legacy encodings whose F3 forms LZCNT/TZCNT occupy,
// and what those bytes decode to without decode_init's chip -- are NOT
// flagged, and must never be: their destination dependency is load-bearing.
// With a zero source the SDM leaves the destination undefined and real
// silicon preserves it, which an inserted xor would change to zero.
//
// Not flagged:
//   * same-register forms (popcnt eax, eax): the dependency is real, and
//     the xor would destroy the input;
//   * memory sources addressed through the destination (popcnt rax, [rax]):
//     the xor would corrupt the address;
//   * 16-bit forms: no zero idiom writes only the low word;
//   * an RSP destination: between the inserted xor and the count the stack
//     pointer would be null, exactly where an asynchronous signal delivers;
//   * a previous instruction that already redefined the register at 32 bits
//     or wider (`prev`, NULL at the buffer start and after a resync): the
//     compilers' xor shape, or any adjacent producer -- the dependency is
//     then at most one instruction stale, and re-flagging mitigated code
//     would bury the real findings. A direct edge onto the count reaches it
//     without that predecessor; the suppression forgoes that path's
//     finding, erring toward false negatives as everywhere else.
// The recently decoded instructions, for the two backward-looking
// dependency-break gates. Both ask whether something upstream already wrote
// the register whole, which is what severs a false dependency; consulting
// only the immediate predecessor answers that question too narrowly, because
// a compiler that emits the break does not always place it adjacent to the
// consumer. In libcrypto,
//
//     pxor  xmm0, xmm0
//     cvttsd2si rax, xmm1
//     cvtsi2sd xmm0, rax
//
// has the break two instructions up and was reported as missing one.
//
// Depth is the window bound the other multi-instruction checks share. The
// ring resets at a resync, so it never spans undecodable bytes. It carries no
// branch-target reasoning, matching the single-predecessor behavior it
// replaces: the walk only ever suppresses a finding, so a direct edge landing
// inside the window costs recall and nothing else.
#define DEP_HISTORY (APX_NDD_WINDOW - 1)

struct dep_history {
    xed_decoded_inst_t insn[DEP_HISTORY];
    int pos;                    // next slot to overwrite
    int depth;                  // valid entries, at most DEP_HISTORY
};

static void dep_history_reset(struct dep_history *h)
{
    h->pos = 0;
    h->depth = 0;
}

static void dep_history_push(struct dep_history *h,
                             const xed_decoded_inst_t *xedd)
{
    h->insn[h->pos] = *xedd;
    h->pos = (h->pos + 1) % DEP_HISTORY;
    if (h->depth < DEP_HISTORY) {
        ++h->depth;
    }
}

// A self-XOR or self-SUB on `parent` at 32 bits or wider: the shape a
// compiler emits deliberately to break a false dependency, as opposed to an
// ordinary producer that happens to write the register.
static bool gpr_dep_mitigation(const xed_decoded_inst_t *xedd,
                               xed_reg_enum_t parent)
{
    xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass(xedd);
    if ((iclass != XED_ICLASS_XOR && iclass != XED_ICLASS_SUB) ||
        xed_decoded_inst_number_of_memory_operands(xedd) != 0) {
        return false;
    }
    xed_reg_enum_t r0 = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);
    xed_reg_enum_t r1 = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1);
    return r0 == r1 && xed_reg_class(r0) == XED_REG_CLASS_GPR &&
           xed_get_register_width_bits64(r0) >= 32 &&
           xed_get_largest_enclosing_register(r0) == parent;
}

// The vector counterpart: a same-register XORPS/XORPD/PXOR on `parent`.
static bool xmm_dep_mitigation(const xed_decoded_inst_t *xedd,
                               xed_reg_enum_t parent)
{
    switch (xed_decoded_inst_get_iclass(xedd)) {
    case XED_ICLASS_XORPS:
    case XED_ICLASS_XORPD:
    case XED_ICLASS_PXOR:
    case XED_ICLASS_VXORPS:
    case XED_ICLASS_VXORPD:
    case XED_ICLASS_VPXOR:
        break;
    default:
        return false;
    }
    const xed_inst_t *xi = xed_decoded_inst_inst(xedd);
    unsigned nops = xed_inst_noperands(xi);
    bool any = false;
    for (unsigned i = 0; i < nops; ++i) {
        xed_operand_enum_t name = xed_operand_name(xed_inst_operand(xi, i));
        if (!xed_operand_is_register(name)) {
            continue;
        }
        if (xed_get_largest_enclosing_register(
                xed_decoded_inst_get_reg(xedd, name)) != parent) {
            return false;
        }
        any = true;
    }
    return any;
}

// True when something upstream already severed the dependency. The two
// distances answer different questions and so use different rules. The
// immediate predecessor is judged by the caller's full-redefinition rule,
// preserving the original gate: any producer there leaves the dependency at
// most one instruction stale, which is too cheap to be worth flagging.
// Further back only a deliberate mitigation counts -- the self-XOR a compiler
// emits for exactly this purpose -- because an ordinary producer several
// instructions up may still be in flight, and that is a real cost the finding
// should report.
static bool dep_broken_in_history(const struct dep_history *h,
                                  xed_reg_enum_t parent,
                                  bool (*redefines)(const xed_decoded_inst_t *,
                                                    xed_reg_enum_t),
                                  bool (*mitigation)(const xed_decoded_inst_t *,
                                                     xed_reg_enum_t))
{
    for (int i = 0; i < h->depth; ++i) {
        int idx = (h->pos - 1 - i + DEP_HISTORY) % DEP_HISTORY;
        const xed_decoded_inst_t *p = &h->insn[idx];
        if (i == 0 ? redefines(p, parent) : mitigation(p, parent)) {
            return true;
        }
    }
    return false;
}

static bool popcnt_false_dep(const xed_decoded_inst_t *xedd,
                             const struct dep_history *history)
{
    switch (xed_decoded_inst_get_iclass(xedd)) {
    case XED_ICLASS_POPCNT:
    case XED_ICLASS_LZCNT:
    case XED_ICLASS_TZCNT:
        break;
    default:
        return false;
    }
    unsigned width = xed_decoded_inst_get_operand_width(xedd);
    if (width != 32 && width != 64) {
        return false;
    }
    xed_reg_enum_t dst = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);
    if (xed_reg_class(dst) != XED_REG_CLASS_GPR) {
        return false;
    }
    xed_reg_enum_t parent = xed_get_largest_enclosing_register(dst);
    if (parent == XED_REG_RSP) {
        return false;
    }
    if (xed_decoded_inst_number_of_memory_operands(xedd) > 0) {
        if (xed_get_largest_enclosing_register(
                xed_decoded_inst_get_base_reg(xedd, 0)) == parent ||
            xed_get_largest_enclosing_register(
                xed_decoded_inst_get_index_reg(xedd, 0)) == parent) {
            return false;
        }
    } else {
        xed_reg_enum_t src = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1);
        if (xed_get_largest_enclosing_register(src) == parent) {
            return false;
        }
    }
    return !dep_broken_in_history(history, parent, redefines_reg_ge32,
                                  gpr_dep_mitigation);
}

// True when `xedd` unconditionally rewrites every bit of the vector register
// enclosed by `vec_parent`, leaving nothing of its previous value for a
// later merge to depend on. The suppression step of sse_merge_false_dep, and
// the vector analogue of redefines_reg_ge32.
//
// XED marks a destination it models as fully overwritten written-only, and a
// destination whose old bits survive read-and-written, which decides almost
// every case on its own: movaps, movd/movq from a GPR, cvtps2pd and movddup
// come back written-only, while the lane inserts (movlps, movhps, movlhps,
// pinsr, insertps) and every scalar op come back read-and-written. Two
// corrections are needed at the edges:
//
//   * a same-register vector XOR -- the mitigation this check asks for --
//     reads its destination as an ALU operand, so XED reports it
//     read-and-written even though the result is a constant zero. Matched
//     ahead of the scan, and only when every register operand is the same
//     register: xorps xmm0, xmm1 zeroes nothing. SUBPS and friends are
//     deliberately not matched -- self-subtraction is not a zero idiom the
//     renamer recognizes, so the dependency it carries is real.
//   * MOVSS and MOVSD come back written-only in both forms, but only the
//     memory form zeroes the upper lanes; the register form merges into them
//     exactly like the instructions this file flags. Excluded by form.
//
// Omitting a full writer costs a suppression, so the correction list errs
// toward reporting; a wrong entry would instead hide a real finding.
static bool redefines_xmm_full(const xed_decoded_inst_t *xedd,
                               xed_reg_enum_t vec_parent)
{
    xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass(xedd);
    const xed_inst_t *xi = xed_decoded_inst_inst(xedd);
    unsigned nops = xed_inst_noperands(xi);

    switch (iclass) {
    case XED_ICLASS_XORPS:
    case XED_ICLASS_XORPD:
    case XED_ICLASS_PXOR:
    case XED_ICLASS_VXORPS:
    case XED_ICLASS_VXORPD:
    case XED_ICLASS_VPXOR: {
        bool all_same = false;
        for (unsigned i = 0; i < nops; ++i) {
            xed_operand_enum_t name =
                xed_operand_name(xed_inst_operand(xi, i));
            if (!xed_operand_is_register(name)) {
                continue;
            }
            if (xed_get_largest_enclosing_register(
                    xed_decoded_inst_get_reg(xedd, name)) != vec_parent) {
                return false;
            }
            all_same = true;
        }
        if (all_same) {
            return true;
        }
        break;
    }
    case XED_ICLASS_MOVSS:
    case XED_ICLASS_MOVSD_XMM:
    case XED_ICLASS_VMOVSS:
    case XED_ICLASS_VMOVSD:
        if (xed_decoded_inst_number_of_memory_operands(xedd) == 0) {
            return false;
        }
        break;
    default:
        break;
    }

    for (unsigned i = 0; i < nops; ++i) {
        const xed_operand_t *op = xed_inst_operand(xi, i);
        xed_operand_enum_t name = xed_operand_name(op);
        if (!xed_operand_is_register(name) || !xed_operand_written_only(op)) {
            continue;
        }
        if (xed_get_largest_enclosing_register(
                xed_decoded_inst_get_reg(xedd, name)) == vec_parent) {
            return true;
        }
    }
    return false;
}

// Single-instruction advisory with a backward suppression, the vector
// counterpart of popcnt_false_dep. The legacy scalar SSE instructions below
// write only the low element of their destination and leave the rest of the
// register untouched -- the SDM spells every one of them "DEST[127:64]
// (unmodified)" -- so the destination is an input to the merge whatever the
// program means by it:
//
//   cvtss2sd xmm0, xmm1   -- waits for xmm0's previous producer
//
// A compiler that keeps scalars in vector registers never wants those upper
// bits, so the dependency is pure latency: the conversion serializes behind
// whatever last wrote the register, however unrelated. The mitigation gcc and
// clang emit -- llvm carries a whole pass for it, X86's BreakFalseDeps -- is a
// zero idiom just before: xorps xmm0, xmm0 ; cvtss2sd xmm0, xmm1. That
// insertion is invisible in the architectural state, since the low element is
// overwritten and the upper bits were dead, and vector XOR writes no flags, so
// nothing downstream can see it and nothing sits between the two either.
// Advisory nonetheless: adding an instruction is a size-for-latency trade, not
// an equivalence rewrite.
//
// The addend and multiplicand scalars -- ADDSD, MULSS, MINSD and the rest --
// merge the same way and are never flagged: their destination is a genuine
// source operand, so the dependency is architectural and a zero idiom would
// destroy the input. That distinction, real input versus phantom input, is the
// same one that keeps BSF and BSR out of popcnt_false_dep.
//
// Not flagged:
//   * same-register forms (cvtss2sd xmm0, xmm0): the destination is the
//     source, so the dependency is real and the xor would destroy it;
//   * the VEX and EVEX forms (vcvtss2sd xmm0, xmm1, xmm2): the merge source
//     is a third operand the encoding names outright, so the fix is to give
//     that operand a register already known dead rather than to insert
//     anything -- a different rewrite this check would misreport, covered
//     separately by vex_merge_false_dep;
//   * a previous instruction that already rewrote the whole register
//     (`prev`, NULL at the buffer start and after a resync): the compilers'
//     xor shape, or any adjacent full producer -- re-flagging mitigated code
//     would bury the real findings. A direct edge onto the instruction
//     reaches it without that predecessor; the suppression forgoes that
//     path's finding, erring toward false negatives as everywhere else.
//
// A memory source needs no special handling, unlike POPCNT's: the address is
// built from general-purpose registers, which a vector zero idiom cannot
// disturb, so cvtss2sd xmm0, [rax] is flagged like any other form.
static bool sse_merge_false_dep(const xed_decoded_inst_t *xedd,
                                const struct dep_history *history)
{
    switch (xed_decoded_inst_get_iclass(xedd)) {
    case XED_ICLASS_CVTSI2SD:
    case XED_ICLASS_CVTSI2SS:
    case XED_ICLASS_CVTSS2SD:
    case XED_ICLASS_CVTSD2SS:
    case XED_ICLASS_SQRTSD:
    case XED_ICLASS_SQRTSS:
    case XED_ICLASS_ROUNDSD:
    case XED_ICLASS_ROUNDSS:
    case XED_ICLASS_RCPSS:
    case XED_ICLASS_RSQRTSS:
        break;
    default:
        return false;
    }
    xed_reg_enum_t dst = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);
    if (xed_reg_class(dst) != XED_REG_CLASS_XMM) {
        return false;
    }
    xed_reg_enum_t parent = xed_get_largest_enclosing_register(dst);
    if (xed_decoded_inst_number_of_memory_operands(xedd) == 0) {
        // CVTSI2SD's source is a GPR, whose enclosing register can never be
        // the vector destination's -- the comparison simply never fires
        // there, which is the right answer.
        xed_reg_enum_t src = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1);
        if (xed_get_largest_enclosing_register(src) == parent) {
            return false;
        }
    }
    return !dep_broken_in_history(history, parent, redefines_xmm_full,
                                  xmm_dep_mitigation);
}

// The VEX and EVEX sibling of sse_merge_false_dep. The three-operand forms
// of the same scalar instructions name the merge source outright -- VEX.vvvv
// supplies the destination's untouched upper bits -- so no insertion is
// needed: passing the data source (or any register known dead) as the merge
// operand makes the destination a pure output at no cost, the same length as
// any other register choice. The hazard is a merge register that is neither
// the source nor fresh, and two shapes of it reach real code:
//
//   vcvtsd2ss xmm2, xmm2, xmm1  -- the destination as merge operand
//     reproduces the legacy form's false dependency in an encoding that
//     could have avoided it for free;
//   vroundsd xmm15, xmm0, xmm1, 1  -- an assembler that fills vvvv with the
//     "unused" 1111b pattern on an instruction that reads vvvv names xmm0,
//     silently serializing every round behind xmm0's last producer
//     (SpiderMonkey's JIT emitted exactly this for Math.floor).
//
// Not flagged:
//   * a merge operand equal to the data source (vcvtsd2ss xmm2, xmm1, xmm1):
//     the canonical dependency-free form, since the merge reads a register
//     the instruction already waits for;
//   * an integer or memory data source (VCVTSI2SD and friends, memory forms)
//     when the merge register was freshly rewritten: with no XMM source to
//     reuse, a zero idiom on the merge register is the only fix, exactly as
//     for the legacy forms, and the same suppression window recognizes it;
//   * a masked EVEX form: XED surfaces the opmask as the second register
//     operand, which fails the XMM class test below, erring toward silence.
//
// Unlike sse_merge_false_dep this advisory's rewrite is operand
// substitution, not insertion, so it is size-neutral and unconditionally
// profitable when an XMM source exists.
static bool vex_merge_false_dep(const xed_decoded_inst_t *xedd,
                                const struct dep_history *history)
{
    switch (xed_decoded_inst_get_iclass(xedd)) {
    case XED_ICLASS_VCVTSI2SD:
    case XED_ICLASS_VCVTSI2SS:
    case XED_ICLASS_VCVTSS2SD:
    case XED_ICLASS_VCVTSD2SS:
    case XED_ICLASS_VSQRTSD:
    case XED_ICLASS_VSQRTSS:
    case XED_ICLASS_VROUNDSD:
    case XED_ICLASS_VROUNDSS:
    case XED_ICLASS_VRCPSS:
    case XED_ICLASS_VRSQRTSS:
        break;
    default:
        return false;
    }
    xed_reg_enum_t dst = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);
    xed_reg_enum_t merge = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1);
    if (xed_reg_class(dst) != XED_REG_CLASS_XMM ||
        xed_reg_class(merge) != XED_REG_CLASS_XMM) {
        return false;
    }
    xed_reg_enum_t parent = xed_get_largest_enclosing_register(merge);
    if (xed_decoded_inst_number_of_memory_operands(xedd) == 0) {
        // For the integer conversions the third operand is a GPR, whose
        // enclosing register can never match the merge's -- the comparison
        // simply never fires there, which is the right answer: there is no
        // XMM source to reuse.
        xed_reg_enum_t src = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG2);
        if (xed_get_largest_enclosing_register(src) == parent) {
            return false;
        }
    }
    return !dep_broken_in_history(history, parent, redefines_xmm_full,
                                  xmm_dep_mitigation);
}

// Forward gate for scalar_move_false_dep: the intent test the backward
// window cannot provide. Walks forward from `offset` and returns true when
// some straight-line instruction reads a register of `parent` wider than
// `moved_bits` before the register is fully redefined -- proof that the
// lanes a scalar move merged are live data, i.e. that the move is a
// deliberate blend. XED's decoded operand lengths carry exactly this
// distinction: a scalar consumer reads its element (ADDSD's destination and
// UCOMISD's operands read 64 bits, a MOVQ store reads 64), while a vector
// consumer reads the register (MOVUPS stores 128, VADDSD's merge operand
// reads 128), so "wider than the element the move wrote" is one comparison.
//
// The endings run against reg_upper32_live_after's every-uncertainty-
// suppresses bias, deliberately. An unconditional direct branch is followed
// -- one successor keeps the walk straight-line -- but any other control
// transfer, the lookahead bound, or running out of bytes ends the walk
// with the finding standing: this
// gate serves an advisory, and the family's founding assumption -- code
// that keeps scalars in vector registers never wants the upper lanes --
// is applied where the walk cannot see, because treating an escape as
// blend evidence would erase the population the check exists for (glibc's
// fmax moves the chosen argument into the return register and returns; the
// caller of a double-returning function cannot read the upper lanes). A
// decode failure still suppresses: garbage downstream argues the site is
// not code this reasoning is about.
static bool xmm_read_above_width_ahead(const uint8_t *inst, size_t len,
                                       size_t offset, xed_reg_enum_t parent,
                                       unsigned moved_bits)
{
    const int MAX_LOOKAHEAD = 16;

    for (int step = 0; step < MAX_LOOKAHEAD && offset < len; ++step) {
        xed_decoded_inst_t xedd;
        decode_init(&xedd);
        if (xed_decode(&xedd, inst + offset, len - offset) != XED_ERROR_NONE) {
            return true;
        }

        // Reads before the kill below: an instruction can read the merged
        // lanes and then redefine the register.
        const xed_inst_t *xi = xed_decoded_inst_inst(&xedd);
        unsigned nops = xed_inst_noperands(xi);
        for (unsigned i = 0; i < nops; ++i) {
            const xed_operand_t *op = xed_inst_operand(xi, i);
            xed_operand_enum_t name = xed_operand_name(op);
            if (!xed_operand_is_register(name) || !xed_operand_read(op)) {
                continue;
            }
            if (xed_get_largest_enclosing_register(
                    xed_decoded_inst_get_reg(&xedd, name)) != parent) {
                continue;
            }
            if (xed_decoded_inst_operand_length_bits(&xedd, i) > moved_bits) {
                return true;
            }
        }

        xed_category_enum_t category = xed_decoded_inst_get_category(&xedd);
        if (category == XED_CATEGORY_UNCOND_BR) {
            // An unconditional direct branch has exactly one successor, so
            // following it keeps the walk straight-line (cf. redundant TEST
            // after SETcc, which scans a direct branch's known target). The
            // shape that needs this is gcc's loop entry, a jump into the
            // loop's middle: the blend's vector consumer sits at the
            // target, one hop away. The step bound already caps a backward
            // jump's revisits. An indirect or out-of-buffer target is an
            // escape like any other transfer: the finding stands.
            if (xed_decoded_inst_get_branch_displacement_width(&xedd) == 0) {
                return false;
            }
            int64_t target = (int64_t) offset +
                xed_decoded_inst_get_length(&xedd) +
                xed_decoded_inst_get_branch_displacement(&xedd);
            if (target < 0 || (uint64_t) target >= (uint64_t) len) {
                return false;
            }
            offset = (size_t) target;
            continue;
        }
        if (category == XED_CATEGORY_CALL ||
            category == XED_CATEGORY_RET ||
            category == XED_CATEGORY_COND_BR ||
            category == XED_CATEGORY_SYSCALL ||
            category == XED_CATEGORY_SYSRET ||
            category == XED_CATEGORY_INTERRUPT) {
            return false;
        }

        if (redefines_xmm_full(&xedd, parent)) {
            return false;
        }

        offset += xed_decoded_inst_get_length(&xedd);
    }

    return false;
}

// The moves of the same scalar family. Between registers MOVSS and MOVSD
// copy one element and merge the rest -- the legacy forms from the
// destination's old value, VMOVSS/VMOVSD from their explicit vvvv operand --
// so a move that meant "copy the scalar" pays the family's false dependency.
// Unlike the conversions the instruction itself is avoidable: MOVAPS copies
// the whole register a byte shorter (VMOVAPS at the same length), reads
// nothing but its source, and is eliminated at rename on current cores,
// which a merging move -- a real two-input uop -- never is. So the fix is
// neither an insertion nor an operand choice but a different instruction,
// strictly better whenever the upper lanes are dead, which is why these
// iclasses get their own finding rather than joining the two checks above
// (each names a fix that would be wrong here).
//
// The register form is also SSE2's idiom for a genuine two-source blend --
// the one consumer of these merge semantics that means them -- and there
// MOVAPS would corrupt the result, so unlike the rest of the family this
// check must read intent, with the forward gate above: a blend's
// destination is consumed as a vector (git's gcc-vectorized delta loops
// merge a paddd lane into a psubd pair and immediately store both lanes
// with movq -- 64 bits, wider than the 32 the movss wrote), while a moved
// scalar is consumed at its own width or escapes. Compilers with SSE4.1
// available spell live blends BLENDPS/BLENDPD instead, so the merging
// spelling on newer code selects for the move intent to begin with. A blend
// whose vector consumer sits past a branch or beyond the lookahead is still
// misflagged -- the accepted, now-narrower residue of an advisory.
//
// Not flagged:
//   * the memory forms: the load direction zeroes the upper lanes outright
//     and the store direction writes no register at all;
//   * a same-register legacy move (movsd xmm0, xmm0), a pure no-op;
//   * a VEX merge operand equal to the data source (vmovsd xmm1, xmm2,
//     xmm2): every bit then comes from the source -- a full copy, however
//     spelled;
//   * a VEX destination equal to the data source (vmovsd xmm1, xmm2, xmm1):
//     as a move it would be a no-op, so the shape only ever means the blend;
//   * a masked EVEX form: the opmask surfaces as the second register
//     operand and fails the XMM class test, erring toward silence;
//   * a merge input freshly rewritten (the family's suppression window):
//     one instruction of staleness is not worth flagging;
//   * a destination read wider than the moved element downstream (the
//     forward gate): the merged lanes are live, so the merge is the point.
static bool scalar_move_false_dep(const xed_decoded_inst_t *xedd,
                                  const struct dep_history *history,
                                  const uint8_t *inst, size_t len,
                                  size_t next_offset)
{
    xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass(xedd);
    bool vex;
    switch (iclass) {
    case XED_ICLASS_MOVSS:
    case XED_ICLASS_MOVSD_XMM:
        vex = false;
        break;
    case XED_ICLASS_VMOVSS:
    case XED_ICLASS_VMOVSD:
        vex = true;
        break;
    default:
        return false;
    }
    if (xed_decoded_inst_number_of_memory_operands(xedd) != 0) {
        return false;
    }
    xed_reg_enum_t dst = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);
    xed_reg_enum_t merge = xed_decoded_inst_get_reg(
        xedd, vex ? XED_OPERAND_REG1 : XED_OPERAND_REG0);
    xed_reg_enum_t src = xed_decoded_inst_get_reg(
        xedd, vex ? XED_OPERAND_REG2 : XED_OPERAND_REG1);
    if (xed_reg_class(dst) != XED_REG_CLASS_XMM ||
        xed_reg_class(merge) != XED_REG_CLASS_XMM) {
        return false;
    }
    xed_reg_enum_t src_parent = xed_get_largest_enclosing_register(src);
    xed_reg_enum_t merge_parent = xed_get_largest_enclosing_register(merge);
    if (src_parent == merge_parent ||
        src_parent == xed_get_largest_enclosing_register(dst)) {
        return false;
    }
    if (dep_broken_in_history(history, merge_parent, redefines_xmm_full,
                              xmm_dep_mitigation)) {
        return false;
    }
    unsigned moved_bits =
        (iclass == XED_ICLASS_MOVSS || iclass == XED_ICLASS_VMOVSS) ? 32 : 64;
    return !xmm_read_above_width_ahead(
        inst, len, next_offset, xed_get_largest_enclosing_register(dst),
        moved_bits);
}

// The general-purpose sibling of the merging scalar move: an 8- or 16-bit
// register-destination MOV writes only the low bits of its parent and
// merges the rest, and on every current core that merge is a real input --
// Sandy Bridge's separate low-byte renaming was dropped in Haswell, and AMD
// never renamed partials, so the narrow write itself reads the register's
// old value and serializes behind its last producer, however unrelated.
// MOVZX (or MOVSX, where the sign is wanted) performs the same load or
// copy writing the register whole: same one uop, the byte forms one byte
// longer (8A 06 -> 0F B6 06), the word forms the same length (the 66
// prefix trades for the 0F escape: 66 8B 06 -> 0F B7 06), and the false
// dependency gone. gcc and clang emit the extending forms for narrow
// values pervasively, which is why a surviving bare narrow MOV is worth a
// look.
//
// Unlike the vector family this rewrite's soundness condition is exactly
// computable here: MOVZX differs from MOV only in the bits at and above
// the written width, so the finding is gated by reg_bits_above_live_after
// -- the deliberate merge (packing bytes into a wider value) reads the
// parent wide downstream and suppresses itself, and an escape suppresses
// too, because a narrow value crossing a RET or branch may be the low end
// of a register whose upper bits carry real data (a struct returned in
// RAX with one byte freshly stored). That makes this a gated equivalence
// rewrite in the mov-eax-eax family, not an advisory: every reported site
// is provably safe to rewrite within the walk's stated conservatism.
//
// Not flagged:
//   * store forms (mov [mem], al): no register write at all;
//   * immediate sources: mov al, 5 widens to the 5-byte mov eax, 5 --
//     three bytes for the dependency is a different trade, and the
//     16-bit-immediate shape is already the length-changing prefix stall
//     finding;
//   * a high-byte destination (mov ah, [mem]): no extending spelling
//     writes bits 15:8, so the fix is restructuring, not substitution
//     (reading AH as a source is fine -- movzx eax, ah remains the
//     efficient byte extraction);
//   * a segment or other non-GPR source: MOVZX cannot encode it;
//   * a same-register copy (mov al, al): redundant MOV reg, reg already
//     flags the pure no-op;
//   * a narrow load whose next instruction extends the loaded register
//     in place: that pair is the load-foldable-into-extend finding, whose
//     one-instruction fix subsumes this one;
//   * 8/16-bit arithmetic (add al, bl): it merges identically, but no
//     same-cost full-width spelling preserves its flags and width
//     semantics, so there is nothing sound to suggest.
static bool narrow_move_merge(const xed_decoded_inst_t *xedd,
                              const uint8_t *inst, size_t len,
                              size_t next_offset)
{
    if (xed_decoded_inst_get_iclass(xedd) != XED_ICLASS_MOV ||
        xed_decoded_inst_get_immediate_width_bits(xedd) != 0) {
        return false;
    }
    const xed_inst_t *xi = xed_decoded_inst_inst(xedd);
    const xed_operand_t *op0 = xed_inst_operand(xi, 0);
    if (xed_operand_name(op0) != XED_OPERAND_REG0 ||
        !xed_operand_written(op0)) {
        return false;
    }
    xed_reg_enum_t dst = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);
    if (xed_reg_class(dst) != XED_REG_CLASS_GPR) {
        return false;
    }
    unsigned width = xed_get_register_width_bits64(dst);
    if (width != 8 && width != 16) {
        return false;
    }
    if (dst == XED_REG_AH || dst == XED_REG_BH || dst == XED_REG_CH ||
        dst == XED_REG_DH) {
        return false;
    }
    if (xed_decoded_inst_number_of_memory_operands(xedd) == 0) {
        xed_reg_enum_t src = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1);
        if (src == dst || xed_reg_class(src) != XED_REG_CLASS_GPR) {
            return false;
        }
    }
    if (next_offset < len) {
        xed_decoded_inst_t ext;
        decode_init(&ext);
        if (xed_decode(&ext, inst + next_offset, len - next_offset) ==
                XED_ERROR_NONE) {
            switch (xed_decoded_inst_get_iclass(&ext)) {
            case XED_ICLASS_MOVZX:
            case XED_ICLASS_MOVSX:
            case XED_ICLASS_MOVSXD:
                if (xed_decoded_inst_number_of_memory_operands(&ext) == 0 &&
                    xed_decoded_inst_get_reg(&ext, XED_OPERAND_REG1) == dst) {
                    return false;
                }
                break;
            default:
                break;
            }
        }
    }
    return !reg_bits_above_live_after(
        inst, len, next_offset, xed_get_largest_enclosing_register(dst),
        width);
}

// True for a legacy-encoded SSE instruction that touches an XMM register.
// xed_classify_sse is encoding-exclusive -- the VEX and EVEX spellings
// classify as AVX and AVX512 -- and the XMM-operand requirement drops the
// non-vector members of the SSE ISA sets (SFENCE, LDMXCSR, PREFETCH) and
// the MMX-register forms, none of which the transition machinery below is
// about.
static bool legacy_sse_with_xmm(const xed_decoded_inst_t *xedd)
{
    if (!xed_classify_sse(xedd)) {
        return false;
    }
    const xed_inst_t *xi = xed_decoded_inst_inst(xedd);
    unsigned nops = xed_inst_noperands(xi);
    for (unsigned i = 0; i < nops; ++i) {
        xed_operand_enum_t name = xed_operand_name(xed_inst_operand(xi, i));
        if (!xed_operand_is_register(name)) {
            continue;
        }
        if (xed_reg_class(xed_decoded_inst_get_reg(xedd, name)) ==
                XED_REG_CLASS_XMM) {
            return true;
        }
    }
    return false;
}

// True when the instruction writes any of ymm0-15 or zmm0-15, dirtying
// upper state legacy SSE can see. Registers 16-31 have no legacy alias, so
// writes there leave every SSE-visible upper half as it was; VEX.128
// writes zero their own register's upper bits but say nothing about the
// other fifteen, so they neither set nor clear the state.
static bool writes_wide_vector(const xed_decoded_inst_t *xedd)
{
    const xed_inst_t *xi = xed_decoded_inst_inst(xedd);
    unsigned nops = xed_inst_noperands(xi);
    for (unsigned i = 0; i < nops; ++i) {
        const xed_operand_t *op = xed_inst_operand(xi, i);
        xed_operand_enum_t name = xed_operand_name(op);
        if (!xed_operand_is_register(name) || !xed_operand_written(op)) {
            continue;
        }
        xed_reg_enum_t r = xed_decoded_inst_get_reg(xedd, name);
        if ((xed_reg_class(r) == XED_REG_CLASS_YMM &&
             r - XED_REG_YMM0 < 16) ||
            (xed_reg_class(r) == XED_REG_CLASS_ZMM &&
             r - XED_REG_ZMM0 < 16)) {
            return true;
        }
    }
    return false;
}

int check_instructions(const uint8_t *inst, size_t len, uint64_t vaddr,
                       bool verbose, x86lint_summary *summary,
                       uint32_t extensions)
{
    int errors = 0;

    // Findings attribute against the installed function table at
    // vaddr + offset; keep the base current for this buffer.
    if (summary != NULL) {
        summary->base = vaddr;
    }

    // The immediately preceding decoded instruction, for the one backward-
    // looking gate (check_mov_self's already-zero-extended case). have_prev is
    // false at the start and after any resync skip, so `prev` is consulted only
    // when it is adjacent to the current instruction.
    xed_decoded_inst_t prev;
    bool have_prev = false;

    // Backward window for the dependency-break gates (see struct
    // dep_history); wider than `prev`, which the adjacency-only gates keep.
    struct dep_history dep_history;
    dep_history_reset(&dep_history);

    // True while the upper halves of ymm0-15 are provably dirty on every
    // path reaching the current instruction: a 256- or 512-bit write to
    // them was seen on this straight-line run, with no VZEROUPPER/VZEROALL,
    // no control transfer, and no incoming branch edge since. See the
    // AVX-SSE transition block below.
    bool ymm_upper_dirty = false;

    // Direct branch targets for the multi-instruction windows (see
    // collect_branch_targets). NULL on allocation failure, which
    // branch_target_in treats as every-offset-targeted: the multi-instruction
    // findings are then conservatively suppressed while the single-instruction
    // checks proceed.
    uint8_t *branch_targets = collect_branch_targets(inst, len);

    for (size_t offset = 0; offset < len;) {
        xed_decoded_inst_t xedd;
        decode_init(&xedd);

        xed_error_enum_t err = xed_decode(&xedd, inst + offset, len - offset);
        if (err != XED_ERROR_NONE) {
            // Not a tool failure: executable sections routinely embed data
            // (jump tables, alignment islands, GHC info tables, Go's
            // BoringCrypto signature) that linear-sweep decoding walks into.
            // Skip one byte and resync rather than abandoning the rest of the
            // section. Only the aggregate is reported (via the summary); a
            // stripped GHC binary skips hundreds of thousands of bytes, so
            // enumerating each one would bury the actual findings.
            if (summary != NULL) {
                summary->skipped++;
            }
            have_prev = false;
            dep_history_reset(&dep_history);
            ymm_upper_dirty = false;
            offset += 1;
            continue;
        }

        if (summary != NULL) {
            summary->instructions++;
        }

        // Disabled: the savings are at most one decoded uop (same byte count)
        // and benign alignment-padding patterns generate noise even after the
        // PAUSE/ENDBR and combine-only-if-fits-in-9-bytes filters. The
        // function remains in the public header for library consumers.
        /*
        if (!check_suboptimal_nops(inst + offset, len - offset)) {
            printf("suboptimal NOP sequence at offset: %zu\n", offset);
            dump_instruction(&xedd);
            dump_machine_code(&xedd, inst + offset);

            xed_decoded_inst_t xedd2;
            decode_init(&xedd2);
            size_t cur_len = xed_decoded_inst_get_length(&xedd);
            xed_decode(&xedd2, inst + offset + cur_len, len - offset - cur_len);
            dump_instruction(&xedd2);
            dump_machine_code(&xedd2, inst + offset + cur_len);
            printf("\n");
            ++errors;
        }
        */

        size_t next = offset + xed_decoded_inst_get_length(&xedd);
        for (size_t i = 0; i < sizeof(checks) / sizeof(checks[0]); ++i) {
            if ((checks[i].ext_required & ~extensions) != 0) {
                continue;
            }
            if (checks[i].fn(&xedd)) {
                continue;
            }
            if (checks[i].flag_concerns != 0 &&
                flags_live_after(inst, len, next, checks[i].flag_concerns)) {
                continue;
            }
            if (checks[i].reg_concern != NULL) {
                xed_reg_enum_t reg64 = checks[i].reg_concern(&xedd);
                // Suppress only when the disturbed upper half is read
                // downstream AND the backward escape does not apply: for a
                // check whose rewrite deletes the instruction (reg_zx_escape),
                // a preceding instruction that already zeroed those bits makes
                // the deletion (e.g. of mov eax, eax) state-preserving
                // regardless of any downstream read. The escape holds only if
                // every path here runs through that predecessor, so a direct
                // branch targeting this instruction -- arriving with unknown
                // upper bits -- cancels it.
                if (reg64 != XED_REG_INVALID &&
                    reg_upper32_live_after(inst, len, next, reg64) &&
                    !(checks[i].reg_zx_escape && have_prev &&
                      writes_zero_extended_32(&prev, reg64) &&
                      !branch_target_in(branch_targets, offset, offset + 1))) {
                    continue;
                }
            }
            summary_add(summary, checks[i].name, offset);
            report_finding(summary, checks[i].name, offset, verbose, &xedd,
                inst + offset);
            ++errors;
        }

        // Multi-instruction peephole: a flag-setting ALU write followed by
        // test reg, reg on the same register makes the test redundant. The
        // test need not be adjacent -- it is searched for through the shared
        // APX_NDD_WINDOW, past instructions that write neither the flags nor
        // the tested register (see flags_gap_transparent) -- so the finding is
        // reported at the test's own offset, the removable instruction. See
        // flags_test_redundant.
        xed_decoded_inst_t redundant_test;
        size_t redundant_test_offset;
        if (flags_test_redundant(inst, len, branch_targets, next, &xedd,
                                 &redundant_test, &redundant_test_offset)) {
            summary_add(summary, "redundant TEST after flags",
                        redundant_test_offset);
            report_finding(summary, "redundant TEST after flags", redundant_test_offset,
                verbose, &redundant_test, inst + redundant_test_offset);
            ++errors;
        }

        // Multi-instruction peephole: a SHL/SHR/SAR by a statically nonzero
        // count already set SF/ZF/PF, so test reg, reg on the shifted
        // register recomputes them; a following CF/OF-blind Jcc is handled
        // by scanning both successors. Reported at the test's offset, the
        // removable instruction. See shift_test_redundant.
        if (shift_test_redundant(inst, len, branch_targets, next, &xedd,
                                 &redundant_test, &redundant_test_offset)) {
            summary_add(summary, "redundant TEST after shift",
                        redundant_test_offset);
            report_finding(summary, "redundant TEST after shift",
                redundant_test_offset, verbose, &redundant_test,
                inst + redundant_test_offset);
            ++errors;
        }

        // Multi-instruction peephole: lea reg, [addr] whose address folds into
        // the next instruction's memory operand, leaving reg dead. Reported
        // against the lea (at `offset`), the removable instruction. See
        // lea_foldable_into_memop.
        if (lea_foldable_into_memop(inst, len, branch_targets, next, &xedd)) {
            summary_add(summary, "LEA foldable into memory", offset);
            report_finding(summary, "LEA foldable into memory", offset, verbose, &xedd,
                inst + offset);
            ++errors;
        }

        // Multi-instruction peephole: mov reg, imm whose constant folds into the
        // next instruction's immediate, leaving reg dead. Reported against the
        // mov (at `offset`), the removable instruction. See mov_const_foldable.
        if (mov_const_foldable(inst, len, branch_targets, next, &xedd)) {
            summary_add(summary, "MOV constant foldable", offset);
            report_finding(summary, "MOV constant foldable", offset, verbose, &xedd,
                inst + offset);
            ++errors;
        }

        // Multi-instruction peephole: a narrow load feeding an in-place sign/
        // zero-extension is a single extending load. Reported against the load
        // (at `offset`), the removable instruction. See
        // load_foldable_into_extend.
        if (load_foldable_into_extend(inst, len, branch_targets, next,
                                      &xedd)) {
            summary_add(summary, "load foldable into extend", offset);
            report_finding(summary, "load foldable into extend", offset, verbose, &xedd,
                inst + offset);
            ++errors;
        }

        // Multi-instruction peephole: mov dest, srcA followed by an add into
        // dest -- add dest, srcB, add/sub dest, imm, or inc/dec dest -- is
        // the three-operand lea dest, [srcA + addend], saving the mov.
        // Reported against the mov (at `offset`). See mov_add_foldable_to_lea.
        if (mov_add_foldable_to_lea(inst, len, branch_targets, next, &xedd)) {
            summary_add(summary, "MOV+ADD foldable to LEA", offset);
            report_finding(summary, "MOV+ADD foldable to LEA", offset, verbose, &xedd,
                inst + offset);
            ++errors;
        }

        // Multi-instruction peephole: shl reg, k ; sar/shr reg, k sign- or
        // zero-extends the low width-k bits in place, which a single movsx/
        // movzx computes. Reported against the shl (at `offset`). See
        // shift_pair_foldable_to_extend.
        if (shift_pair_foldable_to_extend(inst, len, branch_targets, next,
                                          &xedd)) {
            summary_add(summary, "shift pair foldable into extend", offset);
            report_finding(summary, "shift pair foldable into extend", offset, verbose,
                &xedd, inst + offset);
            ++errors;
        }

        // Multi-instruction peephole: cmp reg, 1 ; jb/jae branches on
        // "unsigned < 1", which is "== 0" -- test reg, reg ; jz/jnz answers it
        // a byte shorter. Reported against the cmp (at `offset`). See
        // cmp_one_branch_foldable.
        if (cmp_one_branch_foldable(inst, len, branch_targets, next, &xedd)) {
            summary_add(summary, "suboptimal CMP one", offset);
            report_finding(summary, "suboptimal CMP one", offset, verbose, &xedd,
                inst + offset);
            ++errors;
        }

        // Multi-instruction peephole: setcc X ; test X, X ; je/jne branches on a
        // condition the compare flags still hold, so the test is redundant.
        // Reported against the setcc (at `offset`). See redundant_test_after_setcc.
        if (redundant_test_after_setcc(inst, len, branch_targets, next,
                                       &xedd)) {
            summary_add(summary, "redundant TEST after SETcc", offset);
            report_finding(summary, "redundant TEST after SETcc", offset, verbose, &xedd,
                inst + offset);
            ++errors;
        }

        // Multi-instruction peephole: setcc X ; xor X, 1 inverts the boolean
        // the complementary condition code produces outright. Reported against
        // the SETcc (at `offset`), where the replacement lands and from which
        // the XOR disappears. See setcc_xor_one_invertible.
        xed_decoded_inst_t inverting_xor;
        if (setcc_xor_one_invertible(inst, len, branch_targets, next, &xedd,
                                     &inverting_xor)) {
            summary_add(summary, "suboptimal SETcc inversion", offset);
            report_finding(summary, "suboptimal SETcc inversion", offset, verbose, &xedd,
                inst + offset);
            ++errors;
        }

        // Multi-instruction peephole: setcc X ; movzx of X into its own
        // 32/64-bit parent. Under -m apx the pair is one zero-upper setcc
        // -- setzu.cc r32 writes the 0/1 result zero-extended to 64 bits
        // (the EVEX ND=1 form; XED's record models the byte register, the
        // APX spec defines the upper bits zeroed), reads the same
        // condition flags, and nothing sits between the pair to see the
        // dropped intermediate state -- an exact fold, reported against
        // the SETcc (at `offset`), where the replacement lands. Without
        // the extension the finding stays the advisory: Intel's preferred
        // form zeroes the parent ahead of the compare instead, dropping
        // the movzx and its partial-register merge, reported against the
        // movzx (at `next`), the instruction the preferred form removes.
        // One matcher, one site, one finding either way. See
        // setcc_movzx_zero_extend.
        xed_decoded_inst_t widen_movzx;
        if (setcc_movzx_zero_extend(inst, len, branch_targets, next, &xedd,
                                    &widen_movzx)) {
            if ((extensions & X86LINT_EXT_APX) != 0) {
                summary_add(summary, "missing APX SETZU", offset);
                report_finding(summary, "missing APX SETZU", offset, verbose, &xedd,
                    inst + offset);
            } else {
                summary_add(summary, "suboptimal SETcc zero-extension", next);
                report_finding(summary, "suboptimal SETcc zero-extension", next,
                    verbose, &widen_movzx, inst + next);
            }
            ++errors;
        }

        // Multi-instruction peephole, only when the caller enabled BMI1:
        // not rX ; and rX, rY collapses to one andn rX, rX, rY. Reported
        // against the NOT (at `offset`), where the replacement lands. See
        // not_and_foldable_to_andn.
        if ((extensions & X86LINT_EXT_BMI1) != 0 &&
            not_and_foldable_to_andn(inst, len, branch_targets, next, &xedd)) {
            summary_add(summary, "missing ANDN", offset);
            report_finding(summary, "missing ANDN", offset, verbose, &xedd,
                inst + offset);
            ++errors;
        }

        // Multi-instruction peephole, only when the caller enabled BMI1:
        // lea rY, [rX-1] ; and rY, rX collapses to one blsr rY, rX. Reported
        // against the LEA (at `offset`), where the replacement lands. See
        // lea_and_foldable_to_blsr.
        if ((extensions & X86LINT_EXT_BMI1) != 0 &&
            lea_and_foldable_to_blsr(inst, len, branch_targets, next, &xedd)) {
            summary_add(summary, "missing BLSR", offset);
            report_finding(summary, "missing BLSR", offset, verbose, &xedd,
                inst + offset);
            ++errors;
        }

        // Multi-instruction peephole, only when the caller enabled BMI1:
        // lea rY, [rX-1] ; xor rY, rX collapses to one blsmsk rY, rX.
        // Reported against the LEA (at `offset`), where the replacement
        // lands. See lea_xor_foldable_to_blsmsk.
        if ((extensions & X86LINT_EXT_BMI1) != 0 &&
            lea_xor_foldable_to_blsmsk(inst, len, branch_targets, next,
                                       &xedd)) {
            summary_add(summary, "missing BLSMSK", offset);
            report_finding(summary, "missing BLSMSK", offset, verbose, &xedd,
                inst + offset);
            ++errors;
        }

        // Multi-instruction peephole, only when the caller enabled BMI1:
        // mov rY, rX ; neg rY ; and rY, rX collapses to one blsi rY, rX.
        // Reported against the MOV (at `offset`), where the replacement
        // lands. See mov_neg_and_foldable_to_blsi.
        if ((extensions & X86LINT_EXT_BMI1) != 0 &&
            mov_neg_and_foldable_to_blsi(inst, len, branch_targets, next,
                                         &xedd)) {
            summary_add(summary, "missing BLSI", offset);
            report_finding(summary, "missing BLSI", offset, verbose, &xedd,
                inst + offset);
            ++errors;
        }
        // Multi-instruction peephole, only when the caller enabled APX:
        // mov rY, rX ; op rY, src -- a destructive op consuming the fresh
        // copy (or a fresh load: mov rY, [mem]) -- collapses to one EVEX
        // new-data-destination op rY, rX, src (op rY, [mem], src). The
        // `else` keeps it off a site the BLSI collapse above
        // claimed: that triple begins with the same mov/neg pair, and the
        // 3 -> 1 advice supersedes this 2 -> 1 fold (a merely gate-
        // suppressed BLSI still falls through to here). Reported against
        // the MOV (at `offset`), where the replacement lands. See
        // mov_op_foldable_to_apx_ndd.
        else if ((extensions & X86LINT_EXT_APX) != 0 &&
            mov_op_foldable_to_apx_ndd(inst, len, branch_targets, next,
                                       &xedd)) {
            summary_add(summary, "missing APX NDD", offset);
            report_finding(summary, "missing APX NDD", offset, verbose, &xedd,
                inst + offset);
            ++errors;
        }

        // Multi-instruction peephole, only when the caller enabled MOVBE:
        // mov rX, [mem] ; bswap rX collapses to one movbe rX, [mem].
        // Reported against the MOV (at `offset`), where the replacement
        // lands. See mov_bswap_foldable_to_movbe.
        if ((extensions & X86LINT_EXT_MOVBE) != 0 &&
            mov_bswap_foldable_to_movbe(inst, len, branch_targets, next,
                                        &xedd)) {
            summary_add(summary, "missing MOVBE", offset);
            report_finding(summary, "missing MOVBE", offset, verbose, &xedd,
                inst + offset);
            ++errors;
        }

        // Backward peephole: an in-place movzx/movsx/movsxd re-establishing
        // bits the immediately preceding extension already provided is a pure
        // no-op. Justified solely by `prev`, so a direct edge onto this
        // instruction -- a path that skips the producer -- rejects it (the
        // same condition guarding the writes_zero_extended_32 escape above).
        // Reported against the re-extension (at `offset`), the removable
        // instruction. See redundant_reextension.
        if (have_prev && redundant_reextension(&prev, &xedd) &&
            !branch_target_in(branch_targets, offset, offset + 1)) {
            summary_add(summary, "redundant re-extension", offset);
            report_finding(summary, "redundant re-extension", offset, verbose, &xedd,
                inst + offset);
            ++errors;
        }

        // Single-instruction advisory with a backward suppression: a POPCNT/
        // LZCNT/TZCNT whose destination the adjacent predecessor did not
        // redefine carries a false output dependency on affected Intel
        // cores; a zero idiom just before the count breaks it. See
        // popcnt_false_dep.
        if (popcnt_false_dep(&xedd, &dep_history)) {
            summary_add(summary, "missing POPCNT dependency break", offset);
            report_finding(summary, "missing POPCNT dependency break", offset, verbose,
                &xedd, inst + offset);
            ++errors;
        }

        // Single-instruction advisory with a backward suppression: a legacy
        // scalar SSE instruction writes only its destination's low element
        // and merges into the rest, so a destination the adjacent
        // predecessor did not rewrite carries a false dependency; a vector
        // zero idiom just before breaks it. See sse_merge_false_dep.
        if (sse_merge_false_dep(&xedd, &dep_history)) {
            summary_add(summary, "missing SSE dependency break", offset);
            report_finding(summary, "missing SSE dependency break", offset, verbose,
                &xedd, inst + offset);
            ++errors;
        }

        // The VEX/EVEX counterpart: the three-operand scalar forms name the
        // merge source outright, so a merge operand that is neither the data
        // source nor freshly rewritten is a false dependency the encoding
        // could have avoided for free. See vex_merge_false_dep.
        if (vex_merge_false_dep(&xedd, &dep_history)) {
            summary_add(summary, "stale VEX merge operand", offset);
            report_finding(summary, "stale VEX merge operand", offset, verbose,
                &xedd, inst + offset);
            ++errors;
        }

        // The family's moves: a register-to-register MOVSS/MOVSD (or a
        // VMOVSS/VMOVSD whose merge operand is neither the source nor
        // fresh) merges where MOVAPS would copy -- a false dependency and
        // a lost move elimination in one, unless a downstream vector read
        // proves the merge a deliberate blend. See scalar_move_false_dep.
        if (scalar_move_false_dep(&xedd, &dep_history, inst, len, next)) {
            summary_add(summary, "merging scalar move", offset);
            report_finding(summary, "merging scalar move", offset, verbose,
                &xedd, inst + offset);
            ++errors;
        }

        // Its general-purpose sibling: an 8- or 16-bit register-destination
        // MOV merges into its parent, and MOVZX performs the same load or
        // copy writing the register whole -- a gated equivalence rewrite,
        // reported only when the bits above the written width are provably
        // dead. See narrow_move_merge.
        if (narrow_move_merge(&xedd, inst, len, next)) {
            summary_add(summary, "merging narrow move", offset);
            report_finding(summary, "merging narrow move", offset, verbose,
                &xedd, inst + offset);
            ++errors;
        }

        // AVX-SSE transition. A legacy SSE instruction preserves bits
        // 255:128 of its destination's ymm register, so executing one
        // while any of ymm0-15 carries dirty upper state costs: Sandy
        // Bridge through Broadwell take an ~70-cycle state save on the
        // first such instruction (and another restore returning to 256-bit
        // code), and from Skylake every legacy SSE instruction in dirty
        // state carries a false dependency on its destination's stale
        // upper half instead -- a merge input, exactly the scalar-merge
        // hazard at 128-bit scale. AMD cores take no penalty; the finding
        // targets Intel. The fix is VZEROUPPER after the last 256-bit use
        // (what compilers emit before every return and call when ymm was
        // touched -- which is why compiled code is clean and the
        // population is hand-written assembly and JIT output), or the VEX
        // spelling of the SSE code, which does not merge.
        //
        // The state machine claims DIRTY only when it is provable on
        // every path here: a ymm0-15/zmm0-15 write seen on this
        // straight-line run, killed by VZEROUPPER/VZEROALL or an
        // XRSTOR-family state load, by any control transfer (a callee may
        // clean the state; past a RET or JMP the next bytes are another
        // context), and -- the merge point -- by an incoming direct
        // branch edge, whose path may arrive clean. A conditional
        // branch's fallthrough keeps the state. Edges the sweep cannot
        // see (indirect branches, jump tables) are the linear sweep's
        // documented residual and err here toward silence only if they
        // LAND mid-run unobserved -- collect_branch_targets marks every
        // direct target, and an unseen indirect edge could only make a
        // flagged site reachable with clean uppers, where the rewrite
        // (vzeroupper, or the VEX spelling) stays harmless.
        if (branch_target_in(branch_targets, offset, offset + 1)) {
            ymm_upper_dirty = false;
        }
        if (ymm_upper_dirty && legacy_sse_with_xmm(&xedd)) {
            summary_add(summary, "AVX-SSE transition", offset);
            report_finding(summary, "AVX-SSE transition", offset, verbose,
                &xedd, inst + offset);
            ++errors;
        }
        switch (xed_decoded_inst_get_iclass(&xedd)) {
        case XED_ICLASS_VZEROUPPER:
        case XED_ICLASS_VZEROALL:
        case XED_ICLASS_XRSTOR:
        case XED_ICLASS_XRSTOR64:
        case XED_ICLASS_XRSTORS:
        case XED_ICLASS_XRSTORS64:
        case XED_ICLASS_FXRSTOR:
        case XED_ICLASS_FXRSTOR64:
            ymm_upper_dirty = false;
            break;
        default: {
            xed_category_enum_t cat = xed_decoded_inst_get_category(&xedd);
            if (cat == XED_CATEGORY_CALL || cat == XED_CATEGORY_RET ||
                cat == XED_CATEGORY_UNCOND_BR ||
                cat == XED_CATEGORY_SYSCALL || cat == XED_CATEGORY_SYSRET ||
                cat == XED_CATEGORY_INTERRUPT) {
                ymm_upper_dirty = false;
            } else if (writes_wide_vector(&xedd)) {
                ymm_upper_dirty = true;
            }
            break;
        }
        }

        prev = xedd;
        have_prev = true;
        dep_history_push(&dep_history, &xedd);
        offset = next;
    }

    free(branch_targets);
    return errors;
}
