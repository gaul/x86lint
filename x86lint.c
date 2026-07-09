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

// TODO: handle 10-15 byte NOPs
bool check_suboptimal_nops(const uint8_t *inst, size_t len)
{
    int prev_nop = 0;

    for (size_t i = 0; i < len; ) {
        xed_decoded_inst_t xedd;

        // TODO: make these configurable
        xed_machine_mode_enum_t mmode = XED_MACHINE_MODE_LONG_64;
        xed_address_width_enum_t stack_addr_width = XED_ADDRESS_WIDTH_64b;

        xed_decoded_inst_zero(&xedd);
        xed_decoded_inst_set_mode(&xedd, mmode, stack_addr_width);
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

// or/xor reg, imm whose mask sets or flips a single bit at position 7 or
// above -- and and reg, imm whose mask clears one -- drag a 2-4 byte
// immediate along for a one-bit operation the bt family encodes in one byte:
//   or eax, 0x100     0d 00010000     (5 bytes)   ->   bts eax, 8    0f ba e8 08     (4 bytes)
//   xor ecx, 0x8000   81 f1 00800000  (6 bytes)   ->   btc ecx, 15   0f ba f9 0f     (4 bytes)
//   and rax, ~0x100   48 25 fffeffff  (6 bytes)   ->   btr rax, 8    48 0f ba f0 08  (5 bytes)
// Bits 0-6 are excluded: those masks fit the sign-extended imm8 ALU form
// (83 /r ib, 3-4 bytes), which beats the bt encoding -- and a low-bit mask
// dressed up as an imm32 is check_oversized_immediate's finding. From bit 7
// up no imm8 form exists (a positive bit 7 is out of sign-extended-imm8
// reach for or/xor, and the matching clear mask is below it for and), so the
// ALU op needs imm32 and bts/btr/btc is strictly shorter for every register,
// accumulator forms included. Masks are matched at the effective operand
// width, which excludes the 64-bit sign-extension artifacts naturally
// (or rax with imm32 0x80000000 smears bits 32-63: not a single bit).
// bts/btr/btc r, imm8 execute as a single uop on current Intel and AMD, and
// both forms write the register at full operand width, so there is no
// register-liveness concern.
//
// 16-bit operands are excluded (or ax, imm16 via the accumulator opcode is 4
// bytes, beating bts ax's 5) and so are memory destinations: the bt family's
// memory forms micro-code as 3+ uops on several cores, so the byte saved is
// not a clean win there.
//
// False positive if surrounding code reads any arithmetic flag: and/or/xor
// define SF/ZF/PF and clear CF/OF, while the bt family sets CF to the
// selected bit's ORIGINAL value, preserves ZF, and leaves OF/SF/PF
// undefined. The dispatcher gates this on FLAG_ARITH.
bool check_single_bit_immediate(const xed_decoded_inst_t *xedd)
{
    xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass(xedd);
    switch (iclass) {
    case XED_ICLASS_AND:
    case XED_ICLASS_OR:
    case XED_ICLASS_XOR:
        break;
    default:
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

    // The bit the operation touches: set/flipped by or/xor, cleared by and.
    uint64_t bit = (iclass == XED_ICLASS_AND) ? ~eff & opmask : eff;
    return bit == 0 || (bit & (bit - 1)) != 0 || bit < 0x80;
}

bool check_missing_lock_prefix(const xed_decoded_inst_t *xedd)
{
    bool has_lock = xed_operand_values_has_lock_prefix(xed_decoded_inst_operands_const(xedd));

    switch (xed_decoded_inst_get_iclass(xedd)) {
    case XED_ICLASS_CMPXCHG:
    case XED_ICLASS_CMPXCHG16B:
    case XED_ICLASS_CMPXCHG8B:
    case XED_ICLASS_XADD:
        // LOCK is only legal with a memory destination. The register-form
        // encodings (ModRM.mod == 11, e.g. cmpxchg ebx, eax) cannot take a
        // LOCK prefix at all -- it would #UD -- so a missing prefix there is
        // not a fixable finding. (CMPXCHG8B/CMPXCHG16B are memory-only and
        // always pass this guard.)
        if (xed_decoded_inst_number_of_memory_operands(xedd) == 0) {
            return true;
        }
        if (!has_lock) {
            return false;
        }
        return true;
    case XED_ICLASS_CMPXCHG16B_LOCK:
    case XED_ICLASS_CMPXCHG8B_LOCK:
    case XED_ICLASS_CMPXCHG_LOCK:
    case XED_ICLASS_XADD_LOCK:
    default:
        return true;
    }
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
    return olen >= xed_decoded_inst_get_length(xedd);
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
static bool flags_live_after(const uint8_t *inst, size_t len, size_t offset,
                             uint32_t concerns)
{
    const int MAX_LOOKAHEAD = 16;
    uint32_t live = concerns;

    xed_machine_mode_enum_t mmode = XED_MACHINE_MODE_LONG_64;
    xed_address_width_enum_t stack_addr_width = XED_ADDRESS_WIDTH_64b;

    for (int step = 0; step < MAX_LOOKAHEAD && offset < len && live != 0; ++step) {
        xed_decoded_inst_t xedd;
        xed_decoded_inst_zero(&xedd);
        xed_decoded_inst_set_mode(&xedd, mmode, stack_addr_width);
        if (xed_decode(&xedd, inst + offset, len - offset) != XED_ERROR_NONE) {
            return true;
        }

        xed_category_enum_t category = xed_decoded_inst_get_category(&xedd);
        if (category == XED_CATEGORY_RET) {
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

// Walk forward from byte `offset` to decide whether bits 32-63 of the 64-bit
// GPR `reg64` might be read by a downstream instruction before being redefined.
// Returns true (LIVE) on yes or unknown; the dispatcher suppresses a finding
// whose rewrite would disturb those bits when this returns true. This is the
// register analogue of flags_live_after, built to answer the one register
// question the optimizations here raise: mov r32, r32's only effect beyond
// identity is zero-extending bits 32-63, so removing it is sound exactly when
// those bits are dead. Only the 64-bit register name reads them -- a read of
// eax/ax/al does not -- so the match is width-aware.
//
// Returns false (DEAD) only when an instruction unconditionally redefines those
// bits with no dependence on their prior value: a 32-bit write zero-extends
// into them, a 64-bit write sets them (see reg_kill_iclass), with no
// intervening read.
//
// Conservative LIVE on: decode error; ANY control transfer, RET included (a
// register may escape as a return value or a callee-saved register, neither of
// which a linear forward walk can rule out -- unlike flags, which no ABI
// preserves across RET, so flags_live_after treats RET as DEAD); running out of
// input; reaching the lookahead bound. Reads are matched inclusively
// (conditional reads count) and kills exclusively (only the whitelisted
// unconditional writers), so every uncertainty resolves toward LIVE.
static bool reg_upper32_live_after(const uint8_t *inst, size_t len,
                                   size_t offset, xed_reg_enum_t reg64)
{
    const int MAX_LOOKAHEAD = 16;

    xed_machine_mode_enum_t mmode = XED_MACHINE_MODE_LONG_64;
    xed_address_width_enum_t stack_addr_width = XED_ADDRESS_WIDTH_64b;

    for (int step = 0; step < MAX_LOOKAHEAD && offset < len; ++step) {
        xed_decoded_inst_t xedd;
        xed_decoded_inst_zero(&xedd);
        xed_decoded_inst_set_mode(&xedd, mmode, stack_addr_width);
        if (xed_decode(&xedd, inst + offset, len - offset) != XED_ERROR_NONE) {
            return true;
        }

        // A read of the full 64-bit register -- as an explicit or implicit
        // operand, or as a memory base or index -- observes bits 32-63. Matched
        // before the kill below, since an instruction can read the register and
        // then redefine it (e.g. add rax, rbx). Reading a 32/16/8 sub-register
        // does not touch bits 32-63, so compare the 64-bit name exactly.
        const xed_inst_t *xi = xed_decoded_inst_inst(&xedd);
        unsigned nops = xed_inst_noperands(xi);
        for (unsigned i = 0; i < nops; ++i) {
            const xed_operand_t *op = xed_inst_operand(xi, i);
            xed_operand_enum_t name = xed_operand_name(op);
            if (xed_operand_is_register(name) && xed_operand_read(op) &&
                xed_decoded_inst_get_reg(&xedd, name) == reg64) {
                return true;
            }
        }
        int nmem = xed_decoded_inst_number_of_memory_operands(&xedd);
        for (int m = 0; m < nmem; ++m) {
            if (xed_decoded_inst_get_base_reg(&xedd, m) == reg64 ||
                xed_decoded_inst_get_index_reg(&xedd, m) == reg64) {
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

        // An unconditional 32- or 64-bit write to the register redefines bits
        // 32-63 independent of their prior value: DEAD.
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

#define X86LINT_SUMMARY_MAX 64

struct x86lint_summary {
    struct {
        const char *name;
        unsigned count;
    } entries[X86LINT_SUMMARY_MAX];
    size_t count;
    size_t instructions;   // total decoded instructions across all runs
    size_t skipped;        // undecodable bytes skipped during resync
};

x86lint_summary *x86lint_summary_create(void)
{
    return calloc(1, sizeof(struct x86lint_summary));
}

void x86lint_summary_destroy(x86lint_summary *summary)
{
    free(summary);
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
// table). Linear scan -- the table is tiny. Silently ignores a NULL summary
// and the (cannot-happen with the current check set) overflow.
static void summary_add(x86lint_summary *summary, const char *name)
{
    if (summary == NULL || name == NULL) {
        return;
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

    // Undecodable bytes mean the section interleaves data with code (common in
    // Go binaries and jump tables); report them so incomplete coverage is not
    // mistaken for a clean scan.
    if (summary->skipped > 0) {
        printf("%zu undecodable byte%s skipped (data in code section?)\n\n",
            summary->skipped, summary->skipped == 1 ? "" : "s");
    }
}

// In verbose mode print a finding as a one-line summary -- the offending
// instruction disassembled at its address -- followed by the raw encoding
// indented beneath it. Non-verbose runs print nothing per finding; the
// caller's summary is the whole report.
static void report_finding(const char *name, size_t offset, bool verbose,
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
    printf("%s at offset: 0x%zx: %s\n", name, offset, disasm);

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
};

// check_suboptimal_nops is not in the table: it takes the raw byte stream
// (not a decoded instruction) and reports a 2-instruction window.
static const struct check_entry checks[] = {
    {check_oversized_immediate,        "oversized immediate",             0},
    {check_oversized_test_immediate,   "oversized TEST immediate",        0},
    {check_test_minus_one,             "redundant TEST immediate",        0},
    {check_oversized_add_sub_128,      "oversized ADD/SUB 128",           FLAG_CF},
    {check_unneeded_rex,               "unneeded REX prefix",             0},
    {check_cmp_zero,                   "suboptimal CMP zero",             0},
    {check_mov_zero,                   "suboptimal MOV zero",             FLAG_ARITH},
    {check_implicit_register,          "unneeded explicit register",      0},
    {check_implicit_immediate,         "unneeded explicit immediate",     0},
    {check_and_strength_reduce,        "suboptimal AND immediate",        FLAG_ARITH},
    {check_and_minus_one,              "redundant AND immediate",         0, reg0_upper32_concern, true},
    {check_and_zero,                   "suboptimal AND zero",             0},
    {check_xor_to_not,                 "suboptimal XOR immediate",        FLAG_ARITH},
    {check_single_bit_immediate,       "suboptimal single-bit immediate", FLAG_ARITH},
    {check_missing_lock_prefix,        "missing LOCK prefix",             0},
    {check_superfluous_lock_prefix,    "unneeded LOCK prefix",            0},
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

    xed_machine_mode_enum_t mmode = XED_MACHINE_MODE_LONG_64;
    xed_address_width_enum_t stack_addr_width = XED_ADDRESS_WIDTH_64b;

    for (size_t offset = 0; offset < len;) {
        xed_decoded_inst_t xedd;
        xed_decoded_inst_zero(&xedd);
        xed_decoded_inst_set_mode(&xedd, mmode, stack_addr_width);
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

static bool flags_test_redundant(const uint8_t *inst, size_t len,
                                 const uint8_t *branch_targets,
                                 size_t test_offset,
                                 const xed_decoded_inst_t *producer,
                                 xed_decoded_inst_t *test_out)
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
    // first operand when it is not memory.
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
    if (dest == XED_REG_INVALID) {
        return false;
    }

    // The following instruction must be test dest, dest.
    if (test_offset >= len) {
        return false;
    }
    xed_decoded_inst_zero(test_out);
    xed_decoded_inst_set_mode(test_out, XED_MACHINE_MODE_LONG_64,
                              XED_ADDRESS_WIDTH_64b);
    if (xed_decode(test_out, inst + test_offset, len - test_offset) !=
            XED_ERROR_NONE) {
        return false;
    }
    if (xed_decoded_inst_get_iclass(test_out) != XED_ICLASS_TEST ||
        xed_decoded_inst_number_of_memory_operands(test_out) > 0 ||
        xed_decoded_inst_get_reg(test_out, XED_OPERAND_REG0) != dest ||
        xed_decoded_inst_get_reg(test_out, XED_OPERAND_REG1) != dest) {
        return false;
    }

    // An incoming direct edge onto the test reaches it without the producer;
    // dropping the test would break that path.
    if (branch_target_in(branch_targets, test_offset,
            test_offset + xed_decoded_inst_get_length(test_out))) {
        return false;
    }

    // Arithmetic producers diverge from the test on CF/OF; suppress while
    // either might still be read past the test.
    if (divergent != 0) {
        size_t after = test_offset + xed_decoded_inst_get_length(test_out);
        if (flags_live_after(inst, len, after, divergent)) {
            return false;
        }
    }
    return true;
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

    xed_machine_mode_enum_t mmode = XED_MACHINE_MODE_LONG_64;
    xed_address_width_enum_t stack_addr_width = XED_ADDRESS_WIDTH_64b;

    for (int step = 0; step < MAX_LOOKAHEAD && offset < len; ++step) {
        xed_decoded_inst_t xedd;
        xed_decoded_inst_zero(&xedd);
        xed_decoded_inst_set_mode(&xedd, mmode, stack_addr_width);
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
    xed_decoded_inst_zero(&consumer);
    xed_decoded_inst_set_mode(&consumer, XED_MACHINE_MODE_LONG_64,
                              XED_ADDRESS_WIDTH_64b);
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
    xed_decoded_inst_zero(&consumer);
    xed_decoded_inst_set_mode(&consumer, XED_MACHINE_MODE_LONG_64,
                              XED_ADDRESS_WIDTH_64b);
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
    xed_decoded_inst_zero(&ext);
    xed_decoded_inst_set_mode(&ext, XED_MACHINE_MODE_LONG_64,
                              XED_ADDRESS_WIDTH_64b);
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
    // imm, or inc/dec dest (add/sub by an implied 1).
    if (add_offset >= len) {
        return false;
    }
    xed_decoded_inst_t add;
    xed_decoded_inst_zero(&add);
    xed_decoded_inst_set_mode(&add, XED_MACHINE_MODE_LONG_64,
                              XED_ADDRESS_WIDTH_64b);
    if (xed_decode(&add, inst + add_offset, len - add_offset) !=
            XED_ERROR_NONE) {
        return false;
    }
    xed_iclass_enum_t cic = xed_decoded_inst_get_iclass(&add);
    uint32_t divergent;
    switch (cic) {
    case XED_ICLASS_ADD:
    case XED_ICLASS_SUB:
        divergent = FLAG_ARITH;
        break;
    case XED_ICLASS_INC:
    case XED_ICLASS_DEC:
        // inc/dec leave CF untouched exactly as lea does, so only the flags
        // they do write can diverge.
        divergent = FLAG_ARITH & ~FLAG_CF;
        break;
    default:
        return false;
    }
    if (xed_decoded_inst_number_of_memory_operands(&add) != 0 ||
        xed_decoded_inst_get_reg(&add, XED_OPERAND_REG0) != dest) {
        return false;
    }

    // An incoming direct edge onto the consumer reaches it without the mov --
    // the canonical scan loop enters at its increment (mov rbx, rax ; L: add
    // rbx, 1 ; ... ; je L), where the fold would turn the increment into a
    // per-iteration reset. Suppress.
    if (branch_target_in(branch_targets, add_offset,
            add_offset + xed_decoded_inst_get_length(&add))) {
        return false;
    }

    if (cic == XED_ICLASS_ADD &&
        !xed_operand_values_has_immediate(
            xed_decoded_inst_operands_const(&add))) {
        // Register addend: add dest, srcB -> lea dest, [srcA + srcB].
        xed_reg_enum_t src_b = xed_decoded_inst_get_reg(&add, XED_OPERAND_REG1);
        if (xed_reg_class(src_b) != XED_REG_CLASS_GPR ||
            xed_get_largest_enclosing_register(src_b) == dest_enc) {
            return false;
        }
        // [rsp + rsp] cannot be encoded: RSP is not a legal SIB index.
        if (xed_get_largest_enclosing_register(src_a) == XED_REG_RSP &&
            xed_get_largest_enclosing_register(src_b) == XED_REG_RSP) {
            return false;
        }
    } else {
        // Immediate addend: add/sub dest, imm or inc/dec dest ->
        // lea dest, [srcA + disp], the displacement negated for sub/dec.
        int64_t disp;
        if (cic == XED_ICLASS_INC) {
            disp = 1;
        } else if (cic == XED_ICLASS_DEC) {
            disp = -1;
        } else {
            if (!xed_operand_values_has_immediate(
                    xed_decoded_inst_operands_const(&add))) {
                return false;   // sub dest, srcB: lea cannot subtract a register
            }
            int64_t imm = xed_decoded_inst_get_signed_immediate(&add);
            if (imm == 0) {
                return false;   // the add/sub is check_add_sub_zero's finding
            }
            disp = (cic == XED_ICLASS_SUB) ? -imm : imm;
        }
        // A 16/32-bit lea truncates the address to the destination width, so
        // any immediate folds mod 2^w; a 64-bit pair uses the displacement at
        // full value, which must fit disp32 -- everything but the negation of
        // sub rdx, INT32_MIN.
        if (xed_get_register_width_bits64(dest) == 64 &&
            (disp < INT32_MIN || disp > INT32_MAX)) {
            return false;
        }
    }

    // lea writes no flags; suppress while any flag the consumer sets
    // diverges -- i.e. may be read before being overwritten.
    size_t after = add_offset + xed_decoded_inst_get_length(&add);
    return !flags_live_after(inst, len, after, divergent);
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
    xed_decoded_inst_zero(&sar);
    xed_decoded_inst_set_mode(&sar, XED_MACHINE_MODE_LONG_64,
                              XED_ADDRESS_WIDTH_64b);
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
    xed_decoded_inst_zero(&jcc);
    xed_decoded_inst_set_mode(&jcc, XED_MACHINE_MODE_LONG_64,
                              XED_ADDRESS_WIDTH_64b);
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
    xed_decoded_inst_zero(&test);
    xed_decoded_inst_set_mode(&test, XED_MACHINE_MODE_LONG_64,
                              XED_ADDRESS_WIDTH_64b);
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
    xed_decoded_inst_zero(&jcc);
    xed_decoded_inst_set_mode(&jcc, XED_MACHINE_MODE_LONG_64,
                              XED_ADDRESS_WIDTH_64b);
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
// missing LOCK's precedent -- so no liveness gate applies. Matched tightly
// so each finding is the real idiom:
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
    xed_decoded_inst_zero(movzx_out);
    xed_decoded_inst_set_mode(movzx_out, XED_MACHINE_MODE_LONG_64,
                              XED_ADDRESS_WIDTH_64b);
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

int check_instructions(const uint8_t *inst, size_t len, bool verbose,
                       x86lint_summary *summary)
{
    int errors = 0;
    xed_machine_mode_enum_t mmode = XED_MACHINE_MODE_LONG_64;
    xed_address_width_enum_t stack_addr_width = XED_ADDRESS_WIDTH_64b;

    // The immediately preceding decoded instruction, for the one backward-
    // looking gate (check_mov_self's already-zero-extended case). have_prev is
    // false at the start and after any resync skip, so `prev` is consulted only
    // when it is adjacent to the current instruction.
    xed_decoded_inst_t prev;
    bool have_prev = false;

    // Direct branch targets for the multi-instruction windows (see
    // collect_branch_targets). NULL on allocation failure, which
    // branch_target_in treats as every-offset-targeted: the multi-instruction
    // findings are then conservatively suppressed while the single-instruction
    // checks proceed.
    uint8_t *branch_targets = collect_branch_targets(inst, len);

    for (size_t offset = 0; offset < len;) {
        xed_decoded_inst_t xedd;
        xed_decoded_inst_zero(&xedd);
        xed_decoded_inst_set_mode(&xedd, mmode, stack_addr_width);

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
            xed_decoded_inst_zero(&xedd2);
            xed_decoded_inst_set_mode(&xedd2, mmode, stack_addr_width);
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
            summary_add(summary, checks[i].name);
            report_finding(checks[i].name, offset, verbose, &xedd,
                inst + offset);
            ++errors;
        }

        // Multi-instruction peephole: a flag-setting ALU write immediately
        // followed by test reg, reg on the same register makes the test
        // redundant. Reported against the test (at `next`), the removable
        // instruction. See flags_test_redundant.
        xed_decoded_inst_t redundant_test;
        if (flags_test_redundant(inst, len, branch_targets, next, &xedd,
                                 &redundant_test)) {
            summary_add(summary, "redundant TEST after flags");
            report_finding("redundant TEST after flags", next, verbose,
                &redundant_test, inst + next);
            ++errors;
        }

        // Multi-instruction peephole: lea reg, [addr] whose address folds into
        // the next instruction's memory operand, leaving reg dead. Reported
        // against the lea (at `offset`), the removable instruction. See
        // lea_foldable_into_memop.
        if (lea_foldable_into_memop(inst, len, branch_targets, next, &xedd)) {
            summary_add(summary, "LEA foldable into memory");
            report_finding("LEA foldable into memory", offset, verbose, &xedd,
                inst + offset);
            ++errors;
        }

        // Multi-instruction peephole: mov reg, imm whose constant folds into the
        // next instruction's immediate, leaving reg dead. Reported against the
        // mov (at `offset`), the removable instruction. See mov_const_foldable.
        if (mov_const_foldable(inst, len, branch_targets, next, &xedd)) {
            summary_add(summary, "MOV constant foldable");
            report_finding("MOV constant foldable", offset, verbose, &xedd,
                inst + offset);
            ++errors;
        }

        // Multi-instruction peephole: a narrow load feeding an in-place sign/
        // zero-extension is a single extending load. Reported against the load
        // (at `offset`), the removable instruction. See
        // load_foldable_into_extend.
        if (load_foldable_into_extend(inst, len, branch_targets, next,
                                      &xedd)) {
            summary_add(summary, "load foldable into extend");
            report_finding("load foldable into extend", offset, verbose, &xedd,
                inst + offset);
            ++errors;
        }

        // Multi-instruction peephole: mov dest, srcA followed by an add into
        // dest -- add dest, srcB, add/sub dest, imm, or inc/dec dest -- is
        // the three-operand lea dest, [srcA + addend], saving the mov.
        // Reported against the mov (at `offset`). See mov_add_foldable_to_lea.
        if (mov_add_foldable_to_lea(inst, len, branch_targets, next, &xedd)) {
            summary_add(summary, "MOV+ADD foldable to LEA");
            report_finding("MOV+ADD foldable to LEA", offset, verbose, &xedd,
                inst + offset);
            ++errors;
        }

        // Multi-instruction peephole: shl reg, k ; sar/shr reg, k sign- or
        // zero-extends the low width-k bits in place, which a single movsx/
        // movzx computes. Reported against the shl (at `offset`). See
        // shift_pair_foldable_to_extend.
        if (shift_pair_foldable_to_extend(inst, len, branch_targets, next,
                                          &xedd)) {
            summary_add(summary, "shift pair foldable into extend");
            report_finding("shift pair foldable into extend", offset, verbose,
                &xedd, inst + offset);
            ++errors;
        }

        // Multi-instruction peephole: cmp reg, 1 ; jb/jae branches on
        // "unsigned < 1", which is "== 0" -- test reg, reg ; jz/jnz answers it
        // a byte shorter. Reported against the cmp (at `offset`). See
        // cmp_one_branch_foldable.
        if (cmp_one_branch_foldable(inst, len, branch_targets, next, &xedd)) {
            summary_add(summary, "suboptimal CMP one");
            report_finding("suboptimal CMP one", offset, verbose, &xedd,
                inst + offset);
            ++errors;
        }

        // Multi-instruction peephole: setcc X ; test X, X ; je/jne branches on a
        // condition the compare flags still hold, so the test is redundant.
        // Reported against the setcc (at `offset`). See redundant_test_after_setcc.
        if (redundant_test_after_setcc(inst, len, branch_targets, next,
                                       &xedd)) {
            summary_add(summary, "redundant TEST after SETcc");
            report_finding("redundant TEST after SETcc", offset, verbose, &xedd,
                inst + offset);
            ++errors;
        }

        // Multi-instruction peephole (advisory): setcc X ; movzx of X into
        // its own 32/64-bit parent. Intel's preferred form zeroes the parent
        // ahead of the compare instead, dropping the movzx and its
        // partial-register merge. Reported against the movzx (at `next`),
        // the instruction the preferred form removes. See
        // setcc_movzx_zero_extend.
        xed_decoded_inst_t widen_movzx;
        if (setcc_movzx_zero_extend(inst, len, branch_targets, next, &xedd,
                                    &widen_movzx)) {
            summary_add(summary, "suboptimal SETcc zero-extension");
            report_finding("suboptimal SETcc zero-extension", next, verbose,
                &widen_movzx, inst + next);
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
            summary_add(summary, "redundant re-extension");
            report_finding("redundant re-extension", offset, verbose, &xedd,
                inst + offset);
            ++errors;
        }

        prev = xedd;
        have_prev = true;
        offset = next;
    }

    free(branch_targets);
    return errors;
}
