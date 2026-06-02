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
#include "xed/xed-interface.h"

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
            return false;
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

    if (!xed_operand_values_has_immediate(xed_decoded_inst_operands_const(xedd))) {
        return true;
    }

    int64_t imm = (int64_t) xed_decoded_inst_get_unsigned_immediate(xedd);

    switch (xed_decoded_inst_get_immediate_width_bits(xedd)) {
    case 8:
    case 16:
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

// Check for ADD REG, 128 which encodes as 5 bytes instead of SUB REG, -128
// which encodes in 3 bytes.
//
// False positive if surrounding code reads CF: ADD sets CF on unsigned
// overflow, SUB sets CF on borrow, so a subsequent JC/JNC/ADC/SBB diverges.
bool check_oversized_add128(const xed_decoded_inst_t *xedd)
{
    if (!xed_operand_values_has_immediate(xed_decoded_inst_operands_const(xedd))) {
        return true;
    }

    if (xed_decoded_inst_get_iclass(xedd) != XED_ICLASS_ADD) {
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

// AND DST, IMM can be replaced by MOVZBL / MOVZWL / MOV (the last via the
// EAX-write zero-extension rule) when the mask keeps a low byte/word/dword
// and zeros everything above it -- e.g. and eax, 0xff -> movzx eax, al.
// All three replacements produce a register zero-extended through bit 63,
// so the substitution is valid only when:
//
//   * the destination is a register (movzx/mov cannot target memory); and
//   * the AND writes a 32- or 64-bit register, so the write itself clears
//     bits up to 63 (an 8-/16-bit AND preserves the upper register bytes,
//     which movzx/mov would instead zero); and
//   * the *effective* mask -- the immediate sign-extended and truncated to
//     the operand width -- is exactly 0xff, 0xffff, or (32-bit operand
//     only) 0xffffffff.
//
// Matching the effective mask rather than the raw immediate byte is what
// separates a genuine low-byte mask (and eax, 0xff, encoded with an imm32)
// from a sign-extended all-ones no-op (and eax, sx(0xff) = 0xffffffff,
// encoded 83 e0 ff): the former reduces to movzbl, the latter to a plain
// mov eax, eax. An all-ones mask on a 64-bit operand is a no-op with no
// shorter zero-extending equivalent, so it is left alone.
//
// False positive if surrounding code reads ZF/SF/PF: AND sets them based
// on the masked result and clears CF/OF; MOVZX and MOV do not touch
// flags. A subsequent JZ/JS/JP would diverge.
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
    if (width == 32 && eff == 0xffffffff) {
        return false;
    }
    return true;
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

// IMUL r, r, imm by a small constant can be replaced by a single LEA,
// which on most uarches has shorter latency and uses the AGU instead of
// the multiplier.
//
//   * imm in {2,3,5,9}: dst = src*{2,3,5,9} is lea [src + src*{1,2,4,8}],
//     valid for any destination register.
//   * imm in {4,8}: the single-LEA form would be [src*scale], which needs
//     an absolute disp32 (SIB base=101) and is *longer* than the IMUL. The
//     only shorter/faster replacement is SHL by {2,3}, which requires the
//     destination and source to be the same register; a different-register
//     imul r, r2, {4,8} has no improvement and is left alone.
//
// Memory-source IMUL (IMUL r, [m], imm) is not flagged: the replacement
// would need a separate load instruction first, making the sequence
// longer and not strictly faster.
//
// False positive if surrounding code reads CF or OF: IMUL sets both on
// signed overflow; LEA and SHL do not produce the same CF/OF. A subsequent
// JC/JNC/JO/JNO would diverge.
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
    switch (xed_decoded_inst_get_unsigned_immediate(xedd)) {
    case 2: case 3: case 5: case 9:
        return false;
    case 4: case 8: {
        // Only reducible (to SHL) when destination and source coincide.
        xed_reg_enum_t dst = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);
        xed_reg_enum_t src = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1);
        return !(dst != XED_REG_INVALID && dst == src);
    }
    default:
        return true;
    }
}

// Shift and rotate instructions with an immediate count of 0 are pure
// no-ops: the destination is unchanged and per the Intel SDM the flags
// are explicitly "not affected" when the count is 0. The CL-register
// form cannot be checked statically.
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

    if (!xed_operand_values_has_immediate(xed_decoded_inst_operands_const(xedd))) {
        return true;
    }

    return xed_decoded_inst_get_unsigned_immediate(xedd) != 0;
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

// movsxd rax, eax (48 63 c0, 3 bytes) sign-extends EAX into RAX. The
// CDQE / cltq instruction (48 98, 2 bytes) does the same.
// TODO: similar opportunities exist for movsx eax, ax -> cwde and
// movsx ax, al -> cbw.
bool check_unneeded_movsxd(const xed_decoded_inst_t *xedd)
{
    if (xed_decoded_inst_get_iclass(xedd) != XED_ICLASS_MOVSXD) {
        return true;
    }

    xed_reg_enum_t r0 = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);
    xed_reg_enum_t r1 = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1);
    return !(r0 == XED_REG_RAX && r1 == XED_REG_EAX);
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
// regardless of downstream flag liveness.
//
// AL is excluded: add al, 0 already fits in 2 bytes via the 04 ib
// accumulator opcode, exactly tying test al, al, so substituting test
// saves nothing (cf. check_cmp_zero). Memory operands are excluded too:
// those touches may be intentional (cache-line warm, MMIO trigger).
bool check_add_zero(const xed_decoded_inst_t *xedd)
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

// mov reg, reg with both operands the same register is a no-op, with one
// exception: mov r32, r32 deliberately zero-extends to the corresponding
// r64 (writing any 32-bit register clears the upper 32 bits). The 8-,
// 16-, and 64-bit forms have no such side effect and are pure waste.
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

    if (xed_decoded_inst_get_operand_width(xedd) == 32) {
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

    int32_t disp = (int32_t) xed_decoded_inst_get_branch_displacement(xedd);
    int32_t new_disp = disp + size_delta;
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
// Returns false (DEAD) only after seeing every flag in `concerns` written
// by straight-line code, or after hitting a function-exit terminator
// (RET / IRET; neither the SysV nor Win64 ABI preserves flags across calls).
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
            uint32_t w = flag_set_to_mask(xed_simple_flag_get_written_flag_set(fi)) |
                         flag_set_to_mask(xed_simple_flag_get_undefined_flag_set(fi));
            if (r & live) {
                return true;
            }
            live &= ~w;
        }

        offset += xed_decoded_inst_get_length(&xedd);
    }

    return live != 0;
}

static void dump_instruction(const xed_decoded_inst_t *xedd)
{
    char buf[1024];
    xed_decoded_inst_dump(xedd, buf, sizeof(buf));
    printf("%s\n", buf);
}

static void dump_machine_code(const xed_decoded_inst_t *xedd, const uint8_t *inst)
{
    int i;
    int len = xed_decoded_inst_get_length(xedd);
    for (i = 0; i < len; ++i) {
        printf("%02x ", inst[i]);
    }
    printf("\n");
}

static void report_finding(const char *name, size_t offset,
                           const xed_decoded_inst_t *xedd, const uint8_t *bytes)
{
    printf("%s at offset: %zu\n", name, offset);
    dump_instruction(xedd);
    dump_machine_code(xedd, bytes);
    printf("\n");
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
};

// check_suboptimal_nops is not in the table: it takes the raw byte stream
// (not a decoded instruction) and reports a 2-instruction window.
static const struct check_entry checks[] = {
    {check_oversized_immediate,        "oversized immediate",             0},
    {check_oversized_add128,           "oversized ADD 128",               FLAG_CF},
    {check_unneeded_rex,               "unneeded REX prefix",             0},
    {check_cmp_zero,                   "suboptimal CMP zero",             0},
    {check_mov_zero,                   "suboptimal MOV zero",             FLAG_ARITH},
    {check_implicit_register,          "unneeded explicit register",      0},
    {check_implicit_immediate,         "unneeded explicit immediate",     0},
    {check_and_strength_reduce,        "suboptimal AND immediate",        FLAG_ARITH},
    {check_missing_lock_prefix,        "missing LOCK prefix",             0},
    {check_superfluous_lock_prefix,    "unneeded LOCK prefix",            0},
    {check_oversized_branch,           "oversized branch displacement",   0},
    {check_mov_self,                   "redundant MOV reg, reg",          0},
    {check_add_zero,                   "redundant ADD/SUB zero",          0},
    {check_mov_modrm_imm,              "oversized MOV encoding",          0},
    {check_unneeded_sib,               "unneeded SIB byte",               0},
    {check_unneeded_zero_displacement, "unneeded zero displacement",      0},
    {check_unneeded_movsxd,            "unneeded MOVSXD",                 0},
    {check_sub_self,                   "suboptimal SUB reg, reg",         0},
    {check_imul_to_lea,                "suboptimal IMUL constant",        FLAG_CF | FLAG_OF},
    {check_shift_zero,                 "redundant shift/rotate by zero",  0},
};

int check_instructions(const uint8_t *inst, size_t len)
{
    int errors = 0;
    xed_machine_mode_enum_t mmode = XED_MACHINE_MODE_LONG_64;
    xed_address_width_enum_t stack_addr_width = XED_ADDRESS_WIDTH_64b;

    for (size_t offset = 0; offset < len;) {
        xed_decoded_inst_t xedd;
        xed_decoded_inst_zero(&xedd);
        xed_decoded_inst_set_mode(&xedd, mmode, stack_addr_width);

        xed_error_enum_t err = xed_decode(&xedd, inst + offset, len - offset);
        if (err != XED_ERROR_NONE) {
            printf("Decoding error at offset: %zu: %s\n",
                offset, xed_error_enum_t2str(err));
            return -1;
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
            report_finding(checks[i].name, offset, &xedd, inst + offset);
            ++errors;
        }

        offset = next;
    }

    return errors;
}
