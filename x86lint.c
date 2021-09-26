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
        if (!cur_nop) {
            break;
        }
        // Assume that NOPs are greedy, encoding 10 bytes as 9 + 1 NOPs
        if (prev_nop > 0 && prev_nop <= 8) {
            return false;
        }

        prev_nop = xed_decoded_inst_get_length(&xedd);
        i += prev_nop;
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
        if (iclass != XED_ICLASS_MOV && imm >= INT8_MIN && imm <= INT8_MAX) {
            return false;
        }
        break;
    case 64:
        // TODO: sign vs. zero extension; should this be >= 0 and <= UINT32_MAX?
        if (imm >= INT32_MIN && imm <= INT32_MAX) {
            return false;
        }
        break;
    default:
        abort();
    }
    return true;
}

// Check for ADD REG, 128 which encodes as 5 bytes instead of SUB REG, -128
// which encodes in 3 bytes.
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
        abort();
    }
    return true;
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
    switch (xed_decoded_inst_get_iclass(xedd)) {
    // TODO: instructions not requiring a REX prefix in 64-bit mode
    // CALL (Near)
    // ENTER
    // Jcc
    // JrCXZ
    // JMP (Near)
    // LEAVE
    // LGDT
    // LIDT
    // LLDT
    // LOOP
    // LOOPcc
    // LTR
    // MOV CRn
    // MOV DRn
    // POP reg/mem
    // POP reg
    // POP FS
    // POP GS
    // POPF, POPFD, POPFQ
    // PUSH imm8
    // PUSH imm32
    // PUSH reg/mem
    // PUSH reg
    // PUSH FS
    // PUSH GS
    // PUSHF, PUSHFD, PUSHFQ
    // RET (Near)
    case XED_ICLASS_LEAVE:
        return !xed3_operand_get_rex(xedd);
    default:
        break;
    }

    for (int i = 0; i < xed_decoded_inst_number_of_memory_operands(xedd); ++i) {
        if (check_rex_register(xed_decoded_inst_get_base_reg(xedd, i)) ||
            check_rex_register(xed_decoded_inst_get_index_reg(xedd, i))) {
            return true;
        }
    }
    if (check_rex_register(xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0)) ||
        check_rex_register(xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1)) ||
        // TODO: are these correct?
        check_rex_register(xed_decoded_inst_get_seg_reg(xedd, XED_OPERAND_REG0)) ||
        check_rex_register(xed_decoded_inst_get_seg_reg(xedd, XED_OPERAND_REG1))) {
        return true;
    }

    // Check if instruction has a REX prefix.
    // TODO: REX byte must come first but is there a more robust way to test this?
    int8_t prefix = xed_decoded_inst_get_byte(xedd, 0);
    // TODO: handle instructions which do not default to 64-bit operands
    // TODO: look at xed_operand_values_has_rexw_prefix(xed_decoded_inst_operands_const(xedd))
    if ((prefix & 0xf0) != 0x40) {
        return true;
    }

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
    // TODO: POP reg/mem
    // TODO: POP reg
    // TODO: POP FS
    // TODO: POP GS
    case XED_ICLASS_POPFQ:
    // TODO: PUSH imm8
    // TODO: PUSH imm32
    // TODO: PUSH reg/mem
    // TODO: PUSH reg
    // TODO: PUSH FS
    // TODO: PUSH GS
    case XED_ICLASS_PUSHFQ:
    case XED_ICLASS_RET_NEAR:
        return false;
    case XED_ICLASS_XOR:
        // register could be zero-extended from 32-bit
        if (xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0) != XED_REG_INVALID &&
            xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1) != XED_REG_INVALID) {
            return false;
        }
        break;
    default:
        break;
    }

    if ((prefix & 0x0f) == 0) {
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
        abort();
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
    switch (xedd->_inst->_iform_enum) {
    case XED_IFORM_RCL_GPRv_IMMb:
    case XED_IFORM_RCR_GPRv_IMMb:
    case XED_IFORM_ROL_GPRv_IMMb:
    case XED_IFORM_ROR_GPRv_IMMb:
    //case XED_IFORM_SAL_GPRv_IMMb:
    case XED_IFORM_SAR_GPRv_IMMb:
    //case XED_IFORM_SHL_GPRv_IMMb:
    case XED_IFORM_SHR_GPRv_IMMb:
        return false;
    }
    return true;
}

bool check_and_strength_reduce(const xed_decoded_inst_t *xedd)
{
    if (xed_decoded_inst_get_iclass(xedd) != XED_ICLASS_AND) {
        return true;
    }

    xed_uint64_t imm = xed_decoded_inst_get_unsigned_immediate(xedd);
    return imm != 0xff && imm != 0xffff && imm != 0xffffffff;
}

bool check_missing_lock_prefix(const xed_decoded_inst_t *xedd)
{
    bool has_lock = xed_operand_values_has_lock_prefix(xed_decoded_inst_operands_const(xedd));

    switch (xed_decoded_inst_get_iclass(xedd)) {
    case XED_ICLASS_CMPXCHG:
    case XED_ICLASS_CMPXCHG16B:
    case XED_ICLASS_CMPXCHG8B:
    case XED_ICLASS_XADD:
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
            printf("Decoding error at offset: %zu: %s\n", offset, xed_error_enum_t2str(err));
            return -1;
        }

        bool result = check_suboptimal_nops(inst + offset, len - offset);
        if (!result) {
            printf("suboptimal nops at offset: %zu\n", offset);
            dump_instruction(&xedd);
            dump_machine_code(&xedd, inst + offset);

            xed_decoded_inst_t xedd2;
            xed_decoded_inst_zero(&xedd2);
            xed_decoded_inst_set_mode(&xedd2, mmode, stack_addr_width);

            size_t len2 = xed_decoded_inst_get_length(&xedd);
            xed_decode(&xedd2, inst + offset + len2, len - offset - len2);
            dump_instruction(&xedd2);
            dump_machine_code(&xedd2, inst + offset + len2);
            printf("\n");
            ++errors;
        }

        result = check_oversized_immediate(&xedd);
        if (!result) {
            printf("oversized immediate at offset: %zu\n", offset);
            dump_instruction(&xedd);
            dump_machine_code(&xedd, inst + offset);
            printf("\n");
            ++errors;
        }

        result = check_oversized_add128(&xedd);
        if (!result) {
            printf("oversized ADD 128 at offset: %zu\n", offset);
            dump_instruction(&xedd);
            dump_machine_code(&xedd, inst + offset);
            printf("\n");
            ++errors;
        }

        result = check_unneeded_rex(&xedd);
        if (!result) {
            printf("unneeded REX prefix at offset: %zu\n", offset);
            dump_instruction(&xedd);
            dump_machine_code(&xedd, inst + offset);
            printf("\n");
            ++errors;
        }

        result = check_cmp_zero(&xedd);
        if (!result) {
            printf("suboptimal compare register at offset: %zu\n", offset);
            dump_instruction(&xedd);
            dump_machine_code(&xedd, inst + offset);
            printf("\n");
            ++errors;
        }

        // TODO: Disabled due to false positives from CMOV sequences.  See #7.
        /*
        result = check_mov_zero(&xedd);
        if (!result) {
            printf("suboptimal zero register at offset: %zu\n", offset);
            dump_instruction(&xedd);
            dump_machine_code(&xedd, inst + offset);
            printf("\n");
            ++errors;
        }
        */

        result = check_implicit_register(&xedd);
        if (!result) {
            printf("unneeded explicit register at offset: %zu\n", offset);
            dump_instruction(&xedd);
            dump_machine_code(&xedd, inst + offset);
            printf("\n");
            ++errors;
        }

        result = check_implicit_immediate(&xedd);
        if (!result) {
            printf("unneeded explicit immediate at offset: %zu\n", offset);
            dump_instruction(&xedd);
            dump_machine_code(&xedd, inst + offset);
            printf("\n");
            ++errors;
        }

        result = check_and_strength_reduce(&xedd);
        if (!result) {
            printf("unneeded AND immediate at offset: %zu\n", offset);
            dump_instruction(&xedd);
            dump_machine_code(&xedd, inst + offset);
            printf("\n");
            ++errors;
        }

        result = check_missing_lock_prefix(&xedd);
        if (!result) {
            printf("expected lock prefix at offset: %zu\n", offset);
            dump_instruction(&xedd);
            dump_machine_code(&xedd, inst + offset);
            printf("\n");
            ++errors;
        }

        result = check_superfluous_lock_prefix(&xedd);
        if (!result) {
            printf("superfluous lock prefix at offset: %zu\n", offset);
            dump_instruction(&xedd);
            dump_machine_code(&xedd, inst + offset);
            printf("\n");
            ++errors;
        }

        offset += xed_decoded_inst_get_length(&xedd);
    }

    return errors;
}
