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

// TODO: consider valid uses of oversized immediate to avoid explicit no-op padding
bool check_oversized_immediate(const xed_decoded_inst_t *xedd)
{
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

/**
 * A REX prefix must be encoded when:
 *
 * * using 64-bit operand size and the instruction does not default to 64-bit operand size; or
 * * using one of the extended registers (R8 to R15, XMM8 to XMM15, YMM8 to YMM15, CR8 to CR15 and DR8 to DR15); or
 * * using one of the uniform byte registers SPL, BPL, SIL or DIL.
 */
bool check_unneeded_rex(const xed_decoded_inst_t *xedd)
{
    int8_t prefix = xed_decoded_inst_get_byte(xedd, 0);
    // TODO: handle instructions which do not default to 64-bit operands
    if ((prefix & 0xf0) != 0x40) {
        return true;
    }

    switch (xed_decoded_inst_get_iclass(xedd)) {
    case XED_ICLASS_CALL_NEAR:
    case XED_ICLASS_ENTER:
    case XED_ICLASS_JB: case XED_ICLASS_JBE: case XED_ICLASS_JL: case XED_ICLASS_JLE: case XED_ICLASS_JNB: case XED_ICLASS_JNBE: case XED_ICLASS_JNL: case XED_ICLASS_JNLE: case XED_ICLASS_JNO: case XED_ICLASS_JNP: case XED_ICLASS_JNS: case XED_ICLASS_JNZ: case XED_ICLASS_JO: case XED_ICLASS_JP: case XED_ICLASS_JS: case XED_ICLASS_JZ:
    case XED_ICLASS_JCXZ: case XED_ICLASS_JECXZ: case XED_ICLASS_JRCXZ:
    case XED_ICLASS_JMP:
    case XED_ICLASS_LEAVE:
    case XED_ICLASS_LGDT:
    case XED_ICLASS_LIDT:
    case XED_ICLASS_LLDT:
    case XED_ICLASS_LOOP:
    case XED_ICLASS_LOOPE: case XED_ICLASS_LOOPNE:
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
    default:
        break;
    }

    if ((prefix & 0x0f) == 0) {
        return false;
    }
    return true;
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

    switch (xed_decoded_inst_get_immediate_width_bits(xedd)) {
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

    if (xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0) == XED_REG_EAX && xed_operand_values_has_modrm_byte(xedd)) {
        return false;
    }

    return true;
}

static void dump_instruction(const xed_decoded_inst_t *xedd)
{
    char buf[1024];
    xed_decoded_inst_dump(xedd, buf, sizeof(buf));
    //printf("%s\n", buf);
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
        xed_error_enum_t err = xed_decode(&xedd, inst + offset, len);
        // TODO: better error handling
        assert(err == XED_ERROR_NONE);

        bool result = check_oversized_immediate(&xedd);
        if (!result) {
            printf("oversized immediate at offset: %zu\n", offset);
            dump_instruction(&xedd);
            ++errors;
        }

        result = check_unneeded_rex(&xedd);
        if (!result) {
            printf("unneeded REX prefix at offset: %zu\n", offset);
            dump_instruction(&xedd);
            ++errors;
        }

        result = check_mov_zero(&xedd);
        if (!result) {
            printf("suboptimal zero register: %zu\n", offset);
            dump_instruction(&xedd);
            ++errors;
        }

        result = check_implicit_register(&xedd);
        if (!result) {
            printf("unneeded explicit register: %zu\n", offset);
            dump_instruction(&xedd);
            ++errors;
        }

        offset += xed_decoded_inst_get_length(&xedd);
    }

    return errors;
}
