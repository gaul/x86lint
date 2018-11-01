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
#include <stdio.h>

#include "asmlint.h"
#include "xed/xed-interface.h"

static void decode_instruction(xed_decoded_inst_t *xedd, const uint8_t *inst, size_t len)
{
    xed_machine_mode_enum_t mmode = XED_MACHINE_MODE_LONG_64;
    xed_address_width_enum_t stack_addr_width = XED_ADDRESS_WIDTH_64b;

    xed_decoded_inst_zero(xedd);
    xed_decoded_inst_set_mode(xedd, mmode, stack_addr_width);
    xed_error_enum_t err = xed_decode(xedd, inst, len);
    assert(err == XED_ERROR_NONE);
}

static void check_oversized_immediate_test(void)
{
    xed_decoded_inst_t xedd;

    static const uint8_t add_imm4_256[] = { 0x81, 0xC0, 0x00, 0x01, 0x00, 0x00, };  // add eax, 0x100
    decode_instruction(&xedd, add_imm4_256, sizeof(add_imm4_256));
    assert(check_oversized_immediate(&xedd));

    static const uint8_t add_imm4_1[] = { 0x81, 0xC0, 0x01, 0x00, 0x00, 0x00, };  // add eax, 1
    decode_instruction(&xedd, add_imm4_1, sizeof(add_imm4_1));
    assert(!check_oversized_immediate(&xedd));

    static const uint8_t add_eax_imm4_256[] = { 0x05, 0x00, 0x01, 0x00, 0x00, };  // add eax, 0x100
    decode_instruction(&xedd, add_eax_imm4_256, sizeof(add_eax_imm4_256));
    assert(check_oversized_immediate(&xedd));

    static const uint8_t add_eax_imm4_1[] = { 0x05, 0x01, 0x00, 0x00, 0x00, };  // add eax, 1
    decode_instruction(&xedd, add_eax_imm4_1, sizeof(add_eax_imm4_1));
    assert(!check_oversized_immediate(&xedd));

    static const uint8_t add_imm1_1[] = { 0x83, 0xC0, 0x01, };  // add eax, 0x01
    decode_instruction(&xedd, add_imm1_1, sizeof(add_imm1_1));
    assert(check_oversized_immediate(&xedd));

    static const uint8_t mov_imm4_0[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, };  // mov eax, 0
    decode_instruction(&xedd, mov_imm4_0, sizeof(mov_imm4_0));
    assert(check_oversized_immediate(&xedd));

    static const uint8_t mov_imm8_0[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, };  // mov rax, 0
    decode_instruction(&xedd, mov_imm8_0, sizeof(mov_imm8_0));
    assert(!check_oversized_immediate(&xedd));
}

static void check_unneedex_rex_test(void)
{
    xed_decoded_inst_t xedd;

    static const uint8_t add_al_imm1_1[] = { 0x04, 0x01, };  // add al, 0x1
    decode_instruction(&xedd, add_al_imm1_1, sizeof(add_al_imm1_1));
    assert(check_unneeded_rex(&xedd));

    static const uint8_t add_al_imm1_1_rex[] = { 0x40, 0x04, 0x01, };  // add al, 0x1
    decode_instruction(&xedd, add_al_imm1_1_rex, sizeof(add_al_imm1_1_rex));
    assert(!check_unneeded_rex(&xedd));

    static const uint8_t add_r8b_imm1_1_rex[] = { 0x41, 0x80, 0xC0, 0x01, };  // add r8b, 1
    decode_instruction(&xedd, add_r8b_imm1_1_rex, sizeof(add_r8b_imm1_1_rex));
    assert(check_unneeded_rex(&xedd));

    static const uint8_t leave[] = { 0xc9, };  // leave
    decode_instruction(&xedd, leave, sizeof(leave));
    assert(check_unneeded_rex(&xedd));

    static const uint8_t leave_rex[] = { 0x40, 0xc9, };  // leave
    decode_instruction(&xedd, leave_rex, sizeof(leave_rex));
    assert(!check_unneeded_rex(&xedd));
}

static void check_mov_zero_test(void)
{
    xed_decoded_inst_t xedd;

    static const uint8_t mov_eax_imm4_0[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, };  // mov eax, 0
    decode_instruction(&xedd, mov_eax_imm4_0, sizeof(mov_eax_imm4_0));
    assert(!check_mov_zero(&xedd));

    static const uint8_t mov_ebx_imm4_0[] = { 0xBB, 0x00, 0x00, 0x00, 0x00, };  // mov ebx, 0
    decode_instruction(&xedd, mov_ebx_imm4_0, sizeof(mov_ebx_imm4_0));
    assert(!check_mov_zero(&xedd));

    static const uint8_t xor_eax_eax[] = { 0x31, 0xC0, };  // xor eax, eax
    decode_instruction(&xedd, xor_eax_eax, sizeof(xor_eax_eax));
    assert(check_mov_zero(&xedd));
}

static void check_implicit_register_test(void)
{
    xed_decoded_inst_t xedd;

    static const uint8_t add_eax_imm4_1_implicit[] = { 0x05, 0x01, 0x00, 0x00, 0x00, };  // add eax, 1
    decode_instruction(&xedd, add_eax_imm4_1_implicit, sizeof(add_eax_imm4_1_implicit));
    assert(check_implicit_register(&xedd));

    static const uint8_t add_eax_imm4_1_explicit[] = { 0x81, 0xC0, 0x01, 0x00, 0x00, 0x00, };  // add eax, 1
    decode_instruction(&xedd, add_eax_imm4_1_explicit, sizeof(add_eax_imm4_1_explicit));
    assert(!check_implicit_register(&xedd));

    static const uint8_t add_ebx_imm4_1[] = { 0x81, 0xC3, 0x01, 0x00, 0x00, 0x00, };  // add ebx, 1
    decode_instruction(&xedd, add_ebx_imm4_1, sizeof(add_ebx_imm4_1));
    assert(check_implicit_register(&xedd));
}

int main(int argc, char *argv[])
{
    xed_tables_init();
    xed_set_verbosity(99);

    check_oversized_immediate_test();
    check_unneedex_rex_test();
    check_mov_zero_test();
    check_implicit_register_test();

    static const uint8_t inst[] = {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, 0
        0x40, 0xc9,  // leave
        0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, 0
        0x81, 0xC0, 0x00, 0x01, 0x00, 0x00,  // add eax, 0x100
    };
    int errors = check_instructions(inst, sizeof(inst));
    assert(errors == 4);

    return 0;
}
