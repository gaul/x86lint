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

#include "x86lint.h"
#include "xed/xed-interface.h"

#define CHECK_BYTES(func, ...) \
do { \
    static const uint8_t bytes[] = { __VA_ARGS__ }; \
    xed_decoded_inst_t xedd; \
    decode_instruction(&xedd, bytes, sizeof(bytes)); \
    assert(func(&xedd)); \
} while (0)

static void decode_instruction(xed_decoded_inst_t *xedd, const uint8_t *inst, size_t len)
{
    xed_machine_mode_enum_t mmode = XED_MACHINE_MODE_LONG_64;
    xed_address_width_enum_t stack_addr_width = XED_ADDRESS_WIDTH_64b;

    xed_decoded_inst_zero(xedd);
    xed_decoded_inst_set_mode(xedd, mmode, stack_addr_width);
    xed_error_enum_t err = xed_decode(xedd, inst, len);
    assert(err == XED_ERROR_NONE);
}

static void check_suboptimal_nops_test(void)
{
    static const uint8_t nop[] = { 0x90, };  // nop
    assert(check_suboptimal_nops(nop, sizeof(nop)));

    static const uint8_t nop2[] = { 0x90, 0x90, };  // nop ; nop
    assert(!check_suboptimal_nops(nop2, sizeof(nop2)));

    static const uint8_t nop_nop[] = { 0x66, 0x90, };  // data16 nop
    assert(check_suboptimal_nops(nop_nop, sizeof(nop_nop)));

    static const uint8_t nop4[] = { 0x0f, 0x1f, 0x40, 0x00, };  // NOP DWORD ptr [EAX + 00H]
    assert(check_suboptimal_nops(nop4, sizeof(nop4)));

    static const uint8_t nop4_nop4[] = {
        0x0f, 0x1f, 0x40, 0x00,
        0x0f, 0x1f, 0x40, 0x00,
    };
    assert(!check_suboptimal_nops(nop4_nop4, sizeof(nop4_nop4)));

    static const uint8_t nop9[] = { 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, };  // NOP DWORD ptr [AX + AX*1 + 00000000H]
    assert(check_suboptimal_nops(nop9, sizeof(nop9)));

    static const uint8_t nop9_nop9[] = {
        0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    assert(check_suboptimal_nops(nop9_nop9, sizeof(nop9_nop9)));
}

static void check_oversized_immediate_test(void)
{
    CHECK_BYTES( check_oversized_immediate, 0x81, 0xC0, 0x00, 0x01, 0x00, 0x00);  // add eax, 0x100
    CHECK_BYTES(!check_oversized_immediate, 0x81, 0xC0, 0x01, 0x00, 0x00, 0x00);  // add eax, 1
    CHECK_BYTES( check_oversized_immediate, 0x05, 0x00, 0x01, 0x00, 0x00);  // add eax, 0x100
    CHECK_BYTES(!check_oversized_immediate, 0x05, 0x01, 0x00, 0x00, 0x00);  // add eax, 1
    CHECK_BYTES( check_oversized_immediate, 0x83, 0xC0, 0x01);  // add eax, 1
    CHECK_BYTES( check_oversized_immediate, 0xB8, 0x00, 0x00, 0x00, 0x00);  // mov eax, 0
    CHECK_BYTES(!check_oversized_immediate, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);  // mov rax, 0
}

static void check_oversized_add128_test(void)
{
    CHECK_BYTES( check_oversized_add128, 0x83, 0xC0, 0x7F);  // add eax, 0x7f
    CHECK_BYTES(!check_oversized_add128, 0x05, 0x80, 0x00, 0x00, 0x00);  // add eax, 0x80
    CHECK_BYTES( check_oversized_add128, 0x83, 0xE8, 0xFF);  // sub eax, -0x80
}

static void check_unneeded_rex_test(void)
{
    CHECK_BYTES( check_unneeded_rex, 0x48, 0x31, 0xC0);  // xor rax, rax
    CHECK_BYTES( check_unneeded_rex, 0x31, 0xC0);  // xor rax, rax
    CHECK_BYTES( check_unneeded_rex, 0x04, 0x01);  // add al, 1
    CHECK_BYTES(!check_unneeded_rex, 0x40, 0x04, 0x01);  // add al, 1
    CHECK_BYTES( check_unneeded_rex, 0x41, 0x80, 0xC0, 0x01);  // add r8b, 1
    CHECK_BYTES( check_unneeded_rex, 0xc9);  // leave
    CHECK_BYTES(!check_unneeded_rex, 0x40, 0xc9);  // leave
}

static void check_mov_zero_test(void)
{
    CHECK_BYTES(!check_mov_zero, 0xB8, 0x00, 0x00, 0x00, 0x00);  // mov eax, 0
    CHECK_BYTES(!check_mov_zero, 0xBB, 0x00, 0x00, 0x00, 0x00);  // mov ebx, 0
    CHECK_BYTES( check_mov_zero, 0x31, 0xC0);  // xor eax, eax
    CHECK_BYTES( check_mov_zero, 0xC7, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00);  // mov dword ptr [rbp], 0
}

static void check_cmp_zero_test(void)
{
    CHECK_BYTES(!check_cmp_zero, 0x83, 0xff, 0x00);  // cmp edx, 0
    CHECK_BYTES( check_cmp_zero, 0x83, 0xff, 0x01);  // cmp edx, 1
}

static void check_implicit_register_test(void)
{
    CHECK_BYTES( check_implicit_register, 0x05, 0x01, 0x00, 0x00, 0x00);  // add eax, 1
    CHECK_BYTES(!check_implicit_register, 0x81, 0xC0, 0x01, 0x00, 0x00, 0x00);  // add eax, 1
    CHECK_BYTES( check_implicit_register, 0x81, 0xC3, 0x01, 0x00, 0x00, 0x00);  // add ebx, 1
    CHECK_BYTES( check_implicit_register, 0x31, 0xC0);  // xor eax, eax
    CHECK_BYTES( check_implicit_register, 0x48, 0x31, 0xC0);  // xor rax, rax
}

static void check_implicit_immediate_test(void)
{
    CHECK_BYTES( check_implicit_immediate, 0xd1, 0xd0);  // rcl eax, 1
    CHECK_BYTES(!check_implicit_immediate, 0xc1, 0xd0, 0x01);  // rcl eax, 1
}

static void check_and_strength_reduce_test(void)
{
    CHECK_BYTES(!check_and_strength_reduce, 0x83, 0xe0, 0xff);  // and eax, 0xff
    CHECK_BYTES( check_and_strength_reduce, 0x83, 0xe0, 0xfe);  // and eax, 0xfe
    CHECK_BYTES(!check_and_strength_reduce, 0x25, 0xff, 0xff, 0x00, 0x00);  // and eax, 0xffff
    CHECK_BYTES(!check_and_strength_reduce, 0x25, 0xff, 0xff, 0xff, 0xff);  // and eax, 0xffffffff
}

static void check_missing_lock_prefix_test(void)
{
    CHECK_BYTES( check_missing_lock_prefix, 0x67, 0xf0, 0x0f, 0xc1, 0x18);  // lock xadd [eax], ebx
    CHECK_BYTES(!check_missing_lock_prefix, 0x67, 0x0f, 0xc1, 0x18);  // xadd [eax], ebx
}

static void check_superfluous_lock_prefix_test(void)
{
    CHECK_BYTES(!check_superfluous_lock_prefix, 0xf0, 0x87, 0x07);  // lock xchg [eax], ebx
    CHECK_BYTES( check_superfluous_lock_prefix, 0x87, 0x07);  // xchg [eax], ebx
}

int main(int argc, char *argv[])
{
    xed_tables_init();
    xed_set_verbosity(99);

    check_suboptimal_nops_test();
    check_oversized_immediate_test();
    check_oversized_add128_test();
    check_unneeded_rex_test();
    check_cmp_zero_test();
    check_mov_zero_test();
    check_implicit_register_test();
    check_implicit_immediate_test();
    check_and_strength_reduce_test();
    check_missing_lock_prefix_test();
    check_superfluous_lock_prefix_test();

    static const uint8_t inst[] = {
        0x90, 0x90,  // nop ; nop
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, 0
        0x05, 0x80, 0x00, 0x00, 0x00,  // add eax, 0x80
        0x40, 0xc9,  // leave
        0x83, 0xff, 0x00,  // cmp edi, 0
        // TODO: Disabled due to false positives from CMOV sequences.  See #7.
        /*
        0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, 0
        */
        0x81, 0xC0, 0x00, 0x01, 0x00, 0x00,  // add eax, 0x100
        0x05, 0x01, 0x00, 0x00, 0x00,  // add eax, 1
        0xc1, 0xd0, 0x01,  // rcl eax, 1
        0x83, 0xe0, 0xff,  // and eax, 0xff
        0x67, 0x0f, 0xc1, 0x18,  // xadd [eax], ebx
        0xf0, 0x87, 0x07,  // lock xchg [eax], ebx
    };
    int expected = 11;
    int actual = check_instructions(inst, sizeof(inst));
    if (actual != expected) {
        printf("Expected %d errors, actual: %d\n", expected, actual);
        return 1;
    }

    return 0;
}
