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
    bool _result = func(&xedd); \
    if (!_result) { \
        fprintf(stderr, "%s:%d: " #func " failed on:", __FILE__, __LINE__); \
        for (size_t _i = 0; _i < sizeof(bytes); _i++) \
            fprintf(stderr, " %02x", bytes[_i]); \
        fprintf(stderr, "\n"); \
    } \
    assert(_result); \
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

    // ENDBR64 alone -- CET landing pad, not really a NOP.
    static const uint8_t endbr64[] = { 0xf3, 0x0f, 0x1e, 0xfa };
    assert(check_suboptimal_nops(endbr64, sizeof(endbr64)));

    // PAUSE alone -- spin-loop hint, not really a NOP.
    static const uint8_t pause[] = { 0xf3, 0x90 };
    assert(check_suboptimal_nops(pause, sizeof(pause)));

    // Alignment NOP immediately before ENDBR64 -- the Fedora CET pattern.
    static const uint8_t nop66_endbr[] = { 0x66, 0x90, 0xf3, 0x0f, 0x1e, 0xfa };
    assert(check_suboptimal_nops(nop66_endbr, sizeof(nop66_endbr)));

    // NOP before PAUSE -- still pass, PAUSE doesn't count as a second NOP.
    static const uint8_t nop_pause[] = { 0x90, 0xf3, 0x90 };
    assert(check_suboptimal_nops(nop_pause, sizeof(nop_pause)));

    // Two real NOPs before ENDBR64 -- still flagged, the two NOPs are wasteful.
    static const uint8_t nopnop_endbr[] = { 0x90, 0x90, 0xf3, 0x0f, 0x1e, 0xfa };
    assert(!check_suboptimal_nops(nopnop_endbr, sizeof(nopnop_endbr)));

    // gcc emits NOPs longer than 9 bytes via redundant prefixes for alignment.
    // A small leading NOP plus an extended-prefix NOP is two instructions but
    // would require an even longer extended NOP to merge -- not a real
    // optimization opportunity, so don't flag.
    static const uint8_t nop2_pad11[] = {
        0x66, 0x90,
        0x66, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    assert(check_suboptimal_nops(nop2_pad11, sizeof(nop2_pad11)));

    // Two 3-byte NOPs fit in a single 6-byte NOP -- real finding.
    static const uint8_t nop3_nop3[] = {
        0x0f, 0x1f, 0x00,
        0x0f, 0x1f, 0x00,
    };
    assert(!check_suboptimal_nops(nop3_nop3, sizeof(nop3_nop3)));
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
    CHECK_BYTES(!check_oversized_immediate, 0x48, 0xB8, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00);  // mov rax, 0xffffffff (zero-ext via mov eax)
    CHECK_BYTES(!check_oversized_immediate, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00);  // mov rax, 0x80000000 (zero-ext via mov eax)
    CHECK_BYTES( check_oversized_immediate, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80);  // mov rax, 0x8000000000000000 (needs full 64-bit)
    CHECK_BYTES(!check_oversized_immediate, 0x81, 0xD0, 0x01, 0x00, 0x00, 0x00);  // adc eax, 1
    CHECK_BYTES(!check_oversized_immediate, 0x81, 0xE0, 0x01, 0x00, 0x00, 0x00);  // and eax, 1
    CHECK_BYTES(!check_oversized_immediate, 0x81, 0xF8, 0x01, 0x00, 0x00, 0x00);  // cmp eax, 1
    CHECK_BYTES(!check_oversized_immediate, 0x69, 0xC0, 0x01, 0x00, 0x00, 0x00);  // imul eax, eax, 1
    CHECK_BYTES(!check_oversized_immediate, 0x81, 0xC8, 0x01, 0x00, 0x00, 0x00);  // or eax, 1
    CHECK_BYTES(!check_oversized_immediate, 0x81, 0xD8, 0x01, 0x00, 0x00, 0x00);  // sbb eax, 1
    CHECK_BYTES(!check_oversized_immediate, 0x81, 0xE8, 0x01, 0x00, 0x00, 0x00);  // sub eax, 1
    CHECK_BYTES(!check_oversized_immediate, 0x81, 0xF0, 0x01, 0x00, 0x00, 0x00);  // xor eax, 1
    CHECK_BYTES( check_oversized_immediate, 0xF7, 0xC0, 0x01, 0x00, 0x00, 0x00);  // test eax, 1 (TEST not in switch)
}

static void check_oversized_add128_test(void)
{
    CHECK_BYTES( check_oversized_add128, 0x83, 0xC0, 0x7F);  // add eax, 0x7f
    CHECK_BYTES(!check_oversized_add128, 0x05, 0x80, 0x00, 0x00, 0x00);  // add eax, 0x80
    CHECK_BYTES( check_oversized_add128, 0x83, 0xE8, 0xFF);  // sub eax, -0x80
}

static void check_unneeded_rex_test(void)
{
    CHECK_BYTES(!check_unneeded_rex, 0x48, 0x31, 0xC0);  // xor rax, rax (could be 31 C0)
    CHECK_BYTES( check_unneeded_rex, 0x31, 0xC0);  // xor eax, eax
    CHECK_BYTES( check_unneeded_rex, 0x4d, 0x31, 0xC0);  // xor r8, r8 (REX.B truly needed)
    CHECK_BYTES( check_unneeded_rex, 0x48, 0x31, 0xD0);  // xor rax, rdx (full 64-bit XOR, REX.W needed)
    CHECK_BYTES( check_unneeded_rex, 0x04, 0x01);  // add al, 1
    CHECK_BYTES(!check_unneeded_rex, 0x40, 0x04, 0x01);  // add al, 1
    CHECK_BYTES( check_unneeded_rex, 0x41, 0x80, 0xC0, 0x01);  // add r8b, 1
    CHECK_BYTES( check_unneeded_rex, 0xc9);  // leave
    CHECK_BYTES(!check_unneeded_rex, 0x40, 0xc9);  // leave
    CHECK_BYTES( check_unneeded_rex, 0xc3);  // ret
    CHECK_BYTES(!check_unneeded_rex, 0x48, 0xc3);  // ret
    CHECK_BYTES( check_unneeded_rex, 0xe8, 0x00, 0x00, 0x00, 0x00);  // call rel32
    CHECK_BYTES(!check_unneeded_rex, 0x48, 0xe8, 0x00, 0x00, 0x00, 0x00);  // call rel32
    CHECK_BYTES( check_unneeded_rex, 0x9c);  // pushfq
    CHECK_BYTES(!check_unneeded_rex, 0x48, 0x9c);  // pushfq
    CHECK_BYTES( check_unneeded_rex, 0x9d);  // popfq
    CHECK_BYTES(!check_unneeded_rex, 0x48, 0x9d);  // popfq
    CHECK_BYTES( check_unneeded_rex, 0xe2, 0x00);  // loop
    CHECK_BYTES(!check_unneeded_rex, 0x48, 0xe2, 0x00);  // loop
    CHECK_BYTES( check_unneeded_rex, 0xeb, 0x00);  // jmp short
    CHECK_BYTES(!check_unneeded_rex, 0x48, 0xeb, 0x00);  // jmp short
    CHECK_BYTES( check_unneeded_rex, 0x74, 0x00);  // jz short
    CHECK_BYTES(!check_unneeded_rex, 0x48, 0x74, 0x00);  // jz short
    CHECK_BYTES( check_unneeded_rex, 0x41, 0xff, 0xd4);  // call r12 (REX.B needed)
    CHECK_BYTES( check_unneeded_rex, 0x41, 0xff, 0xe4);  // jmp r12 (REX.B needed)
    CHECK_BYTES( check_unneeded_rex, 0x41, 0xff, 0x55, 0x40);  // call [r13+0x40] (REX.B needed)
    CHECK_BYTES( check_unneeded_rex, 0x50);                    // push rax
    CHECK_BYTES(!check_unneeded_rex, 0x48, 0x50);              // rex.w push rax (REX.W has no effect)
    CHECK_BYTES( check_unneeded_rex, 0x41, 0x50);              // push r8 (REX.B needed)
    CHECK_BYTES(!check_unneeded_rex, 0x40, 0x6a, 0x01);        // rex push 1 (bare REX, unneeded)
    CHECK_BYTES(!check_unneeded_rex, 0x48, 0xff, 0x30);        // rex.w push [rax] (REX.W has no effect)
    CHECK_BYTES( check_unneeded_rex, 0x41, 0xff, 0x30);        // push [r8] (REX.B needed for r8)
    CHECK_BYTES( check_unneeded_rex, 0x58);                    // pop rax
    CHECK_BYTES(!check_unneeded_rex, 0x48, 0x58);              // rex.w pop rax (REX.W has no effect)
    CHECK_BYTES( check_unneeded_rex, 0x41, 0x58);              // pop r8 (REX.B needed)
    CHECK_BYTES(!check_unneeded_rex, 0x40, 0x8b, 0x00);  // mov eax, [rax] with bare REX (unneeded)
    CHECK_BYTES( check_unneeded_rex, 0x48, 0x8b, 0x01);  // mov rax, [rcx] (REX.W needed for 64-bit op)
    CHECK_BYTES( check_unneeded_rex, 0x41, 0x8b, 0x00);  // mov eax, [r8] (REX.B needed for r8 base)
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
    CHECK_BYTES( check_cmp_zero, 0x83, 0x3f, 0x00);  // cmp dword ptr [rdi], 0 (memory exempt)
    CHECK_BYTES( check_cmp_zero, 0x83, 0xc7, 0x00);  // add edi, 0 (not cmp)
}

static void check_implicit_register_test(void)
{
    CHECK_BYTES( check_implicit_register, 0x05, 0x01, 0x00, 0x00, 0x00);  // add eax, 1
    CHECK_BYTES(!check_implicit_register, 0x81, 0xC0, 0x01, 0x00, 0x00, 0x00);  // add eax, 1
    CHECK_BYTES( check_implicit_register, 0x81, 0xC3, 0x01, 0x00, 0x00, 0x00);  // add ebx, 1
    CHECK_BYTES( check_implicit_register, 0x31, 0xC0);  // xor eax, eax
    CHECK_BYTES( check_implicit_register, 0x48, 0x31, 0xC0);  // xor rax, rax
    CHECK_BYTES( check_implicit_register, 0x04, 0x01);  // add al, 1 (implicit)
    CHECK_BYTES(!check_implicit_register, 0x80, 0xC0, 0x01);  // add al, 1 (explicit)
    CHECK_BYTES( check_implicit_register, 0x66, 0x05, 0x01, 0x00);  // add ax, 1 (implicit)
    CHECK_BYTES(!check_implicit_register, 0x66, 0x81, 0xC0, 0x01, 0x00);  // add ax, 1 (explicit)
    CHECK_BYTES( check_implicit_register, 0x48, 0x05, 0x01, 0x00, 0x00, 0x00);  // add rax, 1 (implicit)
    CHECK_BYTES(!check_implicit_register, 0x48, 0x81, 0xC0, 0x01, 0x00, 0x00, 0x00);  // add rax, 1 (explicit)
    CHECK_BYTES( check_implicit_register, 0xa9, 0x01, 0x00, 0x00, 0x00);  // test eax, 1 (implicit)
    CHECK_BYTES(!check_implicit_register, 0xf7, 0xc0, 0x01, 0x00, 0x00, 0x00);  // test eax, 1 (explicit)
}

static void check_implicit_immediate_test(void)
{
    CHECK_BYTES( check_implicit_immediate, 0xd1, 0xd0);  // rcl eax, 1
    CHECK_BYTES(!check_implicit_immediate, 0xc1, 0xd0, 0x01);  // rcl eax, 1
    CHECK_BYTES( check_implicit_immediate, 0xd1, 0xc0);  // rol eax, 1
    CHECK_BYTES(!check_implicit_immediate, 0xc1, 0xc0, 0x01);  // rol eax, 1
    CHECK_BYTES( check_implicit_immediate, 0xd1, 0xc8);  // ror eax, 1
    CHECK_BYTES(!check_implicit_immediate, 0xc1, 0xc8, 0x01);  // ror eax, 1
    CHECK_BYTES( check_implicit_immediate, 0xd1, 0xd8);  // rcr eax, 1
    CHECK_BYTES(!check_implicit_immediate, 0xc1, 0xd8, 0x01);  // rcr eax, 1
    CHECK_BYTES( check_implicit_immediate, 0xd1, 0xe8);  // shr eax, 1
    CHECK_BYTES(!check_implicit_immediate, 0xc1, 0xe8, 0x01);  // shr eax, 1
    CHECK_BYTES( check_implicit_immediate, 0xd1, 0xf8);  // sar eax, 1
    CHECK_BYTES(!check_implicit_immediate, 0xc1, 0xf8, 0x01);  // sar eax, 1
    CHECK_BYTES( check_implicit_immediate, 0xc1, 0xe0, 0x01);  // shl eax, 1 (excluded from check)
    CHECK_BYTES( check_implicit_immediate, 0xc1, 0xd0, 0x02);  // rcl eax, 2 (imm != 1)
}

static void check_and_strength_reduce_test(void)
{
    CHECK_BYTES(!check_and_strength_reduce, 0x83, 0xe0, 0xff);  // and eax, 0xff
    CHECK_BYTES( check_and_strength_reduce, 0x83, 0xe0, 0xfe);  // and eax, 0xfe
    CHECK_BYTES(!check_and_strength_reduce, 0x25, 0xff, 0xff, 0x00, 0x00);  // and eax, 0xffff
    CHECK_BYTES(!check_and_strength_reduce, 0x25, 0xff, 0xff, 0xff, 0xff);  // and eax, 0xffffffff
    CHECK_BYTES( check_and_strength_reduce, 0x48, 0x25, 0xff, 0xff, 0xff, 0xff);  // and rax, 0xffffffff (no-op via sign-ext)
    CHECK_BYTES( check_and_strength_reduce, 0x48, 0x83, 0xe0, 0xff);              // and rax, sign_ext(0xff) (no-op)
    CHECK_BYTES(!check_and_strength_reduce, 0x83, 0xe0, 0xff);                    // and eax, sign_ext(0xff) (still flag)
    CHECK_BYTES( check_and_strength_reduce, 0x83, 0xc0, 0x01);  // add eax, 1 (not AND)
}

static void check_missing_lock_prefix_test(void)
{
    CHECK_BYTES( check_missing_lock_prefix, 0x67, 0xf0, 0x0f, 0xc1, 0x18);  // lock xadd [eax], ebx
    CHECK_BYTES(!check_missing_lock_prefix, 0x67, 0x0f, 0xc1, 0x18);  // xadd [eax], ebx
    CHECK_BYTES( check_missing_lock_prefix, 0xf0, 0x0f, 0xb1, 0x18);  // lock cmpxchg [rax], ebx
    CHECK_BYTES(!check_missing_lock_prefix, 0x0f, 0xb1, 0x18);  // cmpxchg [rax], ebx
    CHECK_BYTES( check_missing_lock_prefix, 0xf0, 0x0f, 0xc7, 0x08);  // lock cmpxchg8b [rax]
    CHECK_BYTES(!check_missing_lock_prefix, 0x0f, 0xc7, 0x08);  // cmpxchg8b [rax]
}

static void check_superfluous_lock_prefix_test(void)
{
    CHECK_BYTES(!check_superfluous_lock_prefix, 0xf0, 0x87, 0x07);  // lock xchg [eax], ebx
    CHECK_BYTES( check_superfluous_lock_prefix, 0x87, 0x07);  // xchg [eax], ebx
}

static void check_oversized_branch_test(void)
{
    // JMP rel32 with small displacement -- fits in rel8.
    // disp_short = disp_long + 3; +0 -> -3 fits as int8, flag.
    CHECK_BYTES(!check_oversized_branch, 0xe9, 0x00, 0x00, 0x00, 0x00);  // jmp +0
    // JMP rel32 at the boundary: disp_long=124, disp_short=127, just fits.
    CHECK_BYTES(!check_oversized_branch, 0xe9, 0x7c, 0x00, 0x00, 0x00);  // jmp +124
    // JMP rel32 just past the boundary: disp_long=125, disp_short=128, doesn't fit.
    CHECK_BYTES( check_oversized_branch, 0xe9, 0x7d, 0x00, 0x00, 0x00);  // jmp +125
    // JMP rel32 with large displacement -- needs rel32.
    CHECK_BYTES( check_oversized_branch, 0xe9, 0x00, 0x10, 0x00, 0x00);  // jmp +0x1000
    // JMP rel8 -- already short.
    CHECK_BYTES( check_oversized_branch, 0xeb, 0x00);  // jmp +0
    // Jcc rel32 with small displacement -- fits in rel8.
    // disp_short = disp_long + 4; +0 -> -4 fits as int8, flag.
    CHECK_BYTES(!check_oversized_branch, 0x0f, 0x84, 0x00, 0x00, 0x00, 0x00);  // jz +0
    // Jcc rel32 boundary: disp_long=123, disp_short=127, just fits.
    CHECK_BYTES(!check_oversized_branch, 0x0f, 0x84, 0x7b, 0x00, 0x00, 0x00);  // jz +123
    // Jcc rel32 just past: disp_long=124, disp_short=128, doesn't fit.
    CHECK_BYTES( check_oversized_branch, 0x0f, 0x84, 0x7c, 0x00, 0x00, 0x00);  // jz +124
    // Jcc rel8 -- already short.
    CHECK_BYTES( check_oversized_branch, 0x74, 0x00);  // jz +0
    // CALL rel32 -- no rel8 alternative exists in x86-64.
    CHECK_BYTES( check_oversized_branch, 0xe8, 0x00, 0x00, 0x00, 0x00);  // call +0
    // JRCXZ has only rel8 form -- no shorter option exists.
    CHECK_BYTES( check_oversized_branch, 0xe3, 0x00);  // jrcxz +0
}

static void check_mov_self_test(void)
{
    CHECK_BYTES(!check_mov_self, 0x48, 0x89, 0xc0);  // mov rax, rax (useless, REX.W)
    CHECK_BYTES(!check_mov_self, 0x48, 0x89, 0xdb);  // mov rbx, rbx
    CHECK_BYTES(!check_mov_self, 0x66, 0x89, 0xc0);  // mov ax, ax (no zero-ext, useless)
    CHECK_BYTES(!check_mov_self, 0x88, 0xc0);        // mov al, al (useless)
    CHECK_BYTES( check_mov_self, 0x89, 0xc0);        // mov eax, eax (zero-ext idiom, keep)
    CHECK_BYTES( check_mov_self, 0x48, 0x89, 0xc3);  // mov rbx, rax (different regs)
    CHECK_BYTES( check_mov_self, 0x90);              // nop (not MOV)
}

static void check_add_zero_test(void)
{
    CHECK_BYTES(!check_add_zero, 0x83, 0xc0, 0x00);              // add eax, 0
    CHECK_BYTES(!check_add_zero, 0x48, 0x83, 0xc0, 0x00);        // add rax, 0
    CHECK_BYTES(!check_add_zero, 0x83, 0xe8, 0x00);              // sub eax, 0
    CHECK_BYTES(!check_add_zero, 0x05, 0x00, 0x00, 0x00, 0x00);  // add eax, 0 (imm32 form)
    CHECK_BYTES( check_add_zero, 0x83, 0xc0, 0x01);              // add eax, 1 (not zero)
    CHECK_BYTES( check_add_zero, 0x83, 0x00, 0x00);              // add dword ptr [rax], 0 (memory)
    CHECK_BYTES( check_add_zero, 0x83, 0xd0, 0x00);              // adc eax, 0 (not ADD/SUB)
    CHECK_BYTES( check_add_zero, 0x90);                          // nop
}

static void check_unneeded_sib_test(void)
{
    // Issue #5: redundant SIB for [rbp+disp8] when modrm alone suffices.
    CHECK_BYTES( check_unneeded_sib, 0xc6, 0x45, 0x04, 0x05);              // mov [rbp+4], 5 (no SIB)
    CHECK_BYTES(!check_unneeded_sib, 0xc6, 0x44, 0x65, 0x04, 0x05);        // mov [rbp+4], 5 (SIB redundant)
    CHECK_BYTES(!check_unneeded_sib, 0xc6, 0x44, 0x25, 0x04, 0x05);        // same, scale=0
    CHECK_BYTES(!check_unneeded_sib, 0xc6, 0x44, 0xa5, 0x04, 0x05);        // same, scale=4
    CHECK_BYTES(!check_unneeded_sib, 0xc6, 0x44, 0xe5, 0x04, 0x05);        // same, scale=8
    // RSP and R12 require SIB -- rm=100 in modrm is the SIB marker.
    CHECK_BYTES( check_unneeded_sib, 0xc6, 0x04, 0x24, 0x05);              // mov [rsp], 5
    CHECK_BYTES( check_unneeded_sib, 0x41, 0xc6, 0x04, 0x24, 0x05);        // mov [r12], 5
    // Absolute disp32 in 64-bit mode uses SIB with base=none.
    CHECK_BYTES( check_unneeded_sib, 0xc6, 0x04, 0x25, 0x00, 0x10, 0x00, 0x00, 0x05); // mov [0x1000], 5
    // Real index register present -- SIB needed.
    CHECK_BYTES( check_unneeded_sib, 0xc6, 0x04, 0x05, 0x00, 0x10, 0x00, 0x00, 0x05); // mov [rax+disp32], 5 with index=rax (base=none)
    // No SIB -- nothing to flag.
    CHECK_BYTES( check_unneeded_sib, 0xc6, 0x00, 0x05);                    // mov [rax], 5
}

static void check_mov_modrm_imm_test(void)
{
    // modrm form -- one byte longer than the b0/b8 +r form, flag.
    CHECK_BYTES(!check_mov_modrm_imm, 0xc6, 0xc0, 0x01);                          // mov al, 1 (modrm)
    CHECK_BYTES(!check_mov_modrm_imm, 0x66, 0xc7, 0xc0, 0x01, 0x00);              // mov ax, 1 (modrm)
    CHECK_BYTES(!check_mov_modrm_imm, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00);        // mov eax, 1 (modrm)
    // b0/b8 +r form -- already short, pass.
    CHECK_BYTES( check_mov_modrm_imm, 0xb0, 0x01);                                // mov al, 1
    CHECK_BYTES( check_mov_modrm_imm, 0x66, 0xb8, 0x01, 0x00);                    // mov ax, 1
    CHECK_BYTES( check_mov_modrm_imm, 0xb8, 0x01, 0x00, 0x00, 0x00);              // mov eax, 1
    // 64-bit modrm form (sign-ext) is shorter than movabs imm64, pass.
    CHECK_BYTES( check_mov_modrm_imm, 0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00);  // mov rax, 1
    // Memory destination -- no +r form alternative, pass.
    CHECK_BYTES( check_mov_modrm_imm, 0xc7, 0x00, 0x01, 0x00, 0x00, 0x00);        // mov [rax], 1
    // Reg-reg mov has no immediate, pass.
    CHECK_BYTES( check_mov_modrm_imm, 0x89, 0xc3);                                // mov ebx, eax
    // Not a MOV, pass.
    CHECK_BYTES( check_mov_modrm_imm, 0x90);                                      // nop
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
    check_oversized_branch_test();
    check_mov_self_test();
    check_add_zero_test();
    check_mov_modrm_imm_test();
    check_unneeded_sib_test();

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
