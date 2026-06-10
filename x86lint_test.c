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
#include <stdlib.h>
#include <string.h>

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

// Runs check_instructions(inst, len) with stdout captured to a memory
// buffer so we can count per-category findings rather than just the total.
// Returns the number of `name at offset:` reports (i.e., findings produced
// by the check whose dispatcher name is `name`) and stores
// check_instructions's return value -- the total finding count -- into
// *total_out.
static int count_findings(const uint8_t *inst, size_t len,
                          const char *name, int *total_out)
{
    char *buf = NULL;
    size_t bufsz = 0;
    FILE *mem = open_memstream(&buf, &bufsz);
    assert(mem != NULL);

    FILE *saved = stdout;
    fflush(stdout);
    stdout = mem;
    // verbose=true so each finding prints its "<name> at offset:" line into
    // the captured buffer for the per-category count below.
    int total = check_instructions(inst, len, true, NULL);
    fflush(mem);
    stdout = saved;
    fclose(mem);

    char pat[128];
    int written = snprintf(pat, sizeof(pat), "%s at offset:", name);
    assert(written > 0 && written < (int) sizeof(pat));
    int count = 0;
    if (buf != NULL) {
        for (char *p = buf; (p = strstr(p, pat)) != NULL; p += written) {
            count++;
        }
    }

    free(buf);
    *total_out = total;
    return count;
}

// Asserts that `bytes_arr` (an array-typed local with sizeof() yielding its
// byte length) produces exactly `expected` findings of the given category
// AND no other findings. The second clause catches the common regression
// pattern where a new check starts firing on the same bytes and silently
// keeps a total-count assertion happy.
#define ASSERT_FINDINGS(bytes_arr, category, expected) do { \
    int _total; \
    int _cat = count_findings(bytes_arr, sizeof(bytes_arr), category, &_total); \
    if (_cat != (expected) || _total != (expected)) { \
        fprintf(stderr, \
                "%s:%d: expected %d \"%s\" finding(s) and no others; " \
                "got %d for category, %d total\n", \
                __FILE__, __LINE__, (expected), category, _cat, _total); \
    } \
    assert(_cat == (expected)); \
    assert(_total == (expected)); \
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

    // An undecodable byte ends the NOP run without a finding: a single
    // NOP followed by data is normal padding, not a suboptimal sequence.
    // 0x06 (push es) is illegal in 64-bit mode.
    static const uint8_t nop_bad[] = { 0x90, 0x06 };
    assert(check_suboptimal_nops(nop_bad, sizeof(nop_bad)));

    // Entirely undecodable input -- no NOPs at all, no finding.
    static const uint8_t bad[] = { 0x06 };
    assert(check_suboptimal_nops(bad, sizeof(bad)));

    // Two mergeable NOPs still flag even when data follows them.
    static const uint8_t nopnop_bad[] = { 0x90, 0x90, 0x06 };
    assert(!check_suboptimal_nops(nopnop_bad, sizeof(nopnop_bad)));
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
    CHECK_BYTES(!check_oversized_immediate, 0x81, 0xC0, 0xff, 0xff, 0xff, 0xff);  // add eax, -1 (imm32=0xffffffff, fits in sign-ext imm8)
    CHECK_BYTES(!check_oversized_immediate, 0x81, 0xC0, 0x80, 0xff, 0xff, 0xff);  // add eax, -0x80 (sign-ext imm8 boundary)
    CHECK_BYTES( check_oversized_immediate, 0x81, 0xC0, 0x7f, 0xff, 0xff, 0xff);  // add eax, -129 (just past sign-ext imm8 range)
    // push imm32 / push imm8 -- both sign-extend to the pushed value in 64-bit mode.
    CHECK_BYTES(!check_oversized_immediate, 0x68, 0x01, 0x00, 0x00, 0x00);        // push 1 (imm32, fits in imm8)
    CHECK_BYTES(!check_oversized_immediate, 0x68, 0xff, 0xff, 0xff, 0xff);        // push -1 (sign-ext imm8=0xff)
    CHECK_BYTES( check_oversized_immediate, 0x68, 0x00, 0x01, 0x00, 0x00);        // push 0x100 (needs imm32)
    CHECK_BYTES( check_oversized_immediate, 0x6a, 0x01);                          // push 1 (imm8, already short)
}

static void check_oversized_add_sub_128_test(void)
{
    // ADD 128 -> SUB -128.
    CHECK_BYTES( check_oversized_add_sub_128, 0x83, 0xC0, 0x7F);                    // add eax, 0x7f (imm8, fits)
    CHECK_BYTES(!check_oversized_add_sub_128, 0x05, 0x80, 0x00, 0x00, 0x00);        // add eax, 128 (imm32)
    CHECK_BYTES(!check_oversized_add_sub_128, 0x81, 0xC0, 0x80, 0x00, 0x00, 0x00);  // add eax, 128 (modrm imm32)
    CHECK_BYTES( check_oversized_add_sub_128, 0x83, 0xC0, 0x80);                    // add eax, -128 (imm8, already short)
    // SUB 128 -> ADD -128 (symmetric).
    CHECK_BYTES(!check_oversized_add_sub_128, 0x2D, 0x80, 0x00, 0x00, 0x00);        // sub eax, 128 (imm32)
    CHECK_BYTES(!check_oversized_add_sub_128, 0x81, 0xE8, 0x80, 0x00, 0x00, 0x00);  // sub eax, 128 (modrm imm32)
    CHECK_BYTES(!check_oversized_add_sub_128, 0x48, 0x2D, 0x80, 0x00, 0x00, 0x00);  // sub rax, 128
    CHECK_BYTES(!check_oversized_add_sub_128, 0x81, 0x28, 0x80, 0x00, 0x00, 0x00);  // sub dword [rax], 128 (memory)
    CHECK_BYTES( check_oversized_add_sub_128, 0x83, 0xE8, 0x80);                    // sub eax, -128 (imm8, already short)
    CHECK_BYTES( check_oversized_add_sub_128, 0x83, 0xE8, 0x7F);                    // sub eax, 127 (imm8, fits)
    CHECK_BYTES( check_oversized_add_sub_128, 0x2D, 0x81, 0x00, 0x00, 0x00);        // sub eax, 129 (neither it nor -129 fits imm8)
    // Not ADD/SUB.
    CHECK_BYTES( check_oversized_add_sub_128, 0x81, 0xE0, 0x80, 0x00, 0x00, 0x00);  // and eax, 128
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
    CHECK_BYTES( check_unneeded_rex, 0x48, 0x0f, 0x1f, 0x00);  // rex.w nop [rax] (REX.W kept, not flagged)
    // MOVZX r64, r/m8|r/m16: REX.W is redundant because the r32 form
    // zero-extends identically through bit 63. Flagged only when dropping
    // REX.W removes the whole REX byte.
    CHECK_BYTES(!check_unneeded_rex, 0x48, 0x0f, 0xb6, 0xc3);  // movzx rax, bl
    CHECK_BYTES(!check_unneeded_rex, 0x48, 0x0f, 0xb6, 0xc0);  // movzx rax, al
    CHECK_BYTES(!check_unneeded_rex, 0x48, 0x0f, 0xb7, 0xc3);  // movzx rax, bx (r/m16 form)
    CHECK_BYTES(!check_unneeded_rex, 0x48, 0x0f, 0xb6, 0x00);  // movzx rax, byte [rax]
    CHECK_BYTES( check_unneeded_rex, 0x0f, 0xb6, 0xc3);        // movzx eax, bl (no REX)
    CHECK_BYTES( check_unneeded_rex, 0x4c, 0x0f, 0xb6, 0xc3);  // movzx r8, bl (REX.R needed for dest)
    CHECK_BYTES( check_unneeded_rex, 0x48, 0x0f, 0xb6, 0xc6);  // movzx rax, sil (bare REX needed)
    CHECK_BYTES( check_unneeded_rex, 0x49, 0x0f, 0xb6, 0xc0);  // movzx rax, r8b (REX.B needed)
    CHECK_BYTES( check_unneeded_rex, 0x49, 0x0f, 0xb6, 0x00);  // movzx rax, byte [r8] (REX.B needed)
    CHECK_BYTES( check_unneeded_rex, 0x48, 0x0f, 0xbe, 0xc3);  // movsx rax, bl (REX.W real; MOVSX sign-extends to 64)
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
    // cmp al, 0 ties test al, al (both 2 bytes), so it is not flagged in
    // either encoding; every other byte register and width still is.
    CHECK_BYTES( check_cmp_zero, 0x3c, 0x00);        // cmp al, 0 (2-byte 3C form, ties test al, al)
    CHECK_BYTES( check_cmp_zero, 0x80, 0xf8, 0x00);  // cmp al, 0 (modrm form; test does not beat the 3C form)
    CHECK_BYTES( check_cmp_zero, 0x3c, 0x05);        // cmp al, 5 (nonzero, unchanged)
    CHECK_BYTES(!check_cmp_zero, 0x80, 0xfb, 0x00);  // cmp bl, 0 (no AL short form; test bl, bl is smaller)
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
    CHECK_BYTES( check_implicit_register, 0x66, 0x81, 0xc3, 0x01, 0x00);  // add bx, 1 (16-bit, dest != AX)
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
    // 83 e0 ff is and eax, sx(0xff) = and eax, 0xffffffff: a 32-bit operand
    // whose effective mask is all-ones. It zero-extends eax into rax, so it
    // reduces to mov eax, eax (not movzbl) -- still a finding.
    CHECK_BYTES(!check_and_strength_reduce, 0x83, 0xe0, 0xff);                    // and eax, 0xffffffff (-> mov eax, eax)
    CHECK_BYTES( check_and_strength_reduce, 0x83, 0xe0, 0xfe);                    // and eax, 0xfffffffe (not a mask)
    CHECK_BYTES(!check_and_strength_reduce, 0x25, 0xff, 0xff, 0x00, 0x00);        // and eax, 0xffff (-> movzwl)
    CHECK_BYTES(!check_and_strength_reduce, 0x25, 0xff, 0xff, 0xff, 0xff);        // and eax, 0xffffffff (-> mov eax, eax)
    CHECK_BYTES(!check_and_strength_reduce, 0x48, 0x25, 0xff, 0x00, 0x00, 0x00);  // and rax, 0xff (-> movzbl, zero-extends)
    // REX.W all-ones masks are genuine no-ops with no shorter zero-extending
    // form -- do not flag.
    CHECK_BYTES( check_and_strength_reduce, 0x48, 0x25, 0xff, 0xff, 0xff, 0xff);  // and rax, -1 (no-op)
    CHECK_BYTES( check_and_strength_reduce, 0x48, 0x83, 0xe0, 0xff);              // and rax, sx(0xff) = -1 (no-op)
    // 8-/16-bit AND preserves the upper register bytes; movzx/mov would zero
    // them, so the substitution is not equivalent -- do not flag.
    CHECK_BYTES( check_and_strength_reduce, 0x66, 0x25, 0xff, 0x00);              // and ax, 0xff (preserves bits 16+)
    CHECK_BYTES( check_and_strength_reduce, 0x66, 0x25, 0xff, 0xff);              // and ax, 0xffff (no-op on ax)
    CHECK_BYTES( check_and_strength_reduce, 0x24, 0xff);                          // and al, 0xff (no-op)
    // Memory destination: movzx/mov cannot target memory -- do not flag.
    CHECK_BYTES( check_and_strength_reduce, 0x81, 0x20, 0xff, 0x00, 0x00, 0x00);  // and dword [rax], 0xff
    CHECK_BYTES( check_and_strength_reduce, 0x81, 0x20, 0xff, 0xff, 0xff, 0xff);  // and dword [rax], 0xffffffff
    CHECK_BYTES( check_and_strength_reduce, 0x21, 0xd8);                          // and eax, ebx (no immediate)
    CHECK_BYTES( check_and_strength_reduce, 0x83, 0xc0, 0x01);                    // add eax, 1 (not AND)
}

static void check_missing_lock_prefix_test(void)
{
    CHECK_BYTES( check_missing_lock_prefix, 0x67, 0xf0, 0x0f, 0xc1, 0x18);  // lock xadd [eax], ebx
    CHECK_BYTES(!check_missing_lock_prefix, 0x67, 0x0f, 0xc1, 0x18);  // xadd [eax], ebx
    CHECK_BYTES( check_missing_lock_prefix, 0xf0, 0x0f, 0xb1, 0x18);  // lock cmpxchg [rax], ebx
    CHECK_BYTES(!check_missing_lock_prefix, 0x0f, 0xb1, 0x18);  // cmpxchg [rax], ebx
    CHECK_BYTES( check_missing_lock_prefix, 0xf0, 0x0f, 0xc7, 0x08);  // lock cmpxchg8b [rax]
    CHECK_BYTES(!check_missing_lock_prefix, 0x0f, 0xc7, 0x08);  // cmpxchg8b [rax]
    // Register-form cmpxchg/xadd cannot take a LOCK prefix (#UD), so a
    // missing prefix is not a fixable finding -- do not flag.
    CHECK_BYTES( check_missing_lock_prefix, 0x0f, 0xb1, 0xc3);  // cmpxchg ebx, eax (register dst)
    CHECK_BYTES( check_missing_lock_prefix, 0x0f, 0xc1, 0xc3);  // xadd ebx, eax (register dst)
}

static void check_superfluous_lock_prefix_test(void)
{
    CHECK_BYTES(!check_superfluous_lock_prefix, 0xf0, 0x87, 0x07);  // lock xchg [eax], ebx
    CHECK_BYTES( check_superfluous_lock_prefix, 0x87, 0x07);  // xchg [eax], ebx
}

static void check_xchg_accumulator_test(void)
{
    // modrm xchg with an accumulator operand -- shrinks to the 1-byte 90+r.
    CHECK_BYTES(!check_xchg_accumulator, 0x87, 0xc8);              // xchg eax, ecx
    CHECK_BYTES(!check_xchg_accumulator, 0x87, 0xc1);              // xchg ecx, eax (acc is REG0)
    CHECK_BYTES(!check_xchg_accumulator, 0x48, 0x87, 0xc8);        // xchg rax, rcx
    CHECK_BYTES(!check_xchg_accumulator, 0x66, 0x87, 0xc8);        // xchg ax, cx
    CHECK_BYTES(!check_xchg_accumulator, 0x44, 0x87, 0xc0);        // xchg eax, r8d
    // Already the 90+r short form -- nothing to flag.
    CHECK_BYTES( check_xchg_accumulator, 0x91);                   // xchg ecx, eax (90+r)
    CHECK_BYTES( check_xchg_accumulator, 0x90);                   // nop (xchg eax, eax short form)
    // xchg eax, eax via modrm: 90 is NOP and does not zero-extend, so the
    // short form is not equivalent.
    CHECK_BYTES( check_xchg_accumulator, 0x87, 0xc0);             // xchg eax, eax
    // No accumulator operand -- no short form exists.
    CHECK_BYTES( check_xchg_accumulator, 0x87, 0xcb);             // xchg ebx, ecx
    // 8-bit xchg has no 90+r form.
    CHECK_BYTES( check_xchg_accumulator, 0x86, 0xc8);             // xchg al, cl
    // Memory operand -- no 90+r form (and an implicit LOCK).
    CHECK_BYTES( check_xchg_accumulator, 0x87, 0x07);            // xchg [rdi], eax
    // Not XCHG.
    CHECK_BYTES( check_xchg_accumulator, 0x89, 0xc8);            // mov eax, ecx
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
    // Top of the rel32 range: disp + size_delta exceeds INT32_MAX, so the
    // sum must be computed in 64 bits (UBSan-visible overflow otherwise).
    CHECK_BYTES( check_oversized_branch, 0xe9, 0xfd, 0xff, 0xff, 0x7f);  // jmp +0x7ffffffd
    CHECK_BYTES( check_oversized_branch, 0x0f, 0x84, 0xfc, 0xff, 0xff, 0x7f);  // jz +0x7ffffffc
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

static void check_add_sub_zero_test(void)
{
    CHECK_BYTES(!check_add_sub_zero, 0x83, 0xc0, 0x00);              // add eax, 0
    CHECK_BYTES(!check_add_sub_zero, 0x48, 0x83, 0xc0, 0x00);        // add rax, 0
    CHECK_BYTES(!check_add_sub_zero, 0x83, 0xe8, 0x00);              // sub eax, 0
    CHECK_BYTES(!check_add_sub_zero, 0x05, 0x00, 0x00, 0x00, 0x00);  // add eax, 0 (imm32 form)
    CHECK_BYTES( check_add_sub_zero, 0x83, 0xc0, 0x01);              // add eax, 1 (not zero)
    CHECK_BYTES( check_add_sub_zero, 0x83, 0x00, 0x00);              // add dword ptr [rax], 0 (memory)
    CHECK_BYTES( check_add_sub_zero, 0x83, 0xd0, 0x00);              // adc eax, 0 (not ADD/SUB)
    CHECK_BYTES( check_add_sub_zero, 0x90);                          // nop
    // add al, 0 / sub al, 0 already fit in 2 bytes (04/2c ib), tying
    // test al, al -- no win, so not flagged. Other byte registers still are.
    CHECK_BYTES( check_add_sub_zero, 0x04, 0x00);                    // add al, 0 (accumulator form)
    CHECK_BYTES( check_add_sub_zero, 0x2c, 0x00);                    // sub al, 0 (accumulator form)
    CHECK_BYTES(!check_add_sub_zero, 0x80, 0xc3, 0x00);              // add bl, 0 (no short form; test bl, bl smaller)
    CHECK_BYTES( check_add_sub_zero, 0x01, 0xd8);                    // add eax, ebx (no immediate)
}

static void check_inc_dec_test(void)
{
    // add/sub reg, +/-1 -> inc/dec reg, one byte shorter.
    CHECK_BYTES(!check_inc_dec, 0x83, 0xc0, 0x01);              // add eax, 1
    CHECK_BYTES(!check_inc_dec, 0x83, 0xc0, 0xff);              // add eax, -1
    CHECK_BYTES(!check_inc_dec, 0x83, 0xe8, 0x01);              // sub eax, 1
    CHECK_BYTES(!check_inc_dec, 0x83, 0xe8, 0xff);              // sub eax, -1
    CHECK_BYTES(!check_inc_dec, 0x48, 0x83, 0xc0, 0x01);        // add rax, 1
    CHECK_BYTES(!check_inc_dec, 0x66, 0x83, 0xc0, 0x01);        // add ax, 1
    CHECK_BYTES(!check_inc_dec, 0x80, 0xc3, 0x01);              // add bl, 1 (8-bit, non-AL)
    CHECK_BYTES(!check_inc_dec, 0x05, 0x01, 0x00, 0x00, 0x00);  // add eax, 1 (imm32 form)
    // AL accumulator form already encodes in 2 bytes (04/2c ib), tying
    // inc/dec al -- no win.
    CHECK_BYTES( check_inc_dec, 0x04, 0x01);                    // add al, 1
    CHECK_BYTES( check_inc_dec, 0x2c, 0x01);                    // sub al, 1
    // |imm| != 1.
    CHECK_BYTES( check_inc_dec, 0x83, 0xc0, 0x02);              // add eax, 2
    CHECK_BYTES( check_inc_dec, 0x83, 0xc0, 0x00);              // add eax, 0
    // No immediate / memory / not ADD-SUB.
    CHECK_BYTES( check_inc_dec, 0x01, 0xd8);                    // add eax, ebx
    CHECK_BYTES( check_inc_dec, 0x83, 0x00, 0x01);              // add dword ptr [rax], 1 (memory)
    CHECK_BYTES( check_inc_dec, 0x83, 0xd0, 0x01);              // adc eax, 1 (not ADD/SUB)
    CHECK_BYTES( check_inc_dec, 0xff, 0xc0);                    // inc eax (already short)
    CHECK_BYTES( check_inc_dec, 0x90);                          // nop
}

static void check_shift_zero_test(void)
{
    // Immediate count of 0 -- pure no-op for every shift/rotate iclass.
    CHECK_BYTES(!check_shift_zero, 0xc1, 0xe0, 0x00);              // shl eax, 0
    CHECK_BYTES(!check_shift_zero, 0xc1, 0xe8, 0x00);              // shr eax, 0
    CHECK_BYTES(!check_shift_zero, 0xc1, 0xf8, 0x00);              // sar eax, 0
    CHECK_BYTES(!check_shift_zero, 0xc1, 0xc0, 0x00);              // rol eax, 0
    CHECK_BYTES(!check_shift_zero, 0xc1, 0xc8, 0x00);              // ror eax, 0
    CHECK_BYTES(!check_shift_zero, 0xc1, 0xd0, 0x00);              // rcl eax, 0
    CHECK_BYTES(!check_shift_zero, 0xc1, 0xd8, 0x00);              // rcr eax, 0
    CHECK_BYTES(!check_shift_zero, 0x0f, 0xa4, 0xd8, 0x00);        // shld eax, ebx, 0
    CHECK_BYTES(!check_shift_zero, 0x0f, 0xac, 0xd8, 0x00);        // shrd eax, ebx, 0
    // REX.W and 8-bit forms.
    CHECK_BYTES(!check_shift_zero, 0x48, 0xc1, 0xe0, 0x00);        // shl rax, 0
    CHECK_BYTES(!check_shift_zero, 0xc0, 0xe0, 0x00);              // shl al, 0
    // Nonzero immediate -- not flagged.
    CHECK_BYTES( check_shift_zero, 0xc1, 0xe0, 0x01);              // shl eax, 1
    CHECK_BYTES( check_shift_zero, 0xc1, 0xe0, 0x07);              // shl eax, 7
    // Implicit-1 form (D1 /4) has no immediate, not flagged.
    CHECK_BYTES( check_shift_zero, 0xd1, 0xe0);                    // shl eax, 1
    // CL-register form -- count not statically knowable, not flagged.
    CHECK_BYTES( check_shift_zero, 0xd3, 0xe0);                    // shl eax, cl
    // Not a shift.
    CHECK_BYTES( check_shift_zero, 0x90);                          // nop
}

static void check_imul_to_lea_test(void)
{
    // imm8 form, all the LEA/SHL-friendly constants.
    CHECK_BYTES(!check_imul_to_lea, 0x6b, 0xc0, 0x02);                    // imul eax, eax, 2
    CHECK_BYTES(!check_imul_to_lea, 0x6b, 0xc0, 0x03);                    // imul eax, eax, 3
    CHECK_BYTES(!check_imul_to_lea, 0x6b, 0xc0, 0x04);                    // imul eax, eax, 4
    CHECK_BYTES(!check_imul_to_lea, 0x6b, 0xc0, 0x05);                    // imul eax, eax, 5
    CHECK_BYTES(!check_imul_to_lea, 0x6b, 0xc0, 0x08);                    // imul eax, eax, 8
    CHECK_BYTES(!check_imul_to_lea, 0x6b, 0xc0, 0x09);                    // imul eax, eax, 9
    // imm32 form also matches.
    CHECK_BYTES(!check_imul_to_lea, 0x69, 0xc0, 0x03, 0x00, 0x00, 0x00);  // imul eax, eax, 3
    // {2,3,5,9} reduce to lea [src + src*s] for any destination register.
    CHECK_BYTES(!check_imul_to_lea, 0x6b, 0xc3, 0x02);                    // imul eax, ebx, 2 (lea [ebx+ebx])
    CHECK_BYTES(!check_imul_to_lea, 0x6b, 0xc3, 0x03);                    // imul eax, ebx, 3 (lea [ebx+ebx*2])
    CHECK_BYTES(!check_imul_to_lea, 0x6b, 0xc3, 0x05);                    // imul eax, ebx, 5 (lea [ebx+ebx*4])
    CHECK_BYTES(!check_imul_to_lea, 0x6b, 0xc3, 0x09);                    // imul eax, ebx, 9 (lea [ebx+ebx*8])
    // {4,8} only reduce (to SHL) when dst == src; lea [src*scale] needs a
    // disp32 and is longer than the IMUL, so different registers are left alone.
    CHECK_BYTES( check_imul_to_lea, 0x6b, 0xc3, 0x04);                    // imul eax, ebx, 4 (different regs)
    CHECK_BYTES( check_imul_to_lea, 0x6b, 0xc3, 0x08);                    // imul eax, ebx, 8 (different regs)
    CHECK_BYTES(!check_imul_to_lea, 0x48, 0x6b, 0xc0, 0x04);              // imul rax, rax, 4 (shl rax, 2)
    // Constants without a single-LEA equivalent.
    CHECK_BYTES( check_imul_to_lea, 0x6b, 0xc0, 0x06);                    // imul eax, eax, 6
    CHECK_BYTES( check_imul_to_lea, 0x6b, 0xc0, 0x07);                    // imul eax, eax, 7
    CHECK_BYTES( check_imul_to_lea, 0x6b, 0xc0, 0x0a);                    // imul eax, eax, 10
    CHECK_BYTES( check_imul_to_lea, 0x6b, 0xc0, 0xfe);                    // imul eax, eax, -2 (sign-ext, LEA can't negate)
    // Two-operand form (no immediate).
    CHECK_BYTES( check_imul_to_lea, 0x0f, 0xaf, 0xc3);                    // imul eax, ebx
    // Memory-source IMUL: LEA replacement needs extra load, would be longer.
    CHECK_BYTES( check_imul_to_lea, 0x48, 0x6b, 0x43, 0x08, 0x03);        // imul rax, [rbx+8], 3
    // Not IMUL.
    CHECK_BYTES( check_imul_to_lea, 0x90);                                // nop
}

static void check_lea_to_mov_test(void)
{
    // lea dst, [base] with no index and zero displacement == mov dst, base.
    CHECK_BYTES(!check_lea_to_mov, 0x48, 0x8d, 0x03);              // lea rax, [rbx]
    CHECK_BYTES(!check_lea_to_mov, 0x67, 0x8d, 0x03);             // lea eax, [ebx] (32/32)
    CHECK_BYTES(!check_lea_to_mov, 0x48, 0x8d, 0x00);            // lea rax, [rax] (degenerate)
    // RBP/R13 force a disp8=0 and RSP forces a SIB -- still a bare base, and
    // the lea is a byte longer than the mov.
    CHECK_BYTES(!check_lea_to_mov, 0x48, 0x8d, 0x45, 0x00);       // lea rax, [rbp+0]
    CHECK_BYTES(!check_lea_to_mov, 0x49, 0x8d, 0x45, 0x00);       // lea rax, [r13+0]
    CHECK_BYTES(!check_lea_to_mov, 0x48, 0x8d, 0x04, 0x24);       // lea rax, [rsp]
    // Mixed operand/address size -- a single same-width mov does not apply.
    CHECK_BYTES( check_lea_to_mov, 0x8d, 0x03);                  // lea eax, [rbx] (32/64)
    CHECK_BYTES( check_lea_to_mov, 0x67, 0x48, 0x8d, 0x03);       // lea rax, [ebx] (64/32)
    // Index, nonzero displacement, RIP-relative, and pure-index forms: not a
    // bare base register.
    CHECK_BYTES( check_lea_to_mov, 0x48, 0x8d, 0x04, 0x0b);       // lea rax, [rbx+rcx]
    CHECK_BYTES( check_lea_to_mov, 0x48, 0x8d, 0x43, 0x08);       // lea rax, [rbx+8]
    CHECK_BYTES( check_lea_to_mov, 0x48, 0x8d, 0x05, 0,0,0,0);    // lea rax, [rip+0]
    CHECK_BYTES( check_lea_to_mov, 0x48, 0x8d, 0x04, 0x1d, 0,0,0,0); // lea rax, [rbx*1] (no base)
    // Not LEA.
    CHECK_BYTES( check_lea_to_mov, 0x48, 0x89, 0xd8);            // mov rax, rbx
    CHECK_BYTES( check_lea_to_mov, 0x90);                        // nop
}

static void check_sub_self_test(void)
{
    CHECK_BYTES(!check_sub_self, 0x29, 0xc0);              // sub eax, eax (use xor)
    CHECK_BYTES(!check_sub_self, 0x48, 0x29, 0xc0);        // sub rax, rax
    CHECK_BYTES(!check_sub_self, 0x4d, 0x29, 0xc0);        // sub r8, r8
    CHECK_BYTES(!check_sub_self, 0x28, 0xc0);              // sub al, al
    CHECK_BYTES(!check_sub_self, 0x66, 0x29, 0xc0);        // sub ax, ax
    CHECK_BYTES( check_sub_self, 0x29, 0xc3);              // sub ebx, eax (different regs)
    CHECK_BYTES( check_sub_self, 0x31, 0xc0);              // xor eax, eax (not SUB)
    CHECK_BYTES( check_sub_self, 0x29, 0x00);              // sub [rax], eax (memory)
    CHECK_BYTES( check_sub_self, 0x90);                    // nop
}

static void check_or_and_self_test(void)
{
    // or/and reg, reg used as a flag test -> test reg, reg (all widths).
    CHECK_BYTES(!check_or_and_self, 0x09, 0xc0);           // or eax, eax
    CHECK_BYTES(!check_or_and_self, 0x21, 0xc0);           // and eax, eax
    CHECK_BYTES(!check_or_and_self, 0x21, 0xdb);           // and ebx, ebx
    CHECK_BYTES(!check_or_and_self, 0x48, 0x09, 0xc0);     // or rax, rax
    CHECK_BYTES(!check_or_and_self, 0x08, 0xc0);           // or al, al
    CHECK_BYTES(!check_or_and_self, 0x66, 0x09, 0xc0);     // or ax, ax
    CHECK_BYTES(!check_or_and_self, 0x4d, 0x09, 0xc0);     // or r8, r8
    // Different registers -- a real computation, not a flag test.
    CHECK_BYTES( check_or_and_self, 0x09, 0xd8);           // or eax, ebx
    CHECK_BYTES( check_or_and_self, 0x21, 0xd8);           // and eax, ebx
    // Immediate and memory forms.
    CHECK_BYTES( check_or_and_self, 0x83, 0xc8, 0x05);     // or eax, 5
    CHECK_BYTES( check_or_and_self, 0x09, 0x00);           // or [rax], eax
    CHECK_BYTES( check_or_and_self, 0x0b, 0x00);           // or eax, [rax]
    // Not OR/AND.
    CHECK_BYTES( check_or_and_self, 0x85, 0xc0);           // test eax, eax (already canonical)
    CHECK_BYTES( check_or_and_self, 0x31, 0xc0);           // xor eax, eax
    CHECK_BYTES( check_or_and_self, 0x90);                 // nop
}

static void check_unneeded_movsxd_test(void)
{
    CHECK_BYTES(!check_unneeded_movsxd, 0x48, 0x63, 0xc0);  // movsxd rax, eax (use cdqe)
    CHECK_BYTES( check_unneeded_movsxd, 0x48, 0x63, 0xc8);  // movsxd rcx, eax (no shorter form)
    CHECK_BYTES( check_unneeded_movsxd, 0x48, 0x63, 0xc1);  // movsxd rax, ecx (no shorter form)
    CHECK_BYTES( check_unneeded_movsxd, 0x48, 0x63, 0x00);  // movsxd rax, [rax] (memory source)
    CHECK_BYTES( check_unneeded_movsxd, 0x48, 0x98);        // cdqe (already short)
    CHECK_BYTES( check_unneeded_movsxd, 0x90);              // nop (not MOVSXD)
}

static void check_unneeded_movsx_test(void)
{
    CHECK_BYTES(!check_unneeded_movsx, 0x0f, 0xbf, 0xc0);        // movsx eax, ax (use cwde)
    CHECK_BYTES(!check_unneeded_movsx, 0x66, 0x0f, 0xbe, 0xc0);  // movsx ax, al (use cbw)
    CHECK_BYTES( check_unneeded_movsx, 0x48, 0x0f, 0xbf, 0xc0);  // movsx rax, ax (16->64, no form)
    CHECK_BYTES( check_unneeded_movsx, 0x0f, 0xbf, 0xc8);        // movsx ecx, ax (dst not eax)
    CHECK_BYTES( check_unneeded_movsx, 0x0f, 0xbf, 0xc1);        // movsx eax, cx (src not ax)
    CHECK_BYTES( check_unneeded_movsx, 0x0f, 0xbf, 0x00);        // movsx eax, [rax] (memory source)
    CHECK_BYTES( check_unneeded_movsx, 0x48, 0x63, 0xc0);        // movsxd rax, eax (MOVSXD, not MOVSX)
    CHECK_BYTES( check_unneeded_movsx, 0x0f, 0xb7, 0xc0);        // movzx eax, ax (MOVZX, not MOVSX)
    CHECK_BYTES( check_unneeded_movsx, 0x98);                    // cwde (already short)
    CHECK_BYTES( check_unneeded_movsx, 0x90);                    // nop (not MOVSX)
}

static void check_unneeded_zero_displacement_test(void)
{
    // Issue #4: disp8=0 and disp32=0 when no displacement would suffice.
    CHECK_BYTES( check_unneeded_zero_displacement, 0x01, 0x3e);                   // add [rsi], edi (no disp)
    CHECK_BYTES(!check_unneeded_zero_displacement, 0x01, 0x7e, 0x00);             // add [rsi+0], edi (disp8=0)
    CHECK_BYTES(!check_unneeded_zero_displacement, 0x01, 0xbe, 0,0,0,0);          // add [rsi+0], edi (disp32=0)
    // RBP/R13 with disp8=0 is required (mod=00 rm=101 means RIP-rel).
    CHECK_BYTES( check_unneeded_zero_displacement, 0x01, 0x7d, 0x00);             // add [rbp+0], edi
    CHECK_BYTES( check_unneeded_zero_displacement, 0x45, 0x01, 0x7d, 0x00);       // add [r13+0], r15d
    // RBP/R13 with disp32=0 is still oversized -- could shrink to disp8=0.
    CHECK_BYTES(!check_unneeded_zero_displacement, 0x01, 0xbd, 0,0,0,0);          // add [rbp+0], edi (disp32=0)
    // RIP-relative always uses disp32.
    CHECK_BYTES( check_unneeded_zero_displacement, 0x01, 0x3d, 0,0,0,0);          // add [rip+0], edi
    // Absolute disp32 always needs disp32 (no base register).
    CHECK_BYTES( check_unneeded_zero_displacement, 0x01, 0x3c, 0x25, 0,0,0,0);    // add [0], edi
    // RSP with disp8=0 -- can shrink to no-disp form using same SIB.
    CHECK_BYTES(!check_unneeded_zero_displacement, 0x01, 0x7c, 0x24, 0x00);       // add [rsp+0], edi
    // RSP with no displacement -- nothing to flag.
    CHECK_BYTES( check_unneeded_zero_displacement, 0x01, 0x3c, 0x24);             // add [rsp], edi
    // Real nonzero displacement -- nothing to flag.
    CHECK_BYTES( check_unneeded_zero_displacement, 0x01, 0x7e, 0x04);             // add [rsi+4], edi
    // Multi-byte NOPs deliberately use zero displacement for padding.
    CHECK_BYTES( check_unneeded_zero_displacement, 0x0f, 0x1f, 0x40, 0x00);       // 4-byte NOP [rax+0]
    CHECK_BYTES( check_unneeded_zero_displacement, 0x0f, 0x1f, 0x80, 0,0,0,0);    // 7-byte NOP [rax+0]
}

static void check_oversized_displacement_test(void)
{
    // disp32 holding a value that fits in a signed disp8 -- narrowable.
    CHECK_BYTES(!check_oversized_displacement, 0x01, 0xbe, 0x10, 0,0,0);          // add [rsi+0x10], edi (disp32)
    CHECK_BYTES( check_oversized_displacement, 0x01, 0x7e, 0x10);                 // add [rsi+0x10], edi (already disp8)
    // Signed disp8 boundaries: [-128, 127] narrows, just outside needs disp32.
    CHECK_BYTES(!check_oversized_displacement, 0x01, 0xbe, 0x7f, 0,0,0);          // add [rsi+127], edi
    CHECK_BYTES( check_oversized_displacement, 0x01, 0xbe, 0x80, 0,0,0);          // add [rsi+128], edi (needs disp32)
    CHECK_BYTES(!check_oversized_displacement, 0x01, 0xbe, 0xff, 0xff, 0xff, 0xff); // add [rsi-1], edi
    CHECK_BYTES(!check_oversized_displacement, 0x01, 0xbe, 0x80, 0xff, 0xff, 0xff); // add [rsi-128], edi
    CHECK_BYTES( check_oversized_displacement, 0x01, 0xbe, 0x7f, 0xff, 0xff, 0xff); // add [rsi-129], edi (needs disp32)
    // disp32=0 is the zero-displacement check's job, not this one.
    CHECK_BYTES( check_oversized_displacement, 0x01, 0xbe, 0,0,0,0);              // add [rsi+0], edi
    // RBP/R13 narrow fine -- they require *at least* a disp8, not a disp32.
    CHECK_BYTES(!check_oversized_displacement, 0x01, 0xbd, 0x10, 0,0,0);          // add [rbp+0x10], edi
    CHECK_BYTES(!check_oversized_displacement, 0x45, 0x01, 0xbd, 0x10, 0,0,0);    // add [r13+0x10], r15d
    // RSP keeps its SIB but the disp still narrows.
    CHECK_BYTES(!check_oversized_displacement, 0x01, 0xbc, 0x24, 0x10, 0,0,0);    // add [rsp+0x10], edi (disp32)
    CHECK_BYTES( check_oversized_displacement, 0x01, 0x7c, 0x24, 0x10);           // add [rsp+0x10], edi (already disp8)
    // RIP-relative and absolute disp32 cannot narrow (disp32 is mandatory).
    CHECK_BYTES( check_oversized_displacement, 0x01, 0x3d, 0x10, 0,0,0);          // add [rip+0x10], edi
    CHECK_BYTES( check_oversized_displacement, 0x01, 0x3c, 0x25, 0x10, 0,0,0);    // add [0x10], edi (absolute)
    // Multi-byte NOPs use displacement width as deliberate padding.
    CHECK_BYTES( check_oversized_displacement, 0x0f, 0x1f, 0x80, 0x10, 0,0,0);    // 7-byte NOP [rax+0x10]
    // EVEX compresses disp8 by the tuple factor N (64 for a full zmm
    // operand): 16 is not a multiple of 64, so this disp32 has no disp8
    // form -- it is the only encoding, don't flag.
    CHECK_BYTES( check_oversized_displacement, 0x62, 0xf1, 0x7c, 0x48, 0x58, 0x88, 0x10, 0,0,0); // vaddps zmm1, zmm0, [rax+16] (disp32)
    // Compressed disp8 (stored 1, scaled to 64) -- already short.
    CHECK_BYTES( check_oversized_displacement, 0x62, 0xf1, 0x7c, 0x48, 0x58, 0x48, 0x01);        // vaddps zmm1, zmm0, [rax+64] (disp8*64)
    // VEX disp8 is uncompressed, so a small VEX disp32 still narrows.
    CHECK_BYTES(!check_oversized_displacement, 0xc5, 0xf8, 0x58, 0x88, 0x10, 0,0,0);             // vaddps xmm1, xmm0, [rax+16] (disp32)
    // No memory operand -- nothing to flag.
    CHECK_BYTES( check_oversized_displacement, 0x01, 0xd8);                       // add eax, ebx
    CHECK_BYTES( check_oversized_displacement, 0x90);                            // nop
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
    // REX.W C7 form with non-negative imm32 -- mov r32, imm32 (5 bytes)
    // zero-extends to the same 64-bit value as the 7-byte sign-extending form.
    CHECK_BYTES(!check_mov_modrm_imm, 0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00);  // mov rax, 1
    CHECK_BYTES(!check_mov_modrm_imm, 0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0x7f);  // mov rax, 0x7fffffff (top imm32 positive)
    // REX.W C7 with negative imm32 -- sign-extension differs from zero-extension; C7 is the shortest form.
    CHECK_BYTES( check_mov_modrm_imm, 0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff);  // mov rax, -1
    CHECK_BYTES( check_mov_modrm_imm, 0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x80);  // mov rax, sign_ext(0x80000000)
    // Memory destination -- no +r form alternative, pass.
    CHECK_BYTES( check_mov_modrm_imm, 0xc7, 0x00, 0x01, 0x00, 0x00, 0x00);        // mov [rax], 1
    // Reg-reg mov has no immediate, pass.
    CHECK_BYTES( check_mov_modrm_imm, 0x89, 0xc3);                                // mov ebx, eax
    // Not a MOV, pass.
    CHECK_BYTES( check_mov_modrm_imm, 0x90);                                      // nop
}

// Flag-liveness gating: check_instructions should suppress findings whose
// suggested replacement would clobber a flag that's read downstream. These
// tests construct two-or-three instruction sequences and assert the
// dispatcher's response.
static void check_flag_liveness_test(void)
{
    // mov eax, 0 ; ret -- ret is a flag-killing terminator, finding fires.
    static const uint8_t mov_ret[] = {
        0xB8, 0x00, 0x00, 0x00, 0x00,
        0xC3,
    };
    ASSERT_FINDINGS(mov_ret, "suboptimal MOV zero", 1);

    // mov eax, 0 ; je +0 -- JE reads ZF which xor would clobber, suppress.
    static const uint8_t mov_je[] = {
        0xB8, 0x00, 0x00, 0x00, 0x00,
        0x74, 0x00,
    };
    ASSERT_FINDINGS(mov_je, "suboptimal MOV zero", 0);

    // mov eax, 0 ; mov ebx, 1 ; ret -- intermediate MOV doesn't touch
    // flags, RET kills them, finding fires.
    static const uint8_t mov_mov_ret[] = {
        0xB8, 0x00, 0x00, 0x00, 0x00,
        0xBB, 0x01, 0x00, 0x00, 0x00,
        0xC3,
    };
    ASSERT_FINDINGS(mov_mov_ret, "suboptimal MOV zero", 1);

    // mov eax, 0 ; add ebx, 2 ; ret -- ADD overwrites all arith flags
    // before any reader, finding fires. (imm 2, not 1, so the ADD is not
    // itself an inc/dec candidate.)
    static const uint8_t mov_add_ret[] = {
        0xB8, 0x00, 0x00, 0x00, 0x00,
        0x83, 0xC3, 0x02,
        0xC3,
    };
    ASSERT_FINDINGS(mov_add_ret, "suboptimal MOV zero", 1);

    // imul eax, eax, 4 ; jo +0 -- JO reads OF, LEA/SHL wouldn't produce
    // the same OF, suppress.
    static const uint8_t imul_jo[] = {
        0x6B, 0xC0, 0x04,
        0x70, 0x00,
    };
    ASSERT_FINDINGS(imul_jo, "suboptimal IMUL constant", 0);

    // imul eax, eax, 4 ; add ebx, 2 ; ret -- CF/OF overwritten by ADD
    // before any reader, finding fires. (imm 2 so the ADD is not an
    // inc/dec candidate.)
    static const uint8_t imul_add_ret[] = {
        0x6B, 0xC0, 0x04,
        0x83, 0xC3, 0x02,
        0xC3,
    };
    ASSERT_FINDINGS(imul_add_ret, "suboptimal IMUL constant", 1);

    // and eax, 0xff ; jz +0 -- ZF is live, suppress.
    static const uint8_t and_jz[] = {
        0x83, 0xE0, 0xFF,
        0x74, 0x00,
    };
    ASSERT_FINDINGS(and_jz, "suboptimal AND immediate", 0);

    // and eax, 0xff ; mov ebx, ecx ; ret -- MOV transparent, RET kills,
    // finding fires.
    static const uint8_t and_mov_ret[] = {
        0x83, 0xE0, 0xFF,
        0x89, 0xCB,
        0xC3,
    };
    ASSERT_FINDINGS(and_mov_ret, "suboptimal AND immediate", 1);

    // mov eax, 0 alone at end of buffer -- we don't know what comes next,
    // conservative LIVE, suppress.
    static const uint8_t mov_alone[] = {
        0xB8, 0x00, 0x00, 0x00, 0x00,
    };
    ASSERT_FINDINGS(mov_alone, "suboptimal MOV zero", 0);

    // mov eax, 0 ; call rel32 -- CALL clobbers caller-save flags via the
    // callee; we don't trace into it, conservative LIVE, suppress.
    static const uint8_t mov_call[] = {
        0xB8, 0x00, 0x00, 0x00, 0x00,
        0xE8, 0x00, 0x00, 0x00, 0x00,
    };
    ASSERT_FINDINGS(mov_call, "suboptimal MOV zero", 0);

    // mov eax, 0 ; cmove ebx, ecx ; ret -- CMOV reads ZF, suppress.
    // This is the original CMOV false positive from issue #7.
    static const uint8_t mov_cmove[] = {
        0xB8, 0x00, 0x00, 0x00, 0x00,
        0x0F, 0x44, 0xD9,
        0xC3,
    };
    ASSERT_FINDINGS(mov_cmove, "suboptimal MOV zero", 0);

    // redundant ADD/SUB zero is NOT flag-gated: test reg, reg reproduces the
    // flags exactly, so the finding fires whether or not the flags are live.
    // add ebx, 0 ; je +0 -- ZF live, but test ebx, ebx preserves it, flag.
    static const uint8_t addzero_je[] = {
        0x83, 0xC3, 0x00,
        0x74, 0x00,
    };
    ASSERT_FINDINGS(addzero_je, "redundant ADD/SUB zero", 1);

    // add ebx, 0 ; ret -- flags dead, remove it, also flagged.
    static const uint8_t addzero_ret[] = {
        0x83, 0xC3, 0x00,
        0xC3,
    };
    ASSERT_FINDINGS(addzero_ret, "redundant ADD/SUB zero", 1);

    // add eax, 1 ; ret -- CF dead at ret, inc eax is valid, finding fires.
    static const uint8_t addone_ret[] = {
        0x83, 0xC0, 0x01,
        0xC3,
    };
    ASSERT_FINDINGS(addone_ret, "oversized ADD/SUB one", 1);

    // add eax, 1 ; jc +0 -- JC reads CF, which inc would not set, suppress.
    static const uint8_t addone_jc[] = {
        0x83, 0xC0, 0x01,
        0x72, 0x00,
    };
    ASSERT_FINDINGS(addone_jc, "oversized ADD/SUB one", 0);

    // add eax, 1 ; add ecx, 2 ; ret -- the second ADD overwrites CF before
    // any reader (and imm 2 is not itself a candidate), finding fires once.
    static const uint8_t addone_add_ret[] = {
        0x83, 0xC0, 0x01,
        0x83, 0xC1, 0x02,
        0xC3,
    };
    ASSERT_FINDINGS(addone_add_ret, "oversized ADD/SUB one", 1);
}

// Instruction-flavor corners for flag liveness: pin the analyzer's handling
// of "undefined" flag writes, partial flag writers, flag-only readers, the
// MAX_LOOKAHEAD bound, and trap-style terminators.
static void check_flag_liveness_corners_test(void)
{
    // IDIV leaves all arith flags "undefined" per Intel SDM. The analyzer
    // treats undefined as written (the original value is destroyed), so
    // mov_zero's concern set empties and the finding fires.
    static const uint8_t mov_idiv_ret[] = {
        0xBB, 0x01, 0x00, 0x00, 0x00,  // mov ebx, 1
        0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, 0
        0xF7, 0xFB,                    // idiv ebx
        0xC3,                          // ret
    };
    ASSERT_FINDINGS(mov_idiv_ret, "suboptimal MOV zero", 1);

    // INC writes OF/SF/ZF/AF/PF but not CF. The CF from add eax, 0x80 stays
    // live through INC and gets consumed by ADC -- suppress.
    static const uint8_t add_inc_adc[] = {
        0x05, 0x80, 0x00, 0x00, 0x00,  // add eax, 0x80
        0xFF, 0xC3,                    // inc ebx
        0x11, 0xD1,                    // adc ecx, edx
        0xC3,                          // ret
    };
    ASSERT_FINDINGS(add_inc_adc, "oversized ADD/SUB 128", 0);

    // Same shape but the second ADD (not ADC) overwrites CF before any
    // reader, so the oversized_add128 finding fires.
    static const uint8_t add_inc_add[] = {
        0x05, 0x80, 0x00, 0x00, 0x00,  // add eax, 0x80
        0xFF, 0xC3,                    // inc ebx
        0x83, 0xC1, 0x02,              // add ecx, 2 (imm != 1, not an inc candidate)
        0xC3,                          // ret
    };
    ASSERT_FINDINGS(add_inc_add, "oversized ADD/SUB 128", 1);

    // SETcc reads a status flag and writes a byte register; treated as a
    // flag reader by the analyzer.
    static const uint8_t mov_sete_ret[] = {
        0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, 0
        0x0F, 0x94, 0xC3,              // sete bl   (reads ZF)
        0xC3,                          // ret
    };
    ASSERT_FINDINGS(mov_sete_ret, "suboptimal MOV zero", 0);

    // 16-instruction lookahead bound: 16 transparent NOPs exhaust the
    // budget before RET, so the analyzer returns LIVE conservatively.
    static const uint8_t mov_16nops_ret[] = {
        0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, 0
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0xC3,                          // ret (beyond the bound)
    };
    ASSERT_FINDINGS(mov_16nops_ret, "suboptimal MOV zero", 0);

    // Same shape with 15 NOPs: RET is the 16th instruction, reached as the
    // last iteration, DEAD -> fire.
    static const uint8_t mov_15nops_ret[] = {
        0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, 0
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0xC3,
    };
    ASSERT_FINDINGS(mov_15nops_ret, "suboptimal MOV zero", 1);

    // INT3 carries XED_CATEGORY_INTERRUPT; analyzer bails LIVE.
    static const uint8_t mov_int3[] = {
        0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, 0
        0xCC,                          // int3
    };
    ASSERT_FINDINGS(mov_int3, "suboptimal MOV zero", 0);

    // UD2 isn't a recognized control transfer; the analyzer steps through
    // it and runs out of buffer (-> LIVE). If a future change treats UD2
    // as a terminator (it's overwhelmingly used as an unreachable marker
    // by compilers), this assertion flips to 1.
    static const uint8_t mov_ud2[] = {
        0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, 0
        0x0F, 0x0B,                    // ud2
    };
    ASSERT_FINDINGS(mov_ud2, "suboptimal MOV zero", 0);

    // sysexit (XED_CATEGORY_SYSRET) returns to user mode carrying the flags
    // -- it writes none -- so the analyzer must treat it as a control
    // transfer (LIVE) and not walk past it to the non-successor add. Before
    // the SYSRET case was added this wrongly fired.
    static const uint8_t mov_sysexit[] = {
        0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, 0
        0x0F, 0x35,                    // sysexit
        0x83, 0xC3, 0x02,              // add ebx, 2 (imm != 1, not an inc candidate)
        0xC3,                          // ret
    };
    ASSERT_FINDINGS(mov_sysexit, "suboptimal MOV zero", 0);

    // A shift by CL writes its flags only when the masked runtime count is
    // nonzero (XED may_write), so it must not retire a concern: with cl == 0
    // the JC reads the ADD's CF, which the negated SUB -128 rewrite inverts
    // -- suppress.
    static const uint8_t add128_shlcl_jc[] = {
        0x05, 0x80, 0x00, 0x00, 0x00,  // add eax, 0x80
        0xD3, 0xE3,                    // shl ebx, cl (conditional flag write)
        0x72, 0x00,                    // jc +0 (reads CF)
    };
    ASSERT_FINDINGS(add128_shlcl_jc, "oversized ADD/SUB 128", 0);

    // Same shape with an immediate count: the flag write is unconditional,
    // CF dies at the shift, finding fires.
    static const uint8_t add128_shlimm_jc[] = {
        0x05, 0x80, 0x00, 0x00, 0x00,  // add eax, 0x80
        0xC1, 0xE3, 0x02,              // shl ebx, 2 (unconditional flag write)
        0x72, 0x00,                    // jc +0
    };
    ASSERT_FINDINGS(add128_shlimm_jc, "oversized ADD/SUB 128", 1);

    // REPE CMPSB compares zero times when RCX == 0, leaving the flags
    // untouched -- another conditional writer, suppress.
    static const uint8_t add128_repecmps_jc[] = {
        0x05, 0x80, 0x00, 0x00, 0x00,  // add eax, 0x80
        0xF3, 0xA6,                    // repe cmpsb (conditional flag write)
        0x72, 0x00,                    // jc +0
    };
    ASSERT_FINDINGS(add128_repecmps_jc, "oversized ADD/SUB 128", 0);

    // A conditional writer keeps the concern live but does not stop the
    // walk: a later unconditional writer still retires it and the finding
    // fires.
    static const uint8_t add128_shlcl_add_ret[] = {
        0x05, 0x80, 0x00, 0x00, 0x00,  // add eax, 0x80
        0xD3, 0xE3,                    // shl ebx, cl (conditional flag write)
        0x83, 0xC1, 0x02,              // add ecx, 2 (kills CF; imm != 1)
        0xC3,                          // ret
    };
    ASSERT_FINDINGS(add128_shlcl_add_ret, "oversized ADD/SUB 128", 1);
}

// An undecodable byte (executable sections routinely embed data) must not
// abort the scan: linear sweep skips one byte, resyncs, and still flags the
// instruction that follows. 0x06 (push es) is illegal in 64-bit mode.
static void check_decode_resync_test(void)
{
    static const uint8_t inst[] = {
        0x90,                          // nop (decodes, no finding)
        0x06,                          // (bad) push es -- undecodable
        0x68, 0x01, 0x00, 0x00, 0x00,  // push 0x1 (oversized immediate)
    };

    x86lint_summary *summary = x86lint_summary_create();
    assert(summary != NULL);
    int findings = check_instructions(inst, sizeof(inst), false, summary);
    assert(findings == 1);                              // not -1; scan continued
    assert(x86lint_summary_skipped(summary) == 1);      // the one bad byte
    assert(x86lint_summary_instructions(summary) == 2); // nop + push, not the byte
    x86lint_summary_destroy(summary);
}

int main(int argc, char *argv[])
{
    xed_tables_init();
    xed_set_verbosity(0);

    check_suboptimal_nops_test();
    check_oversized_immediate_test();
    check_oversized_add_sub_128_test();
    check_unneeded_rex_test();
    check_cmp_zero_test();
    check_mov_zero_test();
    check_implicit_register_test();
    check_implicit_immediate_test();
    check_and_strength_reduce_test();
    check_missing_lock_prefix_test();
    check_superfluous_lock_prefix_test();
    check_xchg_accumulator_test();
    check_oversized_branch_test();
    check_mov_self_test();
    check_add_sub_zero_test();
    check_inc_dec_test();
    check_mov_modrm_imm_test();
    check_unneeded_sib_test();
    check_unneeded_zero_displacement_test();
    check_oversized_displacement_test();
    check_unneeded_movsxd_test();
    check_unneeded_movsx_test();
    check_sub_self_test();
    check_or_and_self_test();
    check_imul_to_lea_test();
    check_lea_to_mov_test();
    check_shift_zero_test();
    check_flag_liveness_test();
    check_flag_liveness_corners_test();
    check_decode_resync_test();

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
    int expected = 10;
    int actual = check_instructions(inst, sizeof(inst), false, NULL);
    if (actual != expected) {
        printf("Expected %d errors, actual: %d\n", expected, actual);
        return 1;
    }

    return 0;
}
