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

// Like CHECK_BYTES, but first pins what the fixture actually encodes: the
// bytes must decode to exactly `asm_str` (XED Intel syntax, trailing pad
// spaces trimmed). Plain CHECK_BYTES only asserts that the bytes decode at
// all, so a hand-encoding typo yields a fixture that tests its check against
// some other instruction -- and passes vacuously whenever the check ignores
// that instruction. Prefer this form for new fixtures whose encoding details
// (REX bits, operand forms, prefixes) carry the test's meaning.
#define CHECK_BYTES_ASM(func, asm_str, ...) \
do { \
    static const uint8_t bytes[] = { __VA_ARGS__ }; \
    xed_decoded_inst_t xedd; \
    decode_instruction(&xedd, bytes, sizeof(bytes)); \
    char _disasm[128]; \
    if (!xed_format_context(XED_SYNTAX_INTEL, &xedd, _disasm, \
                            sizeof(_disasm), 0, NULL, NULL)) { \
        _disasm[0] = '\0'; \
    } \
    for (size_t _n = strlen(_disasm); _n > 0 && _disasm[_n - 1] == ' ';) { \
        _disasm[--_n] = '\0'; \
    } \
    if (strcmp(_disasm, asm_str) != 0) { \
        fprintf(stderr, "%s:%d: fixture encodes \"%s\", not \"%s\"\n", \
                __FILE__, __LINE__, _disasm, asm_str); \
    } \
    assert(strcmp(_disasm, asm_str) == 0); \
    bool _result = func(&xedd); \
    if (!_result) { \
        fprintf(stderr, "%s:%d: " #func " failed on: %s\n", \
                __FILE__, __LINE__, asm_str); \
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
                          const char *name, int *total_out,
                          uint32_t extensions)
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
    int total = check_instructions(inst, len, 0, true, NULL, extensions);
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
#define ASSERT_FINDINGS(bytes_arr, category, expected) \
    ASSERT_FINDINGS_EXT(bytes_arr, category, expected, 0)

// ASSERT_FINDINGS with an enabled-extensions mask (enum x86lint_extensions
// bits), for the checks the dispatcher runs only under -m.
#define ASSERT_FINDINGS_EXT(bytes_arr, category, expected, ext) do { \
    int _total; \
    int _cat = count_findings(bytes_arr, sizeof(bytes_arr), category, &_total, \
                              (ext)); \
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
    // Match the library's decode_init: fixtures must decode exactly as the
    // sweep decodes them (XED_CHIP_ALL turns F3 0F BD into LZCNT, not BSR
    // under a stray REP prefix).
    xed_decoded_inst_set_input_chip(xedd, XED_CHIP_ALL);
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
    // 16-bit operand size: 66 81 /r iw -> 66 83 /r ib saves a byte the same
    // way (push and imul included); MOV has no imm8 form and AX's
    // accumulator encoding already ties it.
    CHECK_BYTES(!check_oversized_immediate, 0x66, 0x81, 0xC1, 0x12, 0x00);        // add cx, 0x12
    CHECK_BYTES(!check_oversized_immediate, 0x66, 0x81, 0xC1, 0xF0, 0xFF);        // add cx, -16
    CHECK_BYTES(!check_oversized_immediate, 0x66, 0x81, 0xC1, 0x80, 0xFF);        // add cx, -128 (boundary)
    CHECK_BYTES( check_oversized_immediate, 0x66, 0x81, 0xC1, 0x7F, 0xFF);        // add cx, -129 (past imm8)
    CHECK_BYTES( check_oversized_immediate, 0x66, 0x81, 0xC1, 0x00, 0x01);        // add cx, 0x100 (needs imm16)
    CHECK_BYTES(!check_oversized_immediate, 0x66, 0x81, 0x03, 0x12, 0x00);        // add word ptr [rbx], 0x12
    CHECK_BYTES(!check_oversized_immediate, 0x66, 0x68, 0x12, 0x00);              // push 0x12 (imm16 -> 66 6A 12)
    CHECK_BYTES(!check_oversized_immediate, 0x66, 0x69, 0xCA, 0x12, 0x00);        // imul cx, dx, 0x12 (-> 66 6B)
    CHECK_BYTES( check_oversized_immediate, 0x66, 0x83, 0xC1, 0x12);              // add cx, 0x12 (already imm8)
    CHECK_BYTES( check_oversized_immediate, 0x66, 0xB9, 0x12, 0x00);              // mov cx, 0x12 (no imm8 form)
    CHECK_BYTES( check_oversized_immediate, 0x66, 0x05, 0x12, 0x00);              // add ax, 0x12 (accumulator, 4 bytes: ties imm8 form)
    CHECK_BYTES( check_oversized_immediate, 0x66, 0x81, 0xC0, 0x12, 0x00);        // add ax, 0x12 (modrm: check_implicit_register's finding)

    // Dispatcher wiring: unconditional finding, end-to-end. imm 2 (not 1)
    // so the CF-gated inc/dec rewrite does not co-fire after the ret.
    static const uint8_t add2_imm32[] = {
        0x05, 0x02, 0x00, 0x00, 0x00,  // add eax, 2 (imm32; fits imm8)
        0xC3,                          // ret
    };
    ASSERT_FINDINGS(add2_imm32, "oversized immediate", 1);
}

static void check_oversized_test_immediate_test(void)
{
    // Mask within the low seven bits: the byte form sets identical flags.
    CHECK_BYTES(!check_oversized_test_immediate, 0xa9, 0x01, 0x00, 0x00, 0x00);              // test eax, 1 (-> test al, 1)
    CHECK_BYTES(!check_oversized_test_immediate, 0xf7, 0xc3, 0x40, 0x00, 0x00, 0x00);        // test ebx, 0x40 (-> test bl, 0x40)
    CHECK_BYTES(!check_oversized_test_immediate, 0x48, 0xf7, 0xc0, 0x01, 0x00, 0x00, 0x00);  // test rax, 1
    CHECK_BYTES(!check_oversized_test_immediate, 0x66, 0xf7, 0xc0, 0x01, 0x00);              // test ax, 1 (imm16)
    CHECK_BYTES(!check_oversized_test_immediate, 0x41, 0xf7, 0xc0, 0x01, 0x00, 0x00, 0x00);  // test r8d, 1 (-> test r8b, 1)
    CHECK_BYTES(!check_oversized_test_immediate, 0xf7, 0xc6, 0x01, 0x00, 0x00, 0x00);        // test esi, 1 (-> test sil, 1)
    // Bit 7 in the mask: the narrow form computes SF from a live bit.
    CHECK_BYTES( check_oversized_test_immediate, 0xa9, 0x80, 0x00, 0x00, 0x00);              // test eax, 0x80
    CHECK_BYTES( check_oversized_test_immediate, 0xa9, 0xff, 0x00, 0x00, 0x00);              // test eax, 0xff
    // Bits 8-15 (the test ah, imm rewrite changes PF) -- skipped.
    CHECK_BYTES( check_oversized_test_immediate, 0xa9, 0x00, 0x01, 0x00, 0x00);              // test eax, 0x100
    // Negative imm32 sign-extends at 64-bit width -- high bits set.
    CHECK_BYTES( check_oversized_test_immediate, 0x48, 0xf7, 0xc0, 0xff, 0xff, 0xff, 0xff);  // test rax, -1
    // Already the byte form.
    CHECK_BYTES( check_oversized_test_immediate, 0xa8, 0x01);                                // test al, 1
    CHECK_BYTES( check_oversized_test_immediate, 0xf6, 0xc3, 0x01);                          // test bl, 1
    // Memory operand: narrowing changes the access width (MMIO-visible).
    CHECK_BYTES( check_oversized_test_immediate, 0xf7, 0x00, 0x01, 0x00, 0x00, 0x00);        // test dword ptr [rax], 1
    // Degenerate mask 0 still narrows (ZF=1, PF=1, SF=0 at either width).
    CHECK_BYTES(!check_oversized_test_immediate, 0xa9, 0x00, 0x00, 0x00, 0x00);              // test eax, 0
    // No immediate / not TEST.
    CHECK_BYTES( check_oversized_test_immediate, 0x85, 0xc0);                                // test eax, eax
    CHECK_BYTES( check_oversized_test_immediate, 0x90);                                      // nop
}

static void check_test_minus_one_test(void)
{
    // All-ones mask at the operand width -> test reg, reg.
    CHECK_BYTES(!check_test_minus_one, 0xa9, 0xff, 0xff, 0xff, 0xff);              // test eax, -1 (accumulator)
    CHECK_BYTES(!check_test_minus_one, 0xf7, 0xc3, 0xff, 0xff, 0xff, 0xff);        // test ebx, -1 (modrm)
    CHECK_BYTES(!check_test_minus_one, 0x48, 0xa9, 0xff, 0xff, 0xff, 0xff);        // test rax, -1 (imm32 sign-extended)
    CHECK_BYTES(!check_test_minus_one, 0x48, 0xf7, 0xc3, 0xff, 0xff, 0xff, 0xff);  // test rbx, -1
    CHECK_BYTES(!check_test_minus_one, 0x66, 0xa9, 0xff, 0xff);                    // test ax, -1
    CHECK_BYTES(!check_test_minus_one, 0xf6, 0xc3, 0xff);                          // test bl, -1 (8-bit non-AL)
    CHECK_BYTES(!check_test_minus_one, 0x41, 0xf7, 0xc0, 0xff, 0xff, 0xff, 0xff);  // test r8d, -1
    CHECK_BYTES(!check_test_minus_one, 0x40, 0xf6, 0xc6, 0xff);                    // test sil, -1 (uniform byte reg)
    // AL: the a8 ib accumulator form already ties test al, al; the modrm form
    // is check_implicit_register's finding.
    CHECK_BYTES( check_test_minus_one, 0xa8, 0xff);                                // test al, -1 (accumulator)
    CHECK_BYTES( check_test_minus_one, 0xf6, 0xc0, 0xff);                          // test al, -1 (modrm)
    // Not an all-ones mask at the operand width.
    CHECK_BYTES( check_test_minus_one, 0xa9, 0x01, 0x00, 0x00, 0x00);              // test eax, 1
    CHECK_BYTES( check_test_minus_one, 0xa9, 0xff, 0xff, 0x00, 0x00);              // test eax, 0xffff (not full width)
    CHECK_BYTES( check_test_minus_one, 0x66, 0xa9, 0xff, 0x7f);                    // test ax, 0x7fff
    // Memory operand: no test [mem], [mem] form.
    CHECK_BYTES( check_test_minus_one, 0xf7, 0x00, 0xff, 0xff, 0xff, 0xff);        // test dword ptr [rax], -1
    // No immediate / not TEST.
    CHECK_BYTES( check_test_minus_one, 0x85, 0xc0);                                // test eax, eax
    CHECK_BYTES( check_test_minus_one, 0x83, 0xf0, 0xff);                          // xor eax, -1 (not TEST)
    CHECK_BYTES( check_test_minus_one, 0x90);                                      // nop

    // Dispatcher wiring: flag-exact, so unconditional. Bit 7 is set in the
    // all-ones mask, keeping check_oversized_test_immediate quiet.
    static const uint8_t test_allones[] = {
        0xA9, 0xFF, 0xFF, 0xFF, 0xFF,  // test eax, -1
        0xC3,                          // ret
    };
    ASSERT_FINDINGS(test_allones, "redundant TEST immediate", 1);
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

// Advisory: a 66 prefix that narrows the immediate to 16 bits is a
// length-changing prefix, stalling Intel's pre-decoder. Matched only for the
// whitelisted iclasses whose imm16 exists solely under the prefix.
static void check_lcp_imm16_test(void)
{
    // imm16 under a 66 prefix: the length-changing shape, register and
    // memory destinations alike.
    CHECK_BYTES_ASM(!check_lcp_imm16, "add cx, 0x1234", 0x66, 0x81, 0xC1, 0x34, 0x12);
    CHECK_BYTES_ASM(!check_lcp_imm16, "mov cx, 0x1234", 0x66, 0xB9, 0x34, 0x12);
    CHECK_BYTES_ASM(!check_lcp_imm16, "test ax, 0x1234", 0x66, 0xA9, 0x34, 0x12);
    CHECK_BYTES_ASM(!check_lcp_imm16, "imul cx, ax, 0x1234", 0x66, 0x69, 0xC8, 0x34, 0x12);
    CHECK_BYTES_ASM(!check_lcp_imm16, "push 0x1234", 0x66, 0x68, 0x34, 0x12);
    CHECK_BYTES_ASM(!check_lcp_imm16, "or word ptr [rbx], 0x1234", 0x66, 0x81, 0x0B, 0x34, 0x12);

    // The sign-extended imm8 form is imm8 at any operand size: no length
    // change (and the value-fits case is oversized-immediate's finding).
    CHECK_BYTES_ASM(check_lcp_imm16, "add cx, 0x12", 0x66, 0x83, 0xC1, 0x12);
    // 32-bit operands: no prefix, no stall.
    CHECK_BYTES_ASM(check_lcp_imm16, "add ecx, 0x1234", 0x81, 0xC1, 0x34, 0x12, 0x00, 0x00);
    // ret's imm16 is fixed -- no prefix modulates its length.
    CHECK_BYTES_ASM(check_lcp_imm16, "ret 0x1234", 0xC2, 0x34, 0x12);
    // enter's imm16 likewise (pins the whitelist).
    CHECK_BYTES_ASM(check_lcp_imm16, "enter 0x1234, 0x0", 0xC8, 0x34, 0x12, 0x00);
    // A mandatory-66 SSE opcode: XED reports no operand-size prefix, and no
    // SSE immediate is 16 bits anyway.
    CHECK_BYTES_ASM(check_lcp_imm16, "pshufd xmm1, xmm0, 0x1b", 0x66, 0x0F, 0x70, 0xC8, 0x1B);

    // Dispatcher wiring; 0x1234 has no imm8 form, so nothing co-fires.
    static const uint8_t lcp[] = {
        0x66, 0x81, 0xC1, 0x34, 0x12,  // add cx, 0x1234
        0xC3,                          // ret
    };
    ASSERT_FINDINGS(lcp, "length-changing prefix stall", 1);
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

    // Dispatcher wiring: unconditional finding, end-to-end.
    static const uint8_t rex_leave[] = {
        0x40, 0xC9,  // rex leave (the prefix does nothing)
        0xC3,        // ret
    };
    ASSERT_FINDINGS(rex_leave, "unneeded REX prefix", 1);
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
    CHECK_BYTES(!check_cmp_zero, 0x83, 0xff, 0x00);  // cmp edi, 0
    CHECK_BYTES( check_cmp_zero, 0x83, 0xff, 0x01);  // cmp edi, 1
    CHECK_BYTES( check_cmp_zero, 0x83, 0x3f, 0x00);  // cmp dword ptr [rdi], 0 (memory exempt)
    CHECK_BYTES( check_cmp_zero, 0x83, 0xc7, 0x00);  // add edi, 0 (not cmp)
    // cmp al, 0 ties test al, al (both 2 bytes), so it is not flagged in
    // either encoding; every other byte register and width still is.
    CHECK_BYTES( check_cmp_zero, 0x3c, 0x00);        // cmp al, 0 (2-byte 3C form, ties test al, al)
    CHECK_BYTES( check_cmp_zero, 0x80, 0xf8, 0x00);  // cmp al, 0 (modrm form; test does not beat the 3C form)
    CHECK_BYTES( check_cmp_zero, 0x3c, 0x05);        // cmp al, 5 (nonzero, unchanged)
    CHECK_BYTES(!check_cmp_zero, 0x80, 0xfb, 0x00);  // cmp bl, 0 (no AL short form; test bl, bl is smaller)

    // Dispatcher wiring: test edi, edi is flag-exact for cmp edi, 0 (AF is
    // unobservable in 64-bit mode), so the finding is unconditional.
    static const uint8_t cmp0_ret[] = {
        0x83, 0xFF, 0x00,  // cmp edi, 0
        0xC3,              // ret
    };
    ASSERT_FINDINGS(cmp0_ret, "suboptimal CMP zero", 1);
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

    // Dispatcher wiring: unconditional finding, end-to-end. imm 0x100 does
    // not fit imm8, keeping check_oversized_immediate quiet.
    static const uint8_t add_modrm_acc[] = {
        0x81, 0xC0, 0x00, 0x01, 0x00, 0x00,  // add eax, 0x100 (modrm form)
        0xC3,                                // ret
    };
    ASSERT_FINDINGS(add_modrm_acc, "unneeded explicit register", 1);
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

    // Dispatcher wiring: unconditional finding, end-to-end. RCL (not SHL)
    // so check_shl_one does not co-fire on the count of 1.
    static const uint8_t rcl_imm1[] = {
        0xC1, 0xD0, 0x01,  // rcl eax, 1 (C1 /2 ib; D1 /2 is a byte shorter)
        0xC3,              // ret
    };
    ASSERT_FINDINGS(rcl_imm1, "unneeded explicit immediate", 1);
}

static void check_and_strength_reduce_test(void)
{
    // A low-byte/word mask keeps those bits and zero-extends into rax, so it
    // reduces to movzbl / movzwl -- a finding here. The all-ones mask (any
    // width) is a value no-op and is check_and_minus_one's finding instead.
    CHECK_BYTES( check_and_strength_reduce, 0x83, 0xe0, 0xff);                    // and eax, -1 (all-ones -> and_minus_one)
    CHECK_BYTES( check_and_strength_reduce, 0x83, 0xe0, 0xfe);                    // and eax, 0xfffffffe (not a mask)
    CHECK_BYTES(!check_and_strength_reduce, 0x25, 0xff, 0xff, 0x00, 0x00);        // and eax, 0xffff (-> movzwl)
    CHECK_BYTES( check_and_strength_reduce, 0x25, 0xff, 0xff, 0xff, 0xff);        // and eax, -1 (all-ones -> and_minus_one)
    CHECK_BYTES(!check_and_strength_reduce, 0x48, 0x25, 0xff, 0x00, 0x00, 0x00);  // and rax, 0xff (-> movzbl, zero-extends)
    // REX.W all-ones: no zero-extending win (mov rax, rax is not shorter); the
    // flag-exact test rax, rax is check_and_minus_one's finding.
    CHECK_BYTES( check_and_strength_reduce, 0x48, 0x25, 0xff, 0xff, 0xff, 0xff);  // and rax, -1
    CHECK_BYTES( check_and_strength_reduce, 0x48, 0x83, 0xe0, 0xff);              // and rax, sx(0xff) = -1
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

static void check_and_minus_one_test(void)
{
    // All-ones mask keeps every bit -> test reg, reg (flag-exact, fewer bytes),
    // at any operand width including the 64-bit and 16-bit forms that
    // check_and_strength_reduce leaves alone.
    CHECK_BYTES(!check_and_minus_one, 0x83, 0xe0, 0xff);                    // and eax, -1 (sx imm8)
    CHECK_BYTES(!check_and_minus_one, 0x25, 0xff, 0xff, 0xff, 0xff);        // and eax, -1 (imm32)
    CHECK_BYTES(!check_and_minus_one, 0x48, 0x83, 0xe0, 0xff);              // and rax, -1
    CHECK_BYTES(!check_and_minus_one, 0x48, 0x25, 0xff, 0xff, 0xff, 0xff);  // and rax, -1 (imm32 sx)
    CHECK_BYTES(!check_and_minus_one, 0x66, 0x83, 0xe0, 0xff);              // and ax, -1
    CHECK_BYTES(!check_and_minus_one, 0x80, 0xe3, 0xff);                    // and bl, -1 (8-bit non-AL)
    // AL: the 24 ib accumulator form already ties test al, al; the modrm form
    // is check_implicit_register's finding.
    CHECK_BYTES( check_and_minus_one, 0x24, 0xff);                          // and al, -1 (accumulator)
    CHECK_BYTES( check_and_minus_one, 0x80, 0xe0, 0xff);                    // and al, -1 (modrm)
    // Nonzero non-all-ones masks are check_and_strength_reduce's concern.
    CHECK_BYTES( check_and_minus_one, 0x83, 0xe0, 0xfe);                    // and eax, 0xfffffffe
    CHECK_BYTES( check_and_minus_one, 0x25, 0xff, 0x00, 0x00, 0x00);        // and eax, 0xff (low-byte mask)
    CHECK_BYTES( check_and_minus_one, 0x83, 0xe0, 0x00);                    // and eax, 0 (zero -> check_and_zero)
    // Memory / not AND.
    CHECK_BYTES( check_and_minus_one, 0x83, 0x20, 0xff);                    // and dword ptr [rax], -1 (memory)
    CHECK_BYTES( check_and_minus_one, 0x83, 0xf0, 0xff);                    // xor eax, -1 (not AND)
    CHECK_BYTES( check_and_minus_one, 0x90);                                // nop
}

static void check_xor_to_not_test(void)
{
    // All-ones at the effective operand width, every encoding -> not r/m.
    CHECK_BYTES(!check_xor_to_not, 0x83, 0xf0, 0xff);                          // xor eax, -1 (sx imm8)
    CHECK_BYTES(!check_xor_to_not, 0x81, 0xf0, 0xff, 0xff, 0xff, 0xff);        // xor eax, -1 (imm32)
    CHECK_BYTES(!check_xor_to_not, 0x35, 0xff, 0xff, 0xff, 0xff);              // xor eax, -1 (accumulator)
    CHECK_BYTES(!check_xor_to_not, 0x48, 0x83, 0xf0, 0xff);                    // xor rax, -1
    CHECK_BYTES(!check_xor_to_not, 0x48, 0x81, 0xf0, 0xff, 0xff, 0xff, 0xff);  // xor rax, -1 (sx imm32)
    CHECK_BYTES(!check_xor_to_not, 0x66, 0x83, 0xf0, 0xff);                    // xor ax, -1
    CHECK_BYTES(!check_xor_to_not, 0x80, 0xf3, 0xff);                          // xor bl, -1 (-> not bl, 3 -> 2)
    CHECK_BYTES(!check_xor_to_not, 0x83, 0x30, 0xff);                          // xor dword ptr [rax], -1 (memory)
    // AL accumulator form already ties not al; the modrm form is
    // check_implicit_register's finding.
    CHECK_BYTES( check_xor_to_not, 0x34, 0xff);                                // xor al, -1 (accumulator)
    CHECK_BYTES( check_xor_to_not, 0x80, 0xf0, 0xff);                          // xor al, -1 (modrm)
    // Not all-ones at the operand width.
    CHECK_BYTES( check_xor_to_not, 0x83, 0xf0, 0x7f);                          // xor eax, 0x7f
    CHECK_BYTES( check_xor_to_not, 0x35, 0xfe, 0xff, 0xff, 0xff);              // xor eax, 0xfffffffe
    // LOCK form decodes to the distinct XOR_LOCK iclass.
    CHECK_BYTES( check_xor_to_not, 0xf0, 0x83, 0x30, 0xff);                    // lock xor dword ptr [rax], -1
    // No immediate / not XOR.
    CHECK_BYTES( check_xor_to_not, 0x31, 0xc0);                                // xor eax, eax
    CHECK_BYTES( check_xor_to_not, 0xf7, 0xd0);                                // not eax (already short)
    CHECK_BYTES( check_xor_to_not, 0x83, 0xc8, 0xff);                          // or eax, -1 (not XOR)
    CHECK_BYTES( check_xor_to_not, 0x90);                                      // nop

    // Dispatcher gating: NOT writes no flags where XOR writes them all, so
    // the finding needs the arithmetic flags dead -- ret satisfies that.
    static const uint8_t xornot_ret[] = {
        0x83, 0xF0, 0xFF,  // xor eax, -1
        0xC3,              // ret
    };
    ASSERT_FINDINGS(xornot_ret, "suboptimal XOR immediate", 1);

    // A downstream ZF reader keeps the XOR's flags live: suppress.
    static const uint8_t xornot_jz[] = {
        0x83, 0xF0, 0xFF,  // xor eax, -1
        0x74, 0x00,        // jz +0
    };
    ASSERT_FINDINGS(xornot_jz, "suboptimal XOR immediate", 0);
}


static void check_superfluous_lock_prefix_test(void)
{
    CHECK_BYTES(!check_superfluous_lock_prefix, 0xf0, 0x87, 0x07);  // lock xchg [rdi], eax
    CHECK_BYTES( check_superfluous_lock_prefix, 0x87, 0x07);  // xchg [rdi], eax

    // Dispatcher wiring: unconditional finding, end-to-end (the memory form
    // has no 90+r alternative, so check_xchg_accumulator stays quiet).
    static const uint8_t lock_xchg[] = {
        0xF0, 0x87, 0x07,  // lock xchg [rdi], eax (XCHG locks implicitly)
        0xC3,              // ret
    };
    ASSERT_FINDINGS(lock_xchg, "unneeded LOCK prefix", 1);
}

// rep ret (F3 C3), the obsolete AMD K8/K10 branch-predictor workaround: the
// prefix is architecturally ignored, so dropping it is unconditional. Only
// F3 matches; F2 C3 was MPX's bnd ret, with real semantics on MPX silicon.
static void check_rep_ret_test(void)
{
    CHECK_BYTES_ASM(!check_rep_ret, "ret", 0xF3, 0xC3);          // rep ret
    CHECK_BYTES_ASM(!check_rep_ret, "ret 0x4", 0xF3, 0xC2, 0x04, 0x00);
    CHECK_BYTES_ASM( check_rep_ret, "ret", 0xC3);
    CHECK_BYTES_ASM( check_rep_ret, "ret 0x4", 0xC2, 0x04, 0x00);
    CHECK_BYTES_ASM( check_rep_ret, "bnd ret", 0xF2, 0xC3);

    // Dispatcher wiring: unconditional finding, end-to-end.
    static const uint8_t rep_ret[] = {
        0xF3, 0xC3,  // rep ret
    };
    ASSERT_FINDINGS(rep_ret, "unneeded REP prefix on RET", 1);
}

// notrack call (3E FF /2): a call site exempted from CET indirect-branch
// tracking. Only CALLs match: notrack jmp is the compilers' read-only
// switch-table idiom, and on direct calls, far calls, and non-branches the
// 3E byte is an ignored segment override with no CET meaning (XED reports
// cet_no_track only for near indirect call/jmp -- the CS-prefixed lookalike
// 2E pins that it is specifically 3E).
static void check_notrack_call_test(void)
{
    CHECK_BYTES_ASM(!check_notrack_call, "notrack call rax",
                    0x3E, 0xFF, 0xD0);
    CHECK_BYTES_ASM(!check_notrack_call, "notrack call qword ptr [rax]",
                    0x3E, 0xFF, 0x10);
    CHECK_BYTES_ASM( check_notrack_call, "call rax", 0xFF, 0xD0);
    CHECK_BYTES_ASM( check_notrack_call, "call rax", 0x2E, 0xFF, 0xD0);
    CHECK_BYTES_ASM( check_notrack_call, "notrack jmp rax",
                    0x3E, 0xFF, 0xE0);
    CHECK_BYTES_ASM( check_notrack_call, "call 0x6",
                    0x3E, 0xE8, 0x00, 0x00, 0x00, 0x00);
    CHECK_BYTES( check_notrack_call, 0x3E, 0xC3);  // ds-prefixed ret

    // Dispatcher wiring: unconditional finding, end-to-end.
    static const uint8_t notrack_call[] = {
        0x3E, 0xFF, 0xD0,  // notrack call rax
    };
    ASSERT_FINDINGS(notrack_call, "IBT-bypassing NOTRACK call", 1);
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

    // Dispatcher wiring: unconditional finding, end-to-end (both encodings
    // zero-extend both registers identically, so no gate applies).
    static const uint8_t xchg_modrm[] = {
        0x87, 0xC8,  // xchg eax, ecx (modrm; 91 is one byte)
        0xC3,        // ret
    };
    ASSERT_FINDINGS(xchg_modrm, "oversized XCHG encoding", 1);
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

    // Dispatcher wiring: unconditional finding, end-to-end.
    static const uint8_t jmp_rel32[] = {
        0xE9, 0x00, 0x00, 0x00, 0x00,  // jmp +0 (rel32; rel8 reaches)
        0xC3,                          // ret
    };
    ASSERT_FINDINGS(jmp_rel32, "oversized branch displacement", 1);
}

static void check_mov_self_test(void)
{
    CHECK_BYTES(!check_mov_self, 0x48, 0x89, 0xc0);  // mov rax, rax (useless, REX.W)
    CHECK_BYTES(!check_mov_self, 0x48, 0x89, 0xdb);  // mov rbx, rbx
    CHECK_BYTES(!check_mov_self, 0x66, 0x89, 0xc0);  // mov ax, ax (no zero-ext, useless)
    CHECK_BYTES(!check_mov_self, 0x88, 0xc0);        // mov al, al (useless)
    CHECK_BYTES(!check_mov_self, 0x89, 0xc0);        // mov eax, eax (redundant; dispatcher gates on upper-bit liveness)
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

static void check_or_xor_zero_test(void)
{
    // or/xor reg, 0 leaves the register unchanged but sets flags -> test/remove.
    CHECK_BYTES(!check_or_xor_zero, 0x83, 0xc8, 0x00);              // or eax, 0
    CHECK_BYTES(!check_or_xor_zero, 0x83, 0xf0, 0x00);              // xor eax, 0
    CHECK_BYTES(!check_or_xor_zero, 0x48, 0x83, 0xc8, 0x00);        // or rax, 0
    CHECK_BYTES(!check_or_xor_zero, 0x66, 0x83, 0xc8, 0x00);        // or ax, 0
    CHECK_BYTES(!check_or_xor_zero, 0x80, 0xcb, 0x00);              // or bl, 0 (8-bit non-AL)
    CHECK_BYTES(!check_or_xor_zero, 0x0d, 0x00, 0x00, 0x00, 0x00);  // or eax, 0 (imm32 accumulator form)
    // AL: the 0c/34 ib accumulator forms already tie test al, al; the modrm
    // form is check_implicit_register's finding.
    CHECK_BYTES( check_or_xor_zero, 0x0c, 0x00);                    // or al, 0 (accumulator)
    CHECK_BYTES( check_or_xor_zero, 0x34, 0x00);                    // xor al, 0 (accumulator)
    CHECK_BYTES( check_or_xor_zero, 0x80, 0xc8, 0x00);             // or al, 0 (modrm)
    // Nonzero immediate / no immediate / memory / not OR-XOR.
    CHECK_BYTES( check_or_xor_zero, 0x83, 0xc8, 0x01);             // or eax, 1
    CHECK_BYTES( check_or_xor_zero, 0x83, 0xf0, 0xff);             // xor eax, -1 (check_xor_to_not's)
    CHECK_BYTES( check_or_xor_zero, 0x09, 0xc0);                   // or eax, eax (no immediate)
    CHECK_BYTES( check_or_xor_zero, 0x83, 0x08, 0x00);            // or dword ptr [rax], 0 (memory)
    CHECK_BYTES( check_or_xor_zero, 0x83, 0xe0, 0x00);            // and eax, 0 (not OR/XOR)
    CHECK_BYTES( check_or_xor_zero, 0x90);                         // nop
}

static void check_and_zero_test(void)
{
    // and reg, 0 zeroes the register -> xor reg, reg (fewer bytes, same flags).
    CHECK_BYTES(!check_and_zero, 0x83, 0xe0, 0x00);                // and eax, 0
    CHECK_BYTES(!check_and_zero, 0x48, 0x83, 0xe0, 0x00);          // and rax, 0
    CHECK_BYTES(!check_and_zero, 0x66, 0x83, 0xe0, 0x00);          // and ax, 0
    CHECK_BYTES(!check_and_zero, 0x80, 0xe3, 0x00);                // and bl, 0 (8-bit non-AL)
    CHECK_BYTES(!check_and_zero, 0x25, 0x00, 0x00, 0x00, 0x00);    // and eax, 0 (imm32 accumulator form)
    // AL: the 24 ib accumulator form already ties xor al, al; the modrm form
    // is check_implicit_register's finding.
    CHECK_BYTES( check_and_zero, 0x24, 0x00);                      // and al, 0 (accumulator)
    CHECK_BYTES( check_and_zero, 0x80, 0xe0, 0x00);               // and al, 0 (modrm)
    // Nonzero masks are check_and_strength_reduce's concern, not this one.
    CHECK_BYTES( check_and_zero, 0x83, 0xe0, 0x01);               // and eax, 1
    CHECK_BYTES( check_and_zero, 0x83, 0xe0, 0xff);               // and eax, -1 (all-ones no-op)
    CHECK_BYTES( check_and_zero, 0x25, 0xff, 0x00, 0x00, 0x00);   // and eax, 0xff (low-byte mask)
    // Memory / not AND.
    CHECK_BYTES( check_and_zero, 0x83, 0x20, 0x00);              // and dword ptr [rax], 0 (memory)
    CHECK_BYTES( check_and_zero, 0x83, 0xc8, 0x00);              // or eax, 0 (not AND)
    CHECK_BYTES( check_and_zero, 0x90);                           // nop

    // Dispatcher wiring: xor eax, eax zeroes, zero-extends, and sets flags
    // exactly as and eax, 0 does, so the finding is unconditional.
    static const uint8_t and0_ret[] = {
        0x83, 0xE0, 0x00,  // and eax, 0
        0xC3,              // ret
    };
    ASSERT_FINDINGS(and0_ret, "suboptimal AND zero", 1);
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
    // Memory destinations: inc/dec r/m drops the imm8 for every addressing
    // mode and width. 83 6b 10 01 is glibc's refcount-decrement shape.
    CHECK_BYTES(!check_inc_dec, 0x83, 0x00, 0x01);              // add dword ptr [rax], 1
    CHECK_BYTES(!check_inc_dec, 0x83, 0x6b, 0x10, 0x01);        // sub dword ptr [rbx+0x10], 1
    CHECK_BYTES(!check_inc_dec, 0x48, 0x83, 0x00, 0x01);        // add qword ptr [rax], 1
    CHECK_BYTES(!check_inc_dec, 0x80, 0x00, 0x01);              // add byte ptr [rax], 1
    // LOCK forms decode to the distinct ADD_LOCK/SUB_LOCK iclasses.
    CHECK_BYTES( check_inc_dec, 0xf0, 0x83, 0x00, 0x01);        // lock add dword ptr [rax], 1
    // |imm| != 1.
    CHECK_BYTES( check_inc_dec, 0x83, 0xc0, 0x02);              // add eax, 2
    CHECK_BYTES( check_inc_dec, 0x83, 0xc0, 0x00);              // add eax, 0
    CHECK_BYTES( check_inc_dec, 0x83, 0x00, 0x02);              // add dword ptr [rax], 2 (memory)
    // No immediate / not ADD-SUB.
    CHECK_BYTES( check_inc_dec, 0x01, 0xd8);                    // add eax, ebx
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
    // Memory destinations -- removal would delete an observable memory
    // access (fault, MMIO side effect, racing write-back), not flagged. The
    // byte form is also what a run of C0/00 data bytes decodes to.
    CHECK_BYTES( check_shift_zero, 0xc1, 0x20, 0x00);              // shl dword [rax], 0
    CHECK_BYTES( check_shift_zero, 0xc0, 0x00, 0x00);              // rol byte [rax], 0
    CHECK_BYTES( check_shift_zero, 0x0f, 0xa4, 0x18, 0x00);        // shld [rax], ebx, 0
    // Not a shift.
    CHECK_BYTES( check_shift_zero, 0x90);                          // nop
}

static void check_shl_one_test(void)
{
    // shl reg, 1 -> add reg, reg: value- and flag-exact, more ports, and the
    // imm8 encodings are a byte longer besides. Every width fires, both the
    // implicit-one (D0/D1) and imm8 (C0/C1) encodings.
    CHECK_BYTES(!check_shl_one, 0xd1, 0xe0);              // shl eax, 1 (D1 /4)
    CHECK_BYTES(!check_shl_one, 0xc1, 0xe0, 0x01);        // shl eax, 1 (C1 /4 ib)
    CHECK_BYTES(!check_shl_one, 0x48, 0xd1, 0xe0);        // shl rax, 1
    CHECK_BYTES(!check_shl_one, 0x66, 0xd1, 0xe0);        // shl ax, 1
    CHECK_BYTES(!check_shl_one, 0xd0, 0xe0);              // shl al, 1
    CHECK_BYTES(!check_shl_one, 0xc0, 0xe0, 0x01);        // shl al, 1 (imm8)
    CHECK_BYTES(!check_shl_one, 0x41, 0xd1, 0xe0);        // shl r8d, 1
    // Other counts, the CL form, memory, and the shifts with no ALU twin.
    CHECK_BYTES( check_shl_one, 0xc1, 0xe0, 0x02);        // shl eax, 2
    CHECK_BYTES( check_shl_one, 0xc1, 0xe0, 0x00);        // shl eax, 0 (check_shift_zero's)
    CHECK_BYTES( check_shl_one, 0xd3, 0xe0);              // shl eax, cl
    CHECK_BYTES( check_shl_one, 0xd1, 0x23);              // shl dword ptr [rbx], 1
    CHECK_BYTES( check_shl_one, 0xd1, 0xe8);              // shr eax, 1
    CHECK_BYTES( check_shl_one, 0xd1, 0xf8);              // sar eax, 1
    CHECK_BYTES( check_shl_one, 0xd1, 0xc0);              // rol eax, 1
    CHECK_BYTES( check_shl_one, 0x90);                    // nop

    // Flag-exactness makes the finding unconditional: it fires straight into
    // a CF reader, since add reg, reg produces the identical CF (and OF).
    static const uint8_t shl_jc[] = {
        0xD1, 0xE3,        // shl ebx, 1
        0x72, 0x00,        // jc +0 (reads CF; add ebx, ebx sets the same one)
    };
    ASSERT_FINDINGS(shl_jc, "suboptimal SHL one", 1);
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
    // Higher powers of two also reduce to SHL when dst == src.
    CHECK_BYTES(!check_imul_to_lea, 0x6b, 0xc0, 0x10);                    // imul eax, eax, 16 (shl eax, 4)
    CHECK_BYTES(!check_imul_to_lea, 0x6b, 0xc0, 0x40);                    // imul eax, eax, 64 (shl eax, 6)
    CHECK_BYTES(!check_imul_to_lea, 0x69, 0xc0, 0x80, 0x00, 0x00, 0x00);  // imul eax, eax, 128 (shl eax, 7; imm32 -> size win)
    CHECK_BYTES(!check_imul_to_lea, 0x69, 0xc0, 0x00, 0x00, 0x01, 0x00);  // imul eax, eax, 0x10000 (shl eax, 16)
    CHECK_BYTES(!check_imul_to_lea, 0x69, 0xc0, 0x00, 0x00, 0x00, 0x80);  // imul eax, eax, 0x80000000 (shl eax, 31)
    CHECK_BYTES(!check_imul_to_lea, 0x48, 0x6b, 0xc0, 0x10);              // imul rax, rax, 16 (shl rax, 4)
    CHECK_BYTES(!check_imul_to_lea, 0x48, 0x69, 0xc0, 0x00, 0x00, 0x00, 0x40); // imul rax, rax, 0x40000000 (shl rax, 30)
    // Power of two >= 4 with different registers has no shorter form.
    CHECK_BYTES( check_imul_to_lea, 0x6b, 0xc3, 0x10);                    // imul eax, ebx, 16 (different regs)
    // 64-bit imm32 sign-extends to -2^31, not a power of two -> not shl.
    CHECK_BYTES( check_imul_to_lea, 0x48, 0x69, 0xc0, 0x00, 0x00, 0x00, 0x80); // imul rax, rax, 0xffffffff80000000
    // Constants without a single-LEA equivalent.
    CHECK_BYTES( check_imul_to_lea, 0x6b, 0xc0, 0x06);                    // imul eax, eax, 6
    CHECK_BYTES( check_imul_to_lea, 0x6b, 0xc0, 0x07);                    // imul eax, eax, 7
    CHECK_BYTES( check_imul_to_lea, 0x6b, 0xc0, 0x0a);                    // imul eax, eax, 10
    CHECK_BYTES( check_imul_to_lea, 0x6b, 0xc0, 0x11);                    // imul eax, eax, 17 (not a power of two)
    CHECK_BYTES( check_imul_to_lea, 0x6b, 0xc0, 0xfe);                    // imul eax, eax, -2 (sign-ext, LEA can't negate)
    // Degenerate multipliers: 0 -> xor, 1 -> mov or removal, -1 -> neg.
    CHECK_BYTES(!check_imul_to_lea, 0x6b, 0xc1, 0x00);                    // imul eax, ecx, 0 (xor eax, eax)
    CHECK_BYTES(!check_imul_to_lea, 0x69, 0xc1, 0x00, 0x00, 0x00, 0x00);  // imul eax, ecx, 0 (imm32 form)
    CHECK_BYTES(!check_imul_to_lea, 0x6b, 0xc1, 0x01);                    // imul eax, ecx, 1 (mov eax, ecx)
    CHECK_BYTES(!check_imul_to_lea, 0x6b, 0xc0, 0x01);                    // imul eax, eax, 1 (removable identity)
    CHECK_BYTES(!check_imul_to_lea, 0x6b, 0xc0, 0xff);                    // imul eax, eax, -1 (neg eax)
    CHECK_BYTES(!check_imul_to_lea, 0x48, 0x6b, 0xc0, 0xff);              // imul rax, rax, -1 (neg rax)
    // -1 across registers: the 3-byte imul already beats mov + neg (4).
    CHECK_BYTES( check_imul_to_lea, 0x6b, 0xc1, 0xff);                    // imul eax, ecx, -1
    // Two-operand form (no immediate).
    CHECK_BYTES( check_imul_to_lea, 0x0f, 0xaf, 0xc3);                    // imul eax, ebx
    // Memory-source IMUL: LEA replacement needs extra load, would be longer
    // (and the degenerate rewrites would drop the load entirely).
    CHECK_BYTES( check_imul_to_lea, 0x48, 0x6b, 0x43, 0x08, 0x03);        // imul rax, [rbx+8], 3
    // Not IMUL.
    CHECK_BYTES( check_imul_to_lea, 0x90);                                // nop

    // Dispatcher gating. imul ebx, ebx, 1 -> removal drops both the CF=OF=0
    // write and the 32-bit zero-extension, so it needs the flags AND the
    // upper half dead: a following 32-bit write satisfies both here.
    static const uint8_t identity_kill[] = {
        0x6B, 0xDB, 0x01,        // imul ebx, ebx, 1
        0x89, 0xCB,              // mov ebx, ecx (kills the upper bits)
        0xC3,                    // ret (flags dead)
    };
    ASSERT_FINDINGS(identity_kill, "suboptimal IMUL constant", 1);

    // Same with the full register read downstream: the removal would leave
    // rbx's upper half stale, so the register gate suppresses it even though
    // the add killed the flags.
    static const uint8_t identity_upper_read[] = {
        0x6B, 0xDB, 0x01,        // imul ebx, ebx, 1
        0x83, 0xC1, 0x02,        // add ecx, 2 (kills CF/OF)
        0x48, 0x89, 0x1F,        // mov [rdi], rbx (reads the upper half)
        0xC3,
    };
    ASSERT_FINDINGS(identity_upper_read, "suboptimal IMUL constant", 0);

    // The backward escape: the preceding 32-bit write already zeroed the
    // upper half, so the identity imul changes nothing despite the read.
    static const uint8_t identity_prev_zeroed[] = {
        0x89, 0xCB,              // mov ebx, ecx (zero-extends rbx)
        0x6B, 0xDB, 0x01,        // imul ebx, ebx, 1
        0x48, 0x89, 0x1F,        // mov [rdi], rbx
        0xC3,
    };
    ASSERT_FINDINGS(identity_prev_zeroed, "suboptimal IMUL constant", 1);

    // imul by 0 -> xor: fires when CF/OF are dead...
    static const uint8_t zero_ret[] = {
        0x6B, 0xD9, 0x00,        // imul ebx, ecx, 0
        0xC3,
    };
    ASSERT_FINDINGS(zero_ret, "suboptimal IMUL constant", 1);

    // ...and stays suppressed past a CF reader, though the xor rewrite is
    // CF/OF-exact for a zero product (both leave them 0): the shared gate is
    // conservative here.
    static const uint8_t zero_jc[] = {
        0x6B, 0xD9, 0x00,        // imul ebx, ecx, 0
        0x72, 0x00,              // jc +0
    };
    ASSERT_FINDINGS(zero_jc, "suboptimal IMUL constant", 0);

    // imul by 1 across registers -> mov, and by -1 in place -> neg.
    static const uint8_t one_mov_ret[] = {
        0x6B, 0xD9, 0x01,        // imul ebx, ecx, 1
        0xC3,
    };
    ASSERT_FINDINGS(one_mov_ret, "suboptimal IMUL constant", 1);
    static const uint8_t minus_one_neg_ret[] = {
        0x6B, 0xDB, 0xFF,        // imul ebx, ebx, -1
        0xC3,
    };
    ASSERT_FINDINGS(minus_one_neg_ret, "suboptimal IMUL constant", 1);
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

    // Dispatcher wiring: the mov rewrite preserves value and flags exactly,
    // so it fires unconditionally -- while the same bytes' oversized-LEA-width
    // candidate stays suppressed (rax's upper half is conservatively live at
    // ret), pinning that the two checks do not double-report.
    static const uint8_t lea_bare_base[] = {
        0x48, 0x8D, 0x03,  // lea rax, [rbx] (mov rax, rbx)
        0xC3,              // ret
    };
    ASSERT_FINDINGS(lea_bare_base, "suboptimal LEA", 1);
}

static void check_lea_to_add_test(void)
{
    // Destination is one of the two address registers (an in-place add).
    CHECK_BYTES(!check_lea_to_add, 0x48, 0x8d, 0x04, 0x08);  // lea rax, [rax+rcx]
    CHECK_BYTES(!check_lea_to_add, 0x8d, 0x04, 0x08);        // lea eax, [rax+rcx] (mixed size)
    CHECK_BYTES(!check_lea_to_add, 0x48, 0x8d, 0x04, 0x00);  // lea rax, [rax+rax]
    CHECK_BYTES(!check_lea_to_add, 0x48, 0x8d, 0x04, 0x01);  // lea rax, [rcx+rax] (dest is index)

    // Destination is neither address register: a genuine three-operand add.
    CHECK_BYTES( check_lea_to_add, 0x8d, 0x04, 0x11);            // lea eax, [rcx+rdx]
    // A scale, a displacement, or no index is not a plain two-register add.
    CHECK_BYTES( check_lea_to_add, 0x48, 0x8d, 0x04, 0x48);      // lea rax, [rax+rcx*2]
    CHECK_BYTES( check_lea_to_add, 0x48, 0x8d, 0x44, 0x08, 0x08); // lea rax, [rax+rcx+8]
    CHECK_BYTES( check_lea_to_add, 0x48, 0x8d, 0x03);            // lea rax, [rbx] (no index)
    CHECK_BYTES( check_lea_to_add, 0x48, 0x8d, 0x05, 0,0,0,0);   // lea rax, [rip+0]
    CHECK_BYTES( check_lea_to_add, 0x48, 0x89, 0xd8);           // mov rax, rbx (not LEA)

    // Flag gating: add writes the arithmetic flags the lea preserves, so the
    // dispatcher fires only when they are dead downstream.
    static const uint8_t flags_dead[] = {
        0x48, 0x8d, 0x04, 0x08,  // lea rax, [rax+rcx]
        0xc3,                    // ret (no ABI preserves flags)
    };
    ASSERT_FINDINGS(flags_dead, "suboptimal LEA", 1);

    static const uint8_t flags_live[] = {
        0x48, 0x8d, 0x04, 0x08,  // lea rax, [rax+rcx]
        0x74, 0x00,              // jz +0 (reads ZF)
    };
    ASSERT_FINDINGS(flags_live, "suboptimal LEA", 0);
}

static void check_oversized_lea_width_test(void)
{
    // Shape: only a 64-bit LEA whose REX carries nothing but W -- so the
    // narrowed form actually drops the byte -- is flagged. The upper-32
    // deadness gate is the dispatcher's, exercised below.
    // CHECK_BYTES_ASM: every REX bit here is load-bearing (W-only REX flags,
    // any of R/X/B suppresses), so pin what each fixture actually encodes.
    CHECK_BYTES_ASM(!check_oversized_lea_width, "lea rax, ptr [rdi+0x8]",
                    0x48, 0x8d, 0x47, 0x08);
    CHECK_BYTES_ASM(!check_oversized_lea_width, "lea rax, ptr [rbx+rcx*1]",
                    0x48, 0x8d, 0x04, 0x0b);
    CHECK_BYTES_ASM(!check_oversized_lea_width, "lea rax, ptr [rip+0x10]",
                    0x48, 0x8d, 0x05, 0x10, 0, 0, 0);
    CHECK_BYTES_ASM(!check_oversized_lea_width, "lea rax, ptr [eax+0x8]",
                    0x67, 0x48, 0x8d, 0x40, 0x08);
    CHECK_BYTES_ASM( check_oversized_lea_width, "lea eax, ptr [rdi+0x8]",   // already 32-bit
                    0x8d, 0x47, 0x08);
    CHECK_BYTES_ASM( check_oversized_lea_width, "lea ax, ptr [rdi+0x8]",    // 16-bit
                    0x66, 0x8d, 0x47, 0x08);
    CHECK_BYTES_ASM( check_oversized_lea_width, "lea r8, ptr [rdi+0x8]",    // REX.R stays
                    0x4c, 0x8d, 0x47, 0x08);
    CHECK_BYTES_ASM( check_oversized_lea_width, "lea rax, ptr [r8+0x8]",    // REX.B stays
                    0x49, 0x8d, 0x40, 0x08);
    CHECK_BYTES_ASM( check_oversized_lea_width, "lea rax, ptr [rdi+r9*2]",  // REX.X stays
                    0x4a, 0x8d, 0x04, 0x4f);
    CHECK_BYTES_ASM( check_oversized_lea_width, "mov rax, rcx",             // not LEA
                    0x48, 0x89, 0xc8);

    // Dispatcher gate: flagged only when the destination's bits 32-63 die
    // before being read.
    static const uint8_t killed[] = {
        0x48, 0x8d, 0x47, 0x08,  // lea rax, [rdi+8]
        0x89, 0xc8,              // mov eax, ecx (kills bits 32-63)
        0xc3,                    // ret
    };
    ASSERT_FINDINGS(killed, "oversized LEA width", 1);

    // A 32-bit read consumes the address without touching bits 32-63; the
    // later overwrite still kills them.
    static const uint8_t low_read_then_killed[] = {
        0x48, 0x8d, 0x47, 0x08,  // lea rax, [rdi+8]
        0x89, 0xc2,              // mov edx, eax (reads only the low half)
        0x89, 0xc8,              // mov eax, ecx (kills bits 32-63)
        0xc3,                    // ret
    };
    ASSERT_FINDINGS(low_read_then_killed, "oversized LEA width", 1);

    // A 64-bit read observes the address's upper half: suppress.
    static const uint8_t live[] = {
        0x48, 0x8d, 0x47, 0x08,  // lea rax, [rdi+8]
        0x48, 0x89, 0x06,        // mov [rsi], rax
        0xc3,                    // ret
    };
    ASSERT_FINDINGS(live, "oversized LEA width", 0);

    // RET leaves the register conservatively live: suppress.
    static const uint8_t ret_after[] = {
        0x48, 0x8d, 0x47, 0x08,  // lea rax, [rdi+8]
        0xc3,                    // ret
    };
    ASSERT_FINDINGS(ret_after, "oversized LEA width", 0);

    // The backward zero-extension escape must NOT apply here (reg_zx_escape
    // is unset for this check): mov eax, edx zeroes rax's bits 32-63, but the
    // 64-bit lea then stores the address's upper half in them -- the narrowed
    // form would store zeros instead, and the 64-bit read observes the
    // difference. The identity family's escape licenses deleting a re-zeroing
    // write, not narrowing a fresh one.
    static const uint8_t no_escape[] = {
        0x89, 0xd0,              // mov eax, edx (zero-extends rax)
        0x48, 0x8d, 0x47, 0x08,  // lea rax, [rdi+8]
        0x48, 0x89, 0x06,        // mov [rsi], rax
        0xc3,                    // ret
    };
    ASSERT_FINDINGS(no_escape, "oversized LEA width", 0);
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

    // Dispatcher wiring: xor reg, reg matches sub reg, reg in value, flags
    // (AF aside, unobservable in 64-bit mode), and zero-extension, so the
    // finding is unconditional.
    static const uint8_t sub_self_ret[] = {
        0x29, 0xC0,  // sub eax, eax
        0xC3,        // ret
    };
    ASSERT_FINDINGS(sub_self_ret, "suboptimal SUB reg, reg", 1);
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

    // Dispatcher wiring: cdqe is the identical operation, unconditional.
    static const uint8_t movsxd_rax[] = {
        0x48, 0x63, 0xC0,  // movsxd rax, eax (cdqe is 2 bytes)
        0xC3,              // ret
    };
    ASSERT_FINDINGS(movsxd_rax, "unneeded MOVSXD", 1);
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

    // Dispatcher wiring: cwde is the identical operation, unconditional.
    static const uint8_t movsx_cwde[] = {
        0x0F, 0xBF, 0xC0,  // movsx eax, ax (cwde is 1 byte)
        0xC3,              // ret
    };
    ASSERT_FINDINGS(movsx_cwde, "unneeded MOVSX", 1);
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

    // Dispatcher wiring: same instruction, shorter encoding, unconditional.
    static const uint8_t disp8_zero[] = {
        0x01, 0x7E, 0x00,  // add [rsi+0], edi (disp8=0; [rsi] needs none)
        0xC3,              // ret
    };
    ASSERT_FINDINGS(disp8_zero, "unneeded zero displacement", 1);
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

    // Dispatcher wiring: same instruction, shorter encoding, unconditional.
    static const uint8_t disp32_small[] = {
        0x01, 0xBE, 0x10, 0x00, 0x00, 0x00,  // add [rsi+0x10], edi (disp32)
        0xC3,                                // ret
    };
    ASSERT_FINDINGS(disp32_small, "oversized displacement", 1);
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

    // Dispatcher wiring: same instruction, shorter encoding, unconditional.
    // The nonzero disp8 keeps the displacement checks quiet, and the memory
    // destination keeps check_mov_modrm_imm quiet.
    static const uint8_t sib_rbp[] = {
        0xC6, 0x44, 0x65, 0x04, 0x05,  // mov byte [rbp+4], 5 (SIB redundant)
        0xC3,                          // ret
    };
    ASSERT_FINDINGS(sib_rbp, "unneeded SIB byte", 1);
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

    // Dispatcher wiring: same instruction, shorter encoding, unconditional.
    // imm 1 (not 0) keeps check_mov_zero quiet.
    static const uint8_t mov_modrm[] = {
        0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1 (C7 /0; B8 saves a byte)
        0xC3,                                // ret
    };
    ASSERT_FINDINGS(mov_modrm, "oversized MOV encoding", 1);
}

static void check_sse_mov_opcode_test(void)
{
    // Legacy 66/F3-prefixed copies -- movaps/movups is one byte shorter.
    CHECK_BYTES(!check_sse_mov_opcode, 0x66, 0x0f, 0x6f, 0xca);              // movdqa xmm1, xmm2
    CHECK_BYTES(!check_sse_mov_opcode, 0x66, 0x0f, 0x6f, 0x08);              // movdqa xmm1, [rax]
    CHECK_BYTES(!check_sse_mov_opcode, 0x66, 0x0f, 0x7f, 0x08);              // movdqa [rax], xmm1 (store)
    CHECK_BYTES(!check_sse_mov_opcode, 0xf3, 0x0f, 0x6f, 0x06);              // movdqu xmm0, [rsi]
    CHECK_BYTES(!check_sse_mov_opcode, 0x66, 0x0f, 0x28, 0xca);              // movapd xmm1, xmm2
    CHECK_BYTES(!check_sse_mov_opcode, 0x66, 0x0f, 0x10, 0x08);              // movupd xmm1, [rax]
    // Already the unprefixed PS forms -- nothing to flag.
    CHECK_BYTES( check_sse_mov_opcode, 0x0f, 0x28, 0xca);                    // movaps xmm1, xmm2
    CHECK_BYTES( check_sse_mov_opcode, 0x0f, 0x10, 0x08);                    // movups xmm1, [rax]
    // VEX/EVEX fold the 66/F3 selector into the prefix's pp bits (and
    // decode to distinct V* iclasses) -- no byte to save.
    CHECK_BYTES( check_sse_mov_opcode, 0xc5, 0xf9, 0x6f, 0xca);              // vmovdqa xmm1, xmm2
    CHECK_BYTES( check_sse_mov_opcode, 0xc5, 0xfe, 0x6f, 0xca);              // vmovdqu ymm1, ymm2
    CHECK_BYTES( check_sse_mov_opcode, 0x62, 0xf1, 0xfd, 0x48, 0x6f, 0xca);  // vmovdqa64 zmm1, zmm2
    // Unprefixed 0F 6F is the MMX movq -- a different iclass, not flagged.
    CHECK_BYTES( check_sse_mov_opcode, 0x0f, 0x6f, 0xca);                    // movq mm1, mm2
    // Not an SSE move at all.
    CHECK_BYTES( check_sse_mov_opcode, 0x89, 0xc8);                          // mov eax, ecx

    // Dispatcher wiring: movaps is the identical copy, unconditional.
    static const uint8_t movdqa_reg[] = {
        0x66, 0x0F, 0x6F, 0xCA,  // movdqa xmm1, xmm2
        0xC3,                    // ret
    };
    ASSERT_FINDINGS(movdqa_reg, "suboptimal SSE MOV opcode", 1);
}

static void check_sse_zero_idiom_test(void)
{
    // 66-prefixed self-XOR zeroing idioms -- xorps is one byte shorter.
    CHECK_BYTES(!check_sse_zero_idiom, 0x66, 0x0f, 0xef, 0xc0);        // pxor xmm0, xmm0
    CHECK_BYTES(!check_sse_zero_idiom, 0x66, 0x0f, 0xef, 0xff);        // pxor xmm7, xmm7
    CHECK_BYTES(!check_sse_zero_idiom, 0x66, 0x45, 0x0f, 0xef, 0xc0);  // pxor xmm8, xmm8 (REX)
    CHECK_BYTES(!check_sse_zero_idiom, 0x66, 0x0f, 0x57, 0xc0);        // xorpd xmm0, xmm0
    // Already the unprefixed form.
    CHECK_BYTES( check_sse_zero_idiom, 0x0f, 0x57, 0xc0);              // xorps xmm0, xmm0
    // Not the self form: a data XOR really executes, and the domain choice
    // can matter on older cores.
    CHECK_BYTES( check_sse_zero_idiom, 0x66, 0x0f, 0xef, 0xc1);        // pxor xmm0, xmm1
    CHECK_BYTES( check_sse_zero_idiom, 0x66, 0x0f, 0x57, 0xc1);        // xorpd xmm0, xmm1
    CHECK_BYTES( check_sse_zero_idiom, 0x66, 0x0f, 0xef, 0x00);        // pxor xmm0, [rax]
    // The prefixless MMX pxor shares the iclass but has no xorps twin.
    CHECK_BYTES( check_sse_zero_idiom, 0x0f, 0xef, 0xc0);              // pxor mm0, mm0
    // VEX/EVEX decode as distinct iclasses, and the 66 rides in the VEX pp
    // bits for free -- no byte to save.
    CHECK_BYTES( check_sse_zero_idiom, 0xc5, 0xf9, 0xef, 0xc0);        // vpxor xmm0, xmm0, xmm0
    CHECK_BYTES( check_sse_zero_idiom, 0xc5, 0xf8, 0x57, 0xc0);        // vxorps xmm0, xmm0, xmm0
    CHECK_BYTES( check_sse_zero_idiom, 0x90);                          // nop

    // Dispatcher: unconditional -- no flag or register gate.
    static const uint8_t pxor_self[] = {
        0x66, 0x0f, 0xef, 0xc0,  // pxor xmm0, xmm0
        0xc3,                    // ret
    };
    ASSERT_FINDINGS(pxor_self, "suboptimal SSE zero idiom", 1);

    static const uint8_t xorpd_self[] = {
        0x66, 0x0f, 0x57, 0xc0,  // xorpd xmm0, xmm0
        0xc3,                    // ret
    };
    ASSERT_FINDINGS(xorpd_self, "suboptimal SSE zero idiom", 1);
}

static void check_oversized_evex_test(void)
{
    // No EVEX-only feature in use -- the VEX re-encoding is 1-2 bytes
    // shorter (renamed integer iclasses map back to their VEX ancestors).
    CHECK_BYTES(!check_oversized_evex, 0x62, 0xf1, 0xfd, 0x28, 0x6f, 0xca);              // vmovdqa64 ymm1, ymm2 (-> vmovdqa)
    CHECK_BYTES(!check_oversized_evex, 0x62, 0xf1, 0x7d, 0x28, 0xef, 0xca);              // vpxord ymm1, ymm0, ymm2 (-> vpxor)
    CHECK_BYTES(!check_oversized_evex, 0x62, 0xf1, 0x7c, 0x28, 0x58, 0xca);              // vaddps ymm1, ymm0, ymm2 (shared iclass)
    CHECK_BYTES(!check_oversized_evex, 0x62, 0xf1, 0x7c, 0x08, 0x58, 0x48, 0x04);        // vaddps xmm1, xmm0, [rax+0x40] (disp8*16)
    CHECK_BYTES(!check_oversized_evex, 0x62, 0xf1, 0xfe, 0x28, 0x6f, 0x48, 0x02);        // vmovdqu64 ymm1, [rax+0x40] (-> vmovdqu)
    // EVEX-only features block the demotion.
    CHECK_BYTES( check_oversized_evex, 0x62, 0xf1, 0x7c, 0x48, 0x58, 0xca);              // vaddps zmm (512-bit)
    CHECK_BYTES( check_oversized_evex, 0x62, 0xf1, 0x7c, 0x29, 0x58, 0xca);              // vaddps ymm1{k1}, ymm0, ymm2 (opmask)
    CHECK_BYTES( check_oversized_evex, 0x62, 0xf1, 0x7c, 0x38, 0x58, 0x08);              // vaddps ymm1, ymm0, [rax]{1to8} (broadcast)
    CHECK_BYTES( check_oversized_evex, 0x62, 0xf1, 0xff, 0x78, 0x58, 0xca);              // vaddsd {rz-sae} (embedded rounding)
    CHECK_BYTES( check_oversized_evex, 0x62, 0xe1, 0x7c, 0x08, 0x58, 0xc2);              // vaddps xmm16, xmm0, xmm2 (high reg)
    CHECK_BYTES( check_oversized_evex, 0x62, 0xf3, 0x7d, 0x28, 0x25, 0xca, 0x96);        // vpternlogd (EVEX-only iclass)
    // The compressed disp8 makes the EVEX form shorter than VEX+disp32.
    CHECK_BYTES( check_oversized_evex, 0x62, 0xf1, 0x7c, 0x08, 0x58, 0x48, 0x10);        // vaddps xmm1, xmm0, [rax+0x100]
    // Already VEX or legacy -- nothing to demote.
    CHECK_BYTES( check_oversized_evex, 0xc5, 0xfc, 0x58, 0xca);                          // vaddps ymm1, ymm0, ymm2 (VEX)
    CHECK_BYTES( check_oversized_evex, 0x0f, 0x58, 0xca);                                // addps xmm1, xmm2 (legacy)
    CHECK_BYTES( check_oversized_evex, 0x90);                                            // nop
    // Families whose VEX spelling is a LATER extension with its own CPUID bit,
    // not the older encoding of the same feature: demoting them would fault on
    // the AVX-512 parts the EVEX form targets. Shorter, and still rejected.
    CHECK_BYTES( check_oversized_evex, 0x62, 0xf2, 0xf5, 0x08, 0xb4, 0xc2);              // vpmadd52luq (AVX512_IFMA -> AVX_IFMA)
    CHECK_BYTES( check_oversized_evex, 0x62, 0xf2, 0xf5, 0x08, 0xb5, 0xc2);              // vpmadd52huq (AVX512_IFMA -> AVX_IFMA)
    CHECK_BYTES( check_oversized_evex, 0x62, 0xf2, 0xf5, 0x28, 0xb4, 0x1e);              // vpmadd52luq ymm3, ymm1, [rsi] (a libcrypto site)
    CHECK_BYTES( check_oversized_evex, 0x62, 0xf2, 0x75, 0x08, 0x50, 0xc2);              // vpdpbusd (AVX512_VNNI -> AVX_VNNI)
    CHECK_BYTES( check_oversized_evex, 0x62, 0xf2, 0x75, 0x08, 0x52, 0xc2);              // vpdpwssd (AVX512_VNNI -> AVX_VNNI)
    CHECK_BYTES( check_oversized_evex, 0x62, 0xf2, 0x7e, 0x08, 0x72, 0xc1);              // vcvtneps2bf16 (AVX512_BF16 -> AVX_NE_CONVERT)
    // VAES is the other direction -- its VEX form predates the EVEX one, so
    // any part running the EVEX encoding runs the VEX one too: still flagged.
    CHECK_BYTES(!check_oversized_evex, 0x62, 0xf2, 0x75, 0x08, 0xdc, 0xc2);              // vaesenc xmm0, xmm1, xmm2 (-> VEX vaesenc)

    // Dispatcher wiring: the VEX re-encoding is identical, unconditional.
    static const uint8_t evex_ymm[] = {
        0x62, 0xF1, 0xFD, 0x28, 0x6F, 0xCA,  // vmovdqa64 ymm1, ymm2 (-> vmovdqa)
        0xC3,                                // ret
    };
    ASSERT_FINDINGS(evex_ymm, "oversized EVEX encoding", 1);
}

static void check_oversized_vex_test(void)
{
    // Three-byte C4 prefix where the two-byte C5 form suffices (opcode map 0F,
    // VEX.W clear, no r8-r15 operand) -- flag.
    CHECK_BYTES(!check_oversized_vex, 0xc4, 0xe1, 0x7d, 0x6f, 0xca);        // vmovdqa ymm1, ymm2 (C4 -> C5)
    CHECK_BYTES(!check_oversized_vex, 0xc4, 0xe1, 0x75, 0xfe, 0xc2);        // vpaddd ymm0, ymm1, ymm2 (C4 -> C5)
    CHECK_BYTES(!check_oversized_vex, 0xc4, 0xe1, 0x7e, 0x6f, 0x08);        // vmovdqu ymm1, [rax] (C4 -> C5)
    // A segment override may precede the VEX prefix; the length math still holds.
    CHECK_BYTES(!check_oversized_vex, 0x64, 0xc4, 0xe1, 0x7e, 0x6f, 0x08);  // vmovdqu ymm1, fs:[rax] (C4 -> C5)
    // Destination is an extended reg (VEX.R only) -- the two-byte form carries
    // R, so it is still reducible.
    CHECK_BYTES(!check_oversized_vex, 0xc4, 0x61, 0x7d, 0x6f, 0xc0);        // vmovdqa ymm8, ymm0 (C4 -> C5)
    // Already the minimal two-byte C5 form -- nothing to flag.
    CHECK_BYTES( check_oversized_vex, 0xc5, 0xfd, 0x6f, 0xca);              // vmovdqa ymm1, ymm2 (C5)
    CHECK_BYTES( check_oversized_vex, 0xc5, 0xfe, 0x6f, 0x08);              // vmovdqu ymm1, [rax] (C5)
    CHECK_BYTES( check_oversized_vex, 0xc5, 0x7d, 0x6f, 0xc0);              // vmovdqa ymm8, ymm0 (C5, VEX.R)
    // Genuinely needs C4: opcode map 0F38 / 0F3A.
    CHECK_BYTES( check_oversized_vex, 0xc4, 0xe2, 0x71, 0x00, 0xc2);        // vpshufb xmm0, xmm1, xmm2 (0F38)
    CHECK_BYTES( check_oversized_vex, 0xc4, 0xe3, 0xfd, 0x00, 0xc1, 0x1b);  // vpermq ymm0, ymm1, 0x1b (0F3A)
    // Genuinely needs C4: VEX.W = 1.
    CHECK_BYTES( check_oversized_vex, 0xc4, 0xe1, 0xf9, 0x6e, 0xc0);        // vmovq xmm0, rax (map 0F, W1)
    // Genuinely needs C4: r8-r15 base/index/rm (VEX.B / VEX.X).
    CHECK_BYTES( check_oversized_vex, 0xc4, 0xc1, 0x7d, 0x6f, 0xc0);        // vmovdqa ymm0, ymm8 (VEX.B)
    CHECK_BYTES( check_oversized_vex, 0xc4, 0xa1, 0x7e, 0x6f, 0x04, 0x00);  // vmovdqu ymm0, [rax+r8] (VEX.X)
    // EVEX and legacy encodings are not VEX -- not flagged here.
    CHECK_BYTES( check_oversized_vex, 0x62, 0xf1, 0xfd, 0x28, 0x6f, 0xca);  // vmovdqa64 ymm1, ymm2 (EVEX)
    CHECK_BYTES( check_oversized_vex, 0x0f, 0x28, 0xca);                    // movaps xmm1, xmm2 (legacy)
    CHECK_BYTES( check_oversized_vex, 0x90);                                // nop

    // Dispatcher wiring: the two-byte prefix encodes the same instruction,
    // unconditional.
    static const uint8_t vex_c4[] = {
        0xC4, 0xE1, 0x7D, 0x6F, 0xCA,  // vmovdqa ymm1, ymm2 (C4 -> C5)
        0xC3,                          // ret
    };
    ASSERT_FINDINGS(vex_c4, "oversized VEX encoding", 1);
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

    // and eax, 0xff ; jz +0 -- ZF is live, and the movzbl rewrite would drop
    // it, so suppress. (A genuine low-byte mask, not the all-ones no-op, which
    // check_and_minus_one handles flag-exactly and so does not gate.)
    static const uint8_t and_jz[] = {
        0x25, 0xFF, 0x00, 0x00, 0x00,
        0x74, 0x00,
    };
    ASSERT_FINDINGS(and_jz, "suboptimal AND immediate", 0);

    // and eax, 0xff ; mov ebx, ecx ; ret -- MOV transparent, RET kills,
    // finding fires.
    static const uint8_t and_mov_ret[] = {
        0x25, 0xFF, 0x00, 0x00, 0x00,
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
    // flags exactly, so flag liveness never suppresses it -- here it fires
    // straight into the flag-reading je. It IS register-gated in its 32-bit
    // form (the add zero-extends, test does not), which the mov ebx, ecx
    // satisfies backward: the upper bits are already zero, so the add changes
    // nothing even though the je blocks the forward walk.
    static const uint8_t addzero_je[] = {
        0x89, 0xCB,        // mov ebx, ecx (already zero-extends rbx)
        0x83, 0xC3, 0x00,  // add ebx, 0
        0x74, 0x00,        // je +0 (reads the flags; upper-32 walk blocked)
    };
    ASSERT_FINDINGS(addzero_je, "redundant ADD/SUB zero", 1);

    // add ebx, 0 ; ret -- flags dead, but rbx's upper bits are conservatively
    // live at RET (the value can escape as a callee-saved register), so the
    // 32-bit form is suppressed.
    static const uint8_t addzero_ret[] = {
        0x83, 0xC3, 0x00,
        0xC3,
    };
    ASSERT_FINDINGS(addzero_ret, "redundant ADD/SUB zero", 0);

    // add rbx, 0 ; ret -- the 64-bit form is a full-width identity write with
    // no upper-bit concern: fires.
    static const uint8_t addzero64_ret[] = {
        0x48, 0x83, 0xC3, 0x00,
        0xC3,
    };
    ASSERT_FINDINGS(addzero64_ret, "redundant ADD/SUB zero", 1);

    // add ebx, 0 ; mov ebx, ecx -- the following 32-bit write redefines the
    // upper bits before any read: fires.
    static const uint8_t addzero_kill[] = {
        0x83, 0xC3, 0x00,
        0x89, 0xCB,
    };
    ASSERT_FINDINGS(addzero_kill, "redundant ADD/SUB zero", 1);

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

    // sub dword [rbx+0x10], 1 ; ret -- memory destination: CF dead at ret,
    // dec dword [rbx+0x10] is one byte shorter, finding fires.
    static const uint8_t subonemem_ret[] = {
        0x83, 0x6B, 0x10, 0x01,
        0xC3,
    };
    ASSERT_FINDINGS(subonemem_ret, "oversized ADD/SUB one", 1);

    // sub dword [rbx+0x10], 1 ; jc +0 -- CF may be read, suppress.
    static const uint8_t subonemem_jc[] = {
        0x83, 0x6B, 0x10, 0x01,
        0x72, 0x00,
    };
    ASSERT_FINDINGS(subonemem_jc, "oversized ADD/SUB one", 0);

    // test ebx, 1 ; jne +0 ; ret -- the oversized-TEST finding is
    // flag-exact (mask within the low seven bits), so it fires even
    // though a conditional branch immediately consumes the flags.
    static const uint8_t testnarrow_jne[] = {
        0xF7, 0xC3, 0x01, 0x00, 0x00, 0x00,  // test ebx, 1
        0x75, 0x00,                          // jne +0
        0xC3,                                // ret
    };
    ASSERT_FINDINGS(testnarrow_jne, "oversized TEST immediate", 1);

    // test ebx, 0x80 ; jne +0 ; ret -- bit 7 in the mask would change how
    // SF is computed; not flagged at all.
    static const uint8_t testbit7_jne[] = {
        0xF7, 0xC3, 0x80, 0x00, 0x00, 0x00,  // test ebx, 0x80
        0x75, 0x00,                          // jne +0
        0xC3,                                // ret
    };
    ASSERT_FINDINGS(testbit7_jne, "oversized TEST immediate", 0);
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

// Register-liveness gating: mov r32, r32 (e.g. mov eax, eax) is a no-op only in
// its low 32 bits -- it also zero-extends into the upper 32 bits of the
// enclosing 64-bit register. check_instructions flags it as redundant only when
// that zero-extension is dead: bits 63-32 are redefined before any reader.
// These sequences pin the dispatcher's reg_upper32_live_after gate. The
// 8/16/64-bit same-register forms have no upper bits to disturb and fire
// regardless of what follows.
static void check_reg_liveness_test(void)
{
    // mov eax, eax ; mov eax, ecx -- the second write zero-extends eax again,
    // killing the first's upper bits before any read: redundant, flag it.
    static const uint8_t moveax_kill[] = {
        0x89, 0xC0,        // mov eax, eax
        0x89, 0xC8,        // mov eax, ecx
    };
    ASSERT_FINDINGS(moveax_kill, "redundant MOV reg, reg", 1);

    // mov eax, eax ; add eax, 5 -- add rewrites eax (zero-extending), so the
    // upper bits are dead; it reads only eax's low half. (imm 5, not an
    // inc/dec candidate.) Flag.
    static const uint8_t moveax_add[] = {
        0x89, 0xC0,        // mov eax, eax
        0x83, 0xC0, 0x05,  // add eax, 5
    };
    ASSERT_FINDINGS(moveax_add, "redundant MOV reg, reg", 1);

    // mov eax, eax ; ret -- RET may expose eax/rax as a return value, so the
    // walk is conservatively LIVE at RET (unlike flags): suppress.
    static const uint8_t moveax_ret[] = {
        0x89, 0xC0,
        0xC3,
    };
    ASSERT_FINDINGS(moveax_ret, "redundant MOV reg, reg", 0);

    // mov eax, eax ; mov [rbx], rax -- the store reads the full rax, observing
    // bits 63-32, so the zero-extension is live: suppress.
    static const uint8_t moveax_store_rax[] = {
        0x89, 0xC0,              // mov eax, eax
        0x48, 0x89, 0x03,        // mov [rbx], rax
    };
    ASSERT_FINDINGS(moveax_store_rax, "redundant MOV reg, reg", 0);

    // mov eax, eax ; add rcx, rax -- add reads the full rax (upper bits live);
    // its destination is a different register, so it does not kill eax first.
    // Suppress.
    static const uint8_t moveax_read_rax[] = {
        0x89, 0xC0,              // mov eax, eax
        0x48, 0x01, 0xC1,        // add rcx, rax
    };
    ASSERT_FINDINGS(moveax_read_rax, "redundant MOV reg, reg", 0);

    // mov eax, eax ; mov ecx, [rax] -- rax used as a memory base is a read of
    // the full 64-bit register: upper bits live, suppress.
    static const uint8_t moveax_base_rax[] = {
        0x89, 0xC0,              // mov eax, eax
        0x8B, 0x08,              // mov ecx, [rax]
    };
    ASSERT_FINDINGS(moveax_base_rax, "redundant MOV reg, reg", 0);

    // mov eax, eax ; je +0 -- a conditional branch we cannot follow keeps the
    // upper bits conservatively live, suppress.
    static const uint8_t moveax_je[] = {
        0x89, 0xC0,
        0x74, 0x00,
    };
    ASSERT_FINDINGS(moveax_je, "redundant MOV reg, reg", 0);

    // mov eax, eax ; cmove eax, ecx -- CMOV is a conditional write, excluded
    // from the kill whitelist: the old upper bits can survive a not-taken move,
    // so it is not a redefinition. No later kill, so suppress.
    static const uint8_t moveax_cmov[] = {
        0x89, 0xC0,              // mov eax, eax
        0x0F, 0x44, 0xC1,        // cmove eax, ecx
    };
    ASSERT_FINDINGS(moveax_cmov, "redundant MOV reg, reg", 0);

    // mov eax, eax alone at end of buffer -- unknown successor, conservative
    // LIVE, suppress.
    static const uint8_t moveax_alone[] = {
        0x89, 0xC0,
    };
    ASSERT_FINDINGS(moveax_alone, "redundant MOV reg, reg", 0);

    // The non-32-bit same-register forms are pure no-ops with no upper-bit
    // concern, flagged regardless of a downstream reader: mov rax, rax ; je +0.
    static const uint8_t movrax_je[] = {
        0x48, 0x89, 0xC0,       // mov rax, rax
        0x74, 0x00,
    };
    ASSERT_FINDINGS(movrax_je, "redundant MOV reg, reg", 1);

    // mov al, al ; je +0 -- 8-bit no-op, likewise unconditional.
    static const uint8_t moval_je[] = {
        0x88, 0xC0,             // mov al, al
        0x74, 0x00,
    };
    ASSERT_FINDINGS(moval_je, "redundant MOV reg, reg", 1);
}

// The backward half of check_mov_self's gate: mov r32, r32 is redundant not
// only when its zero-extension is dead downstream but also when the immediately
// preceding instruction already zeroed bits 63:32 with an unconditional 32-bit
// write -- then the mov changes nothing regardless of any downstream read.
// These pin writes_zero_extended_32.
static void check_zero_extend_mov_self_test(void)
{
    // add eax, ebx ; mov eax, eax ; mov [rbx], rax -- the store reads rax, so
    // the zero-extension is live downstream, yet add eax, ebx already zeroed
    // bits 63:32: the mov changes nothing and is flagged.
    static const uint8_t add_movself_store[] = {
        0x01, 0xD8,        // add eax, ebx
        0x89, 0xC0,        // mov eax, eax
        0x48, 0x89, 0x03,  // mov [rbx], rax
    };
    ASSERT_FINDINGS(add_movself_store, "redundant MOV reg, reg", 1);

    // add eax, ebx ; mov eax, eax ; ret -- rax may be a return value (upper half
    // conservatively live at RET), but the prior write already zeroed it: flag.
    static const uint8_t add_movself_ret[] = {
        0x01, 0xD8,        // add eax, ebx
        0x89, 0xC0,        // mov eax, eax
        0xC3,              // ret
    };
    ASSERT_FINDINGS(add_movself_ret, "redundant MOV reg, reg", 1);

    // movzx eax, bl ; mov eax, eax -- movzx zero-extended eax, so the following
    // mov is redundant even at end of buffer, where the upper half is otherwise
    // conservatively live.
    static const uint8_t movzx_movself[] = {
        0x0F, 0xB6, 0xC3,  // movzx eax, bl
        0x89, 0xC0,        // mov eax, eax
    };
    ASSERT_FINDINGS(movzx_movself, "redundant MOV reg, reg", 1);

    // add rax, rbx ; mov eax, eax ; mov [rbx], rax -- the prior write is 64-bit,
    // so bits 63:32 are arbitrary, not zero; mov eax, eax clears them and the
    // store observes the difference: not redundant.
    static const uint8_t add64_movself_store[] = {
        0x48, 0x01, 0xD8,  // add rax, rbx
        0x89, 0xC0,        // mov eax, eax
        0x48, 0x89, 0x03,  // mov [rbx], rax
    };
    ASSERT_FINDINGS(add64_movself_store, "redundant MOV reg, reg", 0);

    // cmove eax, ecx ; mov eax, eax ; mov [rbx], rax -- CMOV writes eax only
    // conditionally, so it does not guarantee bits 63:32 are zero; with the
    // store reading rax the mov is not provably redundant: suppress.
    static const uint8_t cmov_movself_store[] = {
        0x0F, 0x44, 0xC1,  // cmove eax, ecx
        0x89, 0xC0,        // mov eax, eax
        0x48, 0x89, 0x03,  // mov [rbx], rax
    };
    ASSERT_FINDINGS(cmov_movself_store, "redundant MOV reg, reg", 0);

    // The escape holds only when every path runs through the zero-extending
    // predecessor: a direct edge onto the mov itself (from the dead je after
    // the ret) arrives with unknown upper bits, so with the store keeping
    // them live the finding is suppressed despite the escape.
    static const uint8_t edge_on_movself[] = {
        0x89, 0xCB,        // 0: mov ebx, ecx (zero-extends rbx)
        0x89, 0xDB,        // 2: mov ebx, ebx  <- branch target
        0x48, 0x89, 0x18,  // 4: mov [rax], rbx (upper half live)
        0xC3,              // 7: ret
        0x74, 0xF8,        // 8: je 2
    };
    ASSERT_FINDINGS(edge_on_movself, "redundant MOV reg, reg", 0);
}

// The other 32-bit identity operations -- and reg, -1 / or reg, reg /
// or-xor reg, 0 / shl reg, 0 (add reg, 0 is pinned alongside the flag tests)
// -- share check_mov_self's register gate: their rewrite is a non-writing test
// or outright removal, dropping the 32-bit form's incidental zero-extension,
// so the dispatcher suppresses that form while bits 63:32 may be live, with
// the same backward escape when the preceding instruction already zeroed
// them. Other widths fire unconditionally. Hardware zero-extends even for the
// count-0 shift, so it is gated alike.
static void check_upper32_identity_gate_test(void)
{
    // movabs rax, 2^32 ; and eax, -1 ; mov rdx, rax ; ret -- GCC's fused
    // zero-extend-and-test shape: the full-register read observes the
    // zero-extension a test rewrite would drop. Suppress.
    static const uint8_t and_m1_upper_read[] = {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x83, 0xE0, 0xFF,        // and eax, -1
        0x48, 0x89, 0xC2,        // mov rdx, rax
        0xC3,
    };
    ASSERT_FINDINGS(and_m1_upper_read, "redundant AND immediate", 0);

    // and eax, -1 ; mov eax, ecx -- the following 32-bit write redefines the
    // upper bits before any read: fires.
    static const uint8_t and_m1_kill[] = {
        0x83, 0xE0, 0xFF,        // and eax, -1
        0x89, 0xC8,              // mov eax, ecx
    };
    ASSERT_FINDINGS(and_m1_kill, "redundant AND immediate", 1);

    // mov ebx, [rsi] ; or ebx, ebx ; je +0 -- the classic flag-test idiom:
    // the load already zero-extended rbx, so the backward escape fires the
    // finding even though the je blocks the forward walk.
    static const uint8_t or_self_after_load[] = {
        0x8B, 0x1E,              // mov ebx, [rsi]
        0x09, 0xDB,              // or ebx, ebx
        0x74, 0x00,              // je +0
    };
    ASSERT_FINDINGS(or_self_after_load, "suboptimal OR/AND reg, reg", 1);

    // or ebx, ebx ; je +0 -- cold rbx: nothing proves the upper bits dead or
    // already zero, so the 32-bit form is suppressed.
    static const uint8_t or_self_cold[] = {
        0x09, 0xDB,              // or ebx, ebx
        0x74, 0x00,              // je +0
    };
    ASSERT_FINDINGS(or_self_cold, "suboptimal OR/AND reg, reg", 0);

    // or rbx, rbx ; je +0 -- the 64-bit form is a full-width identity write;
    // the rewrite drops nothing: fires.
    static const uint8_t or_self_64[] = {
        0x48, 0x09, 0xDB,        // or rbx, rbx
        0x74, 0x00,              // je +0
    };
    ASSERT_FINDINGS(or_self_64, "suboptimal OR/AND reg, reg", 1);

    // xor ebx, 0 ; mov ebx, ecx -- killed upper bits: fires.
    static const uint8_t xor_zero_kill[] = {
        0x83, 0xF3, 0x00,        // xor ebx, 0
        0x89, 0xCB,              // mov ebx, ecx
    };
    ASSERT_FINDINGS(xor_zero_kill, "redundant OR/XOR zero", 1);

    // xor ebx, 0 ; ret -- conservative at RET: suppress.
    static const uint8_t xor_zero_ret[] = {
        0x83, 0xF3, 0x00,        // xor ebx, 0
        0xC3,
    };
    ASSERT_FINDINGS(xor_zero_ret, "redundant OR/XOR zero", 0);

    // movabs rax, 2^32 ; shl eax, 0 ; mov rdx, rax ; ret -- count-0 shifts
    // zero-extend on real hardware, so removal is gated like the others:
    // suppress while the upper bits are read.
    static const uint8_t shl_zero_upper_read[] = {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0xC1, 0xE0, 0x00,        // shl eax, 0
        0x48, 0x89, 0xC2,        // mov rdx, rax
        0xC3,
    };
    ASSERT_FINDINGS(shl_zero_upper_read, "redundant shift/rotate by zero", 0);

    // shl eax, 0 ; mov eax, ebx -- killed: fires.
    static const uint8_t shl_zero_kill[] = {
        0xC1, 0xE0, 0x00,        // shl eax, 0
        0x89, 0xD8,              // mov eax, ebx
    };
    ASSERT_FINDINGS(shl_zero_kill, "redundant shift/rotate by zero", 1);

    // The 64- and 8-bit forms have no upper-32 concern: fire even at ret.
    static const uint8_t shl_zero_64[] = {
        0x48, 0xC1, 0xE0, 0x00,  // shl rax, 0
        0xC3,
    };
    ASSERT_FINDINGS(shl_zero_64, "redundant shift/rotate by zero", 1);
    static const uint8_t shl_zero_8[] = {
        0xC0, 0xE0, 0x00,        // shl al, 0
        0xC3,
    };
    ASSERT_FINDINGS(shl_zero_8, "redundant shift/rotate by zero", 1);

    // shl dword [rax], 0 ; ret -- a memory destination is excluded by the
    // check itself: removal would delete a memory access, observable through
    // faults, MMIO side effects, and its racing write-back regardless of the
    // unchanged value. (The hook's GPR test never mattered here beyond not
    // crashing on the suppressed RFLAGS in the REG0 slot.)
    static const uint8_t shl_zero_mem[] = {
        0xC1, 0x20, 0x00,        // shl dword [rax], 0
        0xC3,
    };
    ASSERT_FINDINGS(shl_zero_mem, "redundant shift/rotate by zero", 0);
}

// Backward peephole: an in-place movzx/movsx/movsxd re-establishing bits the
// immediately preceding extension already provided is a pure no-op --
// removable with no liveness gate, since neither instruction touches flags
// and every written bit already holds its value. The one rejection is a
// direct edge onto the re-extension, a path that skips the producer.
static void check_redundant_reextension_test(void)
{
    // movzx eax, byte [rsi] ; movzx eax, al -- bits 8-63 already zero: fires.
    static const uint8_t zx_after_load[] = {
        0x0F, 0xB6, 0x06,        // movzx eax, byte [rsi]
        0x0F, 0xB6, 0xC0,        // movzx eax, al
        0xC3,                    // ret
    };
    ASSERT_FINDINGS(zx_after_load, "redundant re-extension", 1);

    // Register-source producer: movzx eax, bl ; movzx eax, al.
    static const uint8_t zx_after_zx[] = {
        0x0F, 0xB6, 0xC3,        // movzx eax, bl
        0x0F, 0xB6, 0xC0,        // movzx eax, al
        0xC3,
    };
    ASSERT_FINDINGS(zx_after_zx, "redundant re-extension", 1);

    // A wider in-place re-extension is covered too: bits 16-63 are already
    // zero because bits 8-63 are.
    static const uint8_t zx16_after_zx8[] = {
        0x0F, 0xB6, 0xC3,        // movzx eax, bl
        0x0F, 0xB7, 0xC0,        // movzx eax, ax
        0xC3,
    };
    ASSERT_FINDINGS(zx16_after_zx8, "redundant re-extension", 1);

    // A 16-bit consumer needs only bits 8-15, which any wider producer set.
    static const uint8_t zx16dest_after_zx[] = {
        0x0F, 0xB6, 0xC3,        // movzx eax, bl
        0x66, 0x0F, 0xB6, 0xC0,  // movzx ax, al
        0xC3,
    };
    ASSERT_FINDINGS(zx16dest_after_zx, "redundant re-extension", 1);

    // Sign twins: movsx rax, bl ; movsx rax, al (bits 8-63 already the sign),
    // and movsx rcx, bl ; movsxd rcx, ecx (bits 32-63 already the sign).
    static const uint8_t sx_after_sx64[] = {
        0x48, 0x0F, 0xBE, 0xC3,  // movsx rax, bl
        0x48, 0x0F, 0xBE, 0xC0,  // movsx rax, al
        0xC3,
    };
    ASSERT_FINDINGS(sx_after_sx64, "redundant re-extension", 1);
    static const uint8_t sxd_after_sx64[] = {
        0x48, 0x0F, 0xBE, 0xCB,  // movsx rcx, bl
        0x48, 0x63, 0xC9,        // movsxd rcx, ecx
        0xC3,
    };
    ASSERT_FINDINGS(sxd_after_sx64, "redundant re-extension", 1);

    // Kind mismatch: after a zero-extension, movsx would sign-fill bits the
    // producer cleared whenever the byte is negative.
    static const uint8_t sx_after_zx[] = {
        0x0F, 0xB6, 0xC3,        // movzx eax, bl
        0x0F, 0xBE, 0xC0,        // movsx eax, al
        0xC3,
    };
    ASSERT_FINDINGS(sx_after_zx, "redundant re-extension", 0);

    // Producer from a wider source: bits 8-15 hold data, and the consumer
    // would clear them.
    static const uint8_t zx8_after_zx16[] = {
        0x0F, 0xB7, 0xC3,        // movzx eax, bx
        0x0F, 0xB6, 0xC0,        // movzx eax, al
        0xC3,
    };
    ASSERT_FINDINGS(zx8_after_zx16, "redundant re-extension", 0);

    // Sign-extension destination widths must match: the 64-bit producer
    // sign-filled bits 63:32, which the 32-bit consumer would zero...
    static const uint8_t sx32_after_sx64[] = {
        0x48, 0x0F, 0xBE, 0xC3,  // movsx rax, bl
        0x0F, 0xBE, 0xC0,        // movsx eax, al
        0xC3,
    };
    ASSERT_FINDINGS(sx32_after_sx64, "redundant re-extension", 0);

    // ...and the 32-bit producer zeroed bits the 64-bit consumer would
    // sign-fill.
    static const uint8_t sx64_after_sx32[] = {
        0x0F, 0xBE, 0xC3,        // movsx eax, bl
        0x48, 0x0F, 0xBE, 0xC0,  // movsx rax, al
        0xC3,
    };
    ASSERT_FINDINGS(sx64_after_sx32, "redundant re-extension", 0);

    // A 16-bit producer guarantees nothing above bit 15.
    static const uint8_t zx32_after_zx16dest[] = {
        0x66, 0x0F, 0xB6, 0xC3,  // movzx ax, bl
        0x0F, 0xB6, 0xC0,        // movzx eax, al
        0xC3,
    };
    ASSERT_FINDINGS(zx32_after_zx16dest, "redundant re-extension", 0);

    // Different register families are unrelated.
    static const uint8_t different_family[] = {
        0x0F, 0xB6, 0xC3,        // movzx eax, bl
        0x0F, 0xB6, 0xC9,        // movzx ecx, cl
        0xC3,
    };
    ASSERT_FINDINGS(different_family, "redundant re-extension", 0);

    // A high-byte consumer source reads bits the producer cleared, not the
    // value: movzx eax, ah is not a re-extension.
    static const uint8_t high_byte_source[] = {
        0x0F, 0xB6, 0xC3,        // movzx eax, bl
        0x0F, 0xB6, 0xC4,        // movzx eax, ah
        0xC3,
    };
    ASSERT_FINDINGS(high_byte_source, "redundant re-extension", 0);

    // An incoming direct edge onto the re-extension skips the producer:
    // suppress. (The trailing je is dead code; the sweep records its target.)
    static const uint8_t edge_on_reextension[] = {
        0x0F, 0xB6, 0xC3,        // 0: movzx eax, bl
        0x0F, 0xB6, 0xC0,        // 3: movzx eax, al  <- branch target
        0xC3,                    // 6: ret
        0x74, 0xFA,              // 7: je 3
    };
    ASSERT_FINDINGS(edge_on_reextension, "redundant re-extension", 0);

    // An edge onto the producer (the pair's head) is fine: fires.
    static const uint8_t edge_on_producer[] = {
        0x0F, 0xB6, 0xC3,        // 0: movzx eax, bl  <- branch target
        0x0F, 0xB6, 0xC0,        // 3: movzx eax, al
        0xC3,                    // 6: ret
        0x74, 0xF7,              // 7: je 0
    };
    ASSERT_FINDINGS(edge_on_producer, "redundant re-extension", 1);
}

// Multi-instruction peephole: a flag-setting ALU (add/sub/and/or/xor/inc/dec/
// neg/...) that writes a register sets SF/ZF/PF from the result, so an
// immediately following test reg, reg on that same register is redundant and
// check_instructions reports it against the test. AND/OR/XOR match test's flags
// exactly (CF/OF cleared) and fire unconditionally; the arithmetic producers
// diverge on CF/OF and fire only when those are dead past the test.
static void check_redundant_flags_test(void)
{
    // and eax, ebx ; test eax, eax -- AND set SF/ZF/PF and cleared CF/OF, the
    // same flags test computes, so the test is a pure duplicate. A logical
    // producer carries no divergence and fires regardless of what follows.
    static const uint8_t and_test[] = {
        0x21, 0xD8,        // and eax, ebx
        0x85, 0xC0,        // test eax, eax
    };
    ASSERT_FINDINGS(and_test, "redundant TEST after flags", 1);

    static const uint8_t or_test[] = {
        0x09, 0xD8,        // or eax, ebx
        0x85, 0xC0,        // test eax, eax
    };
    ASSERT_FINDINGS(or_test, "redundant TEST after flags", 1);

    // An incoming direct edge onto the test reaches it without the producer,
    // so dropping it would break that path: suppress. (The window guard is
    // shared by every multi-instruction peephole.)
    static const uint8_t and_test_edge_on_test[] = {
        0x21, 0xD8,        // 0: and eax, ebx
        0x85, 0xC0,        // 2: test eax, eax  <- branch target
        0xEB, 0xFC,        // 4: jmp 2
    };
    ASSERT_FINDINGS(and_test_edge_on_test, "redundant TEST after flags", 0);

    // An edge onto the producer (the window head) executes the whole pattern:
    // fires.
    static const uint8_t and_test_edge_on_head[] = {
        0x21, 0xD8,        // 0: and eax, ebx   <- branch target
        0x85, 0xC0,        // 2: test eax, eax
        0xEB, 0xFA,        // 4: jmp 0
    };
    ASSERT_FINDINGS(and_test_edge_on_head, "redundant TEST after flags", 1);

    static const uint8_t xor_test[] = {
        0x31, 0xD8,        // xor eax, ebx
        0x85, 0xC0,        // test eax, eax
    };
    ASSERT_FINDINGS(xor_test, "redundant TEST after flags", 1);

    // and eax, ebx ; test eax, eax ; jb -- a logical producer fires even
    // through a following CF reader: AND already set CF=0, exactly what the
    // test would, so dropping the test leaves jb's CF unchanged.
    static const uint8_t and_test_jb[] = {
        0x21, 0xD8,        // and eax, ebx
        0x85, 0xC0,        // test eax, eax
        0x72, 0x00,        // jb +0
    };
    ASSERT_FINDINGS(and_test_jb, "redundant TEST after flags", 1);

    // add eax, ebx ; test eax, eax ; ret -- an arithmetic producer diverges on
    // CF/OF, but RET makes them dead (no ABI preserves flags across a call), so
    // it fires.
    static const uint8_t add_test_ret[] = {
        0x01, 0xD8,        // add eax, ebx
        0x85, 0xC0,        // test eax, eax
        0xC3,              // ret
    };
    ASSERT_FINDINGS(add_test_ret, "redundant TEST after flags", 1);

    // dec ecx ; test ecx, ecx ; ret -- dec sets SF/ZF/PF (and OF) and leaves
    // CF; both are dead at ret, so the test is redundant.
    static const uint8_t dec_test_ret[] = {
        0xFF, 0xC9,        // dec ecx
        0x85, 0xC9,        // test ecx, ecx
        0xC3,              // ret
    };
    ASSERT_FINDINGS(dec_test_ret, "redundant TEST after flags", 1);

    // add eax, ebx ; test eax, eax ; jz -- an arithmetic producer whose test
    // feeds a Jcc: the flag-liveness walk is conservative at any branch, so
    // CF/OF are treated as possibly live and the finding is suppressed.
    static const uint8_t add_test_jz[] = {
        0x01, 0xD8,        // add eax, ebx
        0x85, 0xC0,        // test eax, eax
        0x74, 0x00,        // jz +0
    };
    ASSERT_FINDINGS(add_test_jz, "redundant TEST after flags", 0);

    // add eax, ebx ; test eax, eax ; adc edx, 0 -- adc reads CF before it is
    // overwritten, so removing the test (which cleared CF) is unsound: suppress.
    static const uint8_t add_test_adc[] = {
        0x01, 0xD8,        // add eax, ebx
        0x85, 0xC0,        // test eax, eax
        0x83, 0xD2, 0x00,  // adc edx, 0
    };
    ASSERT_FINDINGS(add_test_adc, "redundant TEST after flags", 0);

    // add eax, ebx ; test edx, edx -- the test is on a different register than
    // the ALU wrote, so its flags are unrelated: no match.
    static const uint8_t add_test_other_reg[] = {
        0x01, 0xD8,        // add eax, ebx
        0x85, 0xD2,        // test edx, edx
    };
    ASSERT_FINDINGS(add_test_other_reg, "redundant TEST after flags", 0);

    // add eax, ebx ; test rax, rax -- same register but wider: test rax reads
    // SF at bit 63, which add eax zeroed by zero-extension rather than setting
    // from the arithmetic. Width must match exactly: no match.
    static const uint8_t add_test_wide[] = {
        0x01, 0xD8,        // add eax, ebx
        0x48, 0x85, 0xC0,  // test rax, rax
    };
    ASSERT_FINDINGS(add_test_wide, "redundant TEST after flags", 0);

    // imul eax, ebx ; test eax, eax -- IMUL leaves SF/ZF/PF undefined, so the
    // test is not recomputing anything the imul produced: not a producer.
    static const uint8_t imul_test[] = {
        0x0F, 0xAF, 0xC3,  // imul eax, ebx
        0x85, 0xC0,        // test eax, eax
    };
    ASSERT_FINDINGS(imul_test, "redundant TEST after flags", 0);

    // mov eax, ebx ; test eax, eax -- MOV writes no flags, so the test is the
    // only thing setting them and is required.
    static const uint8_t mov_test[] = {
        0x89, 0xD8,        // mov eax, ebx
        0x85, 0xC0,        // test eax, eax
    };
    ASSERT_FINDINGS(mov_test, "redundant TEST after flags", 0);

    // shl eax, 3 ; test eax, eax -- shifts are excluded from the producer set
    // (a masked or CL count of zero leaves the flags untouched), so the test is
    // not assumed redundant.
    static const uint8_t shl_test[] = {
        0xC1, 0xE0, 0x03,  // shl eax, 3
        0x85, 0xC0,        // test eax, eax
    };
    ASSERT_FINDINGS(shl_test, "redundant TEST after flags", 0);

    // ---- The window, shared with the APX NDD fold (APX_NDD_WINDOW): the test
    // may sit past instructions that leave the producer's flags and the tested
    // register alone (flags_gap_transparent). These expectations track the
    // build's window; the negatives hold at every width.
    const int one_gap = APX_NDD_WINDOW >= 3 ? 1 : 0;
    const int two_gap = APX_NDD_WINDOW >= 4 ? 1 : 0;

    // An alignment NOP between the pair -- the shape that hid these findings
    // in Go binaries, where the assembler pads to align the branch target.
    static const uint8_t gap_nop[] = {
        0x21, 0xD8,        // and eax, ebx
        0x90,              // nop
        0x85, 0xC0,        // test eax, eax
    };
    ASSERT_FINDINGS(gap_nop, "redundant TEST after flags", one_gap);

    static const uint8_t gap_two_nops[] = {
        0x21, 0xD8,        // and eax, ebx
        0x90,              // nop
        0x90,              // nop
        0x85, 0xC0,        // test eax, eax
    };
    ASSERT_FINDINGS(gap_two_nops, "redundant TEST after flags", two_gap);

    // A gap that reads the tested register still leaves the value the test
    // would see, so the fold looks through it. This is where the rule parts
    // company with apx_ndd_gap_independent, which rejects any mention of its
    // destination.
    static const uint8_t gap_reads_dest[] = {
        0x21, 0xD8,        // and eax, ebx
        0x89, 0x06,        // mov [rsi], eax
        0x85, 0xC0,        // test eax, eax
    };
    ASSERT_FINDINGS(gap_reads_dest, "redundant TEST after flags", one_gap);

    // A gap that reads the flags reads the producer's either way, before and
    // after the test is dropped: transparent.
    static const uint8_t gap_reads_flags[] = {
        0x21, 0xD8,        // and eax, ebx
        0x0F, 0x94, 0xC1,  // sete cl
        0x85, 0xC0,        // test eax, eax
    };
    ASSERT_FINDINGS(gap_reads_flags, "redundant TEST after flags", one_gap);

    // A gap that writes the flags replaces what the producer set, so the test
    // is no longer a duplicate of it.
    static const uint8_t gap_writes_flags[] = {
        0x21, 0xD8,        // and eax, ebx
        0x31, 0xC9,        // xor ecx, ecx
        0x85, 0xC0,        // test eax, eax
    };
    ASSERT_FINDINGS(gap_writes_flags, "redundant TEST after flags", 0);

    // A gap that writes the tested register makes the test read a different
    // value than the producer computed -- at any width, so a byte write to
    // the same enclosing register stops the scan too.
    static const uint8_t gap_writes_dest[] = {
        0x21, 0xD8,        // and eax, ebx
        0xB0, 0x05,        // mov al, 5
        0x85, 0xC0,        // test eax, eax
    };
    ASSERT_FINDINGS(gap_writes_dest, "redundant TEST after flags", 0);

    // Control flow ends the straight-line path the fold reasons about.
    static const uint8_t gap_branches[] = {
        0x21, 0xD8,        // and eax, ebx
        0x74, 0x00,        // jz +0
        0x85, 0xC0,        // test eax, eax
    };
    ASSERT_FINDINGS(gap_branches, "redundant TEST after flags", 0);

    // An incoming edge onto a looked-through instruction reaches the test
    // without the producer, exactly as an edge onto the test itself does.
    static const uint8_t gap_edge_on_gap[] = {
        0x21, 0xD8,        // 0: and eax, ebx
        0x90,              // 2: nop            <- branch target
        0x85, 0xC0,        // 3: test eax, eax
        0xEB, 0xFB,        // 5: jmp 2
    };
    ASSERT_FINDINGS(gap_edge_on_gap, "redundant TEST after flags", 0);

    // An edge onto the producer executes the whole pattern: fires.
    static const uint8_t gap_edge_on_head[] = {
        0x21, 0xD8,        // 0: and eax, ebx   <- branch target
        0x90,              // 2: nop
        0x85, 0xC0,        // 3: test eax, eax
        0xEB, 0xF9,        // 5: jmp 0
    };
    ASSERT_FINDINGS(gap_edge_on_head, "redundant TEST after flags", one_gap);

    // The divergence gate evaluates at the test wherever the window found it:
    // an arithmetic producer fires through a gap when CF/OF die at the RET,
    // and stays suppressed when a later reader keeps them live.
    static const uint8_t gap_add_ret[] = {
        0x01, 0xD8,        // add eax, ebx
        0x90,              // nop
        0x85, 0xC0,        // test eax, eax
        0xC3,              // ret
    };
    ASSERT_FINDINGS(gap_add_ret, "redundant TEST after flags", one_gap);
    static const uint8_t gap_add_jb[] = {
        0x01, 0xD8,        // add eax, ebx
        0x90,              // nop
        0x85, 0xC0,        // test eax, eax
        0x72, 0x00,        // jb +0
    };
    ASSERT_FINDINGS(gap_add_jb, "redundant TEST after flags", 0);
}

// Multi-instruction peephole: a SHL/SHR/SAR of a register by a statically
// nonzero count -- a nonzero masked immediate, or the by-one D0/D1 forms --
// sets SF/ZF/PF exactly as test reg, reg would, so a following test on the
// shifted register is redundant. CF/OF diverge, so their readers suppress; a
// directly following CF/OF-blind Jcc (JZ/JNZ/JS/JNS/JP/JNP) is scanned on
// both successors. check_instructions reports against the test.
static void check_redundant_shift_test(void)
{
    // shr rax, 1 ; test rax, rax ; jne ; ret ; ret -- the by-one D0/D1 forms
    // carry no immediate but their count is statically 1; jne reads only ZF
    // and CF/OF are dead on both successors (ret).
    static const uint8_t shr_one_test_jne[] = {
        0x48, 0xD1, 0xE8,  // 0: shr rax, 1
        0x48, 0x85, 0xC0,  // 3: test rax, rax
        0x75, 0x01,        // 6: jne 9
        0xC3,              // 8: ret
        0xC3,              // 9: ret
    };
    ASSERT_FINDINGS(shr_one_test_jne, "redundant TEST after shift", 1);

    // The flagship: shl rax, 1 ; test rax, rax ; jne -- rustc/LLVM's
    // panic-counter shape ((x & ~(1 << 63)) == 0). check_shl_one flags the
    // same shl (add rax, rax is the better doubling), so the fixture carries
    // both findings; together the rewrites leave add rax, rax ; jne.
    static const uint8_t shl_one_test_jne[] = {
        0x48, 0xD1, 0xE0,  // 0: shl rax, 1
        0x48, 0x85, 0xC0,  // 3: test rax, rax
        0x75, 0x01,        // 6: jne 9
        0xC3,              // 8: ret
        0xC3,              // 9: ret
    };
    int total;
    assert(count_findings(shl_one_test_jne, sizeof(shl_one_test_jne),
                          "redundant TEST after shift", &total, 0) == 1);
    assert(total == 2);
    assert(count_findings(shl_one_test_jne, sizeof(shl_one_test_jne),
                          "suboptimal SHL one", &total, 0) == 1);

    // shr ecx, 2 ; test ecx, ecx ; jz -- any of the three shifts, any
    // nonzero immediate, matched at the shift's width.
    static const uint8_t shr_imm_test_jz[] = {
        0xC1, 0xE9, 0x02,  // 0: shr ecx, 2
        0x85, 0xC9,        // 3: test ecx, ecx
        0x74, 0x01,        // 5: jz 8
        0xC3,              // 7: ret
        0xC3,              // 8: ret
    };
    ASSERT_FINDINGS(shr_imm_test_jz, "redundant TEST after shift", 1);

    // sar rax, 3 ; test rax, rax ; ret -- no branch: the straight-line walk,
    // where RET makes CF/OF dead.
    static const uint8_t sar_test_ret[] = {
        0x48, 0xC1, 0xF8, 0x03,  // sar rax, 3
        0x48, 0x85, 0xC0,        // test rax, rax
        0xC3,                    // ret
    };
    ASSERT_FINDINGS(sar_test_ret, "redundant TEST after shift", 1);

    // The shared window: the test may sit past instructions that write
    // neither the flags nor the tested register (flags_gap_transparent).
    const int one_gap = APX_NDD_WINDOW >= 3 ? 1 : 0;
    static const uint8_t shr_gap_test[] = {
        0x48, 0xC1, 0xE8, 0x05,  // shr rax, 5
        0x48, 0x89, 0xCB,        // mov rbx, rcx
        0x48, 0x85, 0xC0,        // test rax, rax
        0xC3,                    // ret
    };
    ASSERT_FINDINGS(shr_gap_test, "redundant TEST after shift", one_gap);

    // shl rax, cl -- a CL count may mask to zero and write no flags: not a
    // producer (the hole that keeps shifts out of the general fold).
    static const uint8_t shl_cl_test[] = {
        0x48, 0xD3, 0xE0,  // shl rax, cl
        0x48, 0x85, 0xC0,  // test rax, rax
        0xC3,              // ret
    };
    ASSERT_FINDINGS(shl_cl_test, "redundant TEST after shift", 0);

    // shl rax, 64 -- the hardware masks the count to zero: no flags written.
    static const uint8_t shl_masked_zero_test[] = {
        0x48, 0xC1, 0xE0, 0x40,  // shl rax, 64
        0x48, 0x85, 0xC0,        // test rax, rax
        0xC3,                    // ret
    };
    ASSERT_FINDINGS(shl_masked_zero_test, "redundant TEST after shift", 0);

    // rol rax, 1 -- rotates write only CF/OF, never SF/ZF/PF: the test
    // computes flags the rotate did not.
    static const uint8_t rol_test[] = {
        0x48, 0xD1, 0xC0,  // rol rax, 1
        0x48, 0x85, 0xC0,  // test rax, rax
        0xC3,              // ret
    };
    ASSERT_FINDINGS(rol_test, "redundant TEST after shift", 0);

    // shl rax, 2 ; test ; jb -- the branch reads CF, which the test cleared
    // and the shift left as the last bit shifted out: suppress. (Count 2
    // sidesteps check_shl_one's separate finding on by-one shls.)
    static const uint8_t shl_test_jb[] = {
        0x48, 0xC1, 0xE0, 0x02,  // shl rax, 2
        0x48, 0x85, 0xC0,        // test rax, rax
        0x72, 0x00,              // jb +0
        0xC3,                    // ret
    };
    ASSERT_FINDINGS(shl_test_jb, "redundant TEST after shift", 0);

    // shl rax, 2 ; test ; jne ; adc -- the fall-through successor reads CF:
    // suppress despite the ZF-only branch.
    static const uint8_t shl_test_jne_adc[] = {
        0x48, 0xC1, 0xE0, 0x02,  // 0: shl rax, 2
        0x48, 0x85, 0xC0,        // 4: test rax, rax
        0x75, 0x03,              // 7: jne 12
        0x83, 0xD2, 0x00,        // 9: adc edx, 0
        0xC3,                    // 12: ret
    };
    ASSERT_FINDINGS(shl_test_jne_adc, "redundant TEST after shift", 0);

    // shl rax, 2 ; test eax, eax -- width mismatch: the narrow test reads SF
    // at bit 31 where the 64-bit shift set it at bit 63 (and, writing flags,
    // it also ends the window).
    static const uint8_t shl_test_narrow[] = {
        0x48, 0xC1, 0xE0, 0x02,  // shl rax, 2
        0x85, 0xC0,              // test eax, eax
        0xC3,                    // ret
    };
    ASSERT_FINDINGS(shl_test_narrow, "redundant TEST after shift", 0);

    // An incoming direct edge onto the test reaches it without the shift:
    // suppress (shared window guard).
    static const uint8_t shl_test_edge_on_test[] = {
        0x48, 0xC1, 0xE0, 0x02,  // 0: shl rax, 2
        0x48, 0x85, 0xC0,        // 4: test rax, rax  <- branch target
        0xEB, 0xFB,              // 7: jmp 4
    };
    ASSERT_FINDINGS(shl_test_edge_on_test, "redundant TEST after shift", 0);

    // A jne whose target lies outside the scanned bytes cannot be walked:
    // conservatively suppress.
    static const uint8_t shl_test_jne_out[] = {
        0x48, 0xC1, 0xE0, 0x02,  // 0: shl rax, 2
        0x48, 0x85, 0xC0,        // 4: test rax, rax
        0x75, 0x10,              // 7: jne 25 (out of buffer)
        0xC3,                    // 9: ret
    };
    ASSERT_FINDINGS(shl_test_jne_out, "redundant TEST after shift", 0);

    // shl rax, 2 ; test ; jne over a call -- the walks use the call-kills
    // reading: flags do not survive a call in either ABI (the argument the
    // RET case rests on), so a successor that immediately calls leaves CF/OF
    // dead. This is the real panic-counter shape, whose jne targets
    // call is_zero_slow_path.
    static const uint8_t shl_test_jne_call[] = {
        0x48, 0xC1, 0xE0, 0x02,        // 0: shl rax, 2
        0x48, 0x85, 0xC0,              // 4: test rax, rax
        0x75, 0x03,                    // 7: jne 12
        0x31, 0xC9,                    // 9: xor ecx, ecx
        0xC3,                          // 11: ret
        0xE8, 0x00, 0x00, 0x00, 0x00,  // 12: call +0
        0xC3,                          // 17: ret
    };
    ASSERT_FINDINGS(shl_test_jne_call, "redundant TEST after shift", 1);

    // sar rax, 3 ; test ; call -- the straight-line walk with the same
    // call-kills reading.
    static const uint8_t sar_test_call[] = {
        0x48, 0xC1, 0xF8, 0x03,        // sar rax, 3
        0x48, 0x85, 0xC0,              // test rax, rax
        0xE8, 0x00, 0x00, 0x00, 0x00,  // call +0
        0xC3,                          // ret
    };
    ASSERT_FINDINGS(sar_test_call, "redundant TEST after shift", 1);
}

// Multi-instruction peephole: lea reg, [addr] whose address the next
// instruction consumes as its memory base folds into that operand, so the lea
// disappears. check_instructions reports it against the lea when reg is dead
// after the fold. Positive fixtures use indexed or displaced leas so the simple
// lea reg, [base] case (also check_lea_to_mov's "suboptimal LEA") does not add a
// second finding and skew the total.
static void check_lea_fold_test(void)
{
    // lea rax, [rdi+rsi*4] ; mov rax, [rax] -- the load overwrites rax, so its
    // address value is dead; fold to mov rax, [rdi+rsi*4].
    static const uint8_t self_load[] = {
        0x48, 0x8D, 0x04, 0xB7,  // lea rax, [rdi+rsi*4]
        0x48, 0x8B, 0x00,        // mov rax, [rax]
    };
    ASSERT_FINDINGS(self_load, "LEA foldable into memory", 1);

    // lea rax, [rbx+8] ; mov rax, [rax] -- displacement-only lea; disp folds
    // (8 + 0) into the load: mov rax, [rbx+8].
    static const uint8_t disp_lea[] = {
        0x48, 0x8D, 0x43, 0x08,  // lea rax, [rbx+8]
        0x48, 0x8B, 0x00,        // mov rax, [rax]
    };
    ASSERT_FINDINGS(disp_lea, "LEA foldable into memory", 1);

    // lea rax, [rdi+rsi*4] ; mov ecx, [rax+8] ; mov eax, edx -- different
    // destination, so deadness is proven by the walk: mov eax, edx overwrites
    // rax without reading it. Consumer disp 8 folds with the lea's 0.
    static const uint8_t dead_by_scan[] = {
        0x48, 0x8D, 0x04, 0xB7,  // lea rax, [rdi+rsi*4]
        0x8B, 0x48, 0x08,        // mov ecx, [rax+8]
        0x89, 0xD0,              // mov eax, edx (kills rax)
    };
    ASSERT_FINDINGS(dead_by_scan, "LEA foldable into memory", 1);

    // lea rax, [rbx+8] ; mov rax, [rax+rsi*2] -- the index comes from the
    // consumer (the lea has none), so the single index slot suffices:
    // mov rax, [rbx+rsi*2+8].
    static const uint8_t consumer_index[] = {
        0x48, 0x8D, 0x43, 0x08,  // lea rax, [rbx+8]
        0x48, 0x8B, 0x04, 0x70,  // mov rax, [rax+rsi*2]
    };
    ASSERT_FINDINGS(consumer_index, "LEA foldable into memory", 1);

    // lea rax, [rdi+rsi*4] ; mov [rax], ecx ; mov eax, edx -- a store consumer;
    // rax appears only as the base (ecx is the stored value) and is killed next.
    static const uint8_t store_consumer[] = {
        0x48, 0x8D, 0x04, 0xB7,  // lea rax, [rdi+rsi*4]
        0x89, 0x08,              // mov [rax], ecx
        0x89, 0xD0,              // mov eax, edx (kills rax)
    };
    ASSERT_FINDINGS(store_consumer, "LEA foldable into memory", 1);

    // lea rax, [rax+rsi*4] ; mov rax, [rax] -- the lea reads its own dest as the
    // base. Within the load the base is read before rax is written, so folding
    // to mov rax, [rax+rsi*4] preserves the value.
    static const uint8_t self_ref[] = {
        0x48, 0x8D, 0x04, 0xB0,  // lea rax, [rax+rsi*4]
        0x48, 0x8B, 0x00,        // mov rax, [rax]
    };
    ASSERT_FINDINGS(self_ref, "LEA foldable into memory", 1);

    // lea rax, [rdi+rsi*4] ; mov ecx, [rax] ; ret -- different destination and
    // rax is not overwritten before RET, where the walk is conservatively live
    // (rax may be a return value): suppress.
    static const uint8_t live_at_ret[] = {
        0x48, 0x8D, 0x04, 0xB7,  // lea rax, [rdi+rsi*4]
        0x8B, 0x08,              // mov ecx, [rax]
        0xC3,                    // ret
    };
    ASSERT_FINDINGS(live_at_ret, "LEA foldable into memory", 0);

    // lea rax, [rdi+rsi*4] ; add rax, [rax] -- rax is read as the accumulator,
    // not just the base, so it stays live after the base folds away: suppress.
    static const uint8_t accumulator[] = {
        0x48, 0x8D, 0x04, 0xB7,  // lea rax, [rdi+rsi*4]
        0x48, 0x03, 0x00,        // add rax, [rax]
    };
    ASSERT_FINDINGS(accumulator, "LEA foldable into memory", 0);

    // lea rax, [rdi+rsi*4] ; mov ecx, [rax+rdx*2] -- both the lea and the
    // consumer carry an index; the combined address needs two index slots and
    // does not fold: suppress.
    static const uint8_t two_indexes[] = {
        0x48, 0x8D, 0x04, 0xB7,  // lea rax, [rdi+rsi*4]
        0x8B, 0x0C, 0x50,        // mov ecx, [rax+rdx*2]
    };
    ASSERT_FINDINGS(two_indexes, "LEA foldable into memory", 0);

    // lea rax, [rdi+rsi*4] ; mov ecx, [rax+rax*2] -- rax is the consumer's index
    // (and base); substituting into an index would scale the whole address, so
    // only a base use folds: suppress.
    static const uint8_t dest_is_index[] = {
        0x48, 0x8D, 0x04, 0xB7,  // lea rax, [rdi+rsi*4]
        0x8B, 0x0C, 0x40,        // mov ecx, [rax+rax*2]
    };
    ASSERT_FINDINGS(dest_is_index, "LEA foldable into memory", 0);

    // lea rax, [rdi+rsi*4] ; mov ecx, [rbx] -- the consumer's base is not the
    // lea's destination, so there is nothing to fold: suppress.
    static const uint8_t unrelated_base[] = {
        0x48, 0x8D, 0x04, 0xB7,  // lea rax, [rdi+rsi*4]
        0x8B, 0x0B,              // mov ecx, [rbx]
    };
    ASSERT_FINDINGS(unrelated_base, "LEA foldable into memory", 0);

    // lea rax, [rdi+rsi*4] ; mov al, [rax] ; ret -- an 8-bit write to al leaves
    // rax's upper bits (the address) intact, so it is not a kill; rax is then
    // live at RET: suppress.
    static const uint8_t partial_write[] = {
        0x48, 0x8D, 0x04, 0xB7,  // lea rax, [rdi+rsi*4]
        0x8A, 0x00,              // mov al, [rax]
        0xC3,                    // ret
    };
    ASSERT_FINDINGS(partial_write, "LEA foldable into memory", 0);

    // lea rax, [rdi+rsi*4] ; jmp [rax] ; mov eax, edx -- the jmp transfers
    // control, so the mov after it is not its successor; the deadness walk must
    // not read it as one. Without the control-transfer guard the mov would
    // falsely prove rax dead: suppress.
    static const uint8_t jmp_consumer[] = {
        0x48, 0x8D, 0x04, 0xB7,  // lea rax, [rdi+rsi*4]
        0xFF, 0x20,              // jmp [rax]
        0x89, 0xD0,              // mov eax, edx
    };
    ASSERT_FINDINGS(jmp_consumer, "LEA foldable into memory", 0);
}

// Multi-instruction peephole: mov reg, imm followed by an instruction that uses
// reg as its source operand folds the constant into that instruction's own
// immediate, so the mov disappears. check_instructions reports it against the
// mov when reg is dead after the fold. Fixtures kill reg with a following
// mov reg, other (a write with no read) so the deadness walk sees it die.
static void check_mov_const_fold_test(void)
{
    // mov ecx, 5 ; add eax, ecx -> add eax, 5 (ecx killed next).
    static const uint8_t add_fold[] = {
        0xB9, 0x05, 0x00, 0x00, 0x00,  // mov ecx, 5
        0x01, 0xC8,                    // add eax, ecx
        0x89, 0xD1,                    // mov ecx, edx (kills ecx)
    };
    ASSERT_FINDINGS(add_fold, "MOV constant foldable", 1);

    // mov ecx, 5 ; cmp eax, ecx -> cmp eax, 5.
    static const uint8_t cmp_fold[] = {
        0xB9, 0x05, 0x00, 0x00, 0x00,  // mov ecx, 5
        0x39, 0xC8,                    // cmp eax, ecx
        0x89, 0xD1,                    // mov ecx, edx
    };
    ASSERT_FINDINGS(cmp_fold, "MOV constant foldable", 1);

    // mov ecx, 7 ; mov eax, ecx -> mov eax, 7.
    static const uint8_t mov_fold[] = {
        0xB9, 0x07, 0x00, 0x00, 0x00,  // mov ecx, 7
        0x89, 0xC8,                    // mov eax, ecx
        0x89, 0xD1,                    // mov ecx, edx
    };
    ASSERT_FINDINGS(mov_fold, "MOV constant foldable", 1);

    // mov rcx, -1 ; and rax, rcx -> and rax, -1. A 64-bit consumer, but -1 is a
    // sign-extended imm32, so it fits.
    static const uint8_t and64_fold[] = {
        0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF,  // mov rcx, -1
        0x48, 0x21, 0xC8,                          // and rax, rcx
        0x48, 0x89, 0xD1,                          // mov rcx, rdx
    };
    ASSERT_FINDINGS(and64_fold, "MOV constant foldable", 1);

    // mov ecx, 5 ; add eax, ecx ; ret -- ecx is live at RET (conservative), so
    // the mov cannot be dropped: suppress.
    static const uint8_t live_at_ret[] = {
        0xB9, 0x05, 0x00, 0x00, 0x00,  // mov ecx, 5
        0x01, 0xC8,                    // add eax, ecx
        0xC3,                          // ret
    };
    ASSERT_FINDINGS(live_at_ret, "MOV constant foldable", 0);

    // mov ecx, 5 ; add ecx, eax -- ecx is the destination (first operand), not
    // the folded source, and it is written: not an immediate fold.
    static const uint8_t reg_is_dest[] = {
        0xB9, 0x05, 0x00, 0x00, 0x00,  // mov ecx, 5
        0x01, 0xC1,                    // add ecx, eax
        0x89, 0xD1,                    // mov ecx, edx
    };
    ASSERT_FINDINGS(reg_is_dest, "MOV constant foldable", 0);

    // movabs rcx, 0x100000000 ; add rax, rcx -- the 64-bit constant does not fit
    // add's sign-extended imm32: suppress.
    static const uint8_t imm_too_big[] = {
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,  // movabs rcx, 0x100000000
        0x48, 0x01, 0xC8,                                            // add rax, rcx
        0x48, 0x89, 0xD1,                                            // mov rcx, rdx
    };
    ASSERT_FINDINGS(imm_too_big, "MOV constant foldable", 0);

    // mov ecx, 5 ; test ecx, ecx -- ecx is both operands, so folding one still
    // leaves it read: suppress.
    static const uint8_t reg_twice[] = {
        0xB9, 0x05, 0x00, 0x00, 0x00,  // mov ecx, 5
        0x85, 0xC9,                    // test ecx, ecx
        0x89, 0xD1,                    // mov ecx, edx
    };
    ASSERT_FINDINGS(reg_twice, "MOV constant foldable", 0);

    // mov ecx, 5 ; mov eax, [rcx] -- the source is a memory operand (ecx used as
    // an address, not a value), so there is no immediate to fold into: suppress.
    static const uint8_t mem_source[] = {
        0xB9, 0x05, 0x00, 0x00, 0x00,  // mov ecx, 5
        0x8B, 0x01,                    // mov eax, [rcx]
    };
    ASSERT_FINDINGS(mem_source, "MOV constant foldable", 0);

    // movabs rdx, big ; mov [rbp-0x30], rdx -- a memory-store mov takes only a
    // sign-extended imm32, so a full imm64 constant does not fold into it (there
    // is no mov qword ptr, imm64): suppress.
    static const uint8_t imm64_to_mem[] = {
        0x48, 0xBA, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,  // movabs rdx, 0x1122334455667788
        0x48, 0x89, 0x55, 0xD0,        // mov [rbp-0x30], rdx
        0x48, 0x89, 0xCA,              // mov rdx, rcx (kills rdx)
    };
    ASSERT_FINDINGS(imm64_to_mem, "MOV constant foldable", 0);

    // movabs rdx, big ; mov rbx, rdx -- a register-destination mov spells any
    // imm64 via movabs, so this folds.
    static const uint8_t imm64_to_reg[] = {
        0x48, 0xBA, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,  // movabs rdx, 0x1122334455667788
        0x48, 0x89, 0xD3,              // mov rbx, rdx
        0x48, 0x89, 0xCA,              // mov rdx, rcx (kills rdx)
    };
    ASSERT_FINDINGS(imm64_to_reg, "MOV constant foldable", 1);
}

// Multi-instruction peephole: a narrow load feeding an in-place sign/zero
// extension of the loaded register is a single extending load; check_instructions
// reports it against the load. The extension must widen the loaded register in
// place (same family), so its full write subsumes the load. The movsx/movsxd
// fixtures avoid the eax/ax/rax accumulator forms that check_unneeded_movsx and
// check_unneeded_movsxd flag as cwde/cbw/cdqe.
static void check_load_extend_fold_test(void)
{
    // mov al, [rsi] ; movzx eax, al -> movzx eax, byte [rsi].
    static const uint8_t byte_zx[] = {
        0x8A, 0x06,        // mov al, [rsi]
        0x0F, 0xB6, 0xC0,  // movzx eax, al
    };
    ASSERT_FINDINGS(byte_zx, "load foldable into extend", 1);

    // mov al, [rsi] ; movsx eax, al -> movsx eax, byte [rsi].
    static const uint8_t byte_sx[] = {
        0x8A, 0x06,        // mov al, [rsi]
        0x0F, 0xBE, 0xC0,  // movsx eax, al
    };
    ASSERT_FINDINGS(byte_sx, "load foldable into extend", 1);

    // mov ax, [rsi] ; movzx eax, ax -> movzx eax, word [rsi].
    static const uint8_t word_zx[] = {
        0x66, 0x8B, 0x06,  // mov ax, [rsi]
        0x0F, 0xB7, 0xC0,  // movzx eax, ax
    };
    ASSERT_FINDINGS(word_zx, "load foldable into extend", 1);

    // mov ebx, [rsi] ; movsxd rbx, ebx -> movsxd rbx, [rsi]. (rbx, not rax, so
    // not the cdqe form.)
    static const uint8_t dword_sxd[] = {
        0x8B, 0x1E,              // mov ebx, [rsi]
        0x48, 0x63, 0xDB,        // movsxd rbx, ebx
    };
    ASSERT_FINDINGS(dword_sxd, "load foldable into extend", 1);

    // mov al, [rsi] ; movzx ecx, al -- the extension writes ECX, not RAX, so
    // dropping the load would leave RAX's low byte unset: not in place, skip.
    static const uint8_t other_family[] = {
        0x8A, 0x06,        // mov al, [rsi]
        0x0F, 0xB6, 0xC8,  // movzx ecx, al
    };
    ASSERT_FINDINGS(other_family, "load foldable into extend", 0);

    // mov al, [rsi] ; movzx eax, cl -- the extension reads CL, not the loaded
    // AL: no fold. The load itself, its byte instantly buried by the
    // full-width movzx, is a merging narrow move finding instead.
    static const uint8_t other_source[] = {
        0x8A, 0x06,        // mov al, [rsi]
        0x0F, 0xB6, 0xC1,  // movzx eax, cl
    };
    int total;
    assert(count_findings(other_source, sizeof(other_source),
                          "load foldable into extend", &total, 0) == 0);
    assert(count_findings(other_source, sizeof(other_source),
                          "merging narrow move", &total, 0) == 1);
    assert(total == 1);

    // mov [rsi], al ; movzx eax, al -- the mov is a store, not a load: suppress.
    static const uint8_t store[] = {
        0x88, 0x06,        // mov [rsi], al
        0x0F, 0xB6, 0xC0,  // movzx eax, al
    };
    ASSERT_FINDINGS(store, "load foldable into extend", 0);

    // mov al, cl ; movzx eax, al -- the mov is register-to-register, so there is
    // no memory operand to fold: suppress.
    static const uint8_t reg_move[] = {
        0x88, 0xC8,        // mov al, cl
        0x0F, 0xB6, 0xC0,  // movzx eax, al
    };
    ASSERT_FINDINGS(reg_move, "load foldable into extend", 0);
}

// Multi-instruction peephole: mov dest, srcA ; add dest, srcB is the
// three-operand lea dest, [srcA + srcB]. check_instructions reports it against
// the mov when the arithmetic flags the add would set are dead.
static void check_mov_add_lea_test(void)
{
    // mov edx, esi ; add edx, edi -> lea edx, [rsi + rdi].
    static const uint8_t basic[] = {
        0x89, 0xF2,        // mov edx, esi
        0x01, 0xFA,        // add edx, edi
        0xC3,              // ret (flags dead)
    };
    ASSERT_FINDINGS(basic, "MOV+ADD foldable to LEA", 1);

    // 64-bit form.
    static const uint8_t wide[] = {
        0x48, 0x89, 0xF2,  // mov rdx, rsi
        0x48, 0x01, 0xFA,  // add rdx, rdi
        0xC3,              // ret
    };
    ASSERT_FINDINGS(wide, "MOV+ADD foldable to LEA", 1);

    // mov edx, esi ; add edx, esi -> lea edx, [rsi + rsi]. srcA == srcB is fine
    // as long as neither is the destination.
    static const uint8_t doubled[] = {
        0x89, 0xF2,        // mov edx, esi
        0x01, 0xF2,        // add edx, esi
        0xC3,              // ret
    };
    ASSERT_FINDINGS(doubled, "MOV+ADD foldable to LEA", 1);

    // 16-bit form: mov dx, si ; add dx, di -> lea dx, [rsi + rdi]. LEA takes
    // any non-byte destination width.
    static const uint8_t word[] = {
        0x66, 0x89, 0xF2,  // mov dx, si
        0x66, 0x01, 0xFA,  // add dx, di
        0xC3,              // ret
    };
    ASSERT_FINDINGS(word, "MOV+ADD foldable to LEA", 1);

    // Immediate addend: mov edx, esi ; add edx, 5 -> lea edx, [rsi + 5].
    static const uint8_t imm_add[] = {
        0x89, 0xF2,              // mov edx, esi
        0x83, 0xC2, 0x05,        // add edx, 5
        0xC3,                    // ret
    };
    ASSERT_FINDINGS(imm_add, "MOV+ADD foldable to LEA", 1);

    // Subtraction negates the displacement: mov rdx, rsi ; sub rdx, 8 ->
    // lea rdx, [rsi - 8].
    static const uint8_t imm_sub64[] = {
        0x48, 0x89, 0xF2,        // mov rdx, rsi
        0x48, 0x83, 0xEA, 0x08,  // sub rdx, 8
        0xC3,                    // ret
    };
    ASSERT_FINDINGS(imm_sub64, "MOV+ADD foldable to LEA", 1);

    // inc is add by an implied 1: mov edx, esi ; inc edx -> lea edx, [rsi+1].
    static const uint8_t imm_inc[] = {
        0x89, 0xF2,              // mov edx, esi
        0xFF, 0xC2,              // inc edx
        0xC3,                    // ret
    };
    ASSERT_FINDINGS(imm_inc, "MOV+ADD foldable to LEA", 1);

    // dec -- like lea -- leaves CF untouched, so a CF reader does not gate
    // it: the adc reads CF, which flows through dec and lea identically, and
    // overwrites the flags dec does write. Fires.
    static const uint8_t imm_dec_adc[] = {
        0x89, 0xF2,              // mov edx, esi
        0xFF, 0xCA,              // dec edx
        0x11, 0xD8,              // adc eax, ebx (reads CF, kills the rest)
        0xC3,                    // ret
    };
    ASSERT_FINDINGS(imm_dec_adc, "MOV+ADD foldable to LEA", 1);

    // sub edx, 1 writes CF, which the adc reads: suppress. (check_inc_dec is
    // likewise CF-gated on these bytes, so nothing else fires.)
    static const uint8_t imm_sub_adc[] = {
        0x89, 0xF2,              // mov edx, esi
        0x83, 0xEA, 0x01,        // sub edx, 1
        0x11, 0xD8,              // adc eax, ebx (reads CF)
        0xC3,                    // ret
    };
    ASSERT_FINDINGS(imm_sub_adc, "MOV+ADD foldable to LEA", 0);

    // add edx, 0 is check_add_sub_zero's finding -- the mov alone already
    // computes the result -- so the fold defers. The trailing mov kills edx's
    // upper bits so the gated add-zero finding fires, and the total of one
    // proves the fold stayed quiet.
    static const uint8_t imm_zero[] = {
        0x89, 0xF2,              // mov edx, esi
        0x83, 0xC2, 0x00,        // add edx, 0
        0x89, 0xCA,              // mov edx, ecx
    };
    ASSERT_FINDINGS(imm_zero, "redundant ADD/SUB zero", 1);

    // A 64-bit pair uses the displacement at full value: sub rdx, INT32_MIN
    // would need disp32 = +2^31, which does not exist. Suppress.
    static const uint8_t imm_sub_int32min[] = {
        0x48, 0x89, 0xF2,                          // mov rdx, rsi
        0x48, 0x81, 0xEA, 0x00, 0x00, 0x00, 0x80,  // sub rdx, -2^31
        0xC3,                                      // ret
    };
    ASSERT_FINDINGS(imm_sub_int32min, "MOV+ADD foldable to LEA", 0);

    // The same immediate folds at 32 bits, where the address truncates to the
    // destination width: lea edx, [rsi - 2^31] computes esi + 2^31 mod 2^32.
    static const uint8_t imm_sub_int32min_32[] = {
        0x89, 0xF2,                          // mov edx, esi
        0x81, 0xEA, 0x00, 0x00, 0x00, 0x80,  // sub edx, -2^31
        0xC3,                                // ret
    };
    ASSERT_FINDINGS(imm_sub_int32min_32, "MOV+ADD foldable to LEA", 1);

    // Width mismatch: add dx, 5 writes only the low word of the edx the mov
    // defined, so the pair is not one lea. Suppress.
    static const uint8_t imm_width_mismatch[] = {
        0x89, 0xF2,              // mov edx, esi
        0x66, 0x83, 0xC2, 0x05,  // add dx, 5
        0xC3,                    // ret
    };
    ASSERT_FINDINGS(imm_width_mismatch, "MOV+ADD foldable to LEA", 0);

    // The canonical scan loop (observed in bash and git): the je's back edge
    // enters the window at the add, so folding the pair would turn the loop
    // increment into a per-iteration reset. Suppress.
    static const uint8_t loop_into_add[] = {
        0x48, 0x89, 0xC3,        // 0: mov rbx, rax
        0x48, 0x83, 0xC3, 0x05,  // 3: add rbx, 5    <- branch target
        0x80, 0x3B, 0x2D,        // 7: cmp byte [rbx], 0x2d
        0x74, 0xF7,              // a: je 3
    };
    ASSERT_FINDINGS(loop_into_add, "MOV+ADD foldable to LEA", 0);

    // A back edge to the window HEAD executes the whole pattern, which the
    // lea reproduces: fires.
    static const uint8_t loop_into_mov[] = {
        0x48, 0x89, 0xC3,        // 0: mov rbx, rax  <- branch target
        0x48, 0x83, 0xC3, 0x05,  // 3: add rbx, 5
        0x80, 0x3B, 0x2D,        // 7: cmp byte [rbx], 0x2d
        0x74, 0xF4,              // a: je 0
    };
    ASSERT_FINDINGS(loop_into_mov, "MOV+ADD foldable to LEA", 1);

    // A target just past the window (the cmp) does not poison it: fires.
    static const uint8_t loop_past_window[] = {
        0x48, 0x89, 0xC3,        // 0: mov rbx, rax
        0x48, 0x83, 0xC3, 0x05,  // 3: add rbx, 5
        0x80, 0x3B, 0x2D,        // 7: cmp byte [rbx], 0x2d  <- branch target
        0x74, 0xFB,              // a: je 7
    };
    ASSERT_FINDINGS(loop_past_window, "MOV+ADD foldable to LEA", 1);

    // mov al, bl ; add al, cl -- LEA has no byte-width destination, so an
    // 8-bit pair has no single-LEA rewrite: suppress.
    static const uint8_t byte_low[] = {
        0x88, 0xD8,        // mov al, bl
        0x00, 0xC8,        // add al, cl
        0xC3,              // ret
    };
    ASSERT_FINDINGS(byte_low, "MOV+ADD foldable to LEA", 0);

    // Same with a high-byte destination: mov ah, bl ; add ah, cl.
    static const uint8_t byte_high[] = {
        0x88, 0xDC,        // mov ah, bl
        0x00, 0xCC,        // add ah, cl
        0xC3,              // ret
    };
    ASSERT_FINDINGS(byte_high, "MOV+ADD foldable to LEA", 0);

    // mov edx, esi ; add edx, edi ; jz -- the add's flags feed the branch, and
    // lea would not set them: suppress.
    static const uint8_t flags_live[] = {
        0x89, 0xF2,        // mov edx, esi
        0x01, 0xFA,        // add edx, edi
        0x74, 0x00,        // jz +0
    };
    ASSERT_FINDINGS(flags_live, "MOV+ADD foldable to LEA", 0);

    // mov edx, esi ; add edx, edx -- the add's source is the destination, set by
    // the mov; lea [rsi + rdx] would read dest's pre-mov value: suppress.
    static const uint8_t src_is_dest[] = {
        0x89, 0xF2,        // mov edx, esi
        0x01, 0xD2,        // add edx, edx
        0xC3,              // ret
    };
    ASSERT_FINDINGS(src_is_dest, "MOV+ADD foldable to LEA", 0);

    // mov edx, esi ; add edx, [rdi] -- a memory addend is not a lea index
    // register: suppress.
    static const uint8_t mem_addend[] = {
        0x89, 0xF2,        // mov edx, esi
        0x03, 0x17,        // add edx, [rdi]
    };
    ASSERT_FINDINGS(mem_addend, "MOV+ADD foldable to LEA", 0);

    // mov edx, esi ; sub edx, edi -- lea cannot subtract: suppress.
    static const uint8_t sub_consumer[] = {
        0x89, 0xF2,        // mov edx, esi
        0x29, 0xFA,        // sub edx, edi
        0xC3,              // ret
    };
    ASSERT_FINDINGS(sub_consumer, "MOV+ADD foldable to LEA", 0);

    // ---- The window, shared with the APX NDD fold (APX_NDD_WINDOW, and
    // the same independence proof): the consumer may sit past independent
    // instructions. These expectations track the build's window.
    const int one_gap = APX_NDD_WINDOW >= 3 ? 1 : 0;

    // A flag-writing zero idiom between the pair: flags matter only after
    // the add (lea writes none), and ECX is neither dest nor srcA.
    static const uint8_t gap_fold[] = {
        0x89, 0xF2,        // mov edx, esi
        0x31, 0xC9,        // xor ecx, ecx
        0x01, 0xFA,        // add edx, edi
        0xC3,              // ret
    };
    ASSERT_FINDINGS(gap_fold, "MOV+ADD foldable to LEA", one_gap);
    static const uint8_t gap_fold_imm[] = {
        0x89, 0xF2,        // mov edx, esi
        0x31, 0xC9,        // xor ecx, ecx
        0x83, 0xC2, 0x05,  // add edx, 5
        0xC3,              // ret
    };
    ASSERT_FINDINGS(gap_fold_imm, "MOV+ADD foldable to LEA", one_gap);

    // Reading the copy stops the scan; so does writing srcA, whose value
    // the lea reads later than the mov captured it.
    static const uint8_t gap_reads_dest[] = {
        0x89, 0xF2,        // mov edx, esi
        0x85, 0xD2,        // test edx, edx
        0x01, 0xFA,        // add edx, edi
        0xC3,              // ret
    };
    ASSERT_FINDINGS(gap_reads_dest, "MOV+ADD foldable to LEA", 0);
    static const uint8_t gap_writes_src[] = {
        0x89, 0xF2,        // mov edx, esi
        0x89, 0xFE,        // mov esi, edi
        0x01, 0xFA,        // add edx, edi
        0xC3,              // ret
    };
    ASSERT_FINDINGS(gap_writes_src, "MOV+ADD foldable to LEA", 0);

    // A direct branch onto the looked-through instruction: the widened
    // suppression span covers every slot.
    static const uint8_t edge_on_gap[] = {
        0xEB, 0x02,        // jmp +2 (to the xor)
        0x89, 0xF2,        // mov edx, esi
        0x31, 0xC9,        // xor ecx, ecx
        0x01, 0xFA,        // add edx, edi
        0xC3,              // ret
    };
    ASSERT_FINDINGS(edge_on_gap, "MOV+ADD foldable to LEA", 0);

    // The gapped division of labor: while the add's flags live this pair
    // is missing APX NDD's (under -m apx) and never this finding's.
    static const uint8_t gap_flags_live[] = {
        0x89, 0xF2,        // mov edx, esi
        0x31, 0xC9,        // xor ecx, ecx
        0x01, 0xFA,        // add edx, edi
        0x70, 0x00,        // jo +0
        0xC3,              // ret
    };
    ASSERT_FINDINGS(gap_flags_live, "MOV+ADD foldable to LEA", 0);
    int total;
    assert(count_findings(gap_flags_live, sizeof(gap_flags_live),
                          "missing APX NDD", &total,
                          X86LINT_EXT_APX) == one_gap);
    assert(count_findings(gap_flags_live, sizeof(gap_flags_live),
                          "MOV+ADD foldable to LEA", &total,
                          X86LINT_EXT_APX) == 0);
}

// Multi-instruction peephole: shl reg, k ; sar reg, k sign-extends the low
// width-k bits in place (shr zero-extends), which a single movsx/movzx
// computes. check_instructions reports it against the shl. Gated on the
// arithmetic flags being dead past the pair (movsx/movzx write none) and on
// no direct edge entering at the second shift.
static void check_shift_pair_extend_test(void)
{
    // shl eax, 24 ; sar eax, 24 -> movsx eax, al.
    static const uint8_t byte_sign[] = {
        0xC1, 0xE0, 0x18,        // shl eax, 24
        0xC1, 0xF8, 0x18,        // sar eax, 24
        0xC3,                    // ret (flags dead)
    };
    ASSERT_FINDINGS(byte_sign, "shift pair foldable into extend", 1);

    // shl eax, 24 ; shr eax, 24 -> movzx eax, al (the zero-extending twin).
    static const uint8_t byte_zero[] = {
        0xC1, 0xE0, 0x18,        // shl eax, 24
        0xC1, 0xE8, 0x18,        // shr eax, 24
        0xC3,                    // ret
    };
    ASSERT_FINDINGS(byte_zero, "shift pair foldable into extend", 1);

    // shl rax, 32 ; sar rax, 32 -> movsxd rax, eax.
    static const uint8_t dword_sign64[] = {
        0x48, 0xC1, 0xE0, 0x20,  // shl rax, 32
        0x48, 0xC1, 0xF8, 0x20,  // sar rax, 32
        0xC3,                    // ret
    };
    ASSERT_FINDINGS(dword_sign64, "shift pair foldable into extend", 1);

    // 16-bit form: shl ax, 8 ; sar ax, 8 -> movsx ax, al.
    static const uint8_t word_sign[] = {
        0x66, 0xC1, 0xE0, 0x08,  // shl ax, 8
        0x66, 0xC1, 0xF8, 0x08,  // sar ax, 8
        0xC3,                    // ret
    };
    ASSERT_FINDINGS(word_sign, "shift pair foldable into extend", 1);

    // Mismatched counts compute a shifted extension, not an extension.
    static const uint8_t mismatch[] = {
        0xC1, 0xE0, 0x18,        // shl eax, 24
        0xC1, 0xF8, 0x10,        // sar eax, 16
        0xC3,                    // ret
    };
    ASSERT_FINDINGS(mismatch, "shift pair foldable into extend", 0);

    // A low remainder off the register boundaries (32 - 20 = 12 bits) has no
    // movsx source.
    static const uint8_t off_boundary[] = {
        0xC1, 0xE0, 0x14,        // shl eax, 20
        0xC1, 0xF8, 0x14,        // sar eax, 20
        0xC3,                    // ret
    };
    ASSERT_FINDINGS(off_boundary, "shift pair foldable into extend", 0);

    // Different registers are unrelated shifts.
    static const uint8_t different_reg[] = {
        0xC1, 0xE0, 0x18,        // shl eax, 24
        0xC1, 0xF9, 0x18,        // sar ecx, 24
        0xC3,                    // ret
    };
    ASSERT_FINDINGS(different_reg, "shift pair foldable into extend", 0);

    // A CL count is not statically knowable.
    static const uint8_t cl_count[] = {
        0xD3, 0xE0,              // shl eax, cl
        0xD3, 0xF8,              // sar eax, cl
        0xC3,                    // ret
    };
    ASSERT_FINDINGS(cl_count, "shift pair foldable into extend", 0);

    // Memory destinations would need a load-extend-store rewrite: suppress.
    static const uint8_t memory_pair[] = {
        0xC1, 0x23, 0x18,        // shl dword [rbx], 24
        0xC1, 0x3B, 0x18,        // sar dword [rbx], 24
        0xC3,                    // ret
    };
    ASSERT_FINDINGS(memory_pair, "shift pair foldable into extend", 0);

    // The sar's flags feed the branch; movsx would not set them: suppress.
    static const uint8_t flags_live[] = {
        0xC1, 0xE0, 0x18,        // shl eax, 24
        0xC1, 0xF8, 0x18,        // sar eax, 24
        0x74, 0x00,              // jz +0
    };
    ASSERT_FINDINGS(flags_live, "shift pair foldable into extend", 0);

    // An incoming direct edge onto the sar (from the dead je after the ret)
    // reaches it without the shl: suppress. The flags are dead at the ret, so
    // only the window guard is at work here.
    static const uint8_t edge_on_sar[] = {
        0xC1, 0xE0, 0x18,        // 0: shl eax, 24
        0xC1, 0xF8, 0x18,        // 3: sar eax, 24  <- branch target
        0xC3,                    // 6: ret
        0x74, 0xFA,              // 7: je 3
    };
    ASSERT_FINDINGS(edge_on_sar, "shift pair foldable into extend", 0);

    // An edge onto the shl (the window head) executes the whole pair: fires.
    static const uint8_t edge_on_shl[] = {
        0xC1, 0xE0, 0x18,        // 0: shl eax, 24  <- branch target
        0xC1, 0xF8, 0x18,        // 3: sar eax, 24
        0xC3,                    // 6: ret
        0x74, 0xF7,              // 7: je 0
    };
    ASSERT_FINDINGS(edge_on_shl, "shift pair foldable into extend", 1);
}

// Multi-instruction peephole: cmp reg, 1 ; jb/jae branches on unsigned
// "< 1", i.e. "== 0", which test reg, reg ; jz/jnz answers a byte shorter.
// Only the branch decision survives -- the residual flags differ in every
// arithmetic flag -- so both successors must have them dead, and an incoming
// edge onto the branch (which expects jb-on-CF semantics) rejects the fold.
static void check_cmp_one_branch_test(void)
{
    // cmp ebx, 1 ; jb +0 ; ret -- both successors are the ret: fires.
    static const uint8_t jb_ret[] = {
        0x83, 0xFB, 0x01,        // cmp ebx, 1
        0x72, 0x00,              // jb +0
        0xC3,                    // ret
    };
    ASSERT_FINDINGS(jb_ret, "suboptimal CMP one", 1);

    // The jae twin (-> jnz).
    static const uint8_t jae_ret[] = {
        0x83, 0xFB, 0x01,        // cmp ebx, 1
        0x73, 0x00,              // jae +0
        0xC3,                    // ret
    };
    ASSERT_FINDINGS(jae_ret, "suboptimal CMP one", 1);

    // 64- and 16-bit widths fold alike.
    static const uint8_t jb_ret64[] = {
        0x48, 0x83, 0xFB, 0x01,  // cmp rbx, 1
        0x72, 0x00,              // jb +0
        0xC3,
    };
    ASSERT_FINDINGS(jb_ret64, "suboptimal CMP one", 1);
    static const uint8_t jb_ret16[] = {
        0x66, 0x83, 0xF9, 0x01,  // cmp cx, 1
        0x72, 0x00,              // jb +0
        0xC3,
    };
    ASSERT_FINDINGS(jb_ret16, "suboptimal CMP one", 1);

    // je reads ZF = (reg == 1), a condition test cannot answer: suppress.
    static const uint8_t je_wrong_cc[] = {
        0x83, 0xFB, 0x01,        // cmp ebx, 1
        0x74, 0x00,              // je +0
        0xC3,
    };
    ASSERT_FINDINGS(je_wrong_cc, "suboptimal CMP one", 0);

    // cmp ebx, 2 ; jb is "< 2", not "== 0": suppress.
    static const uint8_t imm_two[] = {
        0x83, 0xFB, 0x02,        // cmp ebx, 2
        0x72, 0x00,              // jb +0
        0xC3,
    };
    ASSERT_FINDINGS(imm_two, "suboptimal CMP one", 0);

    // The adc at the shared successor reads CF, which the rewrite replaces
    // with test's 0: suppress.
    static const uint8_t flags_live_fall[] = {
        0x83, 0xFB, 0x01,        // cmp ebx, 1
        0x72, 0x00,              // jb +0
        0x11, 0xD8,              // adc eax, ebx (reads CF)
        0xC3,
    };
    ASSERT_FINDINGS(flags_live_fall, "suboptimal CMP one", 0);

    // Flags dead on the fall-through (ret) but read on the taken target
    // (lahf): the taken-side scan suppresses.
    static const uint8_t flags_live_target[] = {
        0x83, 0xFB, 0x01,        // 0: cmp ebx, 1
        0x72, 0x01,              // 3: jb +1 (target 6)
        0xC3,                    // 5: ret (fall-through: dead)
        0x9F,                    // 6: lahf (reads SF/ZF/AF/PF/CF)
        0xC3,                    // 7: ret
    };
    ASSERT_FINDINGS(flags_live_target, "suboptimal CMP one", 0);

    // An incoming direct edge onto the branch expects jb-on-CF semantics:
    // suppress. (The trailing jmp is dead code, but the linear sweep records
    // its target.)
    static const uint8_t edge_on_branch[] = {
        0x83, 0xFB, 0x01,        // 0: cmp ebx, 1
        0x72, 0x00,              // 3: jb +0  <- branch target
        0xC3,                    // 5: ret
        0xEB, 0xFB,              // 6: jmp 3
    };
    ASSERT_FINDINGS(edge_on_branch, "suboptimal CMP one", 0);

    // An edge onto the cmp (the window head) executes the whole rewritten
    // pair: fires.
    static const uint8_t edge_on_cmp[] = {
        0x83, 0xFB, 0x01,        // 0: cmp ebx, 1  <- branch target
        0x72, 0x00,              // 3: jb +0
        0xC3,                    // 5: ret
        0xEB, 0xF8,              // 6: jmp 0
    };
    ASSERT_FINDINGS(edge_on_cmp, "suboptimal CMP one", 1);

    // cmp al, 1 via the accumulator opcode is 2 bytes, tying test al, al:
    // suppress.
    static const uint8_t al_tie[] = {
        0x3C, 0x01,              // cmp al, 1
        0x72, 0x00,              // jb +0
        0xC3,
    };
    ASSERT_FINDINGS(al_tie, "suboptimal CMP one", 0);

    // Memory operands have no test [mem], [mem] to shrink to: suppress.
    static const uint8_t mem_cmp[] = {
        0x83, 0x3B, 0x01,        // cmp dword [rbx], 1
        0x72, 0x00,              // jb +0
        0xC3,
    };
    ASSERT_FINDINGS(mem_cmp, "suboptimal CMP one", 0);
}

// Multi-instruction peephole: setcc X ; test X, X ; je/jne branches on a
// condition the preceding compare's flags already hold (setcc preserves them),
// so the test is redundant. check_instructions reports it against the setcc. The
// gate is flags, not registers: dropping the test swaps its residual flags for
// the compare's, so every arithmetic flag must be dead on BOTH the fall-through
// and the taken target. X's own liveness is irrelevant -- the rewrite keeps
// setcc when X is live -- so the check fires even when X is stored. Fixtures end
// paths in ret (flags dead) or adc al, 0 (reads CF, flags live) to steer the
// flag-liveness walk.
static void check_setcc_branch_test(void)
{
    // sete al ; test al, al ; je +1 -- both successors are ret, so the flags are
    // dead on each: the test is redundant.
    static const uint8_t fold_je[] = {
        0x0F, 0x94, 0xC0,              // sete al
        0x84, 0xC0,                    // test al, al
        0x74, 0x01,                    // je +1 (to the second ret)
        0xC3,                          // ret   (fall-through)
        0xC3,                          // ret   (target)
    };
    ASSERT_FINDINGS(fold_je, "redundant TEST after SETcc", 1);

    // setne al ; test al, al ; jne +1 -- the jne form is redundant identically.
    static const uint8_t fold_jne[] = {
        0x0F, 0x95, 0xC0,              // setne al
        0x84, 0xC0,                    // test al, al
        0x75, 0x01,                    // jne +1
        0xC3,                          // ret
        0xC3,                          // ret
    };
    ASSERT_FINDINGS(fold_jne, "redundant TEST after SETcc", 1);

    // sete al ; test al, al ; je +2 ; mov [rbx], al ; ret -- the fall-through
    // stores al, so the boolean is LIVE, yet the flags are dead on both paths.
    // The test is still redundant (keep the setcc, drop the test): fire. This is
    // the case the old register-liveness gate wrongly suppressed.
    static const uint8_t live_x_flags_dead[] = {
        0x0F, 0x94, 0xC0,              // sete al
        0x84, 0xC0,                    // test al, al
        0x74, 0x02,                    // je +2 (to ret)
        0x88, 0x03,                    // mov [rbx], al   (fall-through: al live)
        0xC3,                          // ret             (target)
    };
    ASSERT_FINDINGS(live_x_flags_dead, "redundant TEST after SETcc", 1);

    // sete al ; test al, al ; je +2 ; adc al, 0 ; ret -- the fall-through's adc
    // reads CF, so the compare's flags would be observable there: suppress.
    static const uint8_t flags_live_fallthrough[] = {
        0x0F, 0x94, 0xC0,              // sete al
        0x84, 0xC0,                    // test al, al
        0x74, 0x02,                    // je +2 (to ret)
        0x14, 0x00,                    // adc al, 0    (fall-through reads CF)
        0xC3,                          // ret          (target)
    };
    ASSERT_FINDINGS(flags_live_fallthrough, "redundant TEST after SETcc", 0);

    // sete al ; test al, al ; je +1 ; ret ; adc al, 0 -- the fall-through is dead
    // (ret) but the taken target's adc reads CF. The two-successor flags check
    // catches the target: suppress.
    static const uint8_t flags_live_target[] = {
        0x0F, 0x94, 0xC0,              // sete al
        0x84, 0xC0,                    // test al, al
        0x74, 0x01,                    // je +1 (to adc)
        0xC3,                          // ret          (fall-through dead)
        0x14, 0x00,                    // adc al, 0    (target reads CF)
    };
    ASSERT_FINDINGS(flags_live_target, "redundant TEST after SETcc", 0);

    // sete al ; test al, al ; jg +1 -- jg reads more than ZF after test al, al;
    // only je/jne are exact: suppress.
    static const uint8_t wrong_cc[] = {
        0x0F, 0x94, 0xC0,              // sete al
        0x84, 0xC0,                    // test al, al
        0x7F, 0x01,                    // jg +1
        0xC3,                          // ret
        0xC3,                          // ret
    };
    ASSERT_FINDINGS(wrong_cc, "redundant TEST after SETcc", 0);

    // sete al ; test cl, cl ; je +1 -- the test is on a different register than
    // the setcc wrote: suppress.
    static const uint8_t wrong_reg[] = {
        0x0F, 0x94, 0xC0,              // sete al
        0x84, 0xC9,                    // test cl, cl
        0x74, 0x01,                    // je +1
        0xC3,                          // ret
        0xC3,                          // ret
    };
    ASSERT_FINDINGS(wrong_reg, "redundant TEST after SETcc", 0);

    // sete al ; test eax, eax ; je +1 -- the test is a wider alias of the setcc
    // register; its ZF folds in the upper 24 bits of eax, which this window
    // cannot show are zero, so only exact-width test al, al matches: suppress.
    static const uint8_t widened_test[] = {
        0x0F, 0x94, 0xC0,              // sete al
        0x85, 0xC0,                    // test eax, eax
        0x74, 0x01,                    // je +1
        0xC3,                          // ret
        0xC3,                          // ret
    };
    ASSERT_FINDINGS(widened_test, "redundant TEST after SETcc", 0);
}

// Advisory window: setcc r8 followed by a movzx of that byte into its own
// 32/64-bit parent -- Intel's preferred form zeroes the register upstream of
// the compare instead, dropping the movzx. Matched only in the tight
// same-register, low-byte, 32/64-bit shape.
static void check_setcc_movzx_test(void)
{
    // setz al ; movzx eax, al -- the canonical widening idiom.
    static const uint8_t widen[] = {
        0x0F, 0x94, 0xC0,  // setz al
        0x0F, 0xB6, 0xC0,  // movzx eax, al
    };
    ASSERT_FINDINGS(widen, "suboptimal SETcc zero-extension", 1);

    // setz cl ; movzx rcx, cl -- the 64-bit destination is the same idiom,
    // but its REX.W is itself droppable (movzx r32 zero-extends), so the
    // unneeded-REX check co-fires: assert both categories directly.
    static const uint8_t widen64[] = {
        0x0F, 0x94, 0xC1,        // setz cl
        0x48, 0x0F, 0xB6, 0xC9,  // movzx rcx, cl
    };
    int total;
    assert(count_findings(widen64, sizeof(widen64),
                          "suboptimal SETcc zero-extension", &total, 0) == 1);
    assert(total == 2);
    assert(count_findings(widen64, sizeof(widen64),
                          "unneeded REX prefix", &total, 0) == 1);

    // movzx into a DIFFERENT register is a real move, not the widening
    // idiom: the xor form could not replace it.
    static const uint8_t cross_reg[] = {
        0x0F, 0x94, 0xC0,  // setz al
        0x0F, 0xB6, 0xC8,  // movzx ecx, al
    };
    ASSERT_FINDINGS(cross_reg, "suboptimal SETcc zero-extension", 0);

    // A high-byte setcc destination puts the value at bits 8-15; the xor
    // form's setcc writes the low byte: suppress.
    static const uint8_t high_byte[] = {
        0x0F, 0x94, 0xC4,  // setz ah
        0x0F, 0xB6, 0xC4,  // movzx eax, ah
    };
    ASSERT_FINDINGS(high_byte, "suboptimal SETcc zero-extension", 0);

    // A 16-bit movzx leaves bits 16-63 the xor form would zero: suppress.
    static const uint8_t narrow[] = {
        0x0F, 0x94, 0xC0,        // setz al
        0x66, 0x0F, 0xB6, 0xC0,  // movzx ax, al
    };
    ASSERT_FINDINGS(narrow, "suboptimal SETcc zero-extension", 0);

    // setcc to memory has no register to widen.
    static const uint8_t mem_dest[] = {
        0x0F, 0x94, 0x06,  // setz byte [rsi]
        0x0F, 0xB6, 0xC0,  // movzx eax, al
    };
    ASSERT_FINDINGS(mem_dest, "suboptimal SETcc zero-extension", 0);

    // An incoming direct edge onto the movzx reaches it without the setcc:
    // that path's byte was set elsewhere, so zeroing upstream of this setcc
    // proves nothing for it. Suppress.
    static const uint8_t edge_on_movzx[] = {
        0xEB, 0x03,        // 0: jmp 5
        0x0F, 0x94, 0xC0,  // 2: setz al
        0x0F, 0xB6, 0xC0,  // 5: movzx eax, al  <- branch target
    };
    ASSERT_FINDINGS(edge_on_movzx, "suboptimal SETcc zero-extension", 0);

    // An edge onto the setcc (the window head) executes the whole pattern:
    // fires.
    static const uint8_t edge_on_head[] = {
        0xEB, 0x00,        // 0: jmp 2
        0x0F, 0x94, 0xC0,  // 2: setz al  <- branch target
        0x0F, 0xB6, 0xC0,  // 5: movzx eax, al
    };
    ASSERT_FINDINGS(edge_on_head, "suboptimal SETcc zero-extension", 1);
}

// Multi-instruction peephole: setcc X ; xor X, 1 inverts the boolean the
// complementary condition code produces outright, so the XOR disappears.
// check_instructions reports it against the setcc, gated on the arithmetic
// flags the XOR writes being dead afterward.
static void check_setcc_invert_test(void)
{
    // setz al ; xor al, 1 -- the accumulator short form of the XOR. RET makes
    // the flags dead, so it fires.
    static const uint8_t acc_form[] = {
        0x0F, 0x94, 0xC0,  // setz al
        0x34, 0x01,        // xor al, 1
        0xC3,              // ret
    };
    ASSERT_FINDINGS(acc_form, "suboptimal SETcc inversion", 1);

    // The same through the modrm encoding, on a register with no short form.
    static const uint8_t modrm_form[] = {
        0x0F, 0x95, 0xC1,  // setnz cl
        0x80, 0xF1, 0x01,  // xor cl, 1
        0xC3,              // ret
    };
    ASSERT_FINDINGS(modrm_form, "suboptimal SETcc inversion", 1);

    // A different register is not the same boolean.
    static const uint8_t other_reg[] = {
        0x0F, 0x94, 0xC0,  // setz al
        0x80, 0xF1, 0x01,  // xor cl, 1
        0xC3,              // ret
    };
    ASSERT_FINDINGS(other_reg, "suboptimal SETcc inversion", 0);

    // Only 1 inverts a 0/1 boolean.
    static const uint8_t other_imm[] = {
        0x0F, 0x94, 0xC0,  // setz al
        0x34, 0x02,        // xor al, 2
        0xC3,              // ret
    };
    ASSERT_FINDINGS(other_imm, "suboptimal SETcc inversion", 0);

    // A wider XOR flips the same bit but writes the whole register,
    // zero-extending where setnz al leaves bits 63:8 alone.
    static const uint8_t wide_xor[] = {
        0x0F, 0x94, 0xC0,  // setz al
        0x83, 0xF0, 0x01,  // xor eax, 1
        0xC3,              // ret
    };
    ASSERT_FINDINGS(wide_xor, "suboptimal SETcc inversion", 0);

    // The XOR writes the arithmetic flags and setcc writes none, so a reader
    // downstream keeps the pair.
    static const uint8_t flags_live[] = {
        0x0F, 0x94, 0xC0,  // setz al
        0x34, 0x01,        // xor al, 1
        0x74, 0x00,        // jz +0
    };
    ASSERT_FINDINGS(flags_live, "suboptimal SETcc inversion", 0);

    // Memory destinations are out.
    static const uint8_t mem_dest[] = {
        0x0F, 0x94, 0x00,  // setz byte [rax]
        0x80, 0x30, 0x01,  // xor byte [rax], 1
        0xC3,              // ret
    };
    ASSERT_FINDINGS(mem_dest, "suboptimal SETcc inversion", 0);

    // An incoming edge onto the XOR inverts whatever else arrived in the
    // register; one onto the setcc executes the whole pattern.
    static const uint8_t edge_on_xor[] = {
        0x0F, 0x94, 0xC0,  // 0: setz al
        0x34, 0x01,        // 3: xor al, 1   <- branch target
        0xC3,              // 5: ret
        0xEB, 0xFB,        // 6: jmp 3
    };
    ASSERT_FINDINGS(edge_on_xor, "suboptimal SETcc inversion", 0);
    static const uint8_t edge_on_head[] = {
        0x0F, 0x94, 0xC0,  // 0: setz al     <- branch target
        0x34, 0x01,        // 3: xor al, 1
        0xC3,              // 5: ret
        0xEB, 0xF8,        // 6: jmp 0
    };
    ASSERT_FINDINGS(edge_on_head, "suboptimal SETcc inversion", 1);
}


// Advisory: POPCNT/LZCNT/TZCNT's destination is a phantom input on affected
// Intel cores (POPCNT through Cascade Lake, LZCNT/TZCNT through Broadwell),
// so a count into a register the adjacent predecessor did not redefine is
// flagged -- break the dependency with a zero idiom before the count.
static void check_popcnt_false_dep_test(void)
{
    // Stale destination, register and 64-bit forms: flagged.
    static const uint8_t pop32[] = {
        0xF3, 0x0F, 0xB8, 0xC1,  // popcnt eax, ecx
    };
    ASSERT_FINDINGS(pop32, "missing POPCNT dependency break", 1);

    static const uint8_t pop64[] = {
        0xF3, 0x48, 0x0F, 0xB8, 0xC7,  // popcnt rax, rdi
    };
    ASSERT_FINDINGS(pop64, "missing POPCNT dependency break", 1);

    // Same register: the dependency is real, and the xor would destroy the
    // input.
    static const uint8_t same_reg[] = {
        0xF3, 0x0F, 0xB8, 0xC0,  // popcnt eax, eax
    };
    ASSERT_FINDINGS(same_reg, "missing POPCNT dependency break", 0);

    // 16-bit form: no zero idiom writes only the low word.
    static const uint8_t narrow[] = {
        0x66, 0xF3, 0x0F, 0xB8, 0xCA,  // popcnt cx, dx
    };
    ASSERT_FINDINGS(narrow, "missing POPCNT dependency break", 0);

    // A memory source addressed through the destination -- as base or index
    // -- would have its address corrupted by the xor: suppress. Any other
    // address is fair game.
    static const uint8_t mem_base[] = {
        0xF3, 0x0F, 0xB8, 0x00,  // popcnt eax, [rax]
    };
    ASSERT_FINDINGS(mem_base, "missing POPCNT dependency break", 0);

    static const uint8_t mem_index[] = {
        0xF3, 0x0F, 0xB8, 0x0C, 0x48,  // popcnt ecx, [rax+rcx*2]
    };
    ASSERT_FINDINGS(mem_index, "missing POPCNT dependency break", 0);

    static const uint8_t mem_ok[] = {
        0xF3, 0x0F, 0xB8, 0x01,  // popcnt eax, [rcx]
    };
    ASSERT_FINDINGS(mem_ok, "missing POPCNT dependency break", 1);

    // xor eax, eax ; popcnt rax, rdi -- gcc's mitigation: the 32-bit zero
    // idiom redefines the whole register, so the count no longer waits on a
    // stale value. Suppress.
    static const uint8_t mitigated[] = {
        0x31, 0xC0,                    // xor eax, eax
        0xF3, 0x48, 0x0F, 0xB8, 0xC7,  // popcnt rax, rdi
    };
    ASSERT_FINDINGS(mitigated, "missing POPCNT dependency break", 0);

    // The mitigation need not be adjacent: gcc emits the zero idiom and then
    // an unrelated instruction before the count. Suppress at a distance too.
    static const uint8_t mitigated_gap[] = {
        0x31, 0xC0,                    // xor eax, eax
        0x89, 0xD1,                    // mov ecx, edx      (independent)
        0xF3, 0x48, 0x0F, 0xB8, 0xC7,  // popcnt rax, rdi
    };
    ASSERT_FINDINGS(mitigated_gap, "missing POPCNT dependency break",
                    APX_NDD_WINDOW >= 3 ? 0 : 1);

    // Only a deliberate mitigation reaches back. An ordinary producer
    // suppresses when adjacent -- the dependency is then one instruction
    // stale -- but not from further away, where it may still be in flight.
    static const uint8_t producer_adjacent[] = {
        0x89, 0xC8,              // mov eax, ecx
        0xF3, 0x0F, 0xB8, 0xC3,  // popcnt eax, ebx
    };
    ASSERT_FINDINGS(producer_adjacent, "missing POPCNT dependency break", 0);
    static const uint8_t producer_gap[] = {
        0x89, 0xC8,              // mov eax, ecx
        0x89, 0xD1,              // mov ecx, edx
        0xF3, 0x0F, 0xB8, 0xC3,  // popcnt eax, ebx
    };
    ASSERT_FINDINGS(producer_gap, "missing POPCNT dependency break", 1);

    // Zeroing a DIFFERENT register mitigates nothing.
    static const uint8_t wrong_reg[] = {
        0x31, 0xDB,              // xor ebx, ebx
        0xF3, 0x0F, 0xB8, 0xC1,  // popcnt eax, ecx
    };
    ASSERT_FINDINGS(wrong_reg, "missing POPCNT dependency break", 1);

    // A partial (8-bit) write leaves the rest of the register -- and the
    // dependency -- in place.
    static const uint8_t partial_write[] = {
        0x88, 0xD8,              // mov al, bl
        0xF3, 0x0F, 0xB8, 0xC1,  // popcnt eax, ecx
    };
    ASSERT_FINDINGS(partial_write, "missing POPCNT dependency break", 1);

    // lzcnt/tzcnt share the erratum (through Broadwell) and are flagged the
    // same way -- their encodings decode as themselves now that every
    // decode sets XED_CHIP_ALL.
    static const uint8_t lz[] = {
        0xF3, 0x0F, 0xBD, 0xCA,  // lzcnt ecx, edx
    };
    ASSERT_FINDINGS(lz, "missing POPCNT dependency break", 1);

    static const uint8_t tz[] = {
        0xF3, 0x0F, 0xBC, 0xCA,  // tzcnt ecx, edx
    };
    ASSERT_FINDINGS(tz, "missing POPCNT dependency break", 1);

    // Their legacy aliases BSR/BSF are never flagged: the destination
    // dependency is load-bearing (with a zero source real silicon preserves
    // the destination, which the advised xor would change).
    static const uint8_t bsr[] = {
        0x0F, 0xBD, 0xCA,  // bsr ecx, edx
    };
    ASSERT_FINDINGS(bsr, "missing POPCNT dependency break", 0);

    static const uint8_t bsf[] = {
        0x0F, 0xBC, 0xCA,  // bsf ecx, edx
    };
    ASSERT_FINDINGS(bsf, "missing POPCNT dependency break", 0);
}

// Advisory: the legacy scalar SSE instructions write only their
// destination's low element and leave the upper lanes standing, so a
// destination the adjacent predecessor did not rewrite is a phantom input --
// break it with a vector zero idiom before the instruction.
static void check_sse_merge_false_dep_test(void)
{
    // Stale destination: flagged across the whole family.
    static const uint8_t cvtss2sd[] = {
        0xF3, 0x0F, 0x5A, 0xC1,  // cvtss2sd xmm0, xmm1
    };
    ASSERT_FINDINGS(cvtss2sd, "missing SSE dependency break", 1);

    static const uint8_t cvtsd2ss[] = {
        0xF2, 0x0F, 0x5A, 0xC1,  // cvtsd2ss xmm0, xmm1
    };
    ASSERT_FINDINGS(cvtsd2ss, "missing SSE dependency break", 1);

    // The zero idiom that breaks the merge dependency need not be adjacent:
    // libcrypto emits it and then an unrelated instruction before the
    // conversion, and the check used to re-flag its own mitigation.
    static const uint8_t mitigated_gap[] = {
        0x0F, 0x57, 0xC0,              // xorps xmm0, xmm0
        0xF2, 0x48, 0x0F, 0x2C, 0xC1,  // cvttsd2si rax, xmm1  (independent)
        0xF2, 0x48, 0x0F, 0x2A, 0xC0,  // cvtsi2sd xmm0, rax
    };
    ASSERT_FINDINGS(mitigated_gap, "missing SSE dependency break",
                    APX_NDD_WINDOW >= 3 ? 0 : 1);

    // An ordinary full producer suppresses only from the adjacent slot, where
    // the dependency is one instruction stale; from further back it may still
    // be in flight and the finding stands.
    static const uint8_t producer_adjacent[] = {
        0x0F, 0x28, 0xC1,              // movaps xmm0, xmm1
        0xF2, 0x48, 0x0F, 0x2A, 0xC0,  // cvtsi2sd xmm0, rax
    };
    ASSERT_FINDINGS(producer_adjacent, "missing SSE dependency break", 0);
    static const uint8_t producer_gap[] = {
        0x0F, 0x28, 0xC1,              // movaps xmm0, xmm1
        0x89, 0xD1,                    // mov ecx, edx
        0xF2, 0x48, 0x0F, 0x2A, 0xC0,  // cvtsi2sd xmm0, rax
    };
    ASSERT_FINDINGS(producer_gap, "missing SSE dependency break", 1);

    static const uint8_t sqrtsd[] = {
        0xF2, 0x0F, 0x51, 0xC1,  // sqrtsd xmm0, xmm1
    };
    ASSERT_FINDINGS(sqrtsd, "missing SSE dependency break", 1);

    static const uint8_t roundsd[] = {
        0x66, 0x0F, 0x3A, 0x0B, 0xC1, 0x03,  // roundsd xmm0, xmm1, 0x3
    };
    ASSERT_FINDINGS(roundsd, "missing SSE dependency break", 1);

    static const uint8_t rsqrtss[] = {
        0xF3, 0x0F, 0x52, 0xC1,  // rsqrtss xmm0, xmm1
    };
    ASSERT_FINDINGS(rsqrtss, "missing SSE dependency break", 1);

    // An integer source lives in a GPR, so the destination can never be the
    // source: the form is always flagged, memory operand or not. The address
    // is built from general-purpose registers a vector zero idiom cannot
    // disturb, unlike POPCNT's.
    static const uint8_t cvtsi2sd[] = {
        0xF2, 0x0F, 0x2A, 0xC0,  // cvtsi2sd xmm0, eax
    };
    ASSERT_FINDINGS(cvtsi2sd, "missing SSE dependency break", 1);

    static const uint8_t mem_src[] = {
        0xF3, 0x0F, 0x5A, 0x00,  // cvtss2sd xmm0, dword ptr [rax]
    };
    ASSERT_FINDINGS(mem_src, "missing SSE dependency break", 1);

    // Same register: the destination is the source, so the dependency is
    // real and the xor would destroy the input.
    static const uint8_t same_reg[] = {
        0xF3, 0x0F, 0x5A, 0xC0,  // cvtss2sd xmm0, xmm0
    };
    ASSERT_FINDINGS(same_reg, "missing SSE dependency break", 0);

    // The scalar arithmetic that merges the same way is never flagged: its
    // destination is a genuine source operand.
    static const uint8_t addsd[] = {
        0xF2, 0x0F, 0x58, 0xC1,  // addsd xmm0, xmm1
    };
    ASSERT_FINDINGS(addsd, "missing SSE dependency break", 0);

    // VEX names the merge source outright, so the fix is to choose that
    // operand, not to insert a zero idiom: a different rewrite, left to
    // vex_merge_false_dep (the clean form here fires neither check).
    static const uint8_t vex[] = {
        0xC5, 0xEA, 0x5A, 0xC2,  // vcvtss2sd xmm0, xmm2, xmm2
    };
    ASSERT_FINDINGS(vex, "missing SSE dependency break", 0);

    // xorps xmm0, xmm0 ; cvtss2sd xmm0, xmm1 -- the mitigation gcc, clang
    // and Go all emit. XED models the xor's destination as read-and-written,
    // so recognizing it takes the explicit zero-idiom match. Suppress.
    static const uint8_t mitigated[] = {
        0x0F, 0x57, 0xC0,        // xorps xmm0, xmm0
        0xF3, 0x0F, 0x5A, 0xC1,  // cvtss2sd xmm0, xmm1
    };
    ASSERT_FINDINGS(mitigated, "missing SSE dependency break", 0);

    // The integer-domain zero idiom breaks the dependency just as well. Its
    // legacy form is spelled vpxor here only so the fixture stands alone:
    // pxor xmm0, xmm0 is suppressed identically, but carries a suboptimal
    // SSE zero idiom finding of its own that this assertion would count.
    static const uint8_t mitigated_vpxor[] = {
        0xC5, 0xF9, 0xEF, 0xC0,  // vpxor xmm0, xmm0, xmm0
        0xF2, 0x0F, 0x2A, 0xC0,  // cvtsi2sd xmm0, eax
    };
    ASSERT_FINDINGS(mitigated_vpxor, "missing SSE dependency break", 0);

    static const uint8_t mitigated_vex_xor[] = {
        0xC5, 0xF8, 0x57, 0xC0,  // vxorps xmm0, xmm0, xmm0
        0xF3, 0x0F, 0x5A, 0xC1,  // cvtss2sd xmm0, xmm1
    };
    ASSERT_FINDINGS(mitigated_vex_xor, "missing SSE dependency break", 0);

    // Zeroing a DIFFERENT register mitigates nothing.
    static const uint8_t wrong_reg[] = {
        0x0F, 0x57, 0xDB,        // xorps xmm3, xmm3
        0xF3, 0x0F, 0x5A, 0xC1,  // cvtss2sd xmm0, xmm1
    };
    ASSERT_FINDINGS(wrong_reg, "missing SSE dependency break", 1);

    // Nor does a vector XOR against another register: xorps xmm0, xmm1
    // zeroes nothing and leaves the dependency in place.
    static const uint8_t xor_other[] = {
        0x0F, 0x57, 0xC1,        // xorps xmm0, xmm1
        0xF3, 0x0F, 0x5A, 0xC2,  // cvtss2sd xmm0, xmm2
    };
    ASSERT_FINDINGS(xor_other, "missing SSE dependency break", 1);

    // Any adjacent producer that rewrites the whole register leaves the
    // dependency one instruction stale, which is what the advice would buy.
    static const uint8_t full_write[] = {
        0x0F, 0x28, 0xC3,        // movaps xmm0, xmm3
        0xF3, 0x0F, 0x5A, 0xC1,  // cvtss2sd xmm0, xmm1
    };
    ASSERT_FINDINGS(full_write, "missing SSE dependency break", 0);

    static const uint8_t movd[] = {
        0x66, 0x0F, 0x6E, 0xC0,  // movd xmm0, eax
        0xF3, 0x0F, 0x5A, 0xC1,  // cvtss2sd xmm0, xmm1
    };
    ASSERT_FINDINGS(movd, "missing SSE dependency break", 0);

    // A partial write leaves the upper lanes -- and the dependency -- in
    // place. XED reports MOVSS's destination written-only in both forms, so
    // telling the merging register form from the zeroing memory form is the
    // suppression's other correction. The register movss escapes the
    // merging-scalar-move finding here only because the cvt behind it reads
    // its destination at 64 bits -- wider than the 32 the movss wrote --
    // which that check's forward gate takes as blend evidence.
    static const uint8_t movss_reg[] = {
        0xF3, 0x0F, 0x10, 0xC3,  // movss xmm0, xmm3
        0xF3, 0x0F, 0x5A, 0xC1,  // cvtss2sd xmm0, xmm1
    };
    ASSERT_FINDINGS(movss_reg, "missing SSE dependency break", 1);

    static const uint8_t movss_mem[] = {
        0xF3, 0x0F, 0x10, 0x00,  // movss xmm0, dword ptr [rax]
        0xF3, 0x0F, 0x5A, 0xC1,  // cvtss2sd xmm0, xmm1
    };
    ASSERT_FINDINGS(movss_mem, "missing SSE dependency break", 0);

    // A lane insert writes half the register and merges the other half.
    static const uint8_t movhps[] = {
        0x0F, 0x16, 0x00,        // movhps xmm0, qword ptr [rax]
        0xF3, 0x0F, 0x5A, 0xC1,  // cvtss2sd xmm0, xmm1
    };
    ASSERT_FINDINGS(movhps, "missing SSE dependency break", 1);
}

// Advisory: the VEX three-operand scalar forms name their merge source, so
// a merge operand that is neither the data source nor freshly rewritten is
// a false dependency the encoding could avoid for free -- pass the data
// source (or a register known dead) as the merge operand instead.
static void check_vex_merge_false_dep_test(void)
{
    // Destination as merge operand: the legacy false dependency reproduced
    // in an encoding that names the merge outright.
    static const uint8_t stale_dest[] = {
        0xC5, 0xEA, 0x5A, 0xD1,  // vcvtss2sd xmm2, xmm2, xmm1
    };
    ASSERT_FINDINGS(stale_dest, "stale VEX merge operand", 1);

    // Source as merge operand: the canonical dependency-free form.
    static const uint8_t merge_source[] = {
        0xC5, 0xF2, 0x5A, 0xD1,  // vcvtss2sd xmm2, xmm1, xmm1
    };
    ASSERT_FINDINGS(merge_source, "stale VEX merge operand", 0);

    // An "unused" 1111b vvvv on an instruction that reads vvvv names xmm0,
    // serializing every round behind xmm0's last producer -- the encoding
    // SpiderMonkey's JIT emitted for Math.floor.
    static const uint8_t round_xmm0[] = {
        0xC4, 0x63, 0x79, 0x0B, 0xF9, 0x01,  // vroundsd xmm15, xmm0, xmm1, 1
    };
    ASSERT_FINDINGS(round_xmm0, "stale VEX merge operand", 1);

    static const uint8_t round_source[] = {
        0xC4, 0x63, 0x71, 0x0B, 0xF9, 0x01,  // vroundsd xmm15, xmm1, xmm1, 1
    };
    ASSERT_FINDINGS(round_source, "stale VEX merge operand", 0);

    static const uint8_t sqrt_stale[] = {
        0xC5, 0xEB, 0x51, 0xD1,  // vsqrtsd xmm2, xmm2, xmm1
    };
    ASSERT_FINDINGS(sqrt_stale, "stale VEX merge operand", 1);

    // An integer source lives in a GPR, so there is no XMM source to reuse:
    // only a freshly rewritten merge register is clean, exactly as for the
    // legacy forms.
    static const uint8_t int_bare[] = {
        0xC5, 0xEB, 0x2A, 0xD0,  // vcvtsi2sd xmm2, xmm2, eax
    };
    ASSERT_FINDINGS(int_bare, "stale VEX merge operand", 1);

    static const uint8_t int_mitigated[] = {
        0xC5, 0xE8, 0x57, 0xD2,  // vxorps xmm2, xmm2, xmm2
        0xC5, 0xEB, 0x2A, 0xD0,  // vcvtsi2sd xmm2, xmm2, eax
    };
    ASSERT_FINDINGS(int_mitigated, "stale VEX merge operand", 0);

    // A memory source likewise has nothing to reuse, and the stale merge
    // register still costs the dependency.
    static const uint8_t mem_src[] = {
        0xC5, 0xFA, 0x5A, 0x00,  // vcvtss2sd xmm0, xmm0, dword ptr [rax]
    };
    ASSERT_FINDINGS(mem_src, "stale VEX merge operand", 1);
}

// Advisory: a register-to-register MOVSS/MOVSD merges where MOVAPS would
// copy the whole register a byte shorter, dependency-free and eliminable at
// rename; the VEX forms merge from their explicit vvvv operand the same way.
// A downstream read of the destination wider than the moved element proves
// the merge a deliberate blend and suppresses. See scalar_move_false_dep.
static void check_scalar_move_false_dep_test(void)
{
    static const uint8_t movsd_stale[] = {
        0xF2, 0x0F, 0x10, 0xCA,  // movsd xmm1, xmm2
    };
    ASSERT_FINDINGS(movsd_stale, "merging scalar move", 1);

    static const uint8_t movss_stale[] = {
        0xF3, 0x0F, 0x10, 0xCA,  // movss xmm1, xmm2
    };
    ASSERT_FINDINGS(movss_stale, "merging scalar move", 1);

    // The load form zeroes the upper lanes and the store form writes no
    // register: neither merges.
    static const uint8_t movsd_load[] = {
        0xF2, 0x0F, 0x10, 0x08,  // movsd xmm1, qword ptr [rax]
    };
    ASSERT_FINDINGS(movsd_load, "merging scalar move", 0);

    static const uint8_t movsd_store[] = {
        0xF2, 0x0F, 0x11, 0x08,  // movsd qword ptr [rax], xmm1
    };
    ASSERT_FINDINGS(movsd_store, "merging scalar move", 0);

    // Same register: a pure no-op, not a merge hazard.
    static const uint8_t movsd_self[] = {
        0xF2, 0x0F, 0x10, 0xC0,  // movsd xmm0, xmm0
    };
    ASSERT_FINDINGS(movsd_self, "merging scalar move", 0);

    // An adjacent full producer leaves the merge one instruction stale;
    // suppressed as everywhere in the family.
    static const uint8_t fresh_dest[] = {
        0x0F, 0x28, 0xCB,        // movaps xmm1, xmm3
        0xF2, 0x0F, 0x10, 0xCA,  // movsd xmm1, xmm2
    };
    ASSERT_FINDINGS(fresh_dest, "merging scalar move", 0);

    // The zero-idiom mitigation suppresses through the window, not just
    // adjacency.
    static const uint8_t mitigated_window[] = {
        0x0F, 0x57, 0xC9,        // xorps xmm1, xmm1
        0x0F, 0x28, 0xE5,        // movaps xmm4, xmm5
        0xF2, 0x0F, 0x10, 0xCA,  // movsd xmm1, xmm2
    };
    ASSERT_FINDINGS(mitigated_window, "merging scalar move", 0);

    // VEX with a merge operand that is neither the source nor fresh.
    static const uint8_t vmovsd_stale[] = {
        0xC5, 0xEB, 0x10, 0xCB,  // vmovsd xmm1, xmm2, xmm3
    };
    ASSERT_FINDINGS(vmovsd_stale, "merging scalar move", 1);

    static const uint8_t vmovss_stale[] = {
        0xC5, 0xEA, 0x10, 0xCB,  // vmovss xmm1, xmm2, xmm3
    };
    ASSERT_FINDINGS(vmovss_stale, "merging scalar move", 1);

    // Destination as merge operand: the legacy hazard reproduced in an
    // encoding that names the merge outright.
    static const uint8_t vmovsd_dest_merge[] = {
        0xC5, 0xF3, 0x10, 0xCB,  // vmovsd xmm1, xmm1, xmm3
    };
    ASSERT_FINDINGS(vmovsd_dest_merge, "merging scalar move", 1);

    // Merge equal to the source: a full copy of xmm3, however spelled.
    static const uint8_t vmovsd_full_copy[] = {
        0xC5, 0xE3, 0x10, 0xCB,  // vmovsd xmm1, xmm3, xmm3
    };
    ASSERT_FINDINGS(vmovsd_full_copy, "merging scalar move", 0);

    // Destination equal to the source: as a move this would be a no-op, so
    // the shape only ever means the deliberate blend.
    static const uint8_t vmovsd_blend_self[] = {
        0xC5, 0xEB, 0x10, 0xC9,  // vmovsd xmm1, xmm2, xmm1
    };
    ASSERT_FINDINGS(vmovsd_blend_self, "merging scalar move", 0);

    static const uint8_t vmovsd_load[] = {
        0xC5, 0xFB, 0x10, 0x08,  // vmovsd xmm1, qword ptr [rax]
    };
    ASSERT_FINDINGS(vmovsd_load, "merging scalar move", 0);

    // A masked EVEX form surfaces the opmask as the second register
    // operand and is skipped: the mask makes the merge deliberate.
    static const uint8_t evex_masked[] = {
        0x62, 0xF1, 0xF7, 0x09, 0x10, 0xCB,  // vmovsd xmm1{k1}, xmm2, xmm3
    };
    ASSERT_FINDINGS(evex_masked, "merging scalar move", 0);

    // The forward gate: gcc's SSE2 vectorized shape, a movss merging one
    // recomputed lane into a pair whose both lanes are then stored -- the
    // movq reads 64 bits where the movss wrote 32, so the merged lane is
    // live and the "move" is a deliberate blend.
    static const uint8_t blend_store[] = {
        0xF3, 0x0F, 0x10, 0xC2,        // movss xmm0, xmm2
        0x66, 0x0F, 0xD6, 0x40, 0x08,  // movq qword ptr [rax+8], xmm0
    };
    ASSERT_FINDINGS(blend_store, "merging scalar move", 0);

    // Likewise a single-precision move whose result is consumed at double
    // width: bits 32-63 came from the merge.
    static const uint8_t double_read[] = {
        0xF3, 0x0F, 0x10, 0xCA,        // movss xmm1, xmm2
        0xF2, 0x0F, 0x11, 0x48, 0x08,  // movsd qword ptr [rax+8], xmm1
    };
    ASSERT_FINDINGS(double_read, "merging scalar move", 0);

    // A scalar consumer reads only the moved element: no blend evidence,
    // the finding stands.
    static const uint8_t scalar_read[] = {
        0xF2, 0x0F, 0x10, 0xCA,  // movsd xmm1, xmm2
        0xF2, 0x0F, 0x58, 0xCB,  // addsd xmm1, xmm3
    };
    ASSERT_FINDINGS(scalar_read, "merging scalar move", 1);

    // A full redefinition kills the merged lanes before anything reads
    // them: dead, so the finding stands.
    static const uint8_t redefined_after[] = {
        0xF2, 0x0F, 0x10, 0xCA,  // movsd xmm1, xmm2
        0x0F, 0x28, 0xCC,        // movaps xmm1, xmm4
    };
    ASSERT_FINDINGS(redefined_after, "merging scalar move", 1);

    // An escape ends the walk with the finding standing: glibc's fmax
    // moves the chosen argument into the return register and returns, and
    // a double-returning function's caller cannot read the upper lanes.
    static const uint8_t escape_ret[] = {
        0xF2, 0x0F, 0x10, 0xC1,  // movsd xmm0, xmm1
        0xC3,                    // ret
    };
    ASSERT_FINDINGS(escape_ret, "merging scalar move", 1);

    // The walk follows an unconditional direct branch -- gcc enters loops
    // with a jump into the middle, and the blend's vector consumer sits at
    // the target.
    static const uint8_t blend_past_jmp[] = {
        0xF3, 0x0F, 0x10, 0xC2,  // movss xmm0, xmm2
        0xEB, 0x02,              // jmp +2
        0x90, 0x90,              // nop; nop (jumped over)
        0x0F, 0x11, 0x00,        // movups xmmword ptr [rax], xmm0
    };
    ASSERT_FINDINGS(blend_past_jmp, "merging scalar move", 0);

    // An indirect branch cannot be followed: the finding stands.
    static const uint8_t escape_indirect[] = {
        0xF2, 0x0F, 0x10, 0xCA,  // movsd xmm1, xmm2
        0xFF, 0xE0,              // jmp rax
    };
    ASSERT_FINDINGS(escape_indirect, "merging scalar move", 1);
}

// Gated equivalence rewrite: an 8- or 16-bit register-destination MOV
// merges into its parent, and MOVZX performs the same load or copy writing
// the register whole -- flagged only when the bits at and above the written
// width are provably dead. See narrow_move_merge.
static void check_narrow_move_merge_test(void)
{
    // Byte load consumed at byte width, register then rewritten whole: the
    // self-XOR counts as the kill it is, not the read XED records.
    static const uint8_t byte_load_dead[] = {
        0x8A, 0x06,        // mov al, byte ptr [rsi]
        0x88, 0x07,        // mov byte ptr [rdi], al
        0x31, 0xC0,        // xor eax, eax
        0xC3,              // ret
    };
    ASSERT_FINDINGS(byte_load_dead, "merging narrow move", 1);

    // A wide read downstream: the merge is wanted (a value built by bytes).
    static const uint8_t wide_read[] = {
        0x8A, 0x06,        // mov al, byte ptr [rsi]
        0x89, 0x07,        // mov dword ptr [rdi], eax
    };
    ASSERT_FINDINGS(wide_read, "merging narrow move", 0);

    // A high-byte read observes bits 15:8, inside a byte write's span.
    static const uint8_t high8_read[] = {
        0x8A, 0x06,        // mov al, byte ptr [rsi]
        0x88, 0x27,        // mov byte ptr [rdi], ah
        0x31, 0xC0,        // xor eax, eax
        0xC3,              // ret
    };
    ASSERT_FINDINGS(high8_read, "merging narrow move", 0);

    // ...but outside a word write's: the word finding survives it.
    static const uint8_t word_high8_read[] = {
        0x66, 0x8B, 0x06,  // mov ax, word ptr [rsi]
        0x88, 0x27,        // mov byte ptr [rdi], ah
        0x31, 0xC0,        // xor eax, eax
        0xC3,              // ret
    };
    ASSERT_FINDINGS(word_high8_read, "merging narrow move", 1);

    // An escape: the merged register may carry real upper bits out (a
    // struct returned in RAX with one byte freshly stored). Conservative
    // silence, unlike the vector sibling.
    static const uint8_t escape_ret[] = {
        0x8A, 0x06,        // mov al, byte ptr [rsi]
        0xC3,              // ret
    };
    ASSERT_FINDINGS(escape_ret, "merging narrow move", 0);

    // A data XOR reads the old value: only the self form is a kill.
    static const uint8_t xor_other_reg[] = {
        0x8A, 0x06,        // mov al, byte ptr [rsi]
        0x31, 0xD8,        // xor eax, ebx
        0xC3,              // ret
    };
    ASSERT_FINDINGS(xor_other_reg, "merging narrow move", 0);

    // Word load: the movzx spelling is even size-neutral (66 8B vs 0F B7),
    // and a 16-bit read of the written register observes nothing above it.
    static const uint8_t word_load_dead[] = {
        0x66, 0x8B, 0x06,  // mov ax, word ptr [rsi]
        0x66, 0x89, 0x07,  // mov word ptr [rdi], ax
        0x31, 0xC0,        // xor eax, eax
        0xC3,              // ret
    };
    ASSERT_FINDINGS(word_load_dead, "merging narrow move", 1);

    // Register copy form, REX registers included.
    static const uint8_t reg_copy_dead[] = {
        0x88, 0xD8,        // mov al, bl
        0x88, 0x07,        // mov byte ptr [rdi], al
        0x31, 0xC0,        // xor eax, eax
        0xC3,              // ret
    };
    ASSERT_FINDINGS(reg_copy_dead, "merging narrow move", 1);

    static const uint8_t rex_load_dead[] = {
        0x44, 0x8A, 0x06,  // mov r8b, byte ptr [rsi]
        0x44, 0x88, 0x07,  // mov byte ptr [rdi], r8b
        0x45, 0x31, 0xC0,  // xor r8d, r8d
        0xC3,              // ret
    };
    ASSERT_FINDINGS(rex_load_dead, "merging narrow move", 1);

    // An immediate source is a different trade: never flagged.
    static const uint8_t imm_src[] = {
        0xB0, 0x05,        // mov al, 5
        0x88, 0x07,        // mov byte ptr [rdi], al
        0x31, 0xC0,        // xor eax, eax
        0xC3,              // ret
    };
    ASSERT_FINDINGS(imm_src, "merging narrow move", 0);

    // A high-byte destination has no extending spelling.
    static const uint8_t high8_dest[] = {
        0x8A, 0x26,        // mov ah, byte ptr [rsi]
        0x88, 0x27,        // mov byte ptr [rdi], ah
        0x31, 0xC0,        // xor eax, eax
        0xC3,              // ret
    };
    ASSERT_FINDINGS(high8_dest, "merging narrow move", 0);

    // MOVZX cannot take a segment source: never flagged.
    static const uint8_t seg_source[] = {
        0x66, 0x8C, 0xD8,  // mov ax, ds
        0x31, 0xC0,        // xor eax, eax
        0xC3,              // ret
    };
    ASSERT_FINDINGS(seg_source, "merging narrow move", 0);

    // The load may address through its own parent -- the extending load
    // reads memory at the same point with the same base.
    static const uint8_t self_base[] = {
        0x8A, 0x00,        // mov al, byte ptr [rax]
        0x88, 0x03,        // mov byte ptr [rbx], al
        0x31, 0xC0,        // xor eax, eax
        0xC3,              // ret
    };
    ASSERT_FINDINGS(self_base, "merging narrow move", 1);

    // A downstream address built on the parent observes all its bits.
    static const uint8_t base_read[] = {
        0x8A, 0x06,        // mov al, byte ptr [rsi]
        0x8B, 0x18,        // mov ebx, dword ptr [rax]
        0xC3,              // ret
    };
    ASSERT_FINDINGS(base_read, "merging narrow move", 0);

    // The load+extend pair is load foldable into extend's finding alone.
    static const uint8_t folded[] = {
        0x8A, 0x06,        // mov al, byte ptr [rsi]
        0x0F, 0xB6, 0xC0,  // movzx eax, al
    };
    int total;
    assert(count_findings(folded, sizeof(folded),
                          "load foldable into extend", &total, 0) == 1);
    assert(count_findings(folded, sizeof(folded),
                          "merging narrow move", &total, 0) == 0);
    assert(total == 1);

    // A self-copy is redundant MOV reg, reg, not a merge finding.
    static const uint8_t self_copy[] = {
        0x88, 0xC0,        // mov al, al
        0xC3,              // ret
    };
    assert(count_findings(self_copy, sizeof(self_copy),
                          "redundant MOV reg, reg", &total, 0) == 1);
    assert(count_findings(self_copy, sizeof(self_copy),
                          "merging narrow move", &total, 0) == 0);
    assert(total == 1);
}

// not rX ; and rX, rY folds to andn rX, rX, rY -- but only when the caller
// declared BMI1 available (-m bmi1), and only when PF, which AND defines and
// ANDN leaves undefined, is dead. See not_and_foldable_to_andn.
static void check_missing_andn_test(void)
{
    // Canonical fold, 32- and 64-bit. Flags die at the RET.
    static const uint8_t fold32[] = {
        0xF7, 0xD0,        // not eax
        0x21, 0xC8,        // and eax, ecx
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(fold32, "missing ANDN", 1, X86LINT_EXT_BMI1);
    // Without the opt-in the check must not run; nor under bmi2 alone (the
    // bits are independent, matching their CPUID feature flags).
    ASSERT_FINDINGS(fold32, "missing ANDN", 0);
    ASSERT_FINDINGS_EXT(fold32, "missing ANDN", 0, X86LINT_EXT_BMI2);

    static const uint8_t fold64[] = {
        0x48, 0xF7, 0xD0,  // not rax
        0x48, 0x21, 0xC8,  // and rax, rcx
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(fold64, "missing ANDN", 1, X86LINT_EXT_BMI1);

    // Same-register source: andn eax, eax, eax computes ~x & x = 0 where the
    // pair computes ~x. The bytes still total one finding under bmi1 --
    // check_or_and_self flags the and eax, eax (its upper-32 suppression is
    // overridden by the zx-escape: prev `not eax` is a 32-bit kill) -- so
    // assert the two categories directly instead of via ASSERT_FINDINGS_EXT.
    static const uint8_t same_src[] = {
        0xF7, 0xD0,        // not eax
        0x21, 0xC0,        // and eax, eax
        0xC3,              // ret
    };
    int total;
    assert(count_findings(same_src, sizeof(same_src), "missing ANDN", &total,
                          X86LINT_EXT_BMI1) == 0);
    assert(total == 1);
    assert(count_findings(same_src, sizeof(same_src),
                          "suboptimal OR/AND reg, reg", &total,
                          X86LINT_EXT_BMI1) == 1);

    // Immediate mask: ANDN has no immediate form. 0x0f is inert for the
    // immediate-family checks (not -1/0/0xff, not a single high bit, imm8
    // already).
    static const uint8_t imm_mask[] = {
        0xF7, 0xD0,        // not eax
        0x83, 0xE0, 0x0F,  // and eax, 0xf
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(imm_mask, "missing ANDN", 0, X86LINT_EXT_BMI1);

    // AND into a different destination: the original leaves ~ecx behind,
    // which the fold would not compute.
    static const uint8_t cross_dest[] = {
        0xF7, 0xD1,        // not ecx
        0x21, 0xCB,        // and ebx, ecx
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(cross_dest, "missing ANDN", 0, X86LINT_EXT_BMI1);

    // Width mismatch: the exact-register match rejects EAX vs RAX.
    static const uint8_t width_mix[] = {
        0xF7, 0xD0,        // not eax
        0x48, 0x21, 0xC8,  // and rax, rcx
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(width_mix, "missing ANDN", 0, X86LINT_EXT_BMI1);

    // 16-bit pair: ANDN is 32/64-bit only.
    static const uint8_t pair16[] = {
        0x66, 0xF7, 0xD0,  // not ax
        0x66, 0x21, 0xC8,  // and ax, cx
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(pair16, "missing ANDN", 0, X86LINT_EXT_BMI1);

    // Memory operands on either side. The tail case keeps the register match
    // (XED reports the reg source of `and [mem], reg` in the REG0 slot) so
    // the memory-operand rejection itself is what stops it.
    static const uint8_t mem_head[] = {
        0xF7, 0x16,        // not dword ptr [rsi]
        0x21, 0xC8,        // and eax, ecx
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(mem_head, "missing ANDN", 0, X86LINT_EXT_BMI1);
    static const uint8_t mem_tail[] = {
        0xF7, 0xD1,        // not ecx
        0x21, 0x08,        // and dword ptr [rax], ecx
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(mem_tail, "missing ANDN", 0, X86LINT_EXT_BMI1);

    // PF read downstream: AND defines it, ANDN would not. (The liveness walk
    // stops at any conditional branch, so the jp suppresses as a branch, not
    // by matching its PF read -- either way, conservative.)
    static const uint8_t pf_live[] = {
        0xF7, 0xD0,        // not eax
        0x21, 0xC8,        // and eax, ecx
        0x7A, 0x00,        // jp +0
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(pf_live, "missing ANDN", 0, X86LINT_EXT_BMI1);

    // A direct branch onto the AND reaches it without the NOT.
    static const uint8_t edge_on_and[] = {
        0xEB, 0x02,        // jmp +2 (to the and)
        0xF7, 0xD0,        // not eax
        0x21, 0xC8,        // and eax, ecx
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(edge_on_and, "missing ANDN", 0, X86LINT_EXT_BMI1);
}

// lea rY, [rX-1] ; and rY, rX folds to blsr rY, rX (clear lowest set bit) --
// but only when the caller declared BMI1 available (-m bmi1), and only when
// CF (AND clears it, BLSR sets it to source==0) and PF (defined vs
// undefined) are dead. See lea_and_foldable_to_blsr.
static void check_missing_blsr_test(void)
{
    // Canonical fold, 32- and 64-bit. Flags die at the RET.
    static const uint8_t fold32[] = {
        0x8D, 0x50, 0xFF,        // lea edx, [rax-1]
        0x21, 0xC2,              // and edx, eax
        0xC3,                    // ret
    };
    ASSERT_FINDINGS_EXT(fold32, "missing BLSR", 1, X86LINT_EXT_BMI1);
    ASSERT_FINDINGS(fold32, "missing BLSR", 0);

    // The 64-bit LEA's REX.W is load-bearing here in two ways: the fold is
    // 64-bit, and check_oversized_lea_width's predicate does match this LEA
    // -- the dispatcher suppresses that finding only because the AND reads
    // RDX, keeping the upper-32 bits live.
    static const uint8_t fold64[] = {
        0x48, 0x8D, 0x50, 0xFF,  // lea rdx, [rax-1]
        0x48, 0x21, 0xC2,        // and rdx, rax
        0xC3,                    // ret
    };
    ASSERT_FINDINGS_EXT(fold64, "missing BLSR", 1, X86LINT_EXT_BMI1);

    // Any other displacement is not a decrement.
    static const uint8_t disp2[] = {
        0x8D, 0x50, 0xFE,        // lea edx, [rax-2]
        0x21, 0xC2,              // and edx, eax
        0xC3,                    // ret
    };
    ASSERT_FINDINGS_EXT(disp2, "missing BLSR", 0, X86LINT_EXT_BMI1);

    // An index register makes the address more than src-1.
    static const uint8_t indexed[] = {
        0x8D, 0x54, 0x08, 0xFF,  // lea edx, [rax+rcx*1-1]
        0x21, 0xC2,              // and edx, eax
        0xC3,                    // ret
    };
    ASSERT_FINDINGS_EXT(indexed, "missing BLSR", 0, X86LINT_EXT_BMI1);

    // The AND must mask with the decremented register.
    static const uint8_t wrong_src[] = {
        0x8D, 0x50, 0xFF,        // lea edx, [rax-1]
        0x21, 0xCA,              // and edx, ecx
        0xC3,                    // ret
    };
    ASSERT_FINDINGS_EXT(wrong_src, "missing BLSR", 0, X86LINT_EXT_BMI1);

    // Swapped AND: and eax, edx computes the same value into eax, but the
    // original also leaves rax-1 in edx, which blsr eax, eax would not.
    static const uint8_t swapped[] = {
        0x8D, 0x50, 0xFF,        // lea edx, [rax-1]
        0x21, 0xD0,              // and eax, edx
        0xC3,                    // ret
    };
    ASSERT_FINDINGS_EXT(swapped, "missing BLSR", 0, X86LINT_EXT_BMI1);

    // CF read downstream: AND clears it, BLSR sets it to (source == 0).
    static const uint8_t cf_live[] = {
        0x8D, 0x50, 0xFF,        // lea edx, [rax-1]
        0x21, 0xC2,              // and edx, eax
        0x72, 0x00,              // jb +0
        0xC3,                    // ret
    };
    ASSERT_FINDINGS_EXT(cf_live, "missing BLSR", 0, X86LINT_EXT_BMI1);

    // RIP-relative is not a register decrement.
    static const uint8_t rip_base[] = {
        0x8D, 0x15, 0xFF, 0xFF, 0xFF, 0xFF,  // lea edx, [rip-1]
        0x21, 0xC2,                          // and edx, eax
        0xC3,                                // ret
    };
    ASSERT_FINDINGS_EXT(rip_base, "missing BLSR", 0, X86LINT_EXT_BMI1);

    // A 67-prefixed 32-bit base is rejected outright: under a 64-bit
    // destination its zero-extended decrement diverges from BLSR's.
    static const uint8_t base32[] = {
        0x67, 0x8D, 0x50, 0xFF,  // lea edx, [eax-1]
        0x21, 0xC2,              // and edx, eax
        0xC3,                    // ret
    };
    ASSERT_FINDINGS_EXT(base32, "missing BLSR", 0, X86LINT_EXT_BMI1);
}

// lea rY, [rX-1] ; xor rY, rX folds to blsmsk rY, rX (mask through the
// lowest set bit) -- BLSR's idiom with the AND swapped for an XOR, under
// the same gates: -m bmi1, and CF (XOR clears it, BLSMSK sets it to
// source==0) and PF (defined vs undefined) dead. ZF needs no gate: XOR
// computes it from the result and BLSMSK hardwires 0, but src ^ (src-1) is
// never zero. See lea_xor_foldable_to_blsmsk.
static void check_missing_blsmsk_test(void)
{
    // Canonical fold, 32- and 64-bit. Flags die at the RET.
    static const uint8_t fold32[] = {
        0x8D, 0x50, 0xFF,        // lea edx, [rax-1]
        0x31, 0xC2,              // xor edx, eax
        0xC3,                    // ret
    };
    ASSERT_FINDINGS_EXT(fold32, "missing BLSMSK", 1, X86LINT_EXT_BMI1);
    ASSERT_FINDINGS(fold32, "missing BLSMSK", 0);

    // As in the BLSR fold64: the LEA's REX.W is load-bearing, and
    // check_oversized_lea_width stays silent only because the XOR reads RDX,
    // keeping the upper-32 bits live.
    static const uint8_t fold64[] = {
        0x48, 0x8D, 0x50, 0xFF,  // lea rdx, [rax-1]
        0x48, 0x31, 0xC2,        // xor rdx, rax
        0xC3,                    // ret
    };
    ASSERT_FINDINGS_EXT(fold64, "missing BLSMSK", 1, X86LINT_EXT_BMI1);

    // Any other displacement is not a decrement.
    static const uint8_t disp2[] = {
        0x8D, 0x50, 0xFE,        // lea edx, [rax-2]
        0x31, 0xC2,              // xor edx, eax
        0xC3,                    // ret
    };
    ASSERT_FINDINGS_EXT(disp2, "missing BLSMSK", 0, X86LINT_EXT_BMI1);

    // An index register makes the address more than src-1.
    static const uint8_t indexed[] = {
        0x8D, 0x54, 0x08, 0xFF,  // lea edx, [rax+rcx*1-1]
        0x31, 0xC2,              // xor edx, eax
        0xC3,                    // ret
    };
    ASSERT_FINDINGS_EXT(indexed, "missing BLSMSK", 0, X86LINT_EXT_BMI1);

    // The XOR must difference against the decremented register.
    static const uint8_t wrong_src[] = {
        0x8D, 0x50, 0xFF,        // lea edx, [rax-1]
        0x31, 0xCA,              // xor edx, ecx
        0xC3,                    // ret
    };
    ASSERT_FINDINGS_EXT(wrong_src, "missing BLSMSK", 0, X86LINT_EXT_BMI1);

    // Swapped XOR: xor eax, edx computes the same value into eax, but the
    // original also leaves rax-1 in edx, which blsmsk eax, eax would not.
    static const uint8_t swapped[] = {
        0x8D, 0x50, 0xFF,        // lea edx, [rax-1]
        0x31, 0xD0,              // xor eax, edx
        0xC3,                    // ret
    };
    ASSERT_FINDINGS_EXT(swapped, "missing BLSMSK", 0, X86LINT_EXT_BMI1);

    // CF read downstream: XOR clears it, BLSMSK sets it to (source == 0).
    static const uint8_t cf_live[] = {
        0x8D, 0x50, 0xFF,        // lea edx, [rax-1]
        0x31, 0xC2,              // xor edx, eax
        0x72, 0x00,              // jb +0
        0xC3,                    // ret
    };
    ASSERT_FINDINGS_EXT(cf_live, "missing BLSMSK", 0, X86LINT_EXT_BMI1);

    // RIP-relative is not a register decrement.
    static const uint8_t rip_base[] = {
        0x8D, 0x15, 0xFF, 0xFF, 0xFF, 0xFF,  // lea edx, [rip-1]
        0x31, 0xC2,                          // xor edx, eax
        0xC3,                                // ret
    };
    ASSERT_FINDINGS_EXT(rip_base, "missing BLSMSK", 0, X86LINT_EXT_BMI1);

    // A 67-prefixed 32-bit base is rejected outright: under a 64-bit
    // destination its zero-extended decrement diverges from BLSMSK's.
    static const uint8_t base32[] = {
        0x67, 0x8D, 0x50, 0xFF,  // lea edx, [eax-1]
        0x31, 0xC2,              // xor edx, eax
        0xC3,                    // ret
    };
    ASSERT_FINDINGS_EXT(base32, "missing BLSMSK", 0, X86LINT_EXT_BMI1);
}

// mov rY, rX ; neg rY ; and rY, rX folds to blsi rY, rX (isolate the lowest
// set bit), collapsing the whole triple, copy included -- but only when the
// caller declared BMI1 available (-m bmi1), and only when CF (AND clears
// it, BLSI sets it to source != 0) and PF (defined vs undefined) are dead.
// See mov_neg_and_foldable_to_blsi.
static void check_missing_blsi_test(void)
{
    // Canonical fold, 32- and 64-bit. Flags die at the RET.
    static const uint8_t fold32[] = {
        0x89, 0xF9,        // mov ecx, edi
        0xF7, 0xD9,        // neg ecx
        0x21, 0xF9,        // and ecx, edi
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(fold32, "missing BLSI", 1, X86LINT_EXT_BMI1);
    // Without the opt-in the check must not run; nor under bmi2 alone (the
    // bits are independent, matching their CPUID feature flags).
    ASSERT_FINDINGS(fold32, "missing BLSI", 0);
    ASSERT_FINDINGS_EXT(fold32, "missing BLSI", 0, X86LINT_EXT_BMI2);

    static const uint8_t fold64[] = {
        0x48, 0x89, 0xF8,  // mov rax, rdi
        0x48, 0xF7, 0xD8,  // neg rax
        0x48, 0x21, 0xF8,  // and rax, rdi
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(fold64, "missing BLSI", 1, X86LINT_EXT_BMI1);

    // A copy aliasing its source: the NEG destroys the original, so the AND
    // computes -x & -x = -x, not x & -x. The bytes still total two findings
    // under bmi1 -- check_mov_self flags the mov ecx, ecx and
    // check_or_and_self the and ecx, ecx (each upper-32 suppression is
    // overridden by the zx-escape: the neighboring 32-bit write is a kill)
    // -- so assert the categories directly instead of via
    // ASSERT_FINDINGS_EXT.
    static const uint8_t aliased[] = {
        0x89, 0xC9,        // mov ecx, ecx
        0xF7, 0xD9,        // neg ecx
        0x21, 0xC9,        // and ecx, ecx
        0xC3,              // ret
    };
    int total;
    assert(count_findings(aliased, sizeof(aliased), "missing BLSI", &total,
                          X86LINT_EXT_BMI1) == 0);
    assert(total == 2);
    assert(count_findings(aliased, sizeof(aliased),
                          "redundant MOV reg, reg", &total,
                          X86LINT_EXT_BMI1) == 1);
    assert(count_findings(aliased, sizeof(aliased),
                          "suboptimal OR/AND reg, reg", &total,
                          X86LINT_EXT_BMI1) == 1);

    // The NEG must negate the copy.
    static const uint8_t wrong_neg[] = {
        0x89, 0xF9,        // mov ecx, edi
        0xF7, 0xDA,        // neg edx
        0x21, 0xF9,        // and ecx, edi
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(wrong_neg, "missing BLSI", 0, X86LINT_EXT_BMI1);

    // Width mismatch: the exact-register match rejects ECX vs RCX.
    static const uint8_t width_mix[] = {
        0x89, 0xF9,        // mov ecx, edi
        0x48, 0xF7, 0xD9,  // neg rcx
        0x21, 0xF9,        // and ecx, edi
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(width_mix, "missing BLSI", 0, X86LINT_EXT_BMI1);

    // AND into the source register: the original leaves -x behind in the
    // copy, which the fold would not compute.
    static const uint8_t and_into_src[] = {
        0x89, 0xF9,        // mov ecx, edi
        0xF7, 0xD9,        // neg ecx
        0x21, 0xCF,        // and edi, ecx
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(and_into_src, "missing BLSI", 0, X86LINT_EXT_BMI1);

    // The AND must mask with the preserved source.
    static const uint8_t wrong_and_src[] = {
        0x89, 0xF9,        // mov ecx, edi
        0xF7, 0xD9,        // neg ecx
        0x21, 0xD9,        // and ecx, ebx
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(wrong_and_src, "missing BLSI", 0, X86LINT_EXT_BMI1);

    // Immediate mask: not the idiom. 0x0f is inert for the immediate-family
    // checks (not -1/0/0xff, not a single high bit, imm8 already).
    static const uint8_t imm_and[] = {
        0x89, 0xF9,        // mov ecx, edi
        0xF7, 0xD9,        // neg ecx
        0x83, 0xE1, 0x0F,  // and ecx, 0xf
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(imm_and, "missing BLSI", 0, X86LINT_EXT_BMI1);

    // Memory operands. The tail case keeps the register match (XED reports
    // the reg source of `and [mem], reg` in the REG0 slot) so the
    // memory-operand rejection itself is what stops it.
    static const uint8_t mem_head[] = {
        0x8B, 0x0F,        // mov ecx, [rdi]
        0xF7, 0xD9,        // neg ecx
        0x21, 0xF9,        // and ecx, edi
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(mem_head, "missing BLSI", 0, X86LINT_EXT_BMI1);
    static const uint8_t mem_tail[] = {
        0x89, 0xF9,        // mov ecx, edi
        0xF7, 0xD9,        // neg ecx
        0x21, 0x08,        // and dword ptr [rax], ecx
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(mem_tail, "missing BLSI", 0, X86LINT_EXT_BMI1);

    // 16-bit triple: BLSI is 32/64-bit only.
    static const uint8_t triple16[] = {
        0x66, 0x89, 0xF9,  // mov cx, di
        0x66, 0xF7, 0xD9,  // neg cx
        0x66, 0x21, 0xF9,  // and cx, di
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(triple16, "missing BLSI", 0, X86LINT_EXT_BMI1);

    // CF read downstream: AND clears it, BLSI sets it to (source != 0).
    static const uint8_t cf_live[] = {
        0x89, 0xF9,        // mov ecx, edi
        0xF7, 0xD9,        // neg ecx
        0x21, 0xF9,        // and ecx, edi
        0x72, 0x00,        // jb +0
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(cf_live, "missing BLSI", 0, X86LINT_EXT_BMI1);

    // A direct branch onto the NEG reaches a partial idiom.
    static const uint8_t edge_on_neg[] = {
        0xEB, 0x02,        // jmp +2 (to the neg)
        0x89, 0xF9,        // mov ecx, edi
        0xF7, 0xD9,        // neg ecx
        0x21, 0xF9,        // and ecx, edi
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(edge_on_neg, "missing BLSI", 0, X86LINT_EXT_BMI1);
}

// shl/shr/sar reg, cl could be the flagless BMI2 shlx/shrx/sarx -- but only
// when the caller declared BMI2 available (-m bmi2), only when every
// arithmetic flag is dead, and (32-bit forms) only when the destination's
// upper 32 bits are dead. See check_missing_shlx.
static void check_missing_shlx_test(void)
{
    // The predicate itself is extension-agnostic; the dispatcher applies the
    // -m gate and the liveness gates.
    CHECK_BYTES_ASM(!check_missing_shlx, "shl eax, cl", 0xD3, 0xE0);
    CHECK_BYTES_ASM(!check_missing_shlx, "shr eax, cl", 0xD3, 0xE8);
    CHECK_BYTES_ASM(!check_missing_shlx, "sar rax, cl", 0x48, 0xD3, 0xF8);
    // Immediate and by-1 counts are fixed at encode time; no BMI2 form is
    // needed or clearer. (shl reg, 1 is check_shl_one's finding, so only the
    // predicate is exercised here.)
    CHECK_BYTES_ASM(check_missing_shlx, "shl eax, 0x5", 0xC1, 0xE0, 0x05);
    CHECK_BYTES_ASM(check_missing_shlx, "shl eax, 0x1", 0xD1, 0xE0);
    // No 8/16-bit BMI2 shifts exist, and none takes a memory destination.
    CHECK_BYTES_ASM(check_missing_shlx, "shl al, cl", 0xD2, 0xE0);
    CHECK_BYTES_ASM(check_missing_shlx, "shl ax, cl", 0x66, 0xD3, 0xE0);
    CHECK_BYTES_ASM(check_missing_shlx, "shl dword ptr [rsi], cl", 0xD3, 0x26);

    // Dispatcher wiring. The 32-bit positive needs its upper-32 bits killed
    // downstream (mov eax, ecx) -- at a RET they are conservatively live.
    static const uint8_t shift32[] = {
        0xD3, 0xE0,        // shl eax, cl
        0x89, 0xC8,        // mov eax, ecx (kills EAX: upper-32 dead)
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(shift32, "missing SHLX/SHRX/SARX", 1, X86LINT_EXT_BMI2);
    // Without the opt-in the check must not run; nor under bmi1 alone.
    ASSERT_FINDINGS(shift32, "missing SHLX/SHRX/SARX", 0);
    ASSERT_FINDINGS_EXT(shift32, "missing SHLX/SHRX/SARX", 0, X86LINT_EXT_BMI1);

    // 64-bit forms carry no upper-32 concern: at count 0 the rewrite writes
    // back the same value, which nothing can observe.
    static const uint8_t shift64[] = {
        0x48, 0xD3, 0xF8,  // sar rax, cl
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(shift64, "missing SHLX/SHRX/SARX", 1, X86LINT_EXT_BMI2);

    // The upper-32 gate alone: per the SDM a count-0 shift may leave EAX's
    // upper bits unwritten where shlx zero-extends, and at a RET they are
    // conservatively live.
    static const uint8_t upper_live[] = {
        0xD3, 0xE0,        // shl eax, cl
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(upper_live, "missing SHLX/SHRX/SARX", 0,
                        X86LINT_EXT_BMI2);

    // The flag gate alone (64-bit, so no upper-32 gate): the legacy shift
    // writes CF for a nonzero count, shlx never would.
    static const uint8_t cf_live[] = {
        0x48, 0xD3, 0xE0,  // shl rax, cl
        0x72, 0x00,        // jb +0
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(cf_live, "missing SHLX/SHRX/SARX", 0, X86LINT_EXT_BMI2);
}

// mov rX, [mem] ; bswap rX folds to movbe rX, [mem] -- but only when the
// caller declared MOVBE available (-m movbe). No liveness gates: none of the
// three instructions writes a flag, and only the destination register is
// written, with the identical byte-reversed value. See
// mov_bswap_foldable_to_movbe.
static void check_missing_movbe_test(void)
{
    // Canonical fold, 32- and 64-bit.
    static const uint8_t fold32[] = {
        0x8B, 0x06,        // mov eax, [rsi]
        0x0F, 0xC8,        // bswap eax
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(fold32, "missing MOVBE", 1, X86LINT_EXT_MOVBE);
    // Without the opt-in the check must not run; nor under bmi1 alone (the
    // bits are independent, matching their CPUID feature flags).
    ASSERT_FINDINGS(fold32, "missing MOVBE", 0);
    ASSERT_FINDINGS_EXT(fold32, "missing MOVBE", 0, X86LINT_EXT_BMI1);

    static const uint8_t fold64[] = {
        0x48, 0x8B, 0x06,  // mov rax, [rsi]
        0x48, 0x0F, 0xC8,  // bswap rax
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(fold64, "missing MOVBE", 1, X86LINT_EXT_MOVBE);

    // An address using the destination reads the pre-load value in both
    // forms, so the fold stands.
    static const uint8_t base_is_dest[] = {
        0x48, 0x8B, 0x00,  // mov rax, [rax]
        0x48, 0x0F, 0xC8,  // bswap rax
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(base_is_dest, "missing MOVBE", 1, X86LINT_EXT_MOVBE);

    // The swap must hit the loaded register.
    static const uint8_t wrong_reg[] = {
        0x8B, 0x06,        // mov eax, [rsi]
        0x0F, 0xC9,        // bswap ecx
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(wrong_reg, "missing MOVBE", 0, X86LINT_EXT_MOVBE);

    // Width mismatch: the exact-register match rejects EAX vs RAX.
    static const uint8_t width_mix[] = {
        0x8B, 0x06,        // mov eax, [rsi]
        0x48, 0x0F, 0xC8,  // bswap rax
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(width_mix, "missing MOVBE", 0, X86LINT_EXT_MOVBE);

    // The store direction is never flagged: movbe [rsi], eax would leave
    // EAX un-swapped where the original leaves it swapped.
    static const uint8_t store_dir[] = {
        0x89, 0x06,        // mov [rsi], eax
        0x0F, 0xC8,        // bswap eax
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(store_dir, "missing MOVBE", 0, X86LINT_EXT_MOVBE);

    // A register-to-register mov has no memory operand to fold.
    static const uint8_t reg_reg[] = {
        0x89, 0xC8,        // mov eax, ecx
        0x0F, 0xC8,        // bswap eax
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(reg_reg, "missing MOVBE", 0, X86LINT_EXT_MOVBE);

    // 16-bit pair: MOVBE r16 exists but BSWAP of a 16-bit register is
    // SDM-undefined, so the narrow pair is never matched (width gate).
    static const uint8_t pair16[] = {
        0x66, 0x8B, 0x06,  // mov ax, [rsi]
        0x66, 0x0F, 0xC8,  // bswap ax
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(pair16, "missing MOVBE", 0, X86LINT_EXT_MOVBE);

    // The A1 moffs form loads through a 64-bit absolute address, which
    // MOVBE (modrm-only) cannot encode.
    static const uint8_t moffs[] = {
        0xA1, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                           // mov eax, [0x8877665544332211]
        0x0F, 0xC8,        // bswap eax
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(moffs, "missing MOVBE", 0, X86LINT_EXT_MOVBE);

    // A direct branch onto the BSWAP reaches it without the load.
    static const uint8_t edge_on_bswap[] = {
        0xEB, 0x02,        // jmp +2 (to the bswap)
        0x8B, 0x06,        // mov eax, [rsi]
        0x0F, 0xC8,        // bswap eax
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(edge_on_bswap, "missing MOVBE", 0, X86LINT_EXT_MOVBE);
}

// mov rY, rX ; <destructive ALU op> rY, src folds to one EVEX
// new-data-destination op rY, rX, src -- but only when the caller declared
// APX available (-m apx). No liveness gates: each matched op's NDD form
// sets every flag exactly as its legacy twin, and only the destination is
// written, with the identical value. See mov_op_foldable_to_apx_ndd.
static void check_missing_apx_ndd_test(void)
{
    // Canonical fold, 32- and 64-bit, register source.
    static const uint8_t fold32[] = {
        0x89, 0xF8,        // mov eax, edi
        0x29, 0xF0,        // sub eax, esi
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(fold32, "missing APX NDD", 1, X86LINT_EXT_APX);
    // Without the opt-in the check must not run; nor under the other
    // extension bits (independent, matching their CPUID feature flags).
    ASSERT_FINDINGS(fold32, "missing APX NDD", 0);
    ASSERT_FINDINGS_EXT(fold32, "missing APX NDD", 0,
                        X86LINT_EXT_BMI1 | X86LINT_EXT_BMI2 |
                            X86LINT_EXT_MOVBE);

    static const uint8_t fold64[] = {
        0x4C, 0x89, 0xF8,  // mov rax, r15
        0x4C, 0x29, 0xF0,  // sub rax, r14
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(fold64, "missing APX NDD", 1, X86LINT_EXT_APX);

    // The plain-binary path with a register source (SUB above takes its
    // own case): and ecx, ebx reads neither the copy nor its source.
    static const uint8_t and_reg[] = {
        0x89, 0xF9,        // mov ecx, edi
        0x21, 0xD9,        // and ecx, ebx
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(and_reg, "missing APX NDD", 1, X86LINT_EXT_APX);

    // Immediate sources ride the NDD forms unchanged. and rdi, -0x1000 is
    // glibc's page-mask idiom.
    static const uint8_t and_imm[] = {
        0x48, 0x89, 0xC7,                          // mov rdi, rax
        0x48, 0x81, 0xE7, 0x00, 0xF0, 0xFF, 0xFF,  // and rdi, -0x1000
        0xC3,                                      // ret
    };
    ASSERT_FINDINGS_EXT(and_imm, "missing APX NDD", 1, X86LINT_EXT_APX);

    // The accumulator short forms (or eax, imm32: 0D) are the same iclass.
    static const uint8_t or_accum[] = {
        0x89, 0xF0,                    // mov eax, esi
        0x0D, 0x00, 0x00, 0x20, 0x00,  // or eax, 0x200000
        0xC3,                          // ret
    };
    ASSERT_FINDINGS_EXT(or_accum, "missing APX NDD", 1, X86LINT_EXT_APX);

    // ADC reads CF, but the mov between the flag producer and the adc
    // writes no flag, so the NDD form reads the same CF.
    static const uint8_t adc_imm[] = {
        0x4D, 0x89, 0xC8,        // mov r8, r9
        0x49, 0x83, 0xD0, 0x05,  // adc r8, 5
        0xC3,                    // ret
    };
    ASSERT_FINDINGS_EXT(adc_imm, "missing APX NDD", 1, X86LINT_EXT_APX);

    // Two-operand IMUL (0F AF) is a plain destructive consumer.
    static const uint8_t imul_two[] = {
        0x48, 0x89, 0xD8,        // mov rax, rbx
        0x48, 0x0F, 0xAF, 0xC1,  // imul rax, rcx
        0xC3,                    // ret
    };
    ASSERT_FINDINGS_EXT(imul_two, "missing APX NDD", 1, X86LINT_EXT_APX);
    // The one-operand widening IMUL also parks its operand in the REG0
    // slot, but consumes rax, not the copy: the iform check stops it.
    static const uint8_t imul_one[] = {
        0x48, 0x89, 0xF3,  // mov rbx, rsi
        0x48, 0xF7, 0xEB,  // imul rbx
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(imul_one, "missing APX NDD", 0, X86LINT_EXT_APX);

    // Immediate shifts and rotates with a nonzero masked count.
    static const uint8_t shl_imm[] = {
        0x48, 0x89, 0xC1,        // mov rcx, rax
        0x48, 0xC1, 0xE1, 0x04,  // shl rcx, 4
        0xC3,                    // ret
    };
    ASSERT_FINDINGS_EXT(shl_imm, "missing APX NDD", 1, X86LINT_EXT_APX);
    static const uint8_t ror_imm[] = {
        0x4D, 0x89, 0xF2,        // mov r10, r14
        0x49, 0xC1, 0xCA, 0x11,  // ror r10, 17
        0xC3,                    // ret
    };
    ASSERT_FINDINGS_EXT(ror_imm, "missing APX NDD", 1, X86LINT_EXT_APX);

    // The D1 by-one form decodes as an immediate count of 1 and qualifies.
    // The shift itself is also check_shl_one's finding (add rdx, rdx), so
    // the pair totals two -- assert both categories directly.
    static const uint8_t shl_one[] = {
        0x48, 0x89, 0xCA,  // mov rdx, rcx
        0x48, 0xD1, 0xE2,  // shl rdx (by one)
        0xC3,              // ret
    };
    int total;
    assert(count_findings(shl_one, sizeof(shl_one), "missing APX NDD",
                          &total, X86LINT_EXT_APX) == 1);
    assert(total == 2);
    assert(count_findings(shl_one, sizeof(shl_one), "suboptimal SHL one",
                          &total, X86LINT_EXT_APX) == 1);

    // Zero counts leave the legacy destination -- the copy -- unwritten
    // (the SDM's count-0 carve-out), so the pair is not equal to the NDD
    // form. Raw zero (the shift itself stays check_shift_zero's finding),
    // and 0x20 masked to zero at 32-bit width.
    static const uint8_t shl_zero[] = {
        0x48, 0x89, 0xC8,        // mov rax, rcx
        0x48, 0xC1, 0xE0, 0x00,  // shl rax, 0
        0xC3,                    // ret
    };
    assert(count_findings(shl_zero, sizeof(shl_zero), "missing APX NDD",
                          &total, X86LINT_EXT_APX) == 0);
    assert(count_findings(shl_zero, sizeof(shl_zero),
                          "redundant shift/rotate by zero", &total,
                          X86LINT_EXT_APX) == 1);
    assert(total == 1);
    static const uint8_t shl_masked[] = {
        0x89, 0xC8,        // mov eax, ecx
        0xC1, 0xE0, 0x20,  // shl eax, 0x20 (masked count: 0x20 & 31 == 0)
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(shl_masked, "missing APX NDD", 0, X86LINT_EXT_APX);

    // CL counts are missing SHLX territory: under bmi2 the flagless form
    // is the stronger rewrite, and this check never claims the pair.
    static const uint8_t shl_cl[] = {
        0x48, 0x89, 0xD0,  // mov rax, rdx
        0x48, 0xD3, 0xE0,  // shl rax, cl
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(shl_cl, "missing APX NDD", 0, X86LINT_EXT_APX);
    assert(count_findings(shl_cl, sizeof(shl_cl), "missing APX NDD", &total,
                          X86LINT_EXT_APX | X86LINT_EXT_BMI2) == 0);
    ASSERT_FINDINGS_EXT(shl_cl, "missing SHLX/SHRX/SARX", 1,
                        X86LINT_EXT_APX | X86LINT_EXT_BMI2);

    // Unary forms.
    static const uint8_t neg32[] = {
        0x89, 0xDA,        // mov edx, ebx
        0xF7, 0xDA,        // neg edx
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(neg32, "missing APX NDD", 1, X86LINT_EXT_APX);
    static const uint8_t not32[] = {
        0x89, 0xD0,        // mov eax, edx
        0xF7, 0xD0,        // not eax
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(not32, "missing APX NDD", 1, X86LINT_EXT_APX);

    // The BLSI interplay. Under bmi1+apx the full triple is one BLSI
    // finding -- the dispatcher's else arm defers this fold to the 3 -> 1
    // collapse; under apx alone the mov/neg prefix is this finding.
    static const uint8_t blsi_triple[] = {
        0x89, 0xF9,        // mov ecx, edi
        0xF7, 0xD9,        // neg ecx
        0x21, 0xF9,        // and ecx, edi
        0xC3,              // ret
    };
    assert(count_findings(blsi_triple, sizeof(blsi_triple), "missing BLSI",
                          &total, X86LINT_EXT_BMI1 | X86LINT_EXT_APX) == 1);
    assert(total == 1);
    assert(count_findings(blsi_triple, sizeof(blsi_triple),
                          "missing APX NDD", &total,
                          X86LINT_EXT_APX) == 1);
    assert(total == 1);
    // A merely gate-suppressed BLSI does not claim the site: with CF read
    // downstream the triple is no BLSI, but the mov/neg pair still folds
    // (the NDD neg writes CF exactly as neg does).
    static const uint8_t blsi_gated[] = {
        0x89, 0xF9,        // mov ecx, edi
        0xF7, 0xD9,        // neg ecx
        0x21, 0xF9,        // and ecx, edi
        0x72, 0x00,        // jb +0
        0xC3,              // ret
    };
    assert(count_findings(blsi_gated, sizeof(blsi_gated), "missing BLSI",
                          &total, X86LINT_EXT_BMI1 | X86LINT_EXT_APX) == 0);
    assert(count_findings(blsi_gated, sizeof(blsi_gated), "missing APX NDD",
                          &total, X86LINT_EXT_BMI1 | X86LINT_EXT_APX) == 1);
    assert(total == 1);

    // Memory sources are pure loads the NDD forms take directly.
    static const uint8_t mem_sub[] = {
        0x48, 0x89, 0xC2,  // mov rdx, rax
        0x48, 0x2B, 0x13,  // sub rdx, [rbx]
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(mem_sub, "missing APX NDD", 1, X86LINT_EXT_APX);
    // A memory-source ADD is this fold's, not the LEA fold's: lea cannot
    // load.
    static const uint8_t mem_add[] = {
        0x48, 0x89, 0xC8,  // mov rax, rcx
        0x48, 0x03, 0x07,  // add rax, [rdi]
        0xC3,              // ret
    };
    assert(count_findings(mem_add, sizeof(mem_add), "missing APX NDD",
                          &total, X86LINT_EXT_APX) == 1);
    assert(total == 1);
    // RIP-relative sources pass the address guard.
    static const uint8_t mem_rip[] = {
        0x48, 0x89, 0xD8,                          // mov rax, rbx
        0x48, 0x23, 0x05, 0xF6, 0xFF, 0xFF, 0xFF,  // and rax, [rip-0xa]
        0xC3,                                      // ret
    };
    ASSERT_FINDINGS_EXT(mem_rip, "missing APX NDD", 1, X86LINT_EXT_APX);
    // An address through the mov's source reads the same value in both
    // shapes...
    static const uint8_t addr_src[] = {
        0x48, 0x89, 0xF1,  // mov rcx, rsi
        0x48, 0x2B, 0x0E,  // sub rcx, [rsi]
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(addr_src, "missing APX NDD", 1, X86LINT_EXT_APX);
    // ...but an address through the destination would read the stale
    // pre-copy value in the folded shape.
    static const uint8_t addr_dst[] = {
        0x48, 0x89, 0xF1,  // mov rcx, rsi
        0x48, 0x2B, 0x09,  // sub rcx, [rcx]
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(addr_dst, "missing APX NDD", 0, X86LINT_EXT_APX);
    // Memory destinations: XED reports the register source of
    // and [rax], rcx in the REG0 slot, so the write-back rejection is
    // what stops it.
    static const uint8_t mem_dst[] = {
        0x48, 0x89, 0xF1,  // mov rcx, rsi
        0x48, 0x21, 0x08,  // and [rax], rcx
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(mem_dst, "missing APX NDD", 0, X86LINT_EXT_APX);

    // A register source aliasing the destination: the folded op would
    // read the stale pre-copy value. (The sub rax, rax itself stays
    // check_sub_self's finding.)
    static const uint8_t src_alias[] = {
        0x48, 0x89, 0xF0,  // mov rax, rsi
        0x48, 0x29, 0xC0,  // sub rax, rax
        0xC3,              // ret
    };
    assert(count_findings(src_alias, sizeof(src_alias), "missing APX NDD",
                          &total, X86LINT_EXT_APX) == 0);
    assert(count_findings(src_alias, sizeof(src_alias),
                          "suboptimal SUB reg, reg", &total,
                          X86LINT_EXT_APX) == 1);
    assert(total == 1);
    // A copy aliasing its own source is no copy (and check_mov_self's
    // finding: the following 32-bit write kills the upper-32 concern).
    static const uint8_t head_alias[] = {
        0x89, 0xC0,        // mov eax, eax
        0x29, 0xF0,        // sub eax, esi
        0xC3,              // ret
    };
    assert(count_findings(head_alias, sizeof(head_alias), "missing APX NDD",
                          &total, X86LINT_EXT_APX) == 0);
    assert(count_findings(head_alias, sizeof(head_alias),
                          "redundant MOV reg, reg", &total,
                          X86LINT_EXT_APX) == 1);
    assert(total == 1);

    // Width mismatch: the exact-register match rejects EAX vs RAX.
    static const uint8_t width_mix[] = {
        0x48, 0x89, 0xF0,  // mov rax, rsi
        0x29, 0xF0,        // sub eax, esi
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(width_mix, "missing APX NDD", 0, X86LINT_EXT_APX);

    // 16-bit pair: kept out as everywhere in this family.
    static const uint8_t pair16[] = {
        0x66, 0x89, 0xD1,  // mov cx, dx
        0x66, 0x29, 0xD1,  // sub cx, dx
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(pair16, "missing APX NDD", 0, X86LINT_EXT_APX);

    // Pairs LEA expresses stay mov_add_foldable_to_lea's finding, which
    // needs no extension: register add, immediate add, immediate sub.
    static const uint8_t lea_add_reg[] = {
        0x89, 0xF2,        // mov edx, esi
        0x01, 0xFA,        // add edx, edi
        0xC3,              // ret
    };
    assert(count_findings(lea_add_reg, sizeof(lea_add_reg),
                          "missing APX NDD", &total, X86LINT_EXT_APX) == 0);
    assert(count_findings(lea_add_reg, sizeof(lea_add_reg),
                          "MOV+ADD foldable to LEA", &total,
                          X86LINT_EXT_APX) == 1);
    assert(total == 1);
    static const uint8_t lea_add_imm[] = {
        0x89, 0xF2,        // mov edx, esi
        0x83, 0xC2, 0x05,  // add edx, 5
        0xC3,              // ret
    };
    assert(count_findings(lea_add_imm, sizeof(lea_add_imm),
                          "missing APX NDD", &total, X86LINT_EXT_APX) == 0);
    assert(count_findings(lea_add_imm, sizeof(lea_add_imm),
                          "MOV+ADD foldable to LEA", &total,
                          X86LINT_EXT_APX) == 1);
    assert(total == 1);
    static const uint8_t lea_sub_imm[] = {
        0x89, 0xC8,        // mov eax, ecx
        0x83, 0xE8, 0x03,  // sub eax, 3
        0xC3,              // ret
    };
    assert(count_findings(lea_sub_imm, sizeof(lea_sub_imm),
                          "missing APX NDD", &total, X86LINT_EXT_APX) == 0);
    assert(count_findings(lea_sub_imm, sizeof(lea_sub_imm),
                          "MOV+ADD foldable to LEA", &total,
                          X86LINT_EXT_APX) == 1);
    assert(total == 1);

    // ...but only while the flags the op writes die (lea writes none).
    // While they live the LEA fold is suppressed and this fold takes the
    // exact complement: the jo reads OF, so these previously unflagged
    // pairs are the NDD fold's -- and stay unflagged at baseline.
    static const uint8_t live_add_reg[] = {
        0x89, 0xF2,        // mov edx, esi
        0x01, 0xFA,        // add edx, edi
        0x70, 0x00,        // jo +0
        0xC3,              // ret
    };
    assert(count_findings(live_add_reg, sizeof(live_add_reg),
                          "missing APX NDD", &total, X86LINT_EXT_APX) == 1);
    assert(count_findings(live_add_reg, sizeof(live_add_reg),
                          "MOV+ADD foldable to LEA", &total,
                          X86LINT_EXT_APX) == 0);
    assert(total == 1);
    ASSERT_FINDINGS(live_add_reg, "missing APX NDD", 0);
    static const uint8_t live_add_imm[] = {
        0x89, 0xF2,        // mov edx, esi
        0x83, 0xC2, 0x05,  // add edx, 5
        0x70, 0x00,        // jo +0
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(live_add_imm, "missing APX NDD", 1,
                        X86LINT_EXT_APX);
    static const uint8_t live_sub_imm[] = {
        0x89, 0xC8,        // mov eax, ecx
        0x83, 0xE8, 0x03,  // sub eax, 3
        0x70, 0x00,        // jo +0
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(live_sub_imm, "missing APX NDD", 1,
                        X86LINT_EXT_APX);
    // INC divides by the flags it writes -- CF, which it and lea alike
    // leave untouched, plays no part.
    static const uint8_t live_inc[] = {
        0x89, 0xF2,        // mov edx, esi
        0xFF, 0xC2,        // inc edx
        0x70, 0x00,        // jo +0
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(live_inc, "missing APX NDD", 1, X86LINT_EXT_APX);

    // A direct branch onto the op reaches it without the copy.
    static const uint8_t edge_on_op[] = {
        0xEB, 0x02,        // jmp +2 (to the neg)
        0x89, 0xF9,        // mov ecx, edi
        0xF7, 0xD9,        // neg ecx
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(edge_on_op, "missing APX NDD", 0, X86LINT_EXT_APX);

    // ---- The window. Up to APX_NDD_WINDOW - 2 instructions may sit
    // between the copy and its consumer when each proves independence
    // (see apx_ndd_gap_independent); these expectations track the build's
    // window so -DAPX_NDD_WINDOW experiments stay green. The negatives
    // below hold at every window: reads, writes, aliases, and control
    // flow stop the scan regardless of how far it may look.
    const int one_gap = APX_NDD_WINDOW >= 3 ? 1 : 0;
    const int two_gap = APX_NDD_WINDOW >= 4 ? 1 : 0;

    // A flag-writing zero idiom between the pair: flags are free (the
    // mov is flag-transparent), and ECX is neither the copy nor the
    // source.
    static const uint8_t gap_flags[] = {
        0x89, 0xF8,        // mov eax, edi
        0x31, 0xC9,        // xor ecx, ecx
        0x29, 0xF0,        // sub eax, esi
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(gap_flags, "missing APX NDD", one_gap,
                        X86LINT_EXT_APX);

    // A load between: memory is unconstrained, and the loaded ECX could
    // even feed the op -- it holds the same value in both shapes.
    static const uint8_t gap_load[] = {
        0x48, 0x89, 0xC2,  // mov rdx, rax
        0x8B, 0x0B,        // mov ecx, [rbx]
        0x48, 0x29, 0xF2,  // sub rdx, rsi
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(gap_load, "missing APX NDD", one_gap,
                        X86LINT_EXT_APX);

    // A store between: both shapes store the same value at the same
    // point.
    static const uint8_t gap_store[] = {
        0x4D, 0x89, 0xF4,        // mov r12, r14
        0x48, 0x89, 0x55, 0xF8,  // mov [rbp-0x8], rdx
        0x49, 0x83, 0xE4, 0x80,  // and r12, -0x80
        0xC3,                    // ret
    };
    ASSERT_FINDINGS_EXT(gap_store, "missing APX NDD", one_gap,
                        X86LINT_EXT_APX);

    // Reading the copy stops the scan: it is genuinely used, and the
    // folded shape would hand the TEST a stale value.
    static const uint8_t gap_reads_copy[] = {
        0x89, 0xF9,        // mov ecx, edi
        0x85, 0xC9,        // test ecx, ecx
        0x29, 0xF1,        // sub ecx, esi
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(gap_reads_copy, "missing APX NDD", 0,
                        X86LINT_EXT_APX);

    // Writing the copy stops the scan for the first mov, whose copy dies
    // unread -- and the second mov IS the pair: exactly one finding at
    // any window.
    static const uint8_t gap_writes_copy[] = {
        0x89, 0xF9,        // mov ecx, edi
        0x89, 0xD9,        // mov ecx, ebx
        0x29, 0xF1,        // sub ecx, esi
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(gap_writes_copy, "missing APX NDD", 1,
                        X86LINT_EXT_APX);

    // Writing the source stops it: the folded op would read the source
    // after the overwrite, where the original captured it at the mov.
    static const uint8_t gap_writes_src[] = {
        0x89, 0xF9,        // mov ecx, edi
        0x89, 0xD7,        // mov edi, edx
        0x29, 0xF1,        // sub ecx, esi
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(gap_writes_src, "missing APX NDD", 0,
                        X86LINT_EXT_APX);

    // A partial-register alias is still the copy: SHR CL, 5 writes CL
    // inside ECX. (0x7 is inert for the immediate-family checks.)
    static const uint8_t gap_partial_alias[] = {
        0x89, 0xC1,        // mov ecx, eax
        0xC0, 0xE9, 0x05,  // shr cl, 5
        0x83, 0xE1, 0x07,  // and ecx, 7
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(gap_partial_alias, "missing APX NDD", 0,
                        X86LINT_EXT_APX);

    // Control flow stops the scan: a call conservatively reads and
    // writes everything.
    static const uint8_t gap_call[] = {
        0x89, 0xF8,                    // mov eax, edi
        0xE8, 0x00, 0x00, 0x00, 0x00,  // call +0
        0x29, 0xF0,                    // sub eax, esi
        0xC3,                          // ret
    };
    ASSERT_FINDINGS_EXT(gap_call, "missing APX NDD", 0, X86LINT_EXT_APX);

    // A direct branch onto the looked-through instruction reaches code
    // that expects the copy done: the widened suppression span covers
    // every slot, not just the op.
    static const uint8_t edge_on_gap[] = {
        0xEB, 0x02,        // jmp +2 (to the xor)
        0x89, 0xF8,        // mov eax, edi
        0x31, 0xC9,        // xor ecx, ecx
        0x29, 0xF0,        // sub eax, esi
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(edge_on_gap, "missing APX NDD", 0,
                        X86LINT_EXT_APX);

    // The window is bounded by the constant: two independent
    // instructions between the pair need APX_NDD_WINDOW >= 4.
    static const uint8_t two_gaps[] = {
        0x89, 0xF8,        // mov eax, edi
        0x31, 0xC9,        // xor ecx, ecx
        0x31, 0xD2,        // xor edx, edx
        0x29, 0xF0,        // sub eax, esi
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(two_gaps, "missing APX NDD", two_gap,
                        X86LINT_EXT_APX);

    // ---- CMOVcc consumers: the pair is a select, rY = cc ? rZ : rX,
    // and the NDD promotion selects the same way -- exactly, since the
    // 32-bit forms zero-extend on a false condition in both shapes and
    // both read the same flags.
    static const uint8_t cmov_reg32[] = {
        0x89, 0xF8,        // mov eax, edi
        0x0F, 0x44, 0xC2,  // cmovz eax, edx
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(cmov_reg32, "missing APX NDD", 1, X86LINT_EXT_APX);
    ASSERT_FINDINGS(cmov_reg32, "missing APX NDD", 0);
    static const uint8_t cmov_reg64[] = {
        0x48, 0x89, 0xF8,        // mov rax, rdi
        0x48, 0x0F, 0x45, 0xC1,  // cmovnz rax, rcx
        0xC3,                    // ret
    };
    ASSERT_FINDINGS_EXT(cmov_reg64, "missing APX NDD", 1, X86LINT_EXT_APX);
    // A memory taken-value loads unconditionally in both shapes.
    static const uint8_t cmov_mem_src[] = {
        0x48, 0x89, 0xF8,        // mov rax, rdi
        0x48, 0x0F, 0x44, 0x03,  // cmovz rax, [rbx]
        0xC3,                    // ret
    };
    ASSERT_FINDINGS_EXT(cmov_mem_src, "missing APX NDD", 1,
                        X86LINT_EXT_APX);
    // Behind a load head the inverse condition code puts the loaded
    // default in the selectable slot: cc ? rcx : [rdi] is the inverted
    // cmov of ([rdi], rcx).
    static const uint8_t cmov_load_head[] = {
        0x48, 0x8B, 0x07,        // mov rax, [rdi]
        0x48, 0x0F, 0x44, 0xC1,  // cmovz rax, rcx
        0xC3,                    // ret
    };
    ASSERT_FINDINGS_EXT(cmov_load_head, "missing APX NDD", 1,
                        X86LINT_EXT_APX);
    // A flag-writing gap changes what the cmov reads in both shapes
    // alike; the fold still stands.
    static const uint8_t cmov_gap[] = {
        0x89, 0xF8,        // mov eax, edi
        0x31, 0xD2,        // xor edx, edx
        0x0F, 0x44, 0xC1,  // cmovz eax, ecx
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(cmov_gap, "missing APX NDD", one_gap,
                        X86LINT_EXT_APX);
    // The usual rejections carry over: a source aliasing the destination,
    // and an address through it.
    static const uint8_t cmov_src_alias[] = {
        0x89, 0xF8,        // mov eax, edi
        0x0F, 0x44, 0xC0,  // cmovz eax, eax
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(cmov_src_alias, "missing APX NDD", 0,
                        X86LINT_EXT_APX);
    static const uint8_t cmov_addr_dst[] = {
        0x48, 0x89, 0xF1,        // mov rcx, rsi
        0x48, 0x0F, 0x44, 0x09,  // cmovz rcx, [rcx]
        0xC3,                    // ret
    };
    ASSERT_FINDINGS_EXT(cmov_addr_dst, "missing APX NDD", 0,
                        X86LINT_EXT_APX);

    // ---- Load heads: mov rY, [mem] ; op rY, src folds to the NDD form
    // with the load as its memory source, op rY, [mem], src.

    // The dominant shape: a loaded value on the left of a non-commutative
    // op has no legacy single-instruction form. 32- and 64-bit.
    static const uint8_t load_sub32[] = {
        0x8B, 0x06,        // mov eax, [rsi]
        0x29, 0xF8,        // sub eax, edi
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(load_sub32, "missing APX NDD", 1, X86LINT_EXT_APX);
    ASSERT_FINDINGS(load_sub32, "missing APX NDD", 0);
    static const uint8_t load_sub64[] = {
        0x48, 0x8B, 0x03,  // mov rax, [rbx]
        0x48, 0x29, 0xF8,  // sub rax, rdi
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(load_sub64, "missing APX NDD", 1, X86LINT_EXT_APX);

    // Load-then-mask, the other common idiom (and [mem], imm writes
    // memory, so getting the masked value into a register forces the
    // pair).
    static const uint8_t load_and_imm[] = {
        0x48, 0x8B, 0x07,        // mov rax, [rdi]
        0x48, 0x83, 0xE0, 0xF0,  // and rax, -16
        0xC3,                    // ret
    };
    ASSERT_FINDINGS_EXT(load_and_imm, "missing APX NDD", 1,
                        X86LINT_EXT_APX);
    // Load-then-shift (bitfield extraction).
    static const uint8_t load_shr[] = {
        0x8B, 0x06,        // mov eax, [rsi]
        0xC1, 0xE8, 0x05,  // shr eax, 5
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(load_shr, "missing APX NDD", 1, X86LINT_EXT_APX);

    // Behind a load head, ADD and INC belong to this fold -- the LEA
    // fold's head is register-to-register, so there is no division of
    // labor to respect.
    static const uint8_t load_add_reg[] = {
        0x8B, 0x06,        // mov eax, [rsi]
        0x01, 0xF8,        // add eax, edi
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(load_add_reg, "missing APX NDD", 1,
                        X86LINT_EXT_APX);
    static const uint8_t load_inc[] = {
        0x8B, 0x06,        // mov eax, [rsi]
        0xFF, 0xC0,        // inc eax
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(load_inc, "missing APX NDD", 1, X86LINT_EXT_APX);

    // NEG of a loaded value, and the two-operand IMUL (commutative, so
    // the memory source rides in the NDD form's second slot).
    static const uint8_t load_neg[] = {
        0x8B, 0x06,        // mov eax, [rsi]
        0xF7, 0xD8,        // neg eax
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(load_neg, "missing APX NDD", 1, X86LINT_EXT_APX);
    static const uint8_t load_imul[] = {
        0x48, 0x8B, 0x03,        // mov rax, [rbx]
        0x48, 0x0F, 0xAF, 0xC1,  // imul rax, rcx
        0xC3,                    // ret
    };
    ASSERT_FINDINGS_EXT(load_imul, "missing APX NDD", 1, X86LINT_EXT_APX);

    // An address through the destination reads the pre-load value in
    // both shapes (cf. the MOVBE fold's base==dest case).
    static const uint8_t load_base_dst[] = {
        0x48, 0x8B, 0x00,  // mov rax, [rax]
        0x48, 0x29, 0xF8,  // sub rax, rdi
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(load_base_dst, "missing APX NDD", 1,
                        X86LINT_EXT_APX);

    // No NDD form carries two memory operands.
    static const uint8_t load_op_mem[] = {
        0x48, 0x8B, 0x03,  // mov rax, [rbx]
        0x48, 0x2B, 0x07,  // sub rax, [rdi]
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(load_op_mem, "missing APX NDD", 0,
                        X86LINT_EXT_APX);

    // Load-headed pairs must be adjacent: across a gap the fold would
    // reorder the access and its fault against the gap's effects.
    static const uint8_t load_gap[] = {
        0x8B, 0x06,        // mov eax, [rsi]
        0x31, 0xC9,        // xor ecx, ecx
        0x29, 0xF8,        // sub eax, edi
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(load_gap, "missing APX NDD", 0, X86LINT_EXT_APX);

    // The A1 moffs form loads through a 64-bit absolute address, which
    // no EVEX form re-encodes (cf. the MOVBE fold).
    static const uint8_t load_moffs[] = {
        0xA1, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                           // mov eax, [0x8877665544332211]
        0x29, 0xF8,        // sub eax, edi
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(load_moffs, "missing APX NDD", 0, X86LINT_EXT_APX);

    // A store head is not a copy.
    static const uint8_t store_head[] = {
        0x89, 0x06,        // mov [rsi], eax
        0x29, 0xF8,        // sub eax, edi
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(store_head, "missing APX NDD", 0, X86LINT_EXT_APX);

    // 16-bit pair: kept out as everywhere in this family.
    static const uint8_t load_pair16[] = {
        0x66, 0x8B, 0x06,  // mov ax, [rsi]
        0x66, 0x29, 0xF8,  // sub ax, di
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(load_pair16, "missing APX NDD", 0,
                        X86LINT_EXT_APX);

    // The op's register source must not alias the destination, load
    // heads included (sub eax, eax after the load is not [mem] - [mem]).
    static const uint8_t load_src_alias[] = {
        0x8B, 0x06,        // mov eax, [rsi]
        0x29, 0xC0,        // sub eax, eax
        0xC3,              // ret
    };
    assert(count_findings(load_src_alias, sizeof(load_src_alias),
                          "missing APX NDD", &total, X86LINT_EXT_APX) == 0);

    // A direct branch onto the op reaches it without the load.
    static const uint8_t edge_on_load_op[] = {
        0xEB, 0x02,        // jmp +2 (to the sub)
        0x8B, 0x06,        // mov eax, [rsi]
        0x29, 0xF8,        // sub eax, edi
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(edge_on_load_op, "missing APX NDD", 0,
                        X86LINT_EXT_APX);
}

// setcc X ; movzx of X into its own 32/64-bit parent: under -m apx the
// pair is one zero-upper setcc (setzu.cc, EVEX ND=1), which writes the 0/1
// result zero-extended to 64 bits itself -- an exact fold where the
// baseline finding is advisory. One matcher serves both: the dispatcher
// reports missing APX SETZU with the extension and the suboptimal SETcc
// zero-extension advisory without it, never both. See
// setcc_movzx_zero_extend.
static void check_missing_apx_setzu_test(void)
{
    // The canonical pair. Under -m apx: the exact fold and only it; the
    // total of 1 pins that the advisory does not co-fire. Without the
    // extension, and under the unrelated extension bits, the advisory.
    static const uint8_t pair32[] = {
        0x0F, 0x94, 0xC0,  // setz al
        0x0F, 0xB6, 0xC0,  // movzx eax, al
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(pair32, "missing APX SETZU", 1, X86LINT_EXT_APX);
    ASSERT_FINDINGS(pair32, "suboptimal SETcc zero-extension", 1);
    ASSERT_FINDINGS_EXT(pair32, "suboptimal SETcc zero-extension", 1,
                        X86LINT_EXT_BMI1 | X86LINT_EXT_BMI2 |
                            X86LINT_EXT_MOVBE);

    // The 64-bit widening form folds the same way (SETZU zero-extends to
    // 64 bits regardless); the movzx's REX.W is separately the unneeded-
    // REX finding, which keeps firing -- it concerns the pair's encoding,
    // not its replacement.
    static const uint8_t pair64[] = {
        0x0F, 0x94, 0xC0,        // setz al
        0x48, 0x0F, 0xB6, 0xC0,  // movzx rax, al
        0xC3,                    // ret
    };
    int total;
    assert(count_findings(pair64, sizeof(pair64), "missing APX SETZU",
                          &total, X86LINT_EXT_APX) == 1);
    assert(count_findings(pair64, sizeof(pair64), "unneeded REX prefix",
                          &total, X86LINT_EXT_APX) == 1);
    assert(total == 2);

    // Condition- and register-generic: every cc has a zero-upper form.
    static const uint8_t pair_ne[] = {
        0x0F, 0x95, 0xC1,  // setnz cl
        0x0F, 0xB6, 0xC9,  // movzx ecx, cl
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(pair_ne, "missing APX SETZU", 1, X86LINT_EXT_APX);

    // Widening into a different register is a real move, not the idiom
    // (the byte result stays live): no finding in either mode.
    static const uint8_t wrong_reg[] = {
        0x0F, 0x94, 0xC0,  // setz al
        0x0F, 0xB6, 0xC8,  // movzx ecx, al
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(wrong_reg, "missing APX SETZU", 0, X86LINT_EXT_APX);

    // A direct branch onto the movzx reaches it without the setcc.
    static const uint8_t edge_on_movzx[] = {
        0xEB, 0x03,        // jmp +3 (to the movzx)
        0x0F, 0x94, 0xC0,  // setz al
        0x0F, 0xB6, 0xC0,  // movzx eax, al
        0xC3,              // ret
    };
    ASSERT_FINDINGS_EXT(edge_on_movzx, "missing APX SETZU", 0,
                        X86LINT_EXT_APX);
}

// An undecodable byte (executable sections routinely embed data) must not
// abort the scan: linear sweep skips one byte, resyncs, and still flags the
// instruction that follows. 0x06 (push es) is illegal in 64-bit mode.
static void check_endbr64_target_test(void)
{
    static const uint8_t inst[] = {
        0xf3, 0x0f, 0x1e, 0xfa,        // endbr64
        0x90,                          // nop
        0xf3, 0x0f, 0x1e, 0xfb,        // endbr32 (not a 64-bit landing pad)
        0x66, 0xf3, 0x0f, 0x1e, 0xfa,  // endbr64 under a redundant prefix
    };

    assert(check_endbr64_target(inst, sizeof(inst), 0));    // the landing pad
    assert(!check_endbr64_target(inst, sizeof(inst), 4));   // nop
    assert(!check_endbr64_target(inst, sizeof(inst), 1));   // mid-instruction
    assert(!check_endbr64_target(inst, sizeof(inst), 5));   // endbr32
    // Prefixed variants still decode -- and land -- as ENDBR64; the tracker
    // matches the instruction, not the canonical four bytes.
    assert(check_endbr64_target(inst, sizeof(inst), 9));
    // Out of range, at the end, and truncated: no pad, not a crash.
    assert(!check_endbr64_target(inst, sizeof(inst), sizeof(inst)));
    assert(!check_endbr64_target(inst, sizeof(inst), 1000));
    assert(!check_endbr64_target(inst, 3, 0));              // cut mid-pattern
}

static void check_decode_resync_test(void)
{
    static const uint8_t inst[] = {
        0x90,                          // nop (decodes, no finding)
        0x06,                          // (bad) push es -- undecodable
        0x68, 0x01, 0x00, 0x00, 0x00,  // push 0x1 (oversized immediate)
    };

    x86lint_summary *summary = x86lint_summary_create();
    assert(summary != NULL);
    int findings = check_instructions(inst, sizeof(inst), 0, false, summary, 0);
    assert(findings == 1);                              // not -1; scan continued
    assert(x86lint_summary_skipped(summary) == 1);      // the one bad byte
    assert(x86lint_summary_instructions(summary) == 2); // nop + push, not the byte
    x86lint_summary_destroy(summary);
}

static void summary_functions_test(void)
{
    // Two findings at offsets 0 and 7, one instruction between them, so
    // with the scan based at 0x1000 the finding addresses are 0x1000
    // (inside f1), and 0x1007 (past f2's end: outside every range).
    static const uint8_t inst[] = {
        0x68, 0x01, 0x00, 0x00, 0x00,  // push 0x1 (oversized immediate)
        0x87, 0xc8,                    // xchg eax, ecx (oversized XCHG)
        0x87, 0xc8,                    // xchg eax, ecx (oversized XCHG)
    };
    static const x86lint_func_range funcs[] = {
        {0x1000, 0x1005, "f1"},
        {0x1005, 0x1007, "f2"},
    };

    x86lint_summary *summary = x86lint_summary_create();
    assert(summary != NULL);
    x86lint_summary_set_functions(summary, funcs, 2);
    int findings = check_instructions(inst, sizeof(inst), 0x1000, false,
        summary, 0);
    assert(findings == 3);
    assert(x86lint_summary_function_findings(summary, 0) == 1);
    assert(x86lint_summary_function_findings(summary, 1) == 1);
    assert(x86lint_summary_function_findings(summary, 2) == 0);  // range check
    x86lint_summary_destroy(summary);

    // Without a table the accessor reads zero and scans are unaffected.
    summary = x86lint_summary_create();
    assert(summary != NULL);
    assert(check_instructions(inst, sizeof(inst), 0x1000, false, summary,
        0) == 3);
    assert(x86lint_summary_function_findings(summary, 0) == 0);
    x86lint_summary_destroy(summary);

    // NULL summary still tolerated with attribution in the code path.
    assert(check_instructions(inst, sizeof(inst), 0x1000, false, NULL,
        0) == 3);
}

static void census_test(void)
{
    x86lint_census *census = x86lint_census_create();
    assert(census != NULL);
    static const uint8_t code[] = {
        0x89, 0xc0,                          // mov eax, eax (baseline)
        0xf3, 0x0f, 0xb8, 0xc0,              // popcnt eax, eax (v2)
        0xc5, 0xf8, 0x58, 0xc0,              // vaddps xmm0, xmm0, xmm0 (v3 AVX)
        0xc5, 0xfd, 0xfc, 0xc0,              // vpaddb ymm0, ymm0, ymm0 (v3 AVX2)
        0x62, 0xf1, 0x7c, 0x48, 0x58, 0xc0,  // vaddps zmm0, zmm0, zmm0 (v4 AVX512F)
        0x66, 0x0f, 0x38, 0xdc, 0xc1,        // aesenc xmm0, xmm1 (outside the levels)
    };
    x86lint_census_scan(census, code, sizeof(code), 0x1000);
    assert(x86lint_census_instructions(census) == 6);
    assert(x86lint_census_skipped(census) == 0);
    assert(x86lint_census_level_count(census, 1) == 1);
    assert(x86lint_census_level_count(census, 2) == 1);
    assert(x86lint_census_level_count(census, 3) == 2);
    assert(x86lint_census_level_count(census, 4) == 1);
    assert(x86lint_census_level_count(census, 0) == 1);
    assert(x86lint_census_highest_level(census) == 4);
    assert(x86lint_census_x87_count(census, X86LINT_X87_OTHER) == 0);
    x86lint_census_destroy(census);

    // The x87 annotation splits per instruction: control/env, 80-bit
    // memory operands, bare-stack "other". FISTTP (isa-set SSE3X87)
    // counts at v2 in the ladder AND joins the x87 line.
    census = x86lint_census_create();
    assert(census != NULL);
    static const uint8_t x87[] = {
        0xd9, 0x28,  // fldcw [rax] (control/env)
        0xdb, 0x28,  // fld tbyte ptr [rax] (80-bit)
        0xde, 0xc1,  // faddp st(1), st (other)
        0xdb, 0x08,  // fisttp dword ptr [rax] (v2 + other)
    };
    x86lint_census_scan(census, x87, sizeof(x87), 0x3000);
    assert(x86lint_census_instructions(census) == 4);
    assert(x86lint_census_x87_count(census, X86LINT_X87_CONTROL) == 1);
    assert(x86lint_census_x87_count(census, X86LINT_X87_EIGHTY_BIT) == 1);
    assert(x86lint_census_x87_count(census, X86LINT_X87_OTHER) == 2);
    assert(x86lint_census_level_count(census, 1) == 3);
    assert(x86lint_census_level_count(census, 2) == 1);
    assert(x86lint_census_highest_level(census) == 2);
    // Without evidence installed nothing is labeled.
    assert(x86lint_census_level_unevidenced(census, 1) == 0);
    assert(x86lint_census_level_unevidenced(census, 2) == 0);
    x86lint_census_destroy(census);

    // Evidence labeling: a range covering only the first two
    // instructions leaves faddp (level 1) and fisttp (level 2)
    // unevidenced. Labeling happens at scan time, so the evidence is
    // installed first.
    census = x86lint_census_create();
    assert(census != NULL);
    static const x86lint_evidence_range evidence[] = {{0x3000, 0x3004}};
    x86lint_census_set_evidence(census, evidence, 1);
    x86lint_census_scan(census, x87, sizeof(x87), 0x3000);
    assert(x86lint_census_level_count(census, 1) == 3);
    assert(x86lint_census_level_unevidenced(census, 1) == 1);
    assert(x86lint_census_level_unevidenced(census, 2) == 1);
    assert(x86lint_census_level_unevidenced(census, 0) == 0);
    x86lint_census_destroy(census);

    // Undecodable bytes resync one at a time and tally as skipped, and a
    // census that decoded nothing reports the baseline level.
    census = x86lint_census_create();
    assert(census != NULL);
    static const uint8_t junk[] = {0x62, 0x00};  // truncated EVEX prefix
    x86lint_census_scan(census, junk, sizeof(junk), 0);
    assert(x86lint_census_instructions(census) == 0);
    assert(x86lint_census_skipped(census) == 2);
    assert(x86lint_census_highest_level(census) == 1);

    // Tallies accumulate across scans, as the driver's section loop relies
    // on.
    static const uint8_t lzcnt[] = {0xf3, 0x0f, 0xbd, 0xc0};  // lzcnt eax, eax (v3)
    x86lint_census_scan(census, lzcnt, sizeof(lzcnt), 0x2000);
    assert(x86lint_census_instructions(census) == 1);
    assert(x86lint_census_level_count(census, 3) == 1);
    assert(x86lint_census_highest_level(census) == 3);
    x86lint_census_destroy(census);

    // NULL is accepted everywhere.
    x86lint_census_scan(NULL, code, sizeof(code), 0);
    assert(x86lint_census_instructions(NULL) == 0);
    assert(x86lint_census_skipped(NULL) == 0);
    assert(x86lint_census_level_count(NULL, 3) == 0);
    assert(x86lint_census_x87_count(NULL, X86LINT_X87_CONTROL) == 0);
    assert(x86lint_census_level_unevidenced(NULL, 1) == 0);
    x86lint_census_set_evidence(NULL, NULL, 0);
    assert(x86lint_census_highest_level(NULL) == 1);
    x86lint_census_destroy(NULL);
}

int main(int argc, char *argv[])
{
    xed_tables_init();
    xed_set_verbosity(0);

    check_suboptimal_nops_test();
    check_oversized_immediate_test();
    check_oversized_test_immediate_test();
    check_test_minus_one_test();
    check_oversized_add_sub_128_test();
    check_lcp_imm16_test();
    check_unneeded_rex_test();
    check_cmp_zero_test();
    check_mov_zero_test();
    check_implicit_register_test();
    check_implicit_immediate_test();
    check_and_strength_reduce_test();
    check_and_minus_one_test();
    check_xor_to_not_test();
    check_superfluous_lock_prefix_test();
    check_rep_ret_test();
    check_notrack_call_test();
    check_xchg_accumulator_test();
    check_oversized_branch_test();
    check_mov_self_test();
    check_add_sub_zero_test();
    check_or_xor_zero_test();
    check_and_zero_test();
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
    check_lea_to_add_test();
    check_oversized_lea_width_test();
    check_shift_zero_test();
    check_shl_one_test();
    check_sse_mov_opcode_test();
    check_sse_zero_idiom_test();
    check_oversized_evex_test();
    check_oversized_vex_test();
    check_flag_liveness_test();
    check_flag_liveness_corners_test();
    check_reg_liveness_test();
    check_zero_extend_mov_self_test();
    check_redundant_reextension_test();
    check_upper32_identity_gate_test();
    check_redundant_flags_test();
    check_redundant_shift_test();
    check_lea_fold_test();
    check_mov_const_fold_test();
    check_load_extend_fold_test();
    check_mov_add_lea_test();
    check_shift_pair_extend_test();
    check_cmp_one_branch_test();
    check_setcc_branch_test();
    check_setcc_movzx_test();
    check_setcc_invert_test();
    check_popcnt_false_dep_test();
    check_sse_merge_false_dep_test();
    check_vex_merge_false_dep_test();
    check_scalar_move_false_dep_test();
    check_narrow_move_merge_test();
    check_missing_andn_test();
    check_missing_blsr_test();
    check_missing_blsmsk_test();
    check_missing_blsi_test();
    check_missing_shlx_test();
    check_missing_movbe_test();
    check_missing_apx_ndd_test();
    check_missing_apx_setzu_test();
    check_endbr64_target_test();
    check_decode_resync_test();
    summary_functions_test();
    census_test();

    // Integration sweep: one buffer through check_instructions, asserted per
    // category rather than as a bare total (a total alone lets one check
    // regress while another starts firing on the same bytes). The two NOPs
    // pin the disabled state of the in-sweep NOP check: re-enabling it shows
    // up as an unexpected extra finding.
    static const uint8_t inst[] = {
        0x90, 0x90,  // nop ; nop (no finding: the NOP check is disabled)
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, 0 (imm64 fits imm32; mov_zero flags only the composed imm32 form)
        0x05, 0x80, 0x00, 0x00, 0x00,  // add eax, 0x80 (-> sub eax, -128; CF dies at the cmp below)
        0x40, 0xc9,  // rex leave (the prefix does nothing)
        0x83, 0xff, 0x00,  // cmp edi, 0 (-> test edi, edi)
        0x81, 0xC0, 0x00, 0x01, 0x00, 0x00,  // add eax, 0x100 (modrm -> accumulator form)
        0x05, 0x01, 0x00, 0x00, 0x00,  // add eax, 1 (imm32 -> imm8; the inc rewrite stays gated: rcl reads CF)
        0xc1, 0xd0, 0x01,  // rcl eax, 1 (C1 ib -> D1)
        0x83, 0xe0, 0xff,  // and eax, -1 (-> test eax, eax)
        0x89, 0xc8,  // mov eax, ecx (32-bit kill: keeps the gated and eax, -1 firing)
        0xf0, 0x87, 0x07,  // lock xchg [rdi], eax (LOCK is implicit in XCHG)
        0x48, 0x8d, 0x47, 0x08,  // lea rax, [rdi+8] (-> lea eax, [rdi+8])
        0x89, 0xc8,  // mov eax, ecx (kills rax's bits 32-63 for the lea)
        0x66, 0x0f, 0xef, 0xc0,  // pxor xmm0, xmm0 (-> xorps xmm0, xmm0)
        0x66, 0x0f, 0x6f, 0xca,  // movdqa xmm1, xmm2 (-> movaps xmm1, xmm2)
        0xc4, 0xe1, 0x7d, 0x6f, 0xca,  // vmovdqa ymm1, ymm2 (C4 -> C5)
        0x62, 0xf1, 0xfd, 0x28, 0x6f, 0xca,  // vmovdqa64 ymm1, ymm2 (-> VEX vmovdqa)
    };
    static const struct {
        const char *name;
        int count;
    } expected[] = {
        {"oversized immediate",         2},  // mov rax, 0 and add eax, 1
        {"oversized ADD/SUB 128",       1},
        {"unneeded REX prefix",         1},
        {"suboptimal CMP zero",         1},
        {"unneeded explicit register",  1},
        {"unneeded explicit immediate", 1},
        {"redundant AND immediate",     1},
        {"unneeded LOCK prefix",        1},
        {"oversized LEA width",         1},
        {"suboptimal SSE zero idiom",   1},
        {"suboptimal SSE MOV opcode",   1},
        {"oversized VEX encoding",      1},
        {"oversized EVEX encoding",     1},
    };
    int status = 0;
    int expected_total = 0;
    int total = 0;
    for (size_t i = 0; i < sizeof(expected) / sizeof(expected[0]); ++i) {
        int count = count_findings(inst, sizeof(inst), expected[i].name,
                                   &total, 0);
        if (count != expected[i].count) {
            printf("Expected %d \"%s\" finding(s), actual: %d\n",
                   expected[i].count, expected[i].name, count);
            status = 1;
        }
        expected_total += expected[i].count;
    }
    // The total matching the per-category sum proves no unlisted category
    // fired anywhere in the buffer.
    if (total != expected_total) {
        printf("Expected %d findings in total, actual: %d\n",
               expected_total, total);
        status = 1;
    }

    return status;
}
