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

#ifndef X86LINT_H
#define X86LINT_H

#include <stdbool.h>
#include "xed/xed-interface.h"

// return false if instruction sequence contains multiple adjacent no ops
// (an undecodable byte ends the NOP run without a finding)
bool check_suboptimal_nops(const uint8_t *inst, size_t len);

// return false if instruction has an oversized immediate
bool check_oversized_immediate(const xed_decoded_inst_t *xedd);

// return false if test reg, imm carries an imm16/imm32 whose mask fits the
// low seven bits -- the byte-register form (test al, 1 etc.) sets identical
// flags in 2-4 fewer bytes
bool check_oversized_test_immediate(const xed_decoded_inst_t *xedd);

// return false if test reg, -1 (an all-ones mask at the operand width) could
// be test reg, reg, which sets identical flags in fewer bytes
bool check_test_minus_one(const xed_decoded_inst_t *xedd);

// return false if instruction encodes ADD REG, 128 / SUB REG, 128 (5-6 bytes)
// instead of the negated SUB REG, -128 / ADD REG, -128 (3 bytes)
bool check_oversized_add_sub_128(const xed_decoded_inst_t *xedd);

// return false if instruction has an unneeded rex prefix
bool check_unneeded_rex(const xed_decoded_inst_t *xedd);

// return false if instruction uses CMP 0 instead of TEST
bool check_cmp_zero(const xed_decoded_inst_t *xedd);

// return false if instruction zeros a register with mov instead of xor
bool check_mov_zero(const xed_decoded_inst_t *xedd);

// return false if instruction could use an implicit register encoding
bool check_implicit_register(const xed_decoded_inst_t *xedd);

// return false if instruction could use an implicit immediate encoding
bool check_implicit_immediate(const xed_decoded_inst_t *xedd);

// return false if instruction could use movzbl or movzwl instead of AND REG, IMM
bool check_and_strength_reduce(const xed_decoded_inst_t *xedd);

// return false if and reg, -1 (an all-ones mask at the operand width) could be
// test reg, reg, which sets identical flags in fewer bytes. The 32-bit form
// also zero-extends (GCC's fused zero-extend-and-test idiom), so the
// dispatcher gates it on upper-32 register liveness (cf. check_mov_self)
bool check_and_minus_one(const xed_decoded_inst_t *xedd);

// return false if xor r/m, -1 could be not r/m, one byte shorter (valid
// when the arithmetic flags are dead, since NOT writes none)
bool check_xor_to_not(const xed_decoded_inst_t *xedd);

// return false if or/xor reg, imm sets or flips -- or and reg, imm clears --
// a single bit at position 7 or above, where bts/btc/btr reg, imm8 is
// strictly shorter (valid when the arithmetic flags are dead: the bt family
// sets CF to the bit's original value and leaves SF/ZF/PF alone or undefined)
bool check_single_bit_immediate(const xed_decoded_inst_t *xedd);

// return false if instruction should have a LOCK prefix
bool check_missing_lock_prefix(const xed_decoded_inst_t *xedd);

// return false if instruction should not have a LOCK prefix
bool check_superfluous_lock_prefix(const xed_decoded_inst_t *xedd);

// return false if xchg with an accumulator uses the modrm form (87 /r)
// when the one-byte 90+r form would do
bool check_xchg_accumulator(const xed_decoded_inst_t *xedd);

// return false if a JMP or Jcc uses rel32 when rel8 would reach the target
bool check_oversized_branch(const xed_decoded_inst_t *xedd);

// return false if instruction is a no-op mov reg, reg. The 8/16/64-bit forms
// are pure no-ops; the mov r32, r32 form is a no-op only when its incidental
// zero-extension into the upper 32 bits is dead, which the dispatcher gates on
// register liveness (reg_upper32_live_after)
bool check_mov_self(const xed_decoded_inst_t *xedd);

// return false if instruction is add reg, 0 or sub reg, 0 (use TEST
// reg, reg instead for the flag side-effect, or remove the instruction
// if flags are unused). The 32-bit form also zero-extends, so the
// dispatcher gates it on upper-32 register liveness (cf. check_mov_self)
bool check_add_sub_zero(const xed_decoded_inst_t *xedd);

// return false if instruction is or reg, 0 or xor reg, 0 (no-ops that only
// set flags; use TEST reg, reg instead, or remove when flags are unused).
// The 32-bit form also zero-extends, so the dispatcher gates it on upper-32
// register liveness (cf. check_mov_self)
bool check_or_xor_zero(const xed_decoded_inst_t *xedd);

// return false if instruction is and reg, 0, which zeroes the register --
// xor reg, reg does the same with identical flags in fewer bytes
bool check_and_zero(const xed_decoded_inst_t *xedd);

// return false if add r/m, 1 / sub r/m, 1 (or the -1 forms, register or
// memory destination) could be inc / dec, which is one byte shorter (valid
// when CF is dead, since inc/dec leave CF unchanged)
bool check_inc_dec(const xed_decoded_inst_t *xedd);

// return false if a mov reg, imm uses the c6/c7 modrm form with a
// register destination when the b0/b8 +r form would be one byte shorter
bool check_mov_modrm_imm(const xed_decoded_inst_t *xedd);

// return false if instruction has a SIB byte that could be elided by
// encoding the addressing mode directly in modrm
bool check_unneeded_sib(const xed_decoded_inst_t *xedd);

// return false if instruction encodes a zero displacement that could be
// shortened (disp32=0 -> disp8=0, or disp8=0 -> no displacement)
bool check_unneeded_zero_displacement(const xed_decoded_inst_t *xedd);

// return false if instruction encodes a nonzero displacement as disp32
// when its value fits in a signed disp8 (EVEX instructions are skipped:
// their disp8 is compressed by a scale factor, so most small disp32
// values have no disp8 form)
bool check_oversized_displacement(const xed_decoded_inst_t *xedd);

// return false if movsxd rax, eax could be cdqe (cltq in AT&T)
bool check_unneeded_movsxd(const xed_decoded_inst_t *xedd);

// return false if movsx eax, ax could be cwde or movsx ax, al could be cbw
bool check_unneeded_movsx(const xed_decoded_inst_t *xedd);

// return false if sub reg, reg is used as a zero idiom -- xor reg, reg is
// the canonical form that CPUs recognize as dependency-breaking
bool check_sub_self(const xed_decoded_inst_t *xedd);

// return false if or reg, reg or and reg, reg is used as a flag test --
// test reg, reg is the canonical form and does not write the register.
// The 32-bit form's write also zero-extends, so the dispatcher gates it on
// upper-32 register liveness (cf. check_mov_self)
bool check_or_and_self(const xed_decoded_inst_t *xedd);

// return false if IMUL by a constant in {2,3,5,9} or a power of two could be
// replaced by a single LEA or SHL, or if the multiplier is degenerate:
// 0 -> XOR, 1 -> MOV (or removal when destination and source coincide,
// gated on upper-32 register liveness by the dispatcher), -1 in place -> NEG
bool check_imul_to_lea(const xed_decoded_inst_t *xedd);

// return false if lea dst, [base] (no index, zero displacement, base width
// matching the destination) could be mov dst, base
bool check_lea_to_mov(const xed_decoded_inst_t *xedd);

// return false if lea dst, [reg + reg2] (unit scale, no displacement,
// destination one of the two address registers) could be add dst, reg2, which
// is a byte shorter and issues on more ports (flag-gated: add writes flags)
bool check_lea_to_add(const xed_decoded_inst_t *xedd);

// return false if lea r64, [...] could be lea r32: the address's low 32 bits
// come out identical and dropping REX.W saves its byte (flagged only when W
// is the sole REX payload, so the prefix disappears). The narrowed form
// zeroes bits 32-63 of the destination where the original stores the
// address's upper half, so the dispatcher gates the finding on those bits
// being dead -- with no backward zero-extension escape: a predecessor's
// zeroing of the destination says nothing about the new address's upper half
bool check_oversized_lea_width(const xed_decoded_inst_t *xedd);

// return false if a shift or rotate instruction has an immediate count of 0
// (value- and flag-preserving per the Intel SDM; hardware still zero-extends
// a 32-bit destination even at count 0, so the dispatcher gates that form on
// upper-32 register liveness, cf. check_mov_self). Memory destinations are
// excluded: deleting the instruction deletes a memory access, whose faults,
// MMIO side effects, and write-back are observable regardless of the value
bool check_shift_zero(const xed_decoded_inst_t *xedd);

// return false if shl reg, 1 could be add reg, reg -- the same value with
// identical flags (CF and OF included) in the same or fewer bytes, on more
// execution ports; unconditional
bool check_shl_one(const xed_decoded_inst_t *xedd);

// return false if a legacy-encoded movapd/movdqa/movupd/movdqu could be
// movaps/movups, the identical copy without the one-byte 66/F3 prefix
bool check_sse_mov_opcode(const xed_decoded_inst_t *xedd);

// return false if a legacy-encoded self-XOR zeroing idiom -- pxor xmm, xmm or
// xorpd xmm, xmm -- could be xorps xmm, xmm, the identical zeroing without
// the one-byte 66 prefix (XOR is typeless; all three are rename-time zeroing
// idioms on every recent core, so no domain-bypass concern applies)
bool check_sse_zero_idiom(const xed_decoded_inst_t *xedd);

// return false if an EVEX-encoded instruction uses no EVEX-only feature
// (opmask, broadcast, rounding/SAE, 512-bit length, xmm16-31) and a VEX
// re-encoding is strictly shorter
bool check_oversized_evex(const xed_decoded_inst_t *xedd);

// return false if a VEX-encoded instruction uses the three-byte (C4) prefix
// where the two-byte (C5) form would do -- opcode map 0F, VEX.W clear, and no
// r8-r15 base/index/rm operand -- which wastes one byte
bool check_oversized_vex(const xed_decoded_inst_t *xedd);

// A by-type tally of findings accumulated across one or more
// check_instructions runs, so a driver can print a by-prevalence summary.
// Opaque; created and destroyed by the caller. A NULL summary is accepted
// everywhere (tallying is simply skipped).
typedef struct x86lint_summary x86lint_summary;

x86lint_summary *x86lint_summary_create(void);
void x86lint_summary_destroy(x86lint_summary *summary);

// Print the findings grouped by type, most prevalent first.
void x86lint_summary_print(const x86lint_summary *summary);

// Total instructions decoded across the runs tallied into this summary.
// Returns 0 for a NULL summary.
size_t x86lint_summary_instructions(const x86lint_summary *summary);

// Total undecodable bytes skipped across the runs tallied into this summary.
// Nonzero means the input interleaves data with code (common in Go binaries
// and jump tables), so coverage was incomplete. Returns 0 for a NULL summary.
size_t x86lint_summary_skipped(const x86lint_summary *summary);

// return number of failed checks. An undecodable byte is not fatal: linear
// sweep skips it and resyncs (executable sections routinely embed data).
// Skipped bytes are only tallied into the summary, never printed -- a stripped
// binary with data in its code section can skip hundreds of thousands of
// bytes. In verbose mode each finding is printed as a one-line summary
// followed by its offending encoding; otherwise nothing is printed per finding
// (the caller's summary is the whole report). If summary is non-NULL, every
// finding is tallied into it by type and the decoded-instruction and
// skipped-byte counts are accumulated.
int check_instructions(const uint8_t *inst, size_t len, bool verbose,
                       x86lint_summary *summary);

#endif
