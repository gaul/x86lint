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

#ifndef __ASMLINT_H__
#define __ASMLINT_H__

#include <stdbool.h>
#include "xed/xed-interface.h"

// return false if instruction sequence contains multiple adjacent no ops
bool check_suboptimal_nops(const uint8_t *inst, size_t len);

// return false if instruction has an oversized immediate
bool check_oversized_immediate(const xed_decoded_inst_t *xedd);

// return false if instruction encodes ADD REG, 128 (5 bytes) instead of SUB REG, -128 (3 bytes)
bool check_oversized_add128(const xed_decoded_inst_t *xedd);

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

// return false if instruction could use movzbl, movzwl, or mov instead of AND REG, IMM
bool check_and_strength_reduce(const xed_decoded_inst_t *xedd);

// return false if instruction should have a LOCK prefix
bool check_missing_lock_prefix(const xed_decoded_inst_t *xedd);

// return false if instruction should not have a LOCK prefix
bool check_superfluous_lock_prefix(const xed_decoded_inst_t *xedd);

// return false if a JMP or Jcc uses rel32 when rel8 would reach the target
bool check_oversized_branch(const xed_decoded_inst_t *xedd);

// return false if instruction is a no-op mov reg, reg (excluding the
// mov r32, r32 zero-extension idiom)
bool check_mov_self(const xed_decoded_inst_t *xedd);

// return false if instruction is add reg, 0 or sub reg, 0 (use TEST
// reg, reg instead for the flag side-effect, or remove the instruction
// if flags are unused)
bool check_add_zero(const xed_decoded_inst_t *xedd);

// return false if a mov reg, imm uses the c6/c7 modrm form with a
// register destination when the b0/b8 +r form would be one byte shorter
bool check_mov_modrm_imm(const xed_decoded_inst_t *xedd);

// return false if instruction has a SIB byte that could be elided by
// encoding the addressing mode directly in modrm
bool check_unneeded_sib(const xed_decoded_inst_t *xedd);

// return false if instruction encodes a zero displacement that could be
// shortened (disp32=0 -> disp8=0, or disp8=0 -> no displacement)
bool check_unneeded_zero_displacement(const xed_decoded_inst_t *xedd);

// return false if movsxd rax, eax could be cdqe (cltq in AT&T)
bool check_unneeded_movsxd(const xed_decoded_inst_t *xedd);

// return false if sub reg, reg is used as a zero idiom -- xor reg, reg is
// the canonical form that CPUs recognize as dependency-breaking
bool check_sub_self(const xed_decoded_inst_t *xedd);

// return false if IMUL by a constant in {2,3,4,5,8,9} could be replaced
// by a single LEA (or SHL for powers of two)
bool check_imul_to_lea(const xed_decoded_inst_t *xedd);

// return number of failed checks
int check_instructions(const uint8_t *inst, size_t len);

#endif
