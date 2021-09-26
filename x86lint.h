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

// return number of failed checks
int check_instructions(const uint8_t *inst, size_t len);

#endif
