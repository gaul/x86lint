/*
 * Copyright 2026 Andrew Gaul <andrew@gaul.org>
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

#ifndef X86LINT_TOOLS_CORPUS_H
#define X86LINT_TOOLS_CORPUS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "xed/xed-interface.h"

// Corpus walking shared by the mining tools (tools/pairscan, tools/defuse):
// mapping a 64-bit x86 ELF file, finding its executable sections, splitting
// each into the straight-line ranges worth scanning, and marking the direct
// branch targets inside it. Both tools must agree on all of this -- a pair
// statistic and a def-use distance measured over different byte ranges cannot
// be compared -- so it lives in one place rather than being duplicated per
// tool.

// A half-open byte range within a section, in section-relative offsets.
typedef struct {
    uint64_t start;
    uint64_t end;
} corpus_range;

typedef struct {
    const char *path;
    const uint8_t *code;        // the section's bytes
    size_t size;
    uint64_t vaddr;             // sh_addr, so a site can be printed as a vaddr
    const uint8_t *targets;     // direct-branch-target bitmap, one bit per byte
    const corpus_range *ranges; // the ranges to scan, ascending and disjoint
    size_t nranges;
    bool by_symbol;             // ranges came from the symbol table
} corpus_section;

// Invoked once per executable section.
typedef void (*corpus_section_fn)(const corpus_section *sec, void *ctx);

// Machine mode and input chip every decode in the tools must share, matching
// x86lint.c's decode_init: the branch-target prepass and the scan proper have
// to see identical instruction boundaries, and XED_CHIP_ALL keeps chip-gated
// encodings from being misread as their legacy aliases.
void corpus_decode_init(xed_decoded_inst_t *xedd);

// True when a direct branch lands on section-relative byte `off`. A NULL map
// (allocation failure) reads as every byte targeted, which makes the callers
// reset their tracking everywhere rather than trust stale state.
bool corpus_is_target(const uint8_t *targets, size_t off);

// True when the instruction's register write is conditional, so the
// destination's prior value survives whenever the condition does not hold.
//
// XED models CMOVcc's destination as a plain write (read=0, written=1), which
// is right about the encoding and wrong about the dataflow: a tool trusting it
// reads mov rdx, X ; cmovnz rdx, rax as an overwrite that kills the mov, when
// the mov's value is exactly what the not-taken move keeps. Both tools
// therefore add a conditional writer's destination to its read set, and
// x86lint.c's reg_kill_iclass excludes the same instructions from its kills
// for the same reason. Merge-masked vector writes are conditional in the same
// way and are not covered here; the tools measure GPR dataflow.
bool corpus_conditional_write(const xed_decoded_inst_t *xedd);

// Map `path` and invoke `fn` once per SHT_PROGBITS + SHF_EXECINSTR section.
//
// Coverage mirrors x86lint's driver: with a symbol table present, each
// section is split into the byte ranges its STT_FUNC symbols declare, so the
// scan sees code and not the non-code that executable sections interleave --
// jump tables, GHC info tables, alignment padding -- much of which decodes
// cleanly and would otherwise contribute pair counts and def-use distances
// from bytes that are not instructions. Unsized symbols extend to the next
// function's start; overlapping ranges (aliased symbols) are merged so no
// byte is scanned twice. `scan_all` forces whole-section ranges, which is
// also what a stripped binary gets.
//
// Returns 0 on success and -1 on failure, after printing the reason.
int corpus_scan_file(const char *path, bool scan_all, corpus_section_fn fn,
                     void *ctx);

#endif
