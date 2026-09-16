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

// shapescan: size a named candidate with the rewrite's own conditions
// applied, and say what refused the rest.
//
// pairscan ranks every adjacent pair by a normalized shape to discover what
// is frequent; defuse profiles how far a value's use sits from its
// definition. Neither asks whether a specific rewrite is actually available
// at a site, and that is the question a TODO row turns on. Measuring it ad
// hoc is what this tool exists to stop. The 2026-09 armlint port was sized
// four times with throwaway scripts and was wrong four times:
//
//     LOCK CMPXCHG fetch-op loop      614 shape  ->      19 findings
//     vector memory-operand fold    9,279 shape  ->     583 findings
//     GPR load into a vector move     470 shape  ->      12 findings
//     adjacent zero stores         ~6,000 pairs  ->  20,870 runs
//
// Three overstated the rewrite because a condition went unapplied; the
// fourth counted the wrong unit. A fifth estimate ran the other way, high,
// because its liveness model was a regular expression over disassembly where
// the check uses inst_reads_reg64.
//
// Two decisions follow from that, and they are the whole design.
//
// **A candidate is a draft check, not a description of one.** Every
// candidate above needed operand-role matching, register-family comparison
// across widths, branch-displacement arithmetic, memory-operand
// decomposition, encodability decided by re-encoding through XED, or a
// forward liveness walk. None of that is expressible as a pattern language
// short of a real one, so candidates are C predicates with the same shape as
// x86lint's window checks -- which is why this file includes x86lint.c and
// calls the shipped ones directly. A candidate that earns its place is then
// moved into x86lint.c rather than reimplemented, and a shipped one keeps
// being measured by the code that realizes it.
//
// This is also why the counts here are the driver's and not an
// approximation of them: the same masking of non-function bytes, the same
// branch-target prepass, the same decode loop and resync. A shipped
// candidate must report exactly what x86lint reports, which is this tool's
// own regression test.
//
// **A count without a reason is what went wrong before.** Each candidate
// reports three things: how often the pattern matched at all, how often the
// rewrite was available, and which gate refused the difference. The middle
// number is the finding count; the third is what makes it mean something.
// "9,298 sites become 583" is a fact to be puzzled over; "6,670 of them read
// the loaded register again, because a vector constant lives in a register
// precisely when it is reused" is the answer, and only the breakdown says it.
//
// Usage: shapescan [-a] [-e NAME] [-n MAX] <binary>...
//   -a  scan every byte, not just the symbol table's function ranges
//   -e  print example sites for the candidate whose name contains NAME
//   -n  cap the examples printed (default 8)

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// For the shipped window checks and the gates they call, all of which are
// static: reimplementing them here is exactly the error the tool exists to
// prevent, and widening the public header for internal helpers would be a
// worse trade than one include in one tool.
#include "../x86lint.c"

#include "corpus.h"

#define MAX_REASONS 8

struct tally {
    unsigned long shape;        // the pattern matched
    unsigned long realized;     // and every gate passed
    struct {
        const char *why;        // interned: the gate's own literal
        unsigned long n;
    } refused[MAX_REASONS];
    size_t nrefused;
};

static void tally_refusal(struct tally *t, const char *why)
{
    for (size_t i = 0; i < t->nrefused; ++i) {
        if (t->refused[i].why == why) {
            ++t->refused[i].n;
            return;
        }
    }
    if (t->nrefused < MAX_REASONS) {
        t->refused[t->nrefused].why = why;
        t->refused[t->nrefused].n = 1;
        ++t->nrefused;
    }
}

// A window candidate, called once per decoded instruction with that
// instruction as the window's head. Returns true when the rewrite is
// available; leaves *why untouched when the pattern did not match and sets
// it to the refusing gate's name when it did.
typedef bool (*window_fn)(const uint8_t *inst, size_t len,
                          const uint8_t *targets, size_t offset, size_t next,
                          const xed_decoded_inst_t *xedd, const char **why);

// A run candidate owns its own iteration, for a pattern whose length is not
// fixed. See zero_store_runs.
typedef void (*run_fn)(const uint8_t *inst, size_t len,
                       const uint8_t *targets, struct tally *t,
                       const char *path, uint64_t vaddr,
                       const char *example, long *left);

struct candidate {
    const char *name;
    const char *rewrite;
    window_fn window;
    run_fn run;
};

// === window candidates: the shipped checks, measured as themselves ===

static bool w_vecop(const uint8_t *inst, size_t len, const uint8_t *targets,
                    size_t offset, size_t next, const xed_decoded_inst_t *d,
                    const char **why)
{
    (void) offset;
    return load_foldable_into_vecop(inst, len, targets, next, d, why);
}

static bool w_vec_transfer(const uint8_t *inst, size_t len,
                           const uint8_t *targets, size_t offset, size_t next,
                           const xed_decoded_inst_t *d, const char **why)
{
    (void) offset;
    return load_foldable_into_vec_transfer(inst, len, targets, next, d, why);
}

static bool w_cas(const uint8_t *inst, size_t len, const uint8_t *targets,
                  size_t offset, size_t next, const xed_decoded_inst_t *d,
                  const char **why)
{
    return cas_fetch_op_loop(inst, len, targets, offset, next, d, why);
}

// === run candidate: adjacent immediate-zero stores (issue #30) ===

// Decode one `mov <width> PTR [base+index*scale+disp], 0` and report the
// address it writes. Anything else ends the run.
static bool zero_store(const xed_decoded_inst_t *x, xed_reg_enum_t *base,
                       xed_reg_enum_t *index, unsigned *scale,
                       int64_t *disp, unsigned *width)
{
    if (xed_decoded_inst_get_iclass(x) != XED_ICLASS_MOV ||
        xed_decoded_inst_number_of_memory_operands(x) != 1 ||
        !xed_decoded_inst_mem_written(x, 0) ||
        !xed_operand_values_has_immediate(
            xed_decoded_inst_operands_const(x)) ||
        xed_decoded_inst_get_unsigned_immediate(x) != 0) {
        return false;
    }
    *base = xed_decoded_inst_get_base_reg(x, 0);
    *index = xed_decoded_inst_get_index_reg(x, 0);
    *scale = xed_decoded_inst_get_scale(x, 0);
    *disp = xed_decoded_inst_get_memory_displacement(x, 0);
    *width = xed_decoded_inst_get_memory_operand_length(x, 0);
    return *width != 0;
}

// Maximal runs of immediate-zero stores covering a contiguous byte range off
// one base, in either direction and at mixed widths. Counting runs rather
// than pairs is the correction issue #30 records: an eight-store run is one
// opportunity and not seven, and pairing by matching width misses every
// mixed-width run.
//
// "Realized" is the conservative arm alone -- merge up to eight bytes with
// `MOV QWORD PTR, 0` and never allocate a register -- since the wider merge
// wants a zeroed vector register the surrounding code may not have.
static void zero_store_runs(const uint8_t *inst, size_t len,
                            const uint8_t *targets, struct tally *t,
                            const char *path, uint64_t vaddr,
                            const char *example, long *left)
{
    size_t n = 0, run_start = 0;
    xed_reg_enum_t rbase = XED_REG_INVALID, rindex = XED_REG_INVALID;
    unsigned rscale = 0;
    int64_t lo = 0, hi = 0;
    bool side_entry = false;

    for (size_t offset = 0; offset <= len;) {
        xed_decoded_inst_t xedd;
        bool ok = false;
        xed_reg_enum_t base = XED_REG_INVALID, index = XED_REG_INVALID;
        unsigned scale = 0, width = 0;
        int64_t disp = 0;
        size_t next = offset;

        if (offset < len) {
            decode_init(&xedd);
            if (xed_decode(&xedd, inst + offset, len - offset) ==
                    XED_ERROR_NONE) {
                next = offset + xed_decoded_inst_get_length(&xedd);
                ok = zero_store(&xedd, &base, &index, &scale, &disp, &width);
            } else {
                next = offset + 1;
            }
        }

        bool extends = ok && n > 0 && base == rbase && index == rindex &&
            scale == rscale && (disp == hi || disp + (int64_t) width == lo);
        if (extends) {
            if (disp == hi) {
                hi = disp + (int64_t) width;
            } else {
                lo = disp;
            }
            ++n;
            side_entry |= branch_target_in(targets, offset, next);
        } else {
            if (n >= 2) {          // close the run
                ++t->shape;
                int64_t span = hi - lo;
                if (side_entry) {
                    tally_refusal(t, "a branch enters the run");
                } else if (span <= 2) {
                    tally_refusal(t,
                        "a 2-byte span would need an LCP imm16");
                } else if (span > 8) {
                    tally_refusal(t,
                        "over 8 bytes: needs a zero vector register");
                } else {
                    ++t->realized;
                    if (example != NULL && *left > 0) {
                        printf("  %s+0x%" PRIx64 ": %zu zero stores, %"
                            PRId64 " bytes\n", path, vaddr + run_start, n,
                            span);
                        --*left;
                    }
                }
            }
            if (ok) {
                n = 1; run_start = offset; rbase = base; rindex = index;
                rscale = scale; lo = disp; hi = disp + (int64_t) width;
                side_entry = branch_target_in(targets, offset, next);
            } else {
                n = 0;
            }
        }
        if (offset >= len) {
            break;
        }
        offset = next;
    }
}

static const struct candidate candidates[] = {
    { "CAS loop foldable into LOCK op", "LOCK OR/AND/XOR",
      w_cas, NULL },
    { "load foldable into vector op", "fold the load into the SIMD operand",
      w_vecop, NULL },
    { "load foldable into vector transfer", "MOVD/CVTSI2SD xmm, [mem]",
      w_vec_transfer, NULL },
    { "adjacent zero-store run (#30)", "one wider store",
      NULL, zero_store_runs },
};

#define NCAND (sizeof(candidates) / sizeof(candidates[0]))

struct file_result {
    const char *path;
    unsigned long instructions;
    struct tally t[NCAND];
};

struct scan_ctx {
    struct file_result *fr;
    const char *example;        // candidate name substring, or NULL
    long left;                  // examples still to print
};

// Mirror the driver's own scan over one section: mask the bytes outside the
// function ranges the way main.c does, collect branch targets over exactly
// those bytes, then walk instructions with the same decode and resync. A
// shipped candidate must come out equal to what x86lint reports, and it only
// does if the corpus is identical byte for byte.
static void scan_section(const corpus_section *sec, void *vctx)
{
    struct scan_ctx *ctx = vctx;
    uint8_t *buf = malloc(sec->size);
    if (buf == NULL) {
        return;
    }
    memset(buf, 0xCC, sec->size);       // INT3, as the driver's mask uses
    for (size_t r = 0; r < sec->nranges; ++r) {
        memcpy(buf + sec->ranges[r].start, sec->code + sec->ranges[r].start,
            sec->ranges[r].end - sec->ranges[r].start);
    }
    uint8_t *targets = collect_branch_targets(buf, sec->size);

    for (size_t i = 0; i < NCAND; ++i) {
        if (candidates[i].run == NULL) {
            continue;
        }
        bool want = ctx->example != NULL &&
            strstr(candidates[i].name, ctx->example) != NULL;
        candidates[i].run(buf, sec->size, targets, &ctx->fr->t[i], sec->path,
            sec->vaddr, want ? ctx->example : NULL, &ctx->left);
    }

    for (size_t offset = 0; offset < sec->size;) {
        xed_decoded_inst_t xedd;
        decode_init(&xedd);
        if (xed_decode(&xedd, buf + offset, sec->size - offset) !=
                XED_ERROR_NONE) {
            offset += 1;
            continue;
        }
        ++ctx->fr->instructions;
        size_t next = offset + xed_decoded_inst_get_length(&xedd);

        for (size_t i = 0; i < NCAND; ++i) {
            if (candidates[i].window == NULL) {
                continue;
            }
            const char *why = NULL;
            bool hit = candidates[i].window(buf, sec->size, targets, offset,
                next, &xedd, &why);
            if (!hit && why == NULL) {
                continue;               // the pattern did not match
            }
            ++ctx->fr->t[i].shape;
            if (hit) {
                ++ctx->fr->t[i].realized;
                if (ctx->example != NULL && ctx->left > 0 &&
                    strstr(candidates[i].name, ctx->example) != NULL) {
                    char text[128];
                    xed_format_context(XED_SYNTAX_INTEL, &xedd, text,
                        sizeof(text), sec->vaddr + offset, NULL, NULL);
                    printf("  %s+0x%" PRIx64 ": %s\n", sec->path,
                        sec->vaddr + offset, text);
                    --ctx->left;
                }
            } else {
                tally_refusal(&ctx->fr->t[i], why);
            }
        }
        offset = next;
    }
    free(targets);
    free(buf);
}

static void report(const struct file_result *fr, size_t nfr)
{
    const int w = 56;
    printf("%-*s", w, "instructions scanned");
    for (size_t f = 0; f < nfr; ++f) {
        printf("%12lu", fr[f].instructions);
    }
    printf("%12s\n", "TOTAL");

    for (size_t i = 0; i < NCAND; ++i) {
        unsigned long shape = 0, real = 0;
        for (size_t f = 0; f < nfr; ++f) {
            shape += fr[f].t[i].shape;
            real += fr[f].t[i].realized;
        }
        printf("\n%s\n  -> %s\n", candidates[i].name, candidates[i].rewrite);
        printf("  %-*s", w - 2, "shape");
        for (size_t f = 0; f < nfr; ++f) {
            printf("%12lu", fr[f].t[i].shape);
        }
        printf("%12lu\n", shape);
        printf("  %-*s", w - 2, "realized");
        for (size_t f = 0; f < nfr; ++f) {
            printf("%12lu", fr[f].t[i].realized);
        }
        printf("%12lu\n", real);

        // Refusal reasons, unioned across files so every column lines up.
        const char *seen[MAX_REASONS * 4];
        size_t nseen = 0;
        for (size_t f = 0; f < nfr; ++f) {
            for (size_t r = 0; r < fr[f].t[i].nrefused; ++r) {
                const char *why = fr[f].t[i].refused[r].why;
                bool dup = false;
                for (size_t s = 0; s < nseen; ++s) {
                    dup |= seen[s] == why;
                }
                if (!dup && nseen < sizeof(seen) / sizeof(seen[0])) {
                    seen[nseen++] = why;
                }
            }
        }
        for (size_t s = 0; s < nseen; ++s) {
            char label[64];
            snprintf(label, sizeof(label), "refused: %s", seen[s]);
            printf("  %-*s", w - 2, label);
            unsigned long tot = 0;
            for (size_t f = 0; f < nfr; ++f) {
                unsigned long n = 0;
                for (size_t r = 0; r < fr[f].t[i].nrefused; ++r) {
                    if (fr[f].t[i].refused[r].why == seen[s]) {
                        n = fr[f].t[i].refused[r].n;
                    }
                }
                printf("%12lu", n);
                tot += n;
            }
            printf("%12lu\n", tot);
        }
    }
}

static void usage(const char *argv0)
{
    fprintf(stderr, "usage: %s [-a] [-e NAME] [-n MAX] <binary>...\n", argv0);
}

int main(int argc, char **argv)
{
    bool scan_all = false;
    const char *example = NULL;
    long nexamples = 8;
    int argi = 1;
    for (; argi < argc && argv[argi][0] == '-' && argv[argi][1] != '\0';
         ++argi) {
        if (strcmp(argv[argi], "-a") == 0) {
            scan_all = true;
        } else if (strcmp(argv[argi], "-e") == 0 && argi + 1 < argc) {
            example = argv[++argi];
        } else if (strcmp(argv[argi], "-n") == 0 && argi + 1 < argc) {
            nexamples = atol(argv[++argi]);
        } else {
            usage(argv[0]);
            return 2;
        }
    }
    if (argi >= argc) {
        usage(argv[0]);
        return 2;
    }

    xed_tables_init();
    xed_set_verbosity(0);

    size_t nfr = (size_t) (argc - argi);
    struct file_result *fr = calloc(nfr, sizeof(*fr));
    if (fr == NULL) {
        fprintf(stderr, "failed to allocate results\n");
        return 2;
    }

    int rc = 0;
    for (size_t f = 0; f < nfr; ++f) {
        fr[f].path = argv[argi + (int) f];
        struct scan_ctx ctx = { &fr[f], example, nexamples };
        if (corpus_scan_file(fr[f].path, scan_all, scan_section, &ctx) != 0) {
            rc = 2;
        }
        nexamples = ctx.left;
    }

    if (example == NULL) {
        report(fr, nfr);
    }
    free(fr);
    return rc;
}
