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

// cohere: measure whether per-instruction "coherence" separates real
// instructions from phantom decodes of data-in-text, to decide whether
// the ISA census (-i) can label its tallies. Two candidate signals:
//
// Run length. A *run* is a maximal stretch of consecutively decoded
// instructions, broken by an undecodable byte (the sweep skips one byte
// and resyncs, exactly like the census) or a range boundary. Runs are a
// weak signal on their own: GHC info tables frequently decode cleanly
// end to end, so a single run spans both the junk decoded from a table
// and the real entry code after it -- a run-granular verdict cannot
// split that sandwich, and gap adjacency condemns everything in a
// binary with thousands of gaps.
//
// Self-synchronization consensus. x86 decoding re-converges onto the
// true instruction boundaries within a few instructions from any
// misaligned start; the hope was that data produces phase-dependent
// boundaries instead. For each swept instruction at offset o, three
// walks start at o-17, o-18, and o-19 -- far enough back to allow a few
// instructions of resync, at three different misalignments -- and each
// walk steps by decoded length (one byte over undecodable slots,
// mirroring the sweep) until it reaches or passes o. The instruction's
// vote count is how many of the three land exactly on o. Walks clamped
// at a range start begin on a true boundary and vote yes trivially;
// only the first few instructions of a range are affected.
//
// Per isa-set the tool prints the tally, its run-length spread, and the
// 3/3-consensus count, with one sample site from a short and a long run.
//
// MEASURED OUTCOME (2026-08, against ground truth: x87 in libm = real,
// x87 in a GHC binary = phantom info-table decodes, OpenSSL perlasm =
// real crypto interleaved with constant pools): every cheap signal here
// FAILS to separate.
//
//   run length      77% of the GHC binary's phantom x87 sits in runs of
//                   16+ instructions -- info tables decode cleanly, so
//                   one run spans the junk AND the real entry code
//                   after it, and no run-granular verdict can split
//                   that sandwich.
//   gap adjacency   with 220k undecodable bytes sprinkled through the
//                   binary, 99.99% of everything -- real code included
//                   -- is in a gap-bounded run.
//   consensus       phantom x87 scores 92% full consensus vs. 96% for
//                   libm's real x87: self-synchronization is a property
//                   of the DECODER, not of real code -- junk converges
//                   onto its own stable boundary chain just as readily.
//                   The metric even punishes real long-instruction code
//                   (libavutil's AVX: 82%), because it measures resync
//                   distance, not code-ness.
//
// What did separate, on every ground-truth case, is toolchain EVIDENCE:
// .symtab STT_FUNC ranges and .eh_frame FDE pc-ranges. Every phantom
// site tested (GHC info tables, ChromeOS libcrypto's constant-pool
// 3DNOW/VTX/APX singletons) lies outside all FDEs; every real site
// tested lies inside one -- including OpenSSL's XOP tally, which this
// exploration had wrongly presumed phantom until the FDE said
// otherwise. Coverage quality varies by build (Fedora libcrypto: 11810
// FDEs covering the text; a ChromeOS build: 259 covering a quarter;
// GHC: none for Haskell code), so evidence can label tallies
// asymmetrically -- inside-evidence lends trust, outside-evidence means
// "no toolchain claim", never "phantom" -- and must report its own
// coverage. That labeling, not any coherence heuristic, is the census
// extension this tool argues for.
//
// Usage: cohere [-t TOP] <binary>...
//   -t  print only the TOP most tallied isa-sets (default 24)

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xed/xed-interface.h"

#include "corpus.h"

#define RUN_MAX_INSTS 65536     // per-run instruction records kept
#define CONSENSUS_WALKS 3
#define CONSENSUS_BACK 17       // first walk starts this many bytes back

// Length-class edges for the report: 1-3, 4-15, 16-63, 64+.
static int len_class(size_t n)
{
    if (n < 4) {
        return 0;
    }
    if (n < 16) {
        return 1;
    }
    if (n < 64) {
        return 2;
    }
    return 3;
}

struct set_stats {
    size_t total;
    size_t by_len[4];
    size_t coh;         // full-consensus instructions (3/3 walks agree)
    uint64_t sample[2]; // first sites: one from a short run, one from a long
    bool have_sample[2];
};

struct cohere_ctx {
    struct set_stats sets[XED_ISA_SET_LAST];
    size_t runs_by_len[4];
    size_t insts_by_len[4];
    size_t instructions;
    size_t skipped;
};

// One decoded instruction pending its run's length class.
struct pending {
    xed_isa_set_enum_t set;
    uint64_t vaddr;
    bool coherent;
};

static void flush_run(struct cohere_ctx *ctx, const struct pending *insts,
                      size_t n)
{
    if (n == 0) {
        return;
    }
    int lc = len_class(n);
    ctx->runs_by_len[lc]++;
    ctx->insts_by_len[lc] += n;
    for (size_t i = 0; i < n; ++i) {
        struct set_stats *st = &ctx->sets[insts[i].set];
        st->total++;
        st->by_len[lc]++;
        if (insts[i].coherent) {
            st->coh++;
        }
        int which = lc <= 1 ? 0 : 1;
        if (!st->have_sample[which]) {
            st->have_sample[which] = true;
            st->sample[which] = insts[i].vaddr;
        }
    }
}

// How many of the misaligned walks land exactly on `off`. `steps` holds
// the byte advance from every offset of the range (decoded length, or 1
// over an undecodable slot).
static int consensus_votes(const uint8_t *steps, uint64_t range_start,
                           uint64_t off)
{
    int votes = 0;
    for (int j = 0; j < CONSENSUS_WALKS; ++j) {
        uint64_t back = CONSENSUS_BACK + (uint64_t) j;
        uint64_t p = off - range_start >= back ? off - back : range_start;
        while (p < off) {
            p += steps[p - range_start];
        }
        if (p == off) {
            ++votes;
        }
    }
    return votes;
}

static void scan_section(const corpus_section *sec, void *arg)
{
    struct cohere_ctx *ctx = arg;
    struct pending *insts = malloc(RUN_MAX_INSTS * sizeof(*insts));
    if (insts == NULL) {
        return;
    }

    for (size_t r = 0; r < sec->nranges; ++r) {
        uint64_t start = sec->ranges[r].start;
        uint64_t end = sec->ranges[r].end;
        if (end <= start) {
            continue;
        }

        // Prepass: the byte advance from every offset, so the consensus
        // walks need no further decoding.
        uint8_t *steps = malloc(end - start);
        if (steps == NULL) {
            break;
        }
        for (uint64_t off = start; off < end; ++off) {
            xed_decoded_inst_t xedd;
            corpus_decode_init(&xedd);
            steps[off - start] =
                xed_decode(&xedd, sec->code + off, end - off) ==
                    XED_ERROR_NONE
                ? (uint8_t) xed_decoded_inst_get_length(&xedd)
                : 1;
        }

        uint64_t off = start;
        size_t n = 0;
        while (off < end) {
            xed_decoded_inst_t xedd;
            corpus_decode_init(&xedd);
            if (xed_decode(&xedd, sec->code + off, end - off) !=
                XED_ERROR_NONE) {
                flush_run(ctx, insts, n);
                n = 0;
                ++off;
                ctx->skipped++;
                continue;
            }
            if (n == RUN_MAX_INSTS) {
                // A run past the cap is certainly real code; flush what
                // is buffered as a long run and keep counting fresh.
                flush_run(ctx, insts, n);
                n = 0;
            }
            insts[n].set = xed_decoded_inst_get_isa_set(&xedd);
            insts[n].vaddr = sec->vaddr + off;
            insts[n].coherent =
                consensus_votes(steps, start, off) == CONSENSUS_WALKS;
            ++n;
            ctx->instructions++;
            off += xed_decoded_inst_get_length(&xedd);
        }
        flush_run(ctx, insts, n);
        free(steps);
    }

    free(insts);
}

int main(int argc, char **argv)
{
    int top = 24;
    int argi = 1;
    if (argi + 1 < argc && strcmp(argv[argi], "-t") == 0) {
        top = atoi(argv[argi + 1]);
        argi += 2;
    }
    if (argi >= argc) {
        fprintf(stderr, "usage: %s [-t TOP] <binary>...\n", argv[0]);
        return 2;
    }

    xed_tables_init();

    for (; argi < argc; ++argi) {
        struct cohere_ctx *ctx = calloc(1, sizeof(*ctx));
        if (ctx == NULL) {
            return 2;
        }
        // Whole sections, exactly the stream the census scans.
        if (corpus_scan_file(argv[argi], /*scan_all=*/true, scan_section,
                             ctx) != 0) {
            free(ctx);
            return 2;
        }

        printf("=== %s: %zu instructions, %zu undecodable bytes ===\n",
            argv[argi], ctx->instructions, ctx->skipped);
        printf("runs by length: 1-3: %zu (%zu insts), 4-15: %zu (%zu), "
            "16-63: %zu (%zu), 64+: %zu (%zu)\n",
            ctx->runs_by_len[0], ctx->insts_by_len[0],
            ctx->runs_by_len[1], ctx->insts_by_len[1],
            ctx->runs_by_len[2], ctx->insts_by_len[2],
            ctx->runs_by_len[3], ctx->insts_by_len[3]);
        printf("%-22s %9s %8s %8s %8s %9s %6s  samples short|long\n",
            "isa-set", "total", "<16", "16-63", "64+", "coh3", "coh%");

        int order[XED_ISA_SET_LAST];
        int nsets = 0;
        for (int s = 0; s < XED_ISA_SET_LAST; ++s) {
            if (ctx->sets[s].total != 0) {
                order[nsets++] = s;
            }
        }
        for (int i = 1; i < nsets; ++i) {
            int key = order[i];
            int j = i - 1;
            while (j >= 0 &&
                   ctx->sets[order[j]].total < ctx->sets[key].total) {
                order[j + 1] = order[j];
                --j;
            }
            order[j + 1] = key;
        }

        for (int i = 0; i < nsets && i < top; ++i) {
            const struct set_stats *st = &ctx->sets[order[i]];
            printf("%-22s %9zu %8zu %8zu %8zu %9zu %5.1f%%  ",
                xed_isa_set_enum_t2str((xed_isa_set_enum_t) order[i]),
                st->total, st->by_len[0] + st->by_len[1], st->by_len[2],
                st->by_len[3], st->coh,
                100.0 * (double) st->coh / (double) st->total);
            if (st->have_sample[0]) {
                printf("0x%" PRIx64, st->sample[0]);
            } else {
                printf("-");
            }
            printf("|");
            if (st->have_sample[1]) {
                printf("0x%" PRIx64, st->sample[1]);
            } else {
                printf("-");
            }
            printf("\n");
        }
        free(ctx);
    }
    return 0;
}
