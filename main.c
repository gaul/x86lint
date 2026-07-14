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

#include <elf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "x86lint.h"

static bool read_at(FILE *f, long off, void *buf, size_t n)
{
    if (fseek(f, off, SEEK_SET) != 0) {
        return false;
    }
    return fread(buf, 1, n, f) == n;
}

// A defined function symbol's coverage, from the ELF symbol table.
struct func_sym {
    uint64_t value;     // st_value: a vaddr, or a section offset in ET_REL
    uint64_t size;      // st_size: 0 for an unsized assembly label
    uint16_t shndx;     // st_shndx: the holding section, for ET_REL matching
};

struct func_range {
    uint64_t start;
    uint64_t end;
};

static int func_range_cmp(const void *a, const void *b)
{
    const struct func_range *ra = a, *rb = b;
    if (ra->start != rb->start) {
        return ra->start < rb->start ? -1 : 1;
    }
    return 0;
}

// Overwrite every byte of a section's copy that lies outside the symbol
// table's function ranges with 0x06, an opcode invalid in 64-bit mode: the
// scan's decode-and-resync loop then skips those bytes and tallies them as
// undecodable, surfacing the excluded volume in the summary's skipped count.
// Executable sections routinely interleave non-code that DECODES cleanly --
// GHC info tables, LLVM's constexpr tables, jump tables -- which that counter
// alone cannot flag; when the binary says where its functions are, scanning
// only there removes the pseudo-instruction findings at the source (a /bin
// audit found every degenerate-IMUL "finding" inside shellcheck's GHC info
// tables). A function symbol with size 0 -- an unsized assembly label --
// extends to the next function's start, or the section end: coverage errs
// toward keeping bytes, so code is excluded only where a sized symbol table
// positively places the functions. ET_REL objects locate symbols by section
// index and offset; executables and shared objects by virtual address.
static void mask_non_function_bytes(uint8_t *buf, const Elf64_Shdr *shdr,
                                    uint64_t shndx, bool by_shndx,
                                    const struct func_sym *funcs, size_t nfuncs)
{
    struct func_range *r = malloc(nfuncs * sizeof(*r));
    if (r == NULL) {
        return;     // keep the unmasked full sweep on allocation failure
    }
    size_t n = 0;
    for (size_t i = 0; i < nfuncs; ++i) {
        uint64_t start;
        if (by_shndx) {
            if (funcs[i].shndx != shndx || funcs[i].value >= shdr->sh_size) {
                continue;
            }
            start = funcs[i].value;
        } else {
            if (funcs[i].value < shdr->sh_addr ||
                funcs[i].value - shdr->sh_addr >= shdr->sh_size) {
                continue;
            }
            start = funcs[i].value - shdr->sh_addr;
        }
        r[n].start = start;
        r[n].end = funcs[i].size > shdr->sh_size - start
            ? shdr->sh_size : start + funcs[i].size;
        ++n;
    }
    qsort(r, n, sizeof(*r), func_range_cmp);
    for (size_t i = 0; i < n; ++i) {
        if (r[i].end == r[i].start) {
            r[i].end = i + 1 < n ? r[i + 1].start : shdr->sh_size;
        }
    }
    uint64_t pos = 0;
    for (size_t i = 0; i < n; ++i) {
        if (r[i].start > pos) {
            memset(buf + pos, 0x06, r[i].start - pos);
        }
        if (r[i].end > pos) {
            pos = r[i].end;
        }
    }
    if (pos < shdr->sh_size) {
        memset(buf + pos, 0x06, shdr->sh_size - pos);
    }
    free(r);
}

int main(int argc, char **argv)
{
    // Exit status follows the grep convention so a gating CI can tell a
    // dirty scan from a broken run: 0 = clean scan, 1 = opportunities
    // found, 2 = tool failure (usage, I/O, malformed ELF, allocation).
    bool verbose = false;
    bool scan_all = false;
    uint32_t extensions = 0;
    const char *path = NULL;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-v") == 0) {
            verbose = true;
        } else if (strcmp(argv[i], "-a") == 0) {
            scan_all = true;
        } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            ++i;
            if (strcmp(argv[i], "bmi1") == 0) {
                extensions |= X86LINT_EXT_BMI1;
            } else if (strcmp(argv[i], "bmi2") == 0) {
                extensions |= X86LINT_EXT_BMI2;
            } else if (strcmp(argv[i], "movbe") == 0) {
                extensions |= X86LINT_EXT_MOVBE;
            } else if (strcmp(argv[i], "apx") == 0) {
                extensions |= X86LINT_EXT_APX;
            } else {
                fprintf(stderr,
                    "usage: %s [-v] [-a] [-m bmi1|bmi2|movbe|apx] <ELF_FILE>\n",
                    argv[0]);
                return 2;
            }
        } else if (path == NULL && argv[i][0] != '-') {
            path = argv[i];
        } else {
            fprintf(stderr,
                "usage: %s [-v] [-a] [-m bmi1|bmi2|movbe|apx] <ELF_FILE>\n",
                argv[0]);
            return 2;
        }
    }
    if (path == NULL) {
        fprintf(stderr,
            "usage: %s [-v] [-a] [-m bmi1|bmi2|movbe|apx] <ELF_FILE>\n",
            argv[0]);
        return 2;
    }

    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        perror(path);
        return 2;
    }

    // Every goto-out path below is an error, so failure is the default.
    int rc = 2;
    uint8_t *buf = NULL;
    x86lint_summary *summary = NULL;
    struct func_sym *funcs = NULL;
    size_t nfuncs = 0;

    if (fseek(f, 0, SEEK_END) != 0) {
        fprintf(stderr, "%s: failed to seek to end of file\n", path);
        goto out;
    }
    long file_size_signed = ftell(f);
    if (file_size_signed < 0) {
        fprintf(stderr, "%s: failed to get file size\n", path);
        goto out;
    }
    uint64_t file_size = (uint64_t) file_size_signed;

    Elf64_Ehdr ehdr;
    if (!read_at(f, 0, &ehdr, sizeof(ehdr))) {
        fprintf(stderr, "%s: failed to read ELF header\n", path);
        goto out;
    }

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "%s: not an ELF file\n", path);
        goto out;
    }
    if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "%s: only 64-bit ELF files are supported\n", path);
        goto out;
    }

    // Section headers are read below at a stride of sizeof(Elf64_Shdr), so a
    // file declaring any other e_shentsize would be misparsed: reject it.
    // e_shnum is 16 bits; a file with SHN_LORESERVE (0xff00) or more sections
    // -- e.g. a large -ffunction-sections build -- stores 0 there and the real
    // count in section header 0's sh_size (extended section numbering).
    // Without reading that, such a file would scan zero sections and pass as a
    // clean run. e_shoff == 0 means no section header table at all. The whole
    // table must fit in the file; checked in two steps to avoid wraparound on
    // a forged count (cf. the per-section check below), which also bounds the
    // offset arithmetic in the scan loop.
    uint64_t shnum = 0;
    if (ehdr.e_shoff != 0) {
        if (ehdr.e_shentsize != sizeof(Elf64_Shdr)) {
            fprintf(stderr, "%s: unexpected section header entry size %u\n",
                path, ehdr.e_shentsize);
            goto out;
        }
        if (ehdr.e_shoff > file_size) {
            fprintf(stderr,
                "%s: section header table offset %lu beyond file size %lu\n",
                path, (unsigned long) ehdr.e_shoff, (unsigned long) file_size);
            goto out;
        }
        shnum = ehdr.e_shnum;
        if (shnum == 0) {
            Elf64_Shdr shdr0;
            if (!read_at(f, (long) ehdr.e_shoff, &shdr0, sizeof(shdr0))) {
                fprintf(stderr, "%s: failed to read section header 0\n", path);
                goto out;
            }
            shnum = shdr0.sh_size;
        }
        if (shnum > (file_size - ehdr.e_shoff) / sizeof(Elf64_Shdr)) {
            fprintf(stderr,
                "%s: section header count %lu overruns the file\n",
                path, (unsigned long) shnum);
            goto out;
        }
    }

    // Load the function ranges from the symbol table, if the binary kept
    // one. Only SHT_SYMTAB qualifies: the dynamic table survives stripping
    // but lists exported functions only, and restricting the scan to those
    // would silently skip almost every internal function -- a clean report
    // that scanned nothing. With no .symtab (every stripped distro binary)
    // the scan covers whole sections exactly as before; -a forces that even
    // when symbols exist.
    if (!scan_all) {
        for (uint64_t i = 0; i < shnum; ++i) {
            Elf64_Shdr shdr;
            if (!read_at(f, (long) (ehdr.e_shoff + i * sizeof(shdr)), &shdr,
                         sizeof(shdr))) {
                fprintf(stderr, "%s: failed to read section header %lu\n",
                    path, (unsigned long) i);
                goto out;
            }
            if (shdr.sh_type != SHT_SYMTAB) {
                continue;
            }
            if (shdr.sh_entsize != sizeof(Elf64_Sym)) {
                fprintf(stderr, "%s: unexpected symbol table entry size %lu\n",
                    path, (unsigned long) shdr.sh_entsize);
                goto out;
            }
            if (shdr.sh_offset > file_size ||
                shdr.sh_size > file_size - shdr.sh_offset) {
                fprintf(stderr, "%s: symbol table out of bounds\n", path);
                goto out;
            }
            size_t nsyms = shdr.sh_size / sizeof(Elf64_Sym);
            if (nsyms == 0) {
                break;
            }
            Elf64_Sym *syms = malloc(shdr.sh_size);
            if (syms == NULL) {
                fprintf(stderr, "%s: failed to allocate %lu bytes\n",
                    path, (unsigned long) shdr.sh_size);
                goto out;
            }
            if (!read_at(f, (long) shdr.sh_offset, syms, shdr.sh_size)) {
                fprintf(stderr, "%s: failed to read the symbol table\n", path);
                free(syms);
                goto out;
            }
            funcs = malloc(nsyms * sizeof(*funcs));
            if (funcs == NULL) {
                fprintf(stderr, "%s: failed to allocate symbol ranges\n",
                    path);
                free(syms);
                goto out;
            }
            for (size_t s = 0; s < nsyms; ++s) {
                unsigned type = ELF64_ST_TYPE(syms[s].st_info);
                if ((type != STT_FUNC && type != STT_GNU_IFUNC) ||
                    syms[s].st_shndx == SHN_UNDEF) {
                    continue;
                }
                funcs[nfuncs].value = syms[s].st_value;
                funcs[nfuncs].size = syms[s].st_size;
                funcs[nfuncs].shndx = syms[s].st_shndx;
                ++nfuncs;
            }
            free(syms);
            // A table with no function symbols at all (some strippers keep
            // it but drop the types) must not exclude every byte.
            if (nfuncs == 0) {
                free(funcs);
                funcs = NULL;
            }
            break;
        }
    }

    xed_tables_init();
    xed_set_verbosity(0);

    // A NULL summary (allocation failure) is tolerated by the API: tallying
    // is skipped and the instruction count reads back as 0.
    summary = x86lint_summary_create();

    int errors = 0;
    for (uint64_t i = 0; i < shnum; ++i) {
        Elf64_Shdr shdr;
        if (!read_at(f, (long) (ehdr.e_shoff + i * sizeof(shdr)), &shdr, sizeof(shdr))) {
            fprintf(stderr, "%s: failed to read section header %lu\n", path,
                (unsigned long) i);
            goto out;
        }

        if (shdr.sh_type != SHT_PROGBITS || !(shdr.sh_flags & SHF_EXECINSTR) || shdr.sh_size == 0) {
            continue;
        }

        // Validate the section fits within the file. Done as two checks
        // to avoid wraparound on a forged sh_size near UINT64_MAX.
        if (shdr.sh_offset > file_size ||
            shdr.sh_size > file_size - shdr.sh_offset) {
            fprintf(stderr,
                "%s: section %lu out of bounds (offset %lu size %lu, file %lu)\n",
                path, (unsigned long) i, (unsigned long) shdr.sh_offset,
                (unsigned long) shdr.sh_size, (unsigned long) file_size);
            goto out;
        }

        buf = malloc(shdr.sh_size);
        if (buf == NULL) {
            fprintf(stderr, "%s: failed to allocate %lu bytes\n",
                path, (unsigned long) shdr.sh_size);
            goto out;
        }
        if (!read_at(f, shdr.sh_offset, buf, shdr.sh_size)) {
            fprintf(stderr, "%s: failed to read section %lu\n", path,
                (unsigned long) i);
            goto out;
        }

        if (funcs != NULL) {
            mask_non_function_bytes(buf, &shdr, i, ehdr.e_type == ET_REL,
                funcs, nfuncs);
        }

        int n = check_instructions(buf, shdr.sh_size, verbose, summary,
            extensions);
        if (n < 0) {
            goto out;
        }
        errors += n;

        free(buf);
        buf = NULL;
    }

    x86lint_summary_print(summary);
    if (funcs != NULL) {
        printf("scan restricted to %zu function symbols (-a scans every byte)\n",
            nfuncs);
    }
    printf("%d optimization opportunities in %zu instructions\n",
        errors, x86lint_summary_instructions(summary));
    rc = errors != 0;

out:
    x86lint_summary_destroy(summary);
    free(funcs);
    free(buf);
    fclose(f);
    return rc;
}
