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

#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "corpus.h"

void corpus_decode_init(xed_decoded_inst_t *xedd)
{
    xed_decoded_inst_zero(xedd);
    xed_decoded_inst_set_mode(xedd, XED_MACHINE_MODE_LONG_64,
                              XED_ADDRESS_WIDTH_64b);
    xed_decoded_inst_set_input_chip(xedd, XED_CHIP_ALL);
}

bool corpus_is_target(const uint8_t *targets, size_t off)
{
    if (targets == NULL) {
        return true;
    }
    return (targets[off >> 3] & (1u << (off & 7))) != 0;
}

bool corpus_conditional_write(const xed_decoded_inst_t *xedd)
{
    return xed_decoded_inst_get_category(xedd) == XED_CATEGORY_CMOV;
}

// One bit per byte of the section, set where a direct relative transfer lands.
// Mirrors x86lint.c's collect_branch_targets, including its resync: the
// prepass must walk the bytes exactly as the scan does or the two disagree on
// instruction boundaries. Indirect branches and jump tables leave no mark
// here, so a range's straight-line assumption remains a documented residual
// risk, the same one x86lint's multi-instruction windows carry.
static uint8_t *collect_branch_targets(const uint8_t *code, size_t size)
{
    uint8_t *targets = calloc((size + 7) / 8, 1);
    if (targets == NULL) {
        return NULL;
    }
    for (size_t offset = 0; offset < size;) {
        xed_decoded_inst_t xedd;
        corpus_decode_init(&xedd);
        if (xed_decode(&xedd, code + offset, size - offset) !=
                XED_ERROR_NONE) {
            offset += 1;
            continue;
        }
        size_t next = offset + xed_decoded_inst_get_length(&xedd);
        if (xed_decoded_inst_get_branch_displacement_width_bits(&xedd) != 0) {
            int64_t target = (int64_t) next +
                xed_decoded_inst_get_branch_displacement(&xedd);
            if (target >= 0 && (uint64_t) target < (uint64_t) size) {
                targets[target >> 3] |= (uint8_t) (1u << (target & 7));
            }
        }
        offset = next;
    }
    return targets;
}

// A defined function symbol, as main.c's driver reads it.
struct func_sym {
    uint64_t value;     // st_value: a vaddr, or a section offset in ET_REL
    uint64_t size;      // st_size: 0 for an unsized assembly label
    uint16_t shndx;
};

static int range_cmp(const void *a, const void *b)
{
    const corpus_range *ra = a, *rb = b;
    if (ra->start != rb->start) {
        return ra->start < rb->start ? -1 : 1;
    }
    return 0;
}

// Turn the function symbols landing in one section into the ascending,
// disjoint ranges to scan. Same coverage rule as main.c's
// mask_non_function_bytes -- an unsized symbol runs to the next function's
// start, or the section end -- expressed as ranges rather than as masked-out
// bytes, since a mining tool wants the function boundaries themselves: a pair
// or a def-use distance must not span two functions. Returns the range count,
// 0 when the section holds no function symbol.
static size_t build_func_ranges(const Elf64_Shdr *shdr, uint64_t shndx,
                                bool by_shndx, const struct func_sym *funcs,
                                size_t nfuncs, corpus_range **out)
{
    corpus_range *r = malloc((nfuncs + 1) * sizeof(*r));
    if (r == NULL) {
        return 0;
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
    if (n == 0) {
        free(r);
        return 0;
    }
    qsort(r, n, sizeof(*r), range_cmp);
    for (size_t i = 0; i < n; ++i) {
        if (r[i].end == r[i].start) {
            r[i].end = i + 1 < n ? r[i + 1].start : shdr->sh_size;
        }
    }
    // Merge overlaps so no byte is scanned twice. Aliased symbols (one
    // address, several names) are the common case; an unsized label inside a
    // sized function is the other.
    size_t k = 0;
    for (size_t i = 1; i < n; ++i) {
        if (r[i].start <= r[k].end) {
            if (r[i].end > r[k].end) {
                r[k].end = r[i].end;
            }
        } else {
            r[++k] = r[i];
        }
    }
    *out = r;
    return k + 1;
}

// Read the symbol table's function ranges, if the binary kept one. Only
// SHT_SYMTAB qualifies: .dynsym survives stripping but lists exports alone,
// and scanning just those would mine almost no code while reporting success.
static int load_func_syms(const Elf64_Ehdr *ehdr, uint64_t shnum,
                          uint64_t file_size, const uint8_t *base,
                          struct func_sym **out, size_t *nout)
{
    const Elf64_Shdr *shdrs = (const Elf64_Shdr *) (base + ehdr->e_shoff);
    for (uint64_t i = 0; i < shnum; ++i) {
        const Elf64_Shdr *shdr = &shdrs[i];
        if (shdr->sh_type != SHT_SYMTAB ||
            shdr->sh_entsize != sizeof(Elf64_Sym)) {
            continue;
        }
        if (shdr->sh_offset > file_size ||
            shdr->sh_size > file_size - shdr->sh_offset) {
            return -1;
        }
        size_t nsyms = shdr->sh_size / sizeof(Elf64_Sym);
        if (nsyms == 0) {
            return 0;
        }
        const Elf64_Sym *syms = (const Elf64_Sym *) (base + shdr->sh_offset);
        struct func_sym *funcs = malloc(nsyms * sizeof(*funcs));
        if (funcs == NULL) {
            return -1;
        }
        size_t nfuncs = 0;
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
        // A table stripped of symbol types must not exclude every byte.
        if (nfuncs == 0) {
            free(funcs);
            return 0;
        }
        *out = funcs;
        *nout = nfuncs;
        return 0;
    }
    return 0;
}

int corpus_scan_file(const char *path, bool scan_all, corpus_section_fn fn,
                     void *ctx)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror(path);
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < (off_t) sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "%s: not a readable ELF file\n", path);
        close(fd);
        return -1;
    }
    size_t map_len = (size_t) st.st_size;
    uint8_t *base = mmap(NULL, map_len, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) {
        perror(path);
        return -1;
    }

    int rc = -1;
    struct func_sym *funcs = NULL;
    size_t nfuncs = 0;

    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *) base;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "%s: not an ELF file\n", path);
        goto out;
    }
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr->e_machine != EM_X86_64) {
        fprintf(stderr, "%s: not a 64-bit x86 ELF file\n", path);
        goto out;
    }

    // Section header bounds, as main.c validates them: a stride other than
    // sizeof(Elf64_Shdr) would misparse the table, and a file with 0xff00 or
    // more sections keeps its real count in section header 0's sh_size.
    uint64_t shnum = 0;
    if (ehdr->e_shoff != 0) {
        if (ehdr->e_shentsize != sizeof(Elf64_Shdr) ||
            ehdr->e_shoff > map_len ||
            map_len - ehdr->e_shoff < sizeof(Elf64_Shdr)) {
            fprintf(stderr, "%s: malformed section header table\n", path);
            goto out;
        }
        const Elf64_Shdr *shdrs = (const Elf64_Shdr *) (base + ehdr->e_shoff);
        shnum = ehdr->e_shnum != 0 ? ehdr->e_shnum : shdrs[0].sh_size;
        if (shnum > (map_len - ehdr->e_shoff) / sizeof(Elf64_Shdr)) {
            fprintf(stderr, "%s: section header count %lu overruns the file\n",
                path, (unsigned long) shnum);
            goto out;
        }
    }
    if (shnum == 0) {
        fprintf(stderr, "%s: no section headers to scan\n", path);
        goto out;
    }

    if (!scan_all &&
        load_func_syms(ehdr, shnum, map_len, base, &funcs, &nfuncs) != 0) {
        fprintf(stderr, "%s: malformed symbol table\n", path);
        goto out;
    }

    const Elf64_Shdr *shdrs = (const Elf64_Shdr *) (base + ehdr->e_shoff);
    for (uint64_t i = 0; i < shnum; ++i) {
        const Elf64_Shdr *shdr = &shdrs[i];
        if (shdr->sh_type != SHT_PROGBITS ||
            (shdr->sh_flags & SHF_EXECINSTR) == 0 || shdr->sh_size == 0) {
            continue;
        }
        if (shdr->sh_offset > map_len ||
            shdr->sh_size > map_len - shdr->sh_offset) {
            fprintf(stderr, "%s: section %lu out of bounds\n", path,
                (unsigned long) i);
            goto out;
        }

        corpus_range whole = { 0, shdr->sh_size };
        corpus_range *ranges = NULL;
        size_t nranges = 0;
        if (funcs != NULL) {
            nranges = build_func_ranges(shdr, i, ehdr->e_type == ET_REL,
                funcs, nfuncs, &ranges);
        }

        corpus_section sec = {
            .path = path,
            .code = base + shdr->sh_offset,
            .size = shdr->sh_size,
            .vaddr = shdr->sh_addr,
            .targets = collect_branch_targets(base + shdr->sh_offset,
                shdr->sh_size),
            .ranges = nranges != 0 ? ranges : &whole,
            .nranges = nranges != 0 ? nranges : 1,
            .by_symbol = nranges != 0,
        };
        fn(&sec, ctx);
        free((void *) sec.targets);
        free(ranges);
    }
    rc = 0;

out:
    free(funcs);
    munmap(base, map_len);
    return rc;
}
