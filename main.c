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

int main(int argc, char **argv)
{
    // Exit status follows the grep convention so a gating CI can tell a
    // dirty scan from a broken run: 0 = clean scan, 1 = opportunities
    // found, 2 = tool failure (usage, I/O, malformed ELF, allocation).
    bool verbose = false;
    const char *path = NULL;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-v") == 0) {
            verbose = true;
        } else if (path == NULL && argv[i][0] != '-') {
            path = argv[i];
        } else {
            fprintf(stderr, "usage: %s [-v] <ELF_FILE>\n", argv[0]);
            return 2;
        }
    }
    if (path == NULL) {
        fprintf(stderr, "usage: %s [-v] <ELF_FILE>\n", argv[0]);
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

    xed_tables_init();
    xed_set_verbosity(0);

    // A NULL summary (allocation failure) is tolerated by the API: tallying
    // is skipped and the instruction count reads back as 0.
    summary = x86lint_summary_create();

    int errors = 0;
    for (uint16_t i = 0; i < ehdr.e_shnum; ++i) {
        Elf64_Shdr shdr;
        if (!read_at(f, ehdr.e_shoff + (long) i * sizeof(shdr), &shdr, sizeof(shdr))) {
            fprintf(stderr, "%s: failed to read section header %u\n", path, i);
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
                "%s: section %u out of bounds (offset %lu size %lu, file %lu)\n",
                path, i, (unsigned long) shdr.sh_offset,
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
            fprintf(stderr, "%s: failed to read section %u\n", path, i);
            goto out;
        }

        int n = check_instructions(buf, shdr.sh_size, verbose, summary);
        if (n < 0) {
            goto out;
        }
        errors += n;

        free(buf);
        buf = NULL;
    }

    x86lint_summary_print(summary);
    printf("%d optimization opportunities in %zu instructions\n",
        errors, x86lint_summary_instructions(summary));
    rc = errors != 0;

out:
    x86lint_summary_destroy(summary);
    free(buf);
    fclose(f);
    return rc;
}
