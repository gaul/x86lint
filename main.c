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
    if (argc != 2) {
        fprintf(stderr, "usage: %s <ELF_FILE>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (f == NULL) {
        perror(argv[1]);
        return 1;
    }

    int rc = 1;
    uint8_t *buf = NULL;

    Elf64_Ehdr ehdr;
    if (!read_at(f, 0, &ehdr, sizeof(ehdr))) {
        fprintf(stderr, "%s: failed to read ELF header\n", argv[1]);
        goto out;
    }

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "%s: not an ELF file\n", argv[1]);
        goto out;
    }
    if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "%s: only 64-bit ELF files are supported\n", argv[1]);
        goto out;
    }

    xed_tables_init();
    xed_set_verbosity(99);

    int errors = 0;
    for (uint16_t i = 0; i < ehdr.e_shnum; ++i) {
        Elf64_Shdr shdr;
        if (!read_at(f, ehdr.e_shoff + (long) i * sizeof(shdr), &shdr, sizeof(shdr))) {
            fprintf(stderr, "%s: failed to read section header %u\n", argv[1], i);
            goto out;
        }

        if (shdr.sh_type != SHT_PROGBITS || !(shdr.sh_flags & SHF_EXECINSTR) || shdr.sh_size == 0) {
            continue;
        }

        buf = malloc(shdr.sh_size);
        if (buf == NULL) {
            fprintf(stderr, "%s: failed to allocate %lu bytes\n",
                argv[1], (unsigned long) shdr.sh_size);
            goto out;
        }
        if (!read_at(f, shdr.sh_offset, buf, shdr.sh_size)) {
            fprintf(stderr, "%s: failed to read section %u\n", argv[1], i);
            goto out;
        }

        int n = check_instructions(buf, shdr.sh_size);
        if (n < 0) {
            goto out;
        }
        errors += n;

        free(buf);
        buf = NULL;
    }

    printf("%d errors\n", errors);
    rc = errors != 0;

out:
    free(buf);
    fclose(f);
    return rc;
}
