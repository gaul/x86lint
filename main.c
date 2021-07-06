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
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "x86lint.h"

int main(int argc, char **argv)
{
  FILE* ElfFile = NULL;
  char* SectNames = NULL;
  Elf64_Ehdr elfHdr;
  Elf64_Shdr sectHdr;
  uint32_t idx;
  int errors = 0;

  if(argc != 2) {
    printf("usage: %s <ELF_FILE>\n", argv[0]);
    exit(1);
  }

  if((ElfFile = fopen(argv[1], "r")) == NULL) {
    perror("Error opening file");
    exit(1);
  }

  xed_tables_init();
  xed_set_verbosity(99);

  // read ELF header, first thing in the file
  fread(&elfHdr, 1, sizeof(Elf64_Ehdr), ElfFile);

  fseek(ElfFile, elfHdr.e_shoff + elfHdr.e_shstrndx * sizeof(sectHdr), SEEK_SET);
  fread(&sectHdr, 1, sizeof(sectHdr), ElfFile);

  // next, read the section, string data
  SectNames = malloc(sectHdr.sh_size);
  fseek(ElfFile, sectHdr.sh_offset, SEEK_SET);
  fread(SectNames, 1, sectHdr.sh_size, ElfFile);

  // read all section headers
  for (idx = 0; idx < elfHdr.e_shnum; idx++) {
    const char* name = "";

    fseek(ElfFile, elfHdr.e_shoff + idx * sizeof(sectHdr), SEEK_SET);
    fread(&sectHdr, 1, sizeof(sectHdr), ElfFile);

    if (!sectHdr.sh_name) {
      continue;
    }
    name = SectNames + sectHdr.sh_name;

    // TODO: look at p_flags & PF_X instead?
    if (strcmp(name, ".text") != 0) {
      continue;
    }

    char *buf = malloc(sectHdr.sh_size);
    fseek(ElfFile, sectHdr.sh_offset, SEEK_SET);
    fread(buf, 1, sectHdr.sh_size, ElfFile);
    errors += check_instructions((uint8_t *)buf, sectHdr.sh_size);
    free(buf);
  }

  printf("%d errors\n", errors);

  return (bool) errors;
}

