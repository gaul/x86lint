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

// ---- ENDBR64 (CET IBT) verification, -e ---------------------------------
//
// With indirect branch tracking enforced, an indirect JMP or CALL must land
// on an ENDBR64 or the CPU raises #CP. Which addresses an indirect branch
// can reach is not a property of the instruction stream -- nothing in the
// bytes distinguishes a landing site from fallthrough code -- but the ELF
// metadata of a linked binary evidences a checkable subset, collected below.
// The subset under-approximates (a function pointer materialized by a
// RIP-relative LEA leaves no relocation behind), so a target the metadata
// does evidence really is reachable indirectly and a missing landing pad
// there really faults; the converse check -- flagging a superfluous ENDBR64
// -- would be guessing, and is not attempted.

// Evidence sources, strongest first: when several name the same address (an
// exported function also referenced by a GOT relocation), dedup keeps the
// smallest kind. Every kind but the last proves the address is *branched*
// to -- the loader or startup code calls it, or a PLT/GOT slot resolves to
// it. An address relocation proves only that the address is *taken*: glibc
// bakes pointers to bracket labels (__syscall_cancel_arch_start) that are
// compared against interrupted PCs and never branched to, with landing pads
// deliberately omitted. The verify loop therefore counts ENDBR_ADDR
// evidence only when the target is a known function entry, and its
// last-place rank keeps it from shadowing a stronger claim to the same
// address.
enum endbr_kind {
    ENDBR_ENTRY,    // e_entry: the loader enters by indirect jump
    ENDBR_INIT,     // .init/.fini: DT_INIT/DT_FINI, called through a pointer
    ENDBR_ARRAY,    // .preinit_array/.init_array/.fini_array slot
    ENDBR_PLT,      // R_X86_64_JUMP_SLOT resolving to a local definition
    ENDBR_GOT,      // R_X86_64_GLOB_DAT resolving to a local definition
    ENDBR_IFUNC,    // R_X86_64_IRELATIVE: the loader calls the resolver
    ENDBR_EXPORT,   // defined dynsym function: reachable via any caller's PLT
    ENDBR_ADDR,     // absolute-address relocation into an executable section
};

static const char *const endbr_kind_name[] = {
    "entry point",
    ".init/.fini entry",
    "init/fini array entry",
    "PLT relocation",
    "GOT relocation",
    "ifunc resolver",
    "exported function",
    "address relocation",
};

struct endbr_target {
    uint64_t va;
    uint32_t sym;       // index into .dynsym, or 0 (STN_UNDEF) for none
    uint8_t kind;       // enum endbr_kind
};

struct endbr_targets {
    struct endbr_target *v;
    size_t n;
    size_t cap;
};

static bool endbr_push(struct endbr_targets *t, uint64_t va, uint32_t sym,
                       uint8_t kind)
{
    if (t->n == t->cap) {
        size_t cap = t->cap == 0 ? 64 : t->cap * 2;
        struct endbr_target *v = realloc(t->v, cap * sizeof(*v));
        if (v == NULL) {
            return false;
        }
        t->v = v;
        t->cap = cap;
    }
    t->v[t->n].va = va;
    t->v[t->n].sym = sym;
    t->v[t->n].kind = kind;
    ++t->n;
    return true;
}

static int endbr_target_cmp(const void *a, const void *b)
{
    const struct endbr_target *ta = a, *tb = b;
    if (ta->va != tb->va) {
        return ta->va < tb->va ? -1 : 1;
    }
    if (ta->kind != tb->kind) {
        return ta->kind < tb->kind ? -1 : 1;
    }
    return 0;
}

static bool u64_push(uint64_t **v, size_t *n, size_t *cap, uint64_t x)
{
    if (*n == *cap) {
        size_t ncap = *cap == 0 ? 64 : *cap * 2;
        uint64_t *nv = realloc(*v, ncap * sizeof(*nv));
        if (nv == NULL) {
            return false;
        }
        *v = nv;
        *cap = ncap;
    }
    (*v)[(*n)++] = x;
    return true;
}

static int u64_cmp(const void *a, const void *b)
{
    uint64_t ua = *(const uint64_t *) a, ub = *(const uint64_t *) b;
    return ua < ub ? -1 : ua > ub ? 1 : 0;
}

static bool u64_contains(const uint64_t *v, size_t n, uint64_t x)
{
    size_t lo = 0;
    size_t hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (v[mid] < x) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo < n && v[lo] == x;
}

// Read a whole section's contents, bounds-checked against the file. NULL for
// a section with no bytes in the file or on I/O or allocation failure; the
// metadata callers treat all of these as absent evidence and move on (the
// summary line still states how many targets were actually checked).
static uint8_t *load_section(FILE *f, const Elf64_Shdr *shdr,
                             uint64_t file_size)
{
    if (shdr->sh_type == SHT_NOBITS || shdr->sh_size == 0 ||
        shdr->sh_offset > file_size ||
        shdr->sh_size > file_size - shdr->sh_offset) {
        return NULL;
    }
    uint8_t *buf = malloc(shdr->sh_size);
    if (buf != NULL &&
        !read_at(f, (long) shdr->sh_offset, buf, shdr->sh_size)) {
        free(buf);
        buf = NULL;
    }
    return buf;
}

// One word from the GNU property note (an NT_GNU_PROPERTY_TYPE_0 note named
// "GNU"): pr_type selects which -- GNU_PROPERTY_X86_FEATURE_1_AND holds the
// CET bits the loader enables enforcement from, GNU_PROPERTY_X86_ISA_1_NEEDED
// and _USED hold the psABI level masks the toolchain recorded (what the
// binary requires to run at all vs. what it was allowed to emit anywhere).
// *out is written only when the word is present; the return value says so.
// Property notes are 8-aligned in ELF64; other note sections (build-id) use
// 4, hence the per-section alignment. Each property is {u32 pr_type,
// u32 pr_datasz, data padded to 8}.
static bool elf_property_word(FILE *f, const Elf64_Shdr *sh, uint64_t shnum,
                              uint64_t file_size, uint32_t want_pr_type,
                              uint32_t *out)
{
    bool found = false;
    for (uint64_t i = 0; i < shnum && !found; ++i) {
        if (sh[i].sh_type != SHT_NOTE) {
            continue;
        }
        uint8_t *buf = load_section(f, &sh[i], file_size);
        if (buf == NULL) {
            continue;
        }
        uint64_t size = sh[i].sh_size;
        uint64_t align = sh[i].sh_addralign == 8 ? 8 : 4;
        uint64_t off = 0;
        while (off + sizeof(Elf64_Nhdr) <= size) {
            Elf64_Nhdr nh;
            memcpy(&nh, buf + off, sizeof(nh));
            uint64_t name_off = off + sizeof(nh);
            // The padding rounds the cumulative offset to the alignment,
            // not the field size alone: header (12) + "GNU\0" (4) is
            // already 8-aligned, so the descriptor starts at +16.
            uint64_t desc_off = (name_off + nh.n_namesz + align - 1) &
                ~(align - 1);
            if (desc_off > size || nh.n_descsz > size - desc_off ||
                nh.n_namesz > size - name_off) {
                break;      // malformed: stop parsing this section
            }
            if (nh.n_type == NT_GNU_PROPERTY_TYPE_0 && nh.n_namesz == 4 &&
                memcmp(buf + name_off, "GNU", 4) == 0) {
                uint64_t p = desc_off;
                uint64_t dend = desc_off + nh.n_descsz;
                while (p + 8 <= dend) {
                    uint32_t pr_type;
                    uint32_t pr_datasz;
                    memcpy(&pr_type, buf + p, 4);
                    memcpy(&pr_datasz, buf + p + 4, 4);
                    if (pr_datasz > dend - (p + 8)) {
                        break;
                    }
                    if (!found && pr_type == want_pr_type && pr_datasz >= 4) {
                        memcpy(out, buf + p + 8, 4);
                        found = true;
                    }
                    p += 8 + (((uint64_t) pr_datasz + 7) & ~(uint64_t) 7);
                }
            }
            off = (desc_off + nh.n_descsz + align - 1) & ~(align - 1);
        }
        free(buf);
    }
    return found;
}

// The CET feature word, for the -e pass; returns 0 when no note carries it.
static uint32_t elf_feature_1_and(FILE *f, const Elf64_Shdr *sh,
                                  uint64_t shnum, uint64_t file_size)
{
    uint32_t feat = 0;
    elf_property_word(f, sh, shnum, file_size, GNU_PROPERTY_X86_FEATURE_1_AND,
        &feat);
    return feat;
}

// Resolve one RELR-relocated slot: the packed format encodes only WHERE a
// relative relocation applies; its target is the slot's raw link-time value,
// read here from whichever section holds the slot. Slots arrive sorted, so
// the single-section cache almost always hits. Returns false only on
// allocation failure; a slot outside any loadable section, an unreadable
// section, and a 0/-1 sentinel value are skipped.
static bool endbr_relr_slot(FILE *f, const Elf64_Shdr *sh, uint64_t shnum,
                            uint64_t file_size, uint64_t where,
                            uint64_t *cache_i, uint8_t **cache,
                            struct endbr_targets *targets)
{
    if (*cache_i >= shnum || where < sh[*cache_i].sh_addr ||
        where - sh[*cache_i].sh_addr > sh[*cache_i].sh_size - 8) {
        free(*cache);
        *cache = NULL;
        *cache_i = shnum;
        for (uint64_t i = 0; i < shnum; ++i) {
            if ((sh[i].sh_flags & SHF_ALLOC) && sh[i].sh_type != SHT_NOBITS &&
                sh[i].sh_size >= 8 && where >= sh[i].sh_addr &&
                where - sh[i].sh_addr <= sh[i].sh_size - 8) {
                *cache = load_section(f, &sh[i], file_size);
                if (*cache == NULL) {
                    return true;
                }
                *cache_i = i;
                break;
            }
        }
        if (*cache_i >= shnum) {
            return true;
        }
    }
    uint64_t value;
    memcpy(&value, *cache + (where - sh[*cache_i].sh_addr), 8);
    if (value == 0 || value == UINT64_MAX) {
        return true;
    }
    return endbr_push(targets, value, 0, ENDBR_ADDR);
}

// Name a target: by its recorded dynsym index, or by reverse value lookup
// for targets evidenced without a symbol. NULL when nothing matches.
static const char *endbr_sym_name(const Elf64_Sym *dynsym, size_t ndynsym,
                                  const char *dynstr, uint64_t dynstr_size,
                                  uint32_t symi, uint64_t va)
{
    if (dynstr == NULL) {
        return NULL;
    }
    if (symi == 0) {
        for (size_t s = 1; s < ndynsym; ++s) {
            unsigned st = ELF64_ST_TYPE(dynsym[s].st_info);
            if ((st == STT_FUNC || st == STT_GNU_IFUNC) &&
                dynsym[s].st_shndx != SHN_UNDEF && dynsym[s].st_value == va) {
                symi = (uint32_t) s;
                break;
            }
        }
        if (symi == 0) {
            return NULL;
        }
    }
    if (symi >= ndynsym || dynsym[symi].st_name == 0 ||
        dynsym[symi].st_name >= dynstr_size) {
        return NULL;
    }
    return dynstr + dynsym[symi].st_name;
}

// Verify that every indirect branch target the ELF metadata evidences begins
// with ENDBR64 (see check_endbr64_target), and reconcile the result with the
// binary's IBT property note. Four verdicts: IBT declared and all targets
// pad -- clean; IBT declared with misses -- each is a #CP fault once IBT is
// enforced, so every miss is printed regardless of verbosity; IBT not
// declared but landing pads present -- the compiler emitted CET which the
// link then lost (the property is ANDed across inputs, so one non-CET
// object silently disarms the whole binary; Fedora's libzstd ships this
// way, fully padded with the declaration eaten by its hand-written
// assembly), one finding, with the per-target detail behind -v; no
// declaration and no pads -- not an IBT binary, no findings. Returns the
// finding count, or -1 on tool failure.
static int check_elf_endbr64(FILE *f, const char *path,
                             const Elf64_Ehdr *ehdr, uint64_t shnum,
                             uint64_t file_size, const char *shstrtab,
                             uint64_t shstrtab_size, bool verbose)
{
    // A relocatable object's indirect targets are a compile-time question
    // (its address-taken evidence dissolves into the final link), and half
    // its metadata does not exist yet.
    if (ehdr->e_type == ET_REL) {
        fprintf(stderr,
            "%s: -e requires a linked executable or shared object\n", path);
        return -1;
    }
    if (shnum == 0) {
        printf("ENDBR64: no section headers; nothing to check\n");
        return 0;
    }

    int rc = -1;
    struct endbr_targets targets = {NULL, 0, 0};
    Elf64_Sym *dynsym = NULL;
    size_t ndynsym = 0;
    char *dynstr = NULL;
    uint64_t dynstr_size = 0;
    uint8_t **exec_bufs = NULL;
    uint64_t *fentry = NULL;
    size_t nfentry = 0;
    size_t fentry_cap = 0;

    Elf64_Shdr *sh = malloc(shnum * sizeof(*sh));
    if (sh == NULL ||
        !read_at(f, (long) ehdr->e_shoff, sh, shnum * sizeof(*sh))) {
        fprintf(stderr, "%s: failed to read section headers\n", path);
        goto out;
    }

    uint32_t feat = elf_feature_1_and(f, sh, shnum, file_size);
    bool ibt = (feat & GNU_PROPERTY_X86_FEATURE_1_IBT) != 0;
    bool shstk = (feat & GNU_PROPERTY_X86_FEATURE_1_SHSTK) != 0;

    // The dynamic symbol table names relocation targets and lists the
    // exported functions, each an indirect target in its own right.
    for (uint64_t i = 0; i < shnum; ++i) {
        if (sh[i].sh_type != SHT_DYNSYM ||
            sh[i].sh_entsize != sizeof(Elf64_Sym)) {
            continue;
        }
        dynsym = (Elf64_Sym *) load_section(f, &sh[i], file_size);
        if (dynsym == NULL) {
            break;
        }
        ndynsym = sh[i].sh_size / sizeof(Elf64_Sym);
        if (sh[i].sh_link < shnum) {
            dynstr = (char *) load_section(f, &sh[sh[i].sh_link], file_size);
            if (dynstr != NULL) {
                dynstr_size = sh[sh[i].sh_link].sh_size;
                dynstr[dynstr_size - 1] = '\0';     // bound every lookup
            }
        }
        break;
    }

    // Function entries known to the symbol tables (.symtab when the binary
    // kept one, .dynsym always), for grading the address-relocation
    // evidence in the verify loop: a baked code pointer is proven a branch
    // target only when it addresses a function entry. A compare-only label
    // is NOTYPE and drops out here; a stripped binary loses this evidence
    // class and nothing else -- erring, as everywhere, toward the false
    // negative.
    bool oom = false;
    for (uint64_t i = 0; i < shnum && !oom; ++i) {
        if (sh[i].sh_type != SHT_SYMTAB ||
            sh[i].sh_entsize != sizeof(Elf64_Sym)) {
            continue;
        }
        Elf64_Sym *syms = (Elf64_Sym *) load_section(f, &sh[i], file_size);
        if (syms == NULL) {
            continue;
        }
        size_t nsyms = sh[i].sh_size / sizeof(Elf64_Sym);
        for (size_t s = 1; s < nsyms && !oom; ++s) {
            unsigned st = ELF64_ST_TYPE(syms[s].st_info);
            if ((st == STT_FUNC || st == STT_GNU_IFUNC) &&
                syms[s].st_shndx != SHN_UNDEF && syms[s].st_value != 0) {
                oom |= !u64_push(&fentry, &nfentry, &fentry_cap,
                    syms[s].st_value);
            }
        }
        free(syms);
    }
    for (size_t s = 1; s < ndynsym && !oom; ++s) {
        unsigned st = ELF64_ST_TYPE(dynsym[s].st_info);
        if ((st == STT_FUNC || st == STT_GNU_IFUNC) &&
            dynsym[s].st_shndx != SHN_UNDEF && dynsym[s].st_value != 0) {
            oom |= !u64_push(&fentry, &nfentry, &fentry_cap,
                dynsym[s].st_value);
        }
    }
    if (nfentry != 0) {
        qsort(fentry, nfentry, sizeof(*fentry), u64_cmp);
    }

    // The entry point is an indirect branch target only for a program with
    // an interpreter: ld.so transfers to e_entry with an indirect jump
    // (glibc: _dl_start_user's `jmp *%r12`). A kernel-entered binary --
    // static, static-PIE, ld.so itself -- starts with the tracker idle and
    // owes no landing pad there; ld.so's own _start has none, deliberately.
    bool has_interp = false;
    if (ehdr->e_phoff != 0 && ehdr->e_phentsize == sizeof(Elf64_Phdr) &&
        ehdr->e_phoff <= file_size &&
        ehdr->e_phnum <= (file_size - ehdr->e_phoff) / sizeof(Elf64_Phdr)) {
        for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
            Elf64_Phdr ph;
            if (!read_at(f, (long) (ehdr->e_phoff + i * sizeof(ph)), &ph,
                         sizeof(ph))) {
                break;
            }
            if (ph.p_type == PT_INTERP) {
                has_interp = true;
                break;
            }
        }
    }
    if (has_interp && ehdr->e_entry != 0) {
        oom |= !endbr_push(&targets, ehdr->e_entry, 0, ENDBR_ENTRY);
    }

    for (uint64_t i = 0; i < shnum && !oom; ++i) {
        const Elf64_Shdr *s = &sh[i];
        switch (s->sh_type) {
        case SHT_PROGBITS:
            // .init and .fini hold DT_INIT/DT_FINI, which the loader calls
            // through a function pointer. Identified by name; without a
            // section string table they are simply not evidenced.
            if (shstrtab != NULL && s->sh_name < shstrtab_size &&
                (s->sh_flags & SHF_EXECINSTR) && s->sh_addr != 0) {
                const char *name = shstrtab + s->sh_name;
                if (strcmp(name, ".init") == 0 ||
                    strcmp(name, ".fini") == 0) {
                    oom |= !endbr_push(&targets, s->sh_addr, 0, ENDBR_INIT);
                }
            }
            break;
        case SHT_PREINIT_ARRAY:
        case SHT_INIT_ARRAY:
        case SHT_FINI_ARRAY: {
            // Each slot is a function pointer the startup code calls
            // indirectly. The linker stores the link-time address in the
            // slot even when a RELATIVE (or packed RELR) relocation also
            // covers it, so the raw values serve PIE and non-PIE alike.
            uint8_t *buf = load_section(f, s, file_size);
            if (buf == NULL) {
                break;
            }
            for (uint64_t off = 0; off + 8 <= s->sh_size && !oom; off += 8) {
                uint64_t va;
                memcpy(&va, buf + off, 8);
                if (va != 0 && va != UINT64_MAX) {
                    oom |= !endbr_push(&targets, va, 0, ENDBR_ARRAY);
                }
            }
            free(buf);
            break;
        }
        case SHT_RELA: {
            if (s->sh_entsize != sizeof(Elf64_Rela)) {
                break;
            }
            uint8_t *buf = load_section(f, s, file_size);
            if (buf == NULL) {
                break;
            }
            size_t n = s->sh_size / sizeof(Elf64_Rela);
            for (size_t r = 0; r < n && !oom; ++r) {
                Elf64_Rela rela;
                memcpy(&rela, buf + r * sizeof(rela), sizeof(rela));
                uint32_t type = ELF64_R_TYPE(rela.r_info);
                uint32_t symi = ELF64_R_SYM(rela.r_info);
                switch (type) {
                case R_X86_64_JUMP_SLOT:
                case R_X86_64_GLOB_DAT:
                case R_X86_64_64:
                    // Meaningful when the symbol is defined here: the
                    // runtime slot value is then this object's own function
                    // entry. Imports resolve elsewhere. A symbolless
                    // absolute relocation is a baked address, handled like
                    // RELATIVE.
                    if (symi != 0 && symi < ndynsym) {
                        const Elf64_Sym *y = &dynsym[symi];
                        unsigned st = ELF64_ST_TYPE(y->st_info);
                        if ((st != STT_FUNC && st != STT_GNU_IFUNC) ||
                            y->st_shndx == SHN_UNDEF || y->st_value == 0) {
                            break;
                        }
                        uint64_t va = y->st_value;
                        uint8_t kind =
                            type == R_X86_64_JUMP_SLOT ? ENDBR_PLT :
                            type == R_X86_64_GLOB_DAT ? ENDBR_GOT :
                            ENDBR_ADDR;
                        if (type == R_X86_64_64) {
                            va += (uint64_t) rela.r_addend;
                        }
                        oom |= !endbr_push(&targets, va, symi, kind);
                    } else if (type == R_X86_64_64 && rela.r_addend != 0) {
                        oom |= !endbr_push(&targets,
                            (uint64_t) rela.r_addend, 0, ENDBR_ADDR);
                    }
                    break;
                case R_X86_64_IRELATIVE:
                    // The addend is the ifunc resolver, which the loader
                    // calls indirectly at startup.
                    if (rela.r_addend != 0) {
                        oom |= !endbr_push(&targets,
                            (uint64_t) rela.r_addend, 0, ENDBR_IFUNC);
                    }
                    break;
                case R_X86_64_RELATIVE:
                    // A baked pointer; one landing in an executable section
                    // is an address-taken function or label.
                    if (rela.r_addend != 0) {
                        oom |= !endbr_push(&targets,
                            (uint64_t) rela.r_addend, 0, ENDBR_ADDR);
                    }
                    break;
                }
            }
            free(buf);
            break;
        }
        case SHT_RELR: {
            if (s->sh_entsize != 8) {
                break;
            }
            uint8_t *buf = load_section(f, s, file_size);
            if (buf == NULL) {
                break;
            }
            uint64_t cache_i = shnum;
            uint8_t *cache = NULL;
            uint64_t where = 0;
            size_t n = s->sh_size / 8;
            for (size_t r = 0; r < n && !oom; ++r) {
                uint64_t e;
                memcpy(&e, buf + r * 8, 8);
                if ((e & 1) == 0) {
                    oom |= !endbr_relr_slot(f, sh, shnum, file_size, e,
                        &cache_i, &cache, &targets);
                    where = e + 8;
                } else {
                    for (unsigned b = 1; b < 64 && !oom; ++b) {
                        if (e & (1ULL << b)) {
                            oom |= !endbr_relr_slot(f, sh, shnum, file_size,
                                where + (b - 1) * 8, &cache_i, &cache,
                                &targets);
                        }
                    }
                    where += 63 * 8;
                }
            }
            free(cache);
            free(buf);
            break;
        }
        }
    }

    // Every defined dynamic function symbol is indirectly reachable: a
    // cross-object call always arrives through the caller's PLT or GOT,
    // an indirect branch landing here.
    for (size_t s = 1; s < ndynsym && !oom; ++s) {
        unsigned st = ELF64_ST_TYPE(dynsym[s].st_info);
        if ((st == STT_FUNC || st == STT_GNU_IFUNC) &&
            dynsym[s].st_shndx != SHN_UNDEF && dynsym[s].st_value != 0) {
            oom |= !endbr_push(&targets, dynsym[s].st_value, (uint32_t) s,
                ENDBR_EXPORT);
        }
    }

    if (oom) {
        fprintf(stderr, "%s: failed to allocate target list\n", path);
        goto out;
    }

    if (targets.n != 0) {
        qsort(targets.v, targets.n, sizeof(*targets.v), endbr_target_cmp);
    }

    // The landing pads must be read raw, so these buffers are never masked
    // by the symbol-table scan restriction. Only targets inside an
    // executable section are checked: the address-relocation sweep pushes
    // every baked pointer it sees, and the ones aimed at data drop out here.
    exec_bufs = calloc(shnum, sizeof(*exec_bufs));
    if (exec_bufs == NULL) {
        fprintf(stderr, "%s: failed to allocate section list\n", path);
        goto out;
    }
    for (uint64_t i = 0; i < shnum; ++i) {
        if (sh[i].sh_type == SHT_PROGBITS &&
            (sh[i].sh_flags & SHF_EXECINSTR) &&
            (sh[i].sh_flags & SHF_ALLOC) && sh[i].sh_addr != 0) {
            exec_bufs[i] = load_section(f, &sh[i], file_size);
        }
    }

    size_t checked = 0;
    size_t misses = 0;
    uint64_t prev_va = 0;
    bool have_prev = false;
    for (size_t t = 0; t < targets.n; ++t) {
        uint64_t va = targets.v[t].va;
        if (have_prev && va == prev_va) {
            continue;       // sorted dedup; the most specific kind is first
        }
        prev_va = va;
        have_prev = true;
        // Address-taken-only evidence: counts just when the pointer
        // addresses a known function entry (see enum endbr_kind).
        if (targets.v[t].kind == ENDBR_ADDR &&
            !u64_contains(fentry, nfentry, va)) {
            continue;
        }
        uint64_t sec = shnum;
        for (uint64_t i = 0; i < shnum; ++i) {
            if (exec_bufs[i] != NULL && va >= sh[i].sh_addr &&
                va - sh[i].sh_addr < sh[i].sh_size) {
                sec = i;
                break;
            }
        }
        if (sec == shnum) {
            continue;
        }
        ++checked;
        if (check_endbr64_target(exec_bufs[sec], sh[sec].sh_size,
                                 va - sh[sec].sh_addr)) {
            continue;
        }
        ++misses;
        if (ibt || verbose) {
            const char *nm = endbr_sym_name(dynsym, ndynsym, dynstr,
                dynstr_size, targets.v[t].sym, va);
            printf("indirect branch target missing ENDBR64: 0x%lx%s%s%s (%s)\n",
                (unsigned long) va, nm != NULL ? " <" : "",
                nm != NULL ? nm : "", nm != NULL ? ">" : "",
                endbr_kind_name[targets.v[t].kind]);
        }
    }

    if (checked == 0) {
        printf("ENDBR64: no indirect branch targets evidenced; "
            "nothing to check\n");
        rc = 0;
    } else if (ibt) {
        if (misses == 0) {
            printf("ENDBR64: IBT property note present; all %zu indirect "
                "branch targets land on ENDBR64\n", checked);
        } else {
            printf("ENDBR64: IBT property note present; %zu of %zu indirect "
                "branch targets missing ENDBR64 (#CP fault when IBT is "
                "enforced)\n", misses, checked);
        }
        rc = (int) misses;
    } else if (misses < checked) {
        printf("ENDBR64: no IBT in the property note, but %zu of %zu "
            "indirect branch targets begin with ENDBR64 (IBT annotation "
            "lost at link?)\n", checked - misses, checked);
        if (misses > 0 && !verbose) {
            printf("  (pass -v to list the %zu targets without one)\n",
                misses);
        }
        rc = (int) misses + 1;
    } else {
        printf("ENDBR64: no IBT in the property note and no ENDBR64 "
            "landing pads; not an IBT binary\n");
        rc = 0;
    }

    // The same FEATURE_1_AND word carries the shadow-stack bit, and
    // -fcf-protection=full emits both, so an asymmetric declaration earns a
    // line. Calibration across 3,203 /usr/lib64 library files: 3,120
    // declare both, none declare IBT alone, 18 declare SHSTK alone -- all
    // media/JIT libraries (the ffmpeg family, dav1d, x264, libass, LuaJIT)
    // whose hand-written assembly emits an SHSTK-only note: its returns
    // stay paired but its entries lack pads, and under the linker's AND an
    // SHSTK-only output proves every object declared SHSTK while at least
    // one withheld IBT. Each such library pairs this line with the
    // annotation-lost verdict above. Informational only, never the exit
    // status: SHSTK -- unlike IBT -- leaves nothing in the instruction
    // stream to verify, and even a shadow-stack-incompatible idiom is not
    // statically recognizable (glibc's setcontext ends in the classic
    // push-and-ret yet takes an RSTORSSP path first when a shadow stack is
    // live -- a runtime feature gate no instruction matcher can see). In
    // the annotation-lost verdict the pads evidence branch protection only,
    // so the SHSTK line states the bit's absence without claiming a loss.
    if (ibt && shstk) {
        printf("SHSTK: shadow stack declared alongside IBT\n");
    } else if (ibt) {
        printf("SHSTK: no shadow stack in the property note despite IBT "
            "(branch-only -fcf-protection?)\n");
    } else if (shstk) {
        printf("SHSTK: shadow stack declared without IBT (SHSTK-only asm "
            "in the link, or return-only -fcf-protection?)\n");
    } else if (checked != 0 && misses < checked) {
        printf("SHSTK: no shadow stack in the property note\n");
    }

out:
    if (exec_bufs != NULL) {
        for (uint64_t i = 0; i < shnum; ++i) {
            free(exec_bufs[i]);
        }
    }
    free(exec_bufs);
    free(fentry);
    free(dynstr);
    free(dynsym);
    free(targets.v);
    free(sh);
    return rc;
}

// Count the STT_GNU_IFUNC symbols the binary defines -- its runtime
// CPU-dispatch surface, printed beside the ISA census so a baseline-built
// binary with dispatched fast paths (glibc) reads differently from one
// compiled wholesale for a level. .symtab usually contains the dynamic
// table's ifuncs plus internal ones, so the tables are not summed; the
// larger count wins. Returns -1 after printing on a malformed table.
static long count_ifuncs(FILE *f, const char *path, const Elf64_Ehdr *ehdr,
                         uint64_t shnum, uint64_t file_size)
{
    long best = 0;
    for (uint64_t i = 0; i < shnum; ++i) {
        Elf64_Shdr shdr;
        if (!read_at(f, (long) (ehdr->e_shoff + i * sizeof(shdr)), &shdr,
                     sizeof(shdr))) {
            fprintf(stderr, "%s: failed to read section header %lu\n", path,
                (unsigned long) i);
            return -1;
        }
        if (shdr.sh_type != SHT_DYNSYM && shdr.sh_type != SHT_SYMTAB) {
            continue;
        }
        if (shdr.sh_entsize != sizeof(Elf64_Sym)) {
            fprintf(stderr, "%s: unexpected symbol table entry size %lu\n",
                path, (unsigned long) shdr.sh_entsize);
            return -1;
        }
        if (shdr.sh_offset > file_size ||
            shdr.sh_size > file_size - shdr.sh_offset) {
            fprintf(stderr, "%s: symbol table out of bounds\n", path);
            return -1;
        }
        Elf64_Sym *syms = malloc(shdr.sh_size);
        if (syms == NULL) {
            fprintf(stderr, "%s: failed to allocate %lu bytes\n", path,
                (unsigned long) shdr.sh_size);
            return -1;
        }
        if (!read_at(f, (long) shdr.sh_offset, syms, shdr.sh_size)) {
            fprintf(stderr, "%s: failed to read the symbol table\n", path);
            free(syms);
            return -1;
        }
        long count = 0;
        size_t nsyms = shdr.sh_size / sizeof(Elf64_Sym);
        for (size_t s = 0; s < nsyms; ++s) {
            if (ELF64_ST_TYPE(syms[s].st_info) == STT_GNU_IFUNC &&
                syms[s].st_shndx != SHN_UNDEF) {
                ++count;
            }
        }
        free(syms);
        if (count > best) {
            best = count;
        }
    }
    return best;
}

// ==== code evidence for the census ===================================
//
// Ranges of bytes the toolchain recorded as code: sized STT_FUNC symbols
// from .symtab and .dynsym, and .eh_frame FDE pc-ranges. The census
// labels tallies against these (see x86lint_census_set_evidence);
// tools/cohere is the measurement that put this here after every cheap
// coherence heuristic failed. Collection is best-effort by design --
// evidence is optional metadata, so a malformed table or an exotic
// pointer encoding ends or skips parsing rather than failing the run,
// and whatever was gathered before still labels (missing evidence only
// widens the honest "no toolchain claim" bucket).

struct evidence_build {
    x86lint_evidence_range *r;
    size_t n;
    size_t cap;
};

static bool evidence_push(struct evidence_build *b, uint64_t start,
                          uint64_t end)
{
    if (end <= start) {
        return true;
    }
    if (b->n == b->cap) {
        size_t cap = b->cap == 0 ? 64 : b->cap * 2;
        x86lint_evidence_range *r = realloc(b->r, cap * sizeof(*r));
        if (r == NULL) {
            return false;
        }
        b->r = r;
        b->cap = cap;
    }
    b->r[b->n].start = start;
    b->r[b->n].end = end;
    b->n++;
    return true;
}

static bool read_uleb(const uint8_t *buf, uint64_t limit, uint64_t *off,
                      uint64_t *out)
{
    uint64_t v = 0;
    unsigned shift = 0;
    while (*off < limit && shift < 64) {
        uint8_t byte = buf[(*off)++];
        v |= (uint64_t) (byte & 0x7f) << shift;
        if ((byte & 0x80) == 0) {
            *out = v;
            return true;
        }
        shift += 7;
    }
    return false;
}

static bool read_sleb(const uint8_t *buf, uint64_t limit, uint64_t *off,
                      int64_t *out)
{
    uint64_t v = 0;
    unsigned shift = 0;
    while (*off < limit && shift < 64) {
        uint8_t byte = buf[(*off)++];
        v |= (uint64_t) (byte & 0x7f) << shift;
        shift += 7;
        if ((byte & 0x80) == 0) {
            if (shift < 64 && (byte & 0x40) != 0) {
                v |= ~UINT64_C(0) << shift;
            }
            *out = (int64_t) v;
            return true;
        }
    }
    return false;
}

// One DW_EH_PE-encoded pointer at buf[*off], advancing past it. `pc` is
// the vaddr of the field, the base pcrel values are relative to. Only
// the encodings compilers emit into .eh_frame are supported: the fixed
// and LEB formats with absolute or pcrel application. Anything else
// (datarel, aligned, indirect) returns false and the caller skips the
// entry -- conservative, never wrong.
static bool read_eh_pointer(const uint8_t *buf, uint64_t limit,
                            uint64_t *off, uint8_t enc, uint64_t pc,
                            uint64_t *out)
{
    if (enc == 0xff) {          // DW_EH_PE_omit
        return false;
    }
    uint64_t v;
    switch (enc & 0x0f) {
    case 0x00:                  // absptr
    case 0x04:                  // udata8
    case 0x0c: {                // sdata8
        if (limit - *off < 8 || *off > limit) {
            return false;
        }
        memcpy(&v, buf + *off, 8);
        *off += 8;
        break;
    }
    case 0x01: {                // uleb128
        if (!read_uleb(buf, limit, off, &v)) {
            return false;
        }
        break;
    }
    case 0x09: {                // sleb128
        int64_t sv;
        if (!read_sleb(buf, limit, off, &sv)) {
            return false;
        }
        v = (uint64_t) sv;
        break;
    }
    case 0x02: {                // udata2
        uint16_t u;
        if (limit - *off < 2 || *off > limit) {
            return false;
        }
        memcpy(&u, buf + *off, 2);
        *off += 2;
        v = u;
        break;
    }
    case 0x0a: {                // sdata2
        int16_t s;
        if (limit - *off < 2 || *off > limit) {
            return false;
        }
        memcpy(&s, buf + *off, 2);
        *off += 2;
        v = (uint64_t) (int64_t) s;
        break;
    }
    case 0x03: {                // udata4
        uint32_t u;
        if (limit - *off < 4 || *off > limit) {
            return false;
        }
        memcpy(&u, buf + *off, 4);
        *off += 4;
        v = u;
        break;
    }
    case 0x0b: {                // sdata4
        int32_t s;
        if (limit - *off < 4 || *off > limit) {
            return false;
        }
        memcpy(&s, buf + *off, 4);
        *off += 4;
        v = (uint64_t) (int64_t) s;
        break;
    }
    default:
        return false;
    }
    switch (enc & 0x70) {
    case 0x00:                  // absolute
        break;
    case 0x10:                  // pcrel
        v += pc;
        break;
    default:
        return false;
    }
    if ((enc & 0x80) != 0) {    // indirect
        return false;
    }
    *out = v;
    return true;
}

// Walk .eh_frame collecting FDE pc-ranges. Each entry is {u32 length,
// u32 id, ...}: id 0 is a CIE, whose augmentation string dictates how
// its FDEs encode their pointers; any other id is an FDE whose id field
// points back that many bytes to its CIE. Returns the FDE count parsed.
static size_t parse_eh_frame(const uint8_t *buf, uint64_t size,
                             uint64_t sec_vaddr, struct evidence_build *b)
{
    struct {
        uint64_t off;
        uint8_t enc;
        bool usable;
    } cies[64];
    size_t ncies = 0;
    size_t nfdes = 0;

    uint64_t off = 0;
    while (off + 8 <= size) {
        uint32_t len32;
        memcpy(&len32, buf + off, 4);
        off += 4;
        if (len32 == 0) {           // terminator
            break;
        }
        if (len32 == 0xffffffffu) { // 64-bit DWARF: unseen in .eh_frame
            break;
        }
        if (len32 > size - off) {
            break;
        }
        uint64_t next = off + len32;
        uint64_t id_off = off;
        uint32_t id;
        if (next - off < 4) {
            break;
        }
        memcpy(&id, buf + off, 4);
        off += 4;

        if (id == 0) {
            // CIE: dig the 'R' (FDE pointer encoding) out of the
            // augmentation, defaulting to absptr when there is none.
            uint8_t enc = 0x00;
            bool usable = true;
            if (off >= next) {
                break;
            }
            uint8_t version = buf[off++];
            if (version != 1 && version != 3 && version != 4) {
                usable = false;
            }
            const uint8_t *nul = memchr(buf + off, 0, next - off);
            if (nul == NULL) {
                break;
            }
            const char *aug = (const char *) buf + off;
            off = (uint64_t) (nul - buf) + 1;
            if (usable && version == 4) {
                if (next - off < 2 || buf[off + 1] != 0) {
                    usable = false;     // segmented: not supported
                } else {
                    off += 2;           // address_size, segment_size
                }
            }
            uint64_t uleb;
            int64_t sleb;
            if (usable &&
                (!read_uleb(buf, next, &off, &uleb) ||      // code align
                 !read_sleb(buf, next, &off, &sleb))) {     // data align
                usable = false;
            }
            if (usable) {               // return-address register
                if (version == 1) {
                    if (off >= next) {
                        usable = false;
                    } else {
                        off++;
                    }
                } else if (!read_uleb(buf, next, &off, &uleb)) {
                    usable = false;
                }
            }
            if (usable && aug[0] == 'z') {
                uint64_t aug_len;
                if (!read_uleb(buf, next, &off, &aug_len) ||
                    aug_len > next - off) {
                    usable = false;
                }
                for (const char *a = aug + 1; usable && *a != '\0'; ++a) {
                    switch (*a) {
                    case 'R':
                        if (off >= next) {
                            usable = false;
                        } else {
                            enc = buf[off++];
                        }
                        break;
                    case 'L':
                        if (off >= next) {
                            usable = false;
                        } else {
                            off++;      // LSDA encoding byte
                        }
                        break;
                    case 'P': {
                        // Personality: an encoding byte then a pointer
                        // in that encoding, skipped by reading it.
                        if (off >= next) {
                            usable = false;
                            break;
                        }
                        uint8_t penc = buf[off++];
                        uint64_t ignored;
                        if (!read_eh_pointer(buf, next, &off, penc,
                                             sec_vaddr + off, &ignored)) {
                            usable = false;
                        }
                        break;
                    }
                    case 'S':           // signal frame
                    case 'B':           // BTI/PAuth markers
                        break;
                    default:
                        usable = false;
                    }
                }
            } else if (usable && aug[0] != '\0') {
                usable = false;         // legacy "eh" augmentation
            }
            if (ncies < sizeof(cies) / sizeof(cies[0])) {
                cies[ncies].off = id_off - 4;   // CIE starts at its length
                cies[ncies].enc = enc;
                cies[ncies].usable = usable;
                ncies++;
            }
        } else {
            // FDE: its id field holds the distance back to its CIE.
            uint64_t cie_off;
            if ((uint64_t) id > id_off) {
                off = next;
                continue;
            }
            cie_off = id_off - id;
            uint8_t enc = 0x00;
            bool usable = false;
            for (size_t c = 0; c < ncies; ++c) {
                if (cies[c].off == cie_off) {
                    enc = cies[c].enc;
                    usable = cies[c].usable;
                    break;
                }
            }
            uint64_t loc;
            uint64_t range;
            if (usable &&
                read_eh_pointer(buf, next, &off, enc, sec_vaddr + off,
                                &loc) &&
                // address_range shares the format but is an absolute
                // count: mask the application bits off.
                read_eh_pointer(buf, next, &off, enc & 0x0f,
                                sec_vaddr + off, &range) &&
                range < UINT64_MAX - loc) {
                if (!evidence_push(b, loc, loc + range)) {
                    return nfdes;
                }
                nfdes++;
            }
        }
        off = next;
    }
    return nfdes;
}

// Sized function symbols from one symbol table section.
static size_t evidence_from_symtab(FILE *f, const Elf64_Shdr *shdr,
                                   uint64_t file_size,
                                   struct evidence_build *b)
{
    if (shdr->sh_entsize != sizeof(Elf64_Sym)) {
        return 0;
    }
    uint8_t *raw = load_section(f, shdr, file_size);
    if (raw == NULL) {
        return 0;
    }
    const Elf64_Sym *syms = (const Elf64_Sym *) raw;
    size_t nsyms = shdr->sh_size / sizeof(Elf64_Sym);
    size_t pushed = 0;
    for (size_t s = 0; s < nsyms; ++s) {
        unsigned type = ELF64_ST_TYPE(syms[s].st_info);
        if ((type != STT_FUNC && type != STT_GNU_IFUNC) ||
            syms[s].st_shndx == SHN_UNDEF || syms[s].st_value == 0 ||
            syms[s].st_size == 0 ||
            syms[s].st_size > UINT64_MAX - syms[s].st_value) {
            continue;
        }
        if (!evidence_push(b, syms[s].st_value,
                           syms[s].st_value + syms[s].st_size)) {
            break;
        }
        pushed++;
    }
    free(raw);
    return pushed;
}

static int evidence_cmp(const void *a, const void *b)
{
    const x86lint_evidence_range *ra = a;
    const x86lint_evidence_range *rb = b;
    return ra->start < rb->start ? -1 : ra->start > rb->start ? 1 : 0;
}

// Sort, merge overlaps in place (FDEs duplicate symbol ranges all the
// time), and return the merged count; *covered gets the byte total.
static size_t evidence_merge(x86lint_evidence_range *r, size_t n,
                             uint64_t *covered)
{
    *covered = 0;
    if (n == 0) {
        return 0;
    }
    qsort(r, n, sizeof(*r), evidence_cmp);
    size_t out = 0;
    for (size_t i = 1; i < n; ++i) {
        if (r[i].start <= r[out].end) {
            if (r[i].end > r[out].end) {
                r[out].end = r[i].end;
            }
        } else {
            *covered += r[out].end - r[out].start;
            r[++out] = r[i];
        }
    }
    *covered += r[out].end - r[out].start;
    return out + 1;
}

// Spell a GNU_PROPERTY_X86_ISA_1_* mask as its psABI level names, plus any
// residue bits a future psABI level would add, so the output never silently
// drops a bit it does not know.
static void print_isa_mask(uint32_t mask)
{
    static const char *const names[] = {
        "x86-64-baseline", "x86-64-v2", "x86-64-v3", "x86-64-v4",
    };
    if (mask == 0) {
        printf("0");
        return;
    }
    bool first = true;
    for (int b = 0; b < 4; ++b) {
        if (mask & (1u << b)) {
            printf("%s%s", first ? "" : "+", names[b]);
            first = false;
        }
    }
    if ((mask & ~0xfu) != 0) {
        printf("%s0x%x", first ? "" : "+", (unsigned) (mask & ~0xfu));
    }
}

int main(int argc, char **argv)
{
    // Exit status follows the grep convention so a gating CI can tell a
    // dirty scan from a broken run: 0 = clean scan, 1 = opportunities
    // found, 2 = tool failure (usage, I/O, malformed ELF, allocation).
    // The -i census is informational and never contributes findings.
    bool verbose = false;
    bool scan_all = false;
    bool endbr = false;
    bool census = false;
    uint32_t extensions = 0;
    const char *path = NULL;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-v") == 0) {
            verbose = true;
        } else if (strcmp(argv[i], "-a") == 0) {
            scan_all = true;
        } else if (strcmp(argv[i], "-e") == 0) {
            endbr = true;
        } else if (strcmp(argv[i], "-i") == 0) {
            census = true;
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
                    "usage: %s [-v] [-a] [-e] [-i] [-m bmi1|bmi2|movbe|apx] <ELF_FILE>\n",
                    argv[0]);
                return 2;
            }
        } else if (path == NULL && argv[i][0] != '-') {
            path = argv[i];
        } else {
            fprintf(stderr,
                "usage: %s [-v] [-a] [-e] [-i] [-m bmi1|bmi2|movbe|apx] <ELF_FILE>\n",
                argv[0]);
            return 2;
        }
    }
    if (path == NULL) {
        fprintf(stderr,
            "usage: %s [-v] [-a] [-e] [-i] [-m bmi1|bmi2|movbe|apx] <ELF_FILE>\n",
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
    x86lint_census *census_data = NULL;
    struct evidence_build evidence = {NULL, 0, 0};
    size_t evidence_funcs = 0;
    size_t evidence_fdes = 0;
    uint64_t evidence_covered = 0;
    uint64_t exec_bytes = 0;
    struct func_sym *funcs = NULL;
    size_t nfuncs = 0;
    char *shstrtab = NULL;
    uint64_t shstrtab_size = 0;

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
    // when symbols exist. The census always scans every executable byte --
    // it is a description of the file, not a per-function report -- so it
    // skips the restriction the same way -a does.
    if (!scan_all && !census) {
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

    // Section names, for the per-section banner -v prints. Findings carry an
    // offset into the section being scanned, which on a binary with one
    // executable section reads like a file offset but on several -- a
    // BOLT-processed library keeps its unmoved functions in .bolt.org.text
    // beside the ones it moved into .text -- is ambiguous without knowing
    // which section it belongs to. -e needs it too, to identify .init and
    // .fini by name. Only those two callers use it, so a failure to read
    // the table costs the names and nothing else. e_shstrndx holds
    // SHN_XINDEX when the real index does not fit, with the value in section
    // header 0's sh_link (the same overflow convention as e_shnum).
    if ((verbose || endbr || census) && shnum != 0) {
        uint64_t strndx = ehdr.e_shstrndx;
        if (strndx == SHN_XINDEX) {
            Elf64_Shdr shdr0;
            if (read_at(f, (long) ehdr.e_shoff, &shdr0, sizeof(shdr0))) {
                strndx = shdr0.sh_link;
            } else {
                strndx = SHN_UNDEF;
            }
        }
        Elf64_Shdr strhdr;
        if (strndx != SHN_UNDEF && strndx < shnum &&
            read_at(f, (long) (ehdr.e_shoff + strndx * sizeof(strhdr)),
                    &strhdr, sizeof(strhdr)) &&
            strhdr.sh_size != 0 && strhdr.sh_offset <= file_size &&
            strhdr.sh_size <= file_size - strhdr.sh_offset) {
            shstrtab = malloc(strhdr.sh_size);
            if (shstrtab != NULL &&
                read_at(f, (long) strhdr.sh_offset, shstrtab, strhdr.sh_size)) {
                shstrtab_size = strhdr.sh_size;
                shstrtab[strhdr.sh_size - 1] = '\0';    // bound every lookup
            } else {
                free(shstrtab);
                shstrtab = NULL;
            }
        }
    }

    xed_tables_init();
    xed_set_verbosity(0);

    // A NULL summary (allocation failure) is tolerated by the API: tallying
    // is skipped and the instruction count reads back as 0.
    summary = x86lint_summary_create();

    // The census, by contrast, IS the whole report of a -i run, so failing
    // to allocate it degrades to printing zeros; fail hard instead.
    if (census) {
        census_data = x86lint_census_create();
        if (census_data == NULL) {
            fprintf(stderr, "%s: failed to allocate the ISA census\n", path);
            goto out;
        }

        // Code evidence, gathered before the scan so every tally can be
        // labeled. Relocatable objects are skipped: their symbol values
        // are section-relative and their .eh_frame unrelocated, so
        // ranges would land in the wrong address space.
        if (ehdr.e_type != ET_REL) {
            for (uint64_t i = 0; i < shnum; ++i) {
                Elf64_Shdr shdr;
                if (!read_at(f, (long) (ehdr.e_shoff + i * sizeof(shdr)),
                             &shdr, sizeof(shdr))) {
                    break;
                }
                if (shdr.sh_type == SHT_SYMTAB ||
                    shdr.sh_type == SHT_DYNSYM) {
                    evidence_funcs +=
                        evidence_from_symtab(f, &shdr, file_size, &evidence);
                } else if (shdr.sh_type == SHT_PROGBITS &&
                           shstrtab != NULL &&
                           shdr.sh_name < shstrtab_size &&
                           strcmp(shstrtab + shdr.sh_name, ".eh_frame") ==
                               0) {
                    uint8_t *frame = load_section(f, &shdr, file_size);
                    if (frame != NULL) {
                        evidence_fdes += parse_eh_frame(frame, shdr.sh_size,
                            shdr.sh_addr, &evidence);
                        free(frame);
                    }
                }
            }
            evidence.n = evidence_merge(evidence.r, evidence.n,
                &evidence_covered);
            x86lint_census_set_evidence(census_data, evidence.r,
                evidence.n);
        }
    }

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

        if (census) {
            // The census only tallies; its report prints once, after the
            // loop, aggregated across sections.
            x86lint_census_scan(census_data, buf, shdr.sh_size, shdr.sh_addr);
            exec_bytes += shdr.sh_size;
            free(buf);
            buf = NULL;
            continue;
        }

        if (funcs != NULL) {
            mask_non_function_bytes(buf, &shdr, i, ehdr.e_type == ET_REL,
                funcs, nfuncs);
        }

        // Name the section the following findings belong to, and give the
        // address their offsets are relative to, so a site can be located in
        // a disassembly.
        if (verbose) {
            const char *name = shstrtab != NULL && shdr.sh_name < shstrtab_size
                ? shstrtab + shdr.sh_name : "";
            printf("== section %lu%s%s: vaddr 0x%lx, %lu bytes ==\n",
                (unsigned long) i, name[0] != '\0' ? " " : "", name,
                (unsigned long) shdr.sh_addr, (unsigned long) shdr.sh_size);
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

    if (census) {
        x86lint_census_print(census_data, verbose);

        // What backed the unevidenced labels -- or that nothing did, in
        // which case no instruction was labeled and the whole census
        // carries the same "no toolchain claim" weight.
        if (evidence.n != 0) {
            printf("  code evidence: %zu function symbols + %zu .eh_frame "
                "FDEs covering %lu of %lu executable bytes\n",
                evidence_funcs, evidence_fdes,
                (unsigned long) evidence_covered,
                (unsigned long) exec_bytes);
        } else {
            printf("  code evidence: none (no sized function symbols, no "
                "parsable .eh_frame)\n");
        }

        // The toolchain's own ISA accounting, when it recorded one:
        // ISA_1_NEEDED is the authoritative baseline requirement (the loader
        // refuses to run the binary below it), ISA_1_USED the linker's union
        // of what the objects were allowed to emit anywhere -- the same
        // quantity the census measures from the bytes.
        if (shnum != 0) {
            Elf64_Shdr *sh = malloc(shnum * sizeof(*sh));
            if (sh == NULL ||
                !read_at(f, (long) ehdr.e_shoff, sh, shnum * sizeof(*sh))) {
                fprintf(stderr, "%s: failed to read section headers\n", path);
                free(sh);
                goto out;
            }
            uint32_t needed = 0;
            uint32_t used = 0;
            bool have_needed = elf_property_word(f, sh, shnum, file_size,
                GNU_PROPERTY_X86_ISA_1_NEEDED, &needed);
            bool have_used = elf_property_word(f, sh, shnum, file_size,
                GNU_PROPERTY_X86_ISA_1_USED, &used);
            free(sh);
            if (have_needed || have_used) {
                printf("  GNU property ISA note:");
                if (have_needed) {
                    printf(" needed = ");
                    print_isa_mask(needed);
                }
                if (have_used) {
                    printf("%s used = ", have_needed ? "," : "");
                    print_isa_mask(used);
                }
                printf("\n");
            } else {
                printf("  GNU property ISA note: none\n");
            }
        } else {
            printf("  GNU property ISA note: none\n");
        }

        long ifuncs = count_ifuncs(f, path, &ehdr, shnum, file_size);
        if (ifuncs < 0) {
            goto out;
        }
        printf("  IFUNC resolvers defined: %ld%s\n", ifuncs,
            ifuncs > 0 ? " (runtime CPU dispatch present)" : "");
    } else {
        x86lint_summary_print(summary);
    }

    // The ENDBR64 pass is separate from the peephole scan -- its findings
    // are correctness faults located by virtual address, not encoding
    // opportunities located by section offset -- so it reports its own block
    // and only shares the exit code.
    int endbr_errors = 0;
    if (endbr) {
        endbr_errors = check_elf_endbr64(f, path, &ehdr, shnum, file_size,
            shstrtab, shstrtab_size, verbose);
        if (endbr_errors < 0) {
            goto out;
        }
    }

    if (funcs != NULL) {
        printf("scan restricted to %zu function symbols (-a scans every byte)\n",
            nfuncs);
    }
    if (!census) {
        printf("%d optimization opportunities in %zu instructions\n",
            errors, x86lint_summary_instructions(summary));
    }
    rc = errors != 0 || endbr_errors != 0;

out:
    x86lint_census_destroy(census_data);
    free(evidence.r);
    x86lint_summary_destroy(summary);
    free(shstrtab);
    free(funcs);
    free(buf);
    fclose(f);
    return rc;
}
