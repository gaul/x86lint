// rwfuzz: check that the rewrites x86lint's findings describe compute what
// the code they replace computed, by running both.
//
// A check's decision can be right and its advice still wrong -- a proof that
// misses a write, a slot reached through a second base, a fold that drops a
// sign extension -- and the unit tests cover only the cases someone thought
// to write down. rwfuzz generates random x86-64 programs, runs
// check_instructions over each, applies one finding's rewrite to a copy of
// the program at a time, and runs original and rewrite natively from the
// same random registers, flags and memory. Any difference in the body's
// general registers, xmm0..xmm7, the flags or the scratch memory at the end
// -- or a rewrite that faults where the original did not -- is a soundness
// bug in the check, or in the harness.
//
// x86lint's findings name one instruction and carry no rewrite; the advice
// is the finding's name and its row in the README's table. So rwfuzz holds
// one rewriter per finding name, which applies that row's rewrite the way a
// reader of the row would: it deletes, re-spells or folds the instructions
// the row names, finding a window's partner the plain way (the adjacent
// instruction, or for the frame-slot rows the nearest earlier access to the
// slot), and it assumes nothing about memory, flags or liveness. Those are
// the check's proofs, and running the rewrite is what tests them. A
// rewriter that cannot find the shape its row describes reports the finding
// "not applied", which fails the run too: a finding a reader could not act
// on is a bug of its own.
//
// Programs are assembly text. Each is a fixed prologue that saves the
// callee-saved registers, opens a 1032-byte frame under RBP (`mov rbp, rsp`,
// so both RSP and RBP address it), copies random bytes into the frame, and
// loads the twelve body registers (RAX, RBX, RCX, RDX, RSI, RDI, R8-R13),
// xmm0..xmm7 and the arithmetic flags from a state block; a random body; and
// an epilogue that stores them back. After it sits a stub the body can call,
// which reads RDI and RSI, writes the scratch buffer and clobbers every
// caller-saved register and the flags, as a callee may. R14 points at a
// 512-byte scratch buffer and R15 at the state block; the body never writes
// either. The body draws ALU, shift, multiply, LEA, extension, CMOVcc,
// SETcc and vector instructions, loads and stores to frame slots (spelled
// through RSP and RBP both) and to the scratch buffer, stores through a
// pointer to the frame, pushes and pops, forward branches and calls to the
// stub, and plants the shapes the checks look for.
//
// Every program is assembled by the host's compiler driver (RWFUZZ_CC,
// default cc), a batch of programs to one file, and every rewrite is
// assembled again from its own text, so branch targets survive a rewrite of
// any length and what runs is what the advice spells; a rewrite the
// assembler refuses is "not applied". The rewrite of each finding runs on
// its own copy, since two findings' proofs each assume the other's
// instructions are still there.
//
// Flags are compared only where the original program leaves them defined at
// its end: an instruction whose flags the SDM calls undefined (IMUL's
// SF/ZF/PF, a shift's OF) leaves the hardware's value, which a rewrite need
// not reproduce. For the same reason a program in which some instruction
// reads a flag that may be undefined there is drawn again (up to eight
// times, then skipped and counted). AF is never compared -- x86lint treats
// it as unobservable, as compiled code does. The frame is not compared
// either: it is dead once the function returns, which is what lets a dead
// store be deleted. Every run uses one state block at one stack depth, since
// the body can leave a pointer to either in a register.
//
// Rows not run: the encoding-only rows whose original the assembler never
// emits from text (an unneeded REX prefix, SIB byte or displacement, the
// VEX/EVEX and XCHG encodings, the branch displacement), the security and
// advisory classes (the scalar-merge rows among them), the APX rows (no
// host runs them), and CAS loop foldable into LOCK op and missing MULX,
// for which nothing is planted yet.
// A finding without a rewriter is counted as "no rewriter".
//
// A control arm applies the same rewrites where x86lint REFUSED to -- an
// unflagged compare deleted, an unflagged reload replaced by the register
// of the slot's last store -- and counts how often that changes the result:
// a harness that never saw a difference there could not see one anywhere.
// To check the harness after changing it, break a proof in x86lint.c (drop
// the overlapping-store invalidation in frame_observe, say), rebuild, and
// expect mismatches within a few thousand programs.
//
// Usage: rwfuzz [-n PROGRAMS] [-s SEED] [-f NAME] [-k KINDS] [-t TARGET] MODE
//   -n  programs to generate (default 10000)
//   -s  seed (default 0); programs and register values derive from it
//   -f  run only the findings named NAME, over the same programs
//   -k  fail unless at least KINDS finding names were run
//   -t  x86lint's tuning target (default zen, which enables the rows that
//       need move elimination; skylake adds the POPCNT row, silvermont the
//       SUB reg, reg one)
// Modes: all, flags, frame, fold (listed after `modes:` in the usage text).
// Each mode plants its family's shapes, runs every finding with a
// rewriter, and runs its family's control arm; `all` plants every family.
// BMI1, BMI2 and MOVBE rows run when the host has the extension.
// RWFUZZ_DEBUG=1 prints the assembler's errors and each redraw.
//
// Exit status: 0 when every finding run matched and every finding with a
// rewriter was applied; 1 on a mismatch, a finding not applied, a program
// that did not assemble, or fewer kinds than -k; 2 when the run could not
// start.
//
// Needs an x86-64 Linux host: the programs run natively.

#define _GNU_SOURCE
#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <inttypes.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../x86lint.h"

#if !defined(__x86_64__)
int main(void)
{
    fprintf(stderr, "rwfuzz: the programs run natively, and this host is not "
                    "x86-64\n");
    return 2;
}
#else

// ---------------------------------------------------------------- state ---

#define FRAME_SIZE   1032    // RSP-relative slots at [0, 1024)
#define SCRATCH_SIZE 512

struct rstate {
    uint64_t in_gpr[16];
    uint64_t out_gpr[16];
    uint8_t in_xmm[8][16];
    uint8_t out_xmm[8][16];
    uint64_t in_flags;
    uint64_t out_flags;
    uint64_t saved_rsp;
    uint64_t stub[16];
    uint8_t frame[FRAME_SIZE] __attribute__((aligned(16)));
    uint8_t scratch[SCRATCH_SIZE] __attribute__((aligned(16)));
} __attribute__((aligned(64)));

#define OFF(field) ((int) offsetof(struct rstate, field))

enum {
    FL_CF = 1u << 0, FL_PF = 1u << 2, FL_AF = 1u << 4, FL_ZF = 1u << 6,
    FL_SF = 1u << 7, FL_OF = 1u << 11,
};
#define FL_COMPARED (FL_CF | FL_PF | FL_ZF | FL_SF | FL_OF)
#define FL_ARITH (FL_COMPARED | FL_AF)

// --------------------------------------------------------------- random ---

static uint64_t rng_next(uint64_t *s)
{
    uint64_t z = (*s += 0x9e3779b97f4a7c15ull);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
}

static unsigned rnd(uint64_t *s, unsigned n)
{
    return (unsigned) (rng_next(s) % n);
}

static bool chance(uint64_t *s, unsigned percent)
{
    return rnd(s, 100) < percent;
}

// A value that leans on the edges compares and masks meet.
static uint64_t edge_value(uint64_t *s)
{
    static const uint64_t edges[] = {
        0, 1, 2, 3, 7, 8, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xffff,
        0x10000, 0x7fffffff, 0x80000000, 0xffffffff, 0x100000000ull,
        0x7fffffffffffffffull, 0x8000000000000000ull, UINT64_MAX,
        UINT64_MAX - 1, 0xffffffff80000000ull, 0xffffff80ull,
    };
    switch (rnd(s, 6)) {
    case 0:
    case 1:
        return edges[rnd(s, sizeof(edges) / sizeof(edges[0]))];
    case 2:
        return (uint64_t) -(int64_t) rnd(s, 16);
    case 3:
        return rnd(s, 16);
    case 4:
        return (uint32_t) rng_next(s);
    default:
        return rng_next(s);
    }
}

// ------------------------------------------------------------ registers ---

static const char *const GPR[16][4] = {
    {"al", "ax", "eax", "rax"},     {"cl", "cx", "ecx", "rcx"},
    {"dl", "dx", "edx", "rdx"},     {"bl", "bx", "ebx", "rbx"},
    {"spl", "sp", "esp", "rsp"},    {"bpl", "bp", "ebp", "rbp"},
    {"sil", "si", "esi", "rsi"},    {"dil", "di", "edi", "rdi"},
    {"r8b", "r8w", "r8d", "r8"},    {"r9b", "r9w", "r9d", "r9"},
    {"r10b", "r10w", "r10d", "r10"}, {"r11b", "r11w", "r11d", "r11"},
    {"r12b", "r12w", "r12d", "r12"}, {"r13b", "r13w", "r13d", "r13"},
    {"r14b", "r14w", "r14d", "r14"}, {"r15b", "r15w", "r15d", "r15"},
};
// The registers the body computes in and the epilogue compares.
static const int BODY[] = {0, 1, 2, 3, 6, 7, 8, 9, 10, 11, 12, 13};
#define NBODY ((int) (sizeof(BODY) / sizeof(BODY[0])))
// Caller-saved, which a call to the stub clobbers.
static const int CLOBBERED[] = {0, 1, 2, 6, 7, 8, 9, 10, 11};

static int width_index(int bits)
{
    return bits == 8 ? 0 : bits == 16 ? 1 : bits == 32 ? 2 : 3;
}

static const char *gpr(int num, int bits)
{
    return GPR[num][width_index(bits)];
}

static bool gpr_parse(const char *s, int *num, int *bits)
{
    for (int n = 0; n < 16; ++n) {
        for (int w = 0; w < 4; ++w) {
            if (strcmp(s, GPR[n][w]) == 0) {
                *num = n;
                *bits = 8 << w;
                return true;
            }
        }
    }
    return false;
}

static bool xmm_parse(const char *s, int *num)
{
    if (strncmp(s, "xmm", 3) != 0) {
        return false;
    }
    char *end;
    long n = strtol(s + 3, &end, 10);
    if (*end != '\0' || n < 0 || n > 15) {
        return false;
    }
    *num = (int) n;
    return true;
}

static const char *size_word(int bits)
{
    switch (bits) {
    case 8: return "byte";
    case 16: return "word";
    case 32: return "dword";
    case 64: return "qword";
    default: return "xmmword";
    }
}

static uint64_t width_mask(int bits)
{
    return bits >= 64 ? UINT64_MAX : (1ull << bits) - 1;
}

static int64_t sign_extend(uint64_t v, int bits)
{
    if (bits >= 64) {
        return (int64_t) v;
    }
    uint64_t m = 1ull << (bits - 1);
    v &= width_mask(bits);
    return (int64_t) ((v ^ m) - m);
}

// ---------------------------------------------------------------- items ---

#define MAXITEMS 400
#define TEXTLEN  80

enum region { R_PRO, R_BODY, R_EPI, R_STUB };

struct item {
    char text[TEXTLEN];   // empty: a label with no instruction
    short label;          // label defined ahead of the instruction, or -1
    uint8_t region;
    bool sealed;          // inside a group: no label lands here
};

struct prog {
    int n;
    int nlabels;
    struct item it[MAXITEMS];
};

static void item_set(struct item *it, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
static void item_set(struct item *it, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(it->text, sizeof(it->text), fmt, ap);
    va_end(ap);
}

static struct item *prog_add(struct prog *p, enum region r, const char *fmt,
                             ...) __attribute__((format(printf, 3, 4)));
static struct item *prog_add(struct prog *p, enum region r, const char *fmt,
                             ...)
{
    assert(p->n < MAXITEMS);
    struct item *it = &p->it[p->n++];
    memset(it, 0, sizeof(*it));
    it->label = -1;
    it->region = (uint8_t) r;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(it->text, sizeof(it->text), fmt, ap);
    va_end(ap);
    return it;
}

// Insert an instruction ahead of item i, taking over its label.
static bool prog_insert(struct prog *p, int i, const char *text)
{
    if (p->n >= MAXITEMS) {
        return false;
    }
    memmove(&p->it[i + 1], &p->it[i], (size_t) (p->n - i) * sizeof(p->it[0]));
    ++p->n;
    struct item *it = &p->it[i];
    snprintf(it->text, sizeof(it->text), "%s", text);
    it->label = p->it[i + 1].label;
    p->it[i + 1].label = -1;
    return true;
}

// ------------------------------------------------------- text structure ---

struct ins {
    char mn[16];
    char op[3][48];
    int nop;
};

static void ins_parse(const char *text, struct ins *in)
{
    memset(in, 0, sizeof(*in));
    const char *p = text;
    while (*p == ' ') {
        ++p;
    }
    size_t k = 0;
    while (*p != '\0' && *p != ' ' && k + 1 < sizeof(in->mn)) {
        in->mn[k++] = *p++;
    }
    while (*p == ' ') {
        ++p;
    }
    while (*p != '\0' && in->nop < 3) {
        const char *comma = strstr(p, ", ");
        size_t n = comma != NULL ? (size_t) (comma - p) : strlen(p);
        if (n >= sizeof(in->op[0])) {
            n = sizeof(in->op[0]) - 1;
        }
        memcpy(in->op[in->nop], p, n);
        in->op[in->nop][n] = '\0';
        ++in->nop;
        p = comma != NULL ? comma + 2 : p + strlen(p);
    }
}

static bool imm_parse(const char *s, int64_t *v)
{
    if (!((s[0] >= '0' && s[0] <= '9') || s[0] == '-')) {
        return false;
    }
    char *end;
    errno = 0;
    long long x = strtoll(s, &end, 0);
    if (*end != '\0') {
        return false;
    }
    if (errno == ERANGE) {
        unsigned long long u = strtoull(s, &end, 0);
        x = (long long) u;
    }
    *v = x;
    return true;
}

// A memory operand as the generator spells it:
//   <size> ptr [base+index*scale+disp]
struct mem {
    int bits;
    char base[8];
    char index[8];
    int scale;
    int64_t disp;
};

static bool mem_parse(const char *s, struct mem *m)
{
    memset(m, 0, sizeof(*m));
    m->scale = 1;
    const char *br = strchr(s, '[');
    if (br == NULL) {
        return false;
    }
    if (strncmp(s, "byte", 4) == 0) m->bits = 8;
    else if (strncmp(s, "word", 4) == 0) m->bits = 16;
    else if (strncmp(s, "dword", 5) == 0) m->bits = 32;
    else if (strncmp(s, "qword", 5) == 0) m->bits = 64;
    else if (strncmp(s, "xmmword", 7) == 0) m->bits = 128;
    else m->bits = 0;   // LEA's operand carries no size
    const char *p = br + 1;
    int sign = 1;
    while (*p != '\0' && *p != ']') {
        char tok[24];
        size_t k = 0;
        while (*p != '\0' && *p != ']' && *p != '+' && *p != '-' &&
               k + 1 < sizeof(tok)) {
            tok[k++] = *p++;
        }
        tok[k] = '\0';
        if (k > 0) {
            char *star = strchr(tok, '*');
            int64_t v;
            if (star != NULL) {
                *star = '\0';
                snprintf(m->index, sizeof(m->index), "%.7s", tok);
                m->scale = atoi(star + 1);
            } else if (imm_parse(tok, &v)) {
                m->disp += sign * v;
            } else if (m->base[0] == '\0') {
                snprintf(m->base, sizeof(m->base), "%.7s", tok);
            } else {
                snprintf(m->index, sizeof(m->index), "%.7s", tok);
                m->scale = 1;
            }
        }
        if (*p == '+') {
            sign = 1;
            ++p;
        } else if (*p == '-') {
            sign = -1;
            ++p;
        }
    }
    return *p == ']';
}

static void mem_format(const struct mem *m, int bits, char *out, size_t n)
{
    char addr[64];
    int k = snprintf(addr, sizeof(addr), "[");
    bool any = false;
    if (m->base[0] != '\0') {
        k += snprintf(addr + k, sizeof(addr) - (size_t) k, "%s", m->base);
        any = true;
    }
    if (m->index[0] != '\0') {
        k += snprintf(addr + k, sizeof(addr) - (size_t) k, "%s%s*%d",
                      any ? "+" : "", m->index, m->scale);
        any = true;
    }
    if (m->disp != 0 || !any) {
        k += snprintf(addr + k, sizeof(addr) - (size_t) k, "%s%" PRId64,
                      m->disp >= 0 && any ? "+" : "", m->disp);
    }
    snprintf(addr + k, sizeof(addr) - (size_t) k, "]");
    if (bits == 0) {
        snprintf(out, n, "%s", addr);
    } else {
        snprintf(out, n, "%s ptr %s", size_word(bits), addr);
    }
}

static bool is_mem(const char *op)
{
    return strchr(op, '[') != NULL;
}

// --------------------------------------------------------------- labels ---

#define STUB_LABEL 0

static int new_label(struct prog *p)
{
    return p->nlabels++;
}

// --------------------------------------------------------------- layout ---

static void emit_prologue(struct prog *p)
{
    prog_add(p, R_PRO, "push rbx");
    prog_add(p, R_PRO, "push r12");
    prog_add(p, R_PRO, "push r13");
    prog_add(p, R_PRO, "push r14");
    prog_add(p, R_PRO, "push r15");
    prog_add(p, R_PRO, "push rbp");
    prog_add(p, R_PRO, "mov rbp, rsp");
    prog_add(p, R_PRO, "sub rsp, %d", FRAME_SIZE);
    prog_add(p, R_PRO, "mov r15, rdi");
    prog_add(p, R_PRO, "mov qword ptr [r15+%d], rsp", OFF(saved_rsp));
    prog_add(p, R_PRO, "lea r14, [r15+%d]", OFF(scratch));
    prog_add(p, R_PRO, "mov rdi, rsp");
    prog_add(p, R_PRO, "lea rsi, [r15+%d]", OFF(frame));
    prog_add(p, R_PRO, "mov ecx, %d", FRAME_SIZE);
    prog_add(p, R_PRO, "rep movsb");
    for (int x = 0; x < 8; ++x) {
        prog_add(p, R_PRO, "movdqu xmm%d, xmmword ptr [r15+%d]", x,
                 OFF(in_xmm) + 16 * x);
    }
    for (int k = 0; k < NBODY; ++k) {
        prog_add(p, R_PRO, "mov %s, qword ptr [r15+%d]", gpr(BODY[k], 64),
                 OFF(in_gpr) + 8 * BODY[k]);
    }
    prog_add(p, R_PRO, "push qword ptr [r15+%d]", OFF(in_flags));
    prog_add(p, R_PRO, "popfq");
}

static void emit_epilogue(struct prog *p)
{
    prog_add(p, R_EPI, "pushfq");
    prog_add(p, R_EPI, "pop qword ptr [r15+%d]", OFF(out_flags));
    for (int k = 0; k < NBODY; ++k) {
        prog_add(p, R_EPI, "mov qword ptr [r15+%d], %s",
                 OFF(out_gpr) + 8 * BODY[k], gpr(BODY[k], 64));
    }
    for (int x = 0; x < 8; ++x) {
        prog_add(p, R_EPI, "movdqu xmmword ptr [r15+%d], xmm%d",
                 OFF(out_xmm) + 16 * x, x);
    }
    prog_add(p, R_EPI, "mov rsp, qword ptr [r15+%d]", OFF(saved_rsp));
    prog_add(p, R_EPI, "add rsp, %d", FRAME_SIZE);
    prog_add(p, R_EPI, "pop rbp");
    prog_add(p, R_EPI, "pop r15");
    prog_add(p, R_EPI, "pop r14");
    prog_add(p, R_EPI, "pop r13");
    prog_add(p, R_EPI, "pop r12");
    prog_add(p, R_EPI, "pop rbx");
    prog_add(p, R_EPI, "ret");

    // The stub: reads its arguments, writes memory and clobbers what a
    // callee may.
    struct item *it = prog_add(p, R_STUB, "mov rax, qword ptr [r15+%d]",
                               OFF(stub));
    it->label = STUB_LABEL;
    prog_add(p, R_STUB, "xor rax, rdi");
    prog_add(p, R_STUB, "add rax, rsi");
    prog_add(p, R_STUB, "mov qword ptr [r14+8], rax");
    for (int k = 1; k < (int) (sizeof(CLOBBERED) / sizeof(CLOBBERED[0]));
         ++k) {
        prog_add(p, R_STUB, "mov %s, qword ptr [r15+%d]",
                 gpr(CLOBBERED[k], 64), OFF(stub) + 8 * k);
    }
    for (int x = 0; x < 8; ++x) {
        prog_add(p, R_STUB, "movdqu xmm%d, xmmword ptr [r15+%d]", x,
                 OFF(in_xmm) + 16 * (7 - x));
    }
    prog_add(p, R_STUB, "add rcx, rax");
    prog_add(p, R_STUB, "ret");
}

// ------------------------------------------------------------ generator ---

enum mode { MODE_ALL, MODE_FLAGS, MODE_FRAME, MODE_FOLD, NMODES };
static const char *const MODE_NAMES[NMODES] = {"all", "flags", "frame",
                                               "fold"};

struct gen {
    uint64_t rng;
    struct prog *p;
    enum mode mode;
    int pending[64];   // labels awaiting a place
    int npending;
};

static int body_reg(struct gen *g)
{
    return BODY[rnd(&g->rng, NBODY)];
}

static int body_reg_other(struct gen *g, int not)
{
    int r;
    do {
        r = body_reg(g);
    } while (r == not);
    return r;
}

static int rand_width(struct gen *g)
{
    unsigned x = rnd(&g->rng, 20);
    return x < 8 ? 64 : x < 16 ? 32 : x < 18 ? 16 : 8;
}

// An immediate for an operation at `bits`, as text; 64-bit operations take
// a sign-extended imm32.
static void imm_text(struct gen *g, int bits, char *out, size_t n)
{
    int64_t v;
    switch (rnd(&g->rng, 5)) {
    case 0:
        v = (int64_t) rnd(&g->rng, 4);
        break;
    case 1:
        v = -(int64_t) rnd(&g->rng, 3);
        break;
    case 2:
        v = (int64_t) (edge_value(&g->rng));
        break;
    default:
        v = (int64_t) rnd(&g->rng, 300) - 150;
        break;
    }
    if (bits == 64) {
        v = sign_extend((uint64_t) v, 32);
    } else {
        v = sign_extend((uint64_t) v, bits);
    }
    snprintf(out, n, "%" PRId64, v);
}

static const char *const CC[] = {"o", "no", "b", "ae", "e", "ne", "be", "a",
                                 "s", "ns", "p", "np", "l", "ge", "le", "g"};
#define NCC 16

static const char *rand_cc(struct gen *g)
{
    return CC[rnd(&g->rng, NCC)];
}

// A condition that does not read OF, for a consumer of a shift's flags,
// whose OF the SDM leaves undefined at a count other than one.
static const char *rand_cc_no_of(struct gen *g)
{
    static const char *const NOF[] = {"b", "ae", "e", "ne", "be", "a", "s",
                                      "ns", "p", "np"};
    return NOF[rnd(&g->rng, 10)];
}

// A frame slot at `bits`, through RSP or RBP; hot slots repeat.
static void frame_slot(struct gen *g, int bits, char *out, size_t n,
                       int *offset_out)
{
    int bytes = bits / 8;
    int slot = chance(&g->rng, 80) ? (int) rnd(&g->rng, 6)
                                   : (int) rnd(&g->rng, 120);
    int off = slot * 8;
    if (bytes < 8 && chance(&g->rng, 25)) {
        off += bytes * (int) rnd(&g->rng, (unsigned) (8 / bytes));
    }
    if (bytes == 16) {
        off &= ~15;
    }
    if (off + bytes > 1024) {
        off = 0;
    }
    if (offset_out != NULL) {
        *offset_out = off;
    }
    if (chance(&g->rng, 50)) {
        snprintf(out, n, "%s ptr [rsp+%d]", size_word(bits), off);
    } else {
        snprintf(out, n, "%s ptr [rbp-%d]", size_word(bits), FRAME_SIZE - off);
    }
}

static void scratch_slot(struct gen *g, int bits, char *out, size_t n)
{
    int bytes = bits / 8;
    int off = (int) rnd(&g->rng, 24) * 8;
    if (bytes == 16) {
        off &= ~15;
    } else if (bytes < 8 && chance(&g->rng, 25)) {
        off += bytes * (int) rnd(&g->rng, (unsigned) (8 / bytes));
    }
    if (chance(&g->rng, 10)) {
        off += 1;   // misaligned on purpose
        if (bytes == 16) {
            off -= 1;
        }
    }
    snprintf(out, n, "%s ptr [r14+%d]", size_word(bits), off);
}

static void any_mem(struct gen *g, int bits, char *out, size_t n)
{
    if (chance(&g->rng, 65)) {
        frame_slot(g, bits, out, n, NULL);
    } else {
        scratch_slot(g, bits, out, n);
    }
}

#define ADD(...) prog_add(g->p, R_BODY, __VA_ARGS__)

// Mark the last `count` items as one group: no label may land inside.
static void seal_last(struct gen *g, int count)
{
    for (int k = g->p->n - count + 1; k < g->p->n; ++k) {
        g->p->it[k].sealed = true;
    }
}

// A forward branch on cc (NULL: an unconditional one) to a label placed
// later; nothing once the body has its fill of them.
static void gen_branch_cc(struct gen *g, const char *cc)
{
    if (g->npending >= (int) (sizeof(g->pending) / sizeof(g->pending[0]))) {
        return;
    }
    int l = new_label(g->p);
    g->pending[g->npending++] = l;
    if (cc == NULL) {
        ADD("jmp @%d", l);
    } else {
        ADD("j%s @%d", cc, l);
    }
}

static void gen_branch(struct gen *g)
{
    gen_branch_cc(g, chance(&g->rng, 20) ? NULL : rand_cc(g));
}

// An instruction that defines every arithmetic flag, which usually follows
// one that leaves some undefined: a program reading those depends on the
// core (see flags_undefined_at_end), and the flag-gated rows want the flags
// dead.
static void gen_flag_definer(struct gen *g)
{
    static const char *const OPS[] = {"add", "sub", "cmp", "and", "or",
                                      "xor", "test"};
    int w = chance(&g->rng, 50) ? 64 : 32;
    ADD("%s %s, %s", OPS[rnd(&g->rng, 7)], gpr(body_reg(g), w),
        gpr(body_reg(g), w));
}

static void gen_filler_inner(struct gen *g);

static void gen_filler(struct gen *g)
{
    int before = g->p->n;
    gen_filler_inner(g);
    for (int k = before; k < g->p->n; ++k) {
        const char *t = g->p->it[k].text;
        if ((strncmp(t, "imul", 4) == 0 || strncmp(t, "sh", 2) == 0 ||
             strncmp(t, "sa", 2) == 0 || strncmp(t, "ro", 2) == 0 ||
             strncmp(t, "tzcnt", 5) == 0 || strncmp(t, "div", 3) == 0) &&
            chance(&g->rng, 80)) {
            gen_flag_definer(g);
            break;
        }
    }
}

static void gen_filler_inner(struct gen *g)
{
    char a[48], b[48];
    int r = body_reg(g), s = body_reg(g);
    int w = rand_width(g);
    static const char *const ALU[] = {"add", "sub", "and", "or", "xor", "cmp",
                                      "test", "adc", "sbb"};
    unsigned pick = rnd(&g->rng, 100);
    if (pick < 10) {
        ADD("mov %s, %s", gpr(r, w), gpr(s, w));
    } else if (pick < 18) {
        if (w == 64 && chance(&g->rng, 30)) {
            ADD("mov %s, %" PRId64, gpr(r, 64), (int64_t) edge_value(&g->rng));
        } else {
            imm_text(g, w == 64 ? 32 : w, a, sizeof(a));
            ADD("mov %s, %s", gpr(r, w), a);
        }
    } else if (pick < 32) {
        const char *op = ALU[rnd(&g->rng, 9)];
        if (chance(&g->rng, 50)) {
            ADD("%s %s, %s", op, gpr(r, w), gpr(s, w));
        } else {
            imm_text(g, w, a, sizeof(a));
            ADD("%s %s, %s", op, gpr(r, w), a);
        }
    } else if (pick < 36) {
        static const char *const UN[] = {"inc", "dec", "neg", "not"};
        ADD("%s %s", UN[rnd(&g->rng, 4)], gpr(r, w));
    } else if (pick < 42) {
        static const char *const SH[] = {"shl", "shr", "sar", "rol", "ror"};
        const char *op = SH[rnd(&g->rng, 5)];
        if (chance(&g->rng, 25)) {
            ADD("%s %s, cl", op, gpr(r, w));
        } else {
            ADD("%s %s, %u", op, gpr(r, w), rnd(&g->rng, (unsigned) w));
        }
    } else if (pick < 45) {
        if (w == 8) {
            w = 32;
        }
        static const int64_t MUL[] = {0, 1, -1, 2, 3, 4, 5, 8, 9, 16, 7, 100};
        if (chance(&g->rng, 30)) {
            ADD("imul %s, %s", gpr(r, w), gpr(s, w));
        } else {
            ADD("imul %s, %s, %" PRId64, gpr(r, w),
                gpr(chance(&g->rng, 40) ? r : s, w),
                MUL[rnd(&g->rng, sizeof(MUL) / sizeof(MUL[0]))]);
        }
    } else if (pick < 51) {
        int t = body_reg(g);
        int dw = chance(&g->rng, 50) ? 64 : 32;
        static const int SC[] = {1, 2, 4, 8};
        switch (rnd(&g->rng, 5)) {
        case 0:
            ADD("lea %s, [%s]", gpr(r, dw), gpr(s, 64));
            break;
        case 1:
            ADD("lea %s, [%s+%s]", gpr(r, dw), gpr(chance(&g->rng, 50) ? r : s,
                64), gpr(t, 64));
            break;
        case 2:
            ADD("lea %s, [%s+%d]", gpr(r, dw), gpr(s, 64),
                (int) rnd(&g->rng, 200) - 100);
            break;
        case 3:
            ADD("lea %s, [%s+%s*%d+%d]", gpr(r, dw), gpr(s, 64), gpr(t, 64),
                SC[rnd(&g->rng, 4)], (int) rnd(&g->rng, 64));
            break;
        default:
            // A 32-bit address.
            ADD("lea %s, [%s+%s]", gpr(r, dw), gpr(chance(&g->rng, 50) ? r : s,
                32), gpr(t, 32));
            break;
        }
    } else if (pick < 56) {
        switch (rnd(&g->rng, 6)) {
        case 0:
            ADD("movzx %s, %s", gpr(r, 32), gpr(s, 8));
            break;
        case 1:
            ADD("movzx %s, %s", gpr(r, chance(&g->rng, 50) ? 32 : 64),
                gpr(s, 16));
            break;
        case 2:
            ADD("movsx %s, %s", gpr(r, chance(&g->rng, 50) ? 32 : 64),
                gpr(s, 8));
            break;
        case 3:
            ADD("movsx %s, %s", gpr(r, chance(&g->rng, 50) ? 32 : 64),
                gpr(s, 16));
            break;
        case 4:
            ADD("movsxd %s, %s", gpr(r, 64), gpr(s, 32));
            break;
        default: {
            static const char *const CV[] = {"cdqe", "cwde", "cbw", "cqo",
                                             "cdq"};
            ADD("%s", CV[rnd(&g->rng, 5)]);
            break;
        }
        }
    } else if (pick < 60) {
        if (w == 8) {
            w = 32;
        }
        ADD("cmov%s %s, %s", rand_cc(g), gpr(r, w), gpr(s, w));
    } else if (pick < 63) {
        ADD("set%s %s", rand_cc(g), gpr(r, 8));
    } else if (pick < 73) {
        // Loads and stores.
        any_mem(g, w, a, sizeof(a));
        switch (rnd(&g->rng, 6)) {
        case 0:
        case 1:
            ADD("mov %s, %s", gpr(r, w), a);
            break;
        case 2:
        case 3:
            ADD("mov %s, %s", a, gpr(r, w));
            break;
        case 4:
            imm_text(g, w == 64 ? 32 : w, b, sizeof(b));
            ADD("mov %s, %s", a, b);
            break;
        default: {
            const char *op = ALU[rnd(&g->rng, 9)];
            if (chance(&g->rng, 50)) {
                ADD("%s %s, %s", op, gpr(r, w), a);
            } else {
                ADD("%s %s, %s", op, a, gpr(r, w));
            }
            break;
        }
        }
    } else if (pick < 82) {
        // Vector.
        int x = (int) rnd(&g->rng, 8), y = (int) rnd(&g->rng, 8);
        switch (rnd(&g->rng, 14)) {
        case 0:
            ADD("movd xmm%d, %s", x, gpr(r, 32));
            break;
        case 1:
            ADD("movq xmm%d, %s", x, gpr(r, 64));
            break;
        case 2:
            ADD("movd %s, xmm%d", gpr(r, 32), x);
            break;
        case 3:
            ADD("movq %s, xmm%d", gpr(r, 64), x);
            break;
        case 4:
            any_mem(g, 64, a, sizeof(a));
            ADD(chance(&g->rng, 50) ? "movq xmm%d, %s" : "movsd xmm%d, %s",
                x, a);
            break;
        case 5:
            any_mem(g, 32, a, sizeof(a));
            ADD(chance(&g->rng, 50) ? "movd xmm%d, %s" : "movss xmm%d, %s",
                x, a);
            break;
        case 6:
            any_mem(g, 64, a, sizeof(a));
            ADD("movq %s, xmm%d", a, x);
            break;
        case 7: {
            static const char *const MV[] = {"movaps", "movups", "movapd",
                                             "movdqa", "movdqu", "movss",
                                             "movsd"};
            ADD("%s xmm%d, xmm%d", MV[rnd(&g->rng, 7)], x, y);
            break;
        }
        case 8: {
            static const char *const OPS[] = {"addps", "paddd", "pxor",
                                              "xorps", "xorpd", "pand",
                                              "mulps", "por", "psubq"};
            ADD("%s xmm%d, xmm%d", OPS[rnd(&g->rng, 9)], x,
                chance(&g->rng, 20) ? x : y);
            break;
        }
        case 9:
            any_mem(g, 128, a, sizeof(a));
            ADD("movups xmm%d, %s", x, a);
            break;
        case 10:
            any_mem(g, 128, a, sizeof(a));
            ADD("movups %s, xmm%d", a, x);
            break;
        case 11:
            switch (rnd(&g->rng, 3)) {
            case 0:
                ADD("pextrd %s, xmm%d, %u", gpr(r, 32), x, rnd(&g->rng, 2));
                break;
            case 1:
                ADD("pextrq %s, xmm%d, %u", gpr(r, 64), x, rnd(&g->rng, 2));
                break;
            default:
                ADD("extractps %s, xmm%d, %u", gpr(r, 32), x,
                    rnd(&g->rng, 2));
                break;
            }
            break;
        case 12:
            ADD("cvtsi2sd xmm%d, %s", x,
                gpr(r, chance(&g->rng, 50) ? 32 : 64));
            break;
        default:
            ADD("sqrtsd xmm%d, xmm%d", x, y);
            break;
        }
    } else if (pick < 89) {
        gen_branch(g);
    } else if (pick < 91) {
        ADD("call @%d", STUB_LABEL);
    } else if (pick < 93) {
        // A push and pop around a few instructions.
        int start = g->p->n;
        ADD("push %s", gpr(r, 64));
        if (chance(&g->rng, 50)) {
            frame_slot(g, 64, a, sizeof(a), NULL);
            ADD("mov %s, %s", gpr(s, 64), a);
        }
        ADD("pop %s", gpr(body_reg(g), 64));
        seal_last(g, g->p->n - start);
    } else if (pick < 95) {
        // A store or load through a pointer to the frame.
        int off = (int) rnd(&g->rng, 6) * 8;
        int start = g->p->n;
        ADD("lea %s, [rsp+%d]", gpr(r, 64), off);
        if (chance(&g->rng, 60)) {
            ADD("mov qword ptr [%s], %s", gpr(r, 64), gpr(body_reg_other(g, r),
                64));
        } else {
            ADD("mov %s, qword ptr [%s]", gpr(s, 64), gpr(r, 64));
        }
        seal_last(g, g->p->n - start);
    } else if (pick < 96) {
        // A division that cannot fault.
        int start = g->p->n;
        ADD("xor edx, edx");
        ADD("or %s, 1", gpr(3, 64));
        ADD("div %s", gpr(3, chance(&g->rng, 50) ? 64 : 32));
        seal_last(g, g->p->n - start);
    } else if (pick < 97) {
        // RBP rewritten to its own value: no longer provably the frame.
        ADD("lea rbp, [rsp+%d]", FRAME_SIZE);
    } else {
        ADD("popcnt %s, %s", gpr(r, w == 8 ? 32 : w), gpr(s, w == 8 ? 32 : w));
    }
}

// ----------------------------------------------------------------- plants ---

static void plant_frame(struct gen *g)
{
    char a[48];
    int r = body_reg(g), s = body_reg(g);
    int w = chance(&g->rng, 60) ? 64 : 32;
    frame_slot(g, w, a, sizeof(a), NULL);
    switch (rnd(&g->rng, 7)) {
    case 0:   // store, gap, load
        ADD("mov %s, %s", a, gpr(r, w));
        for (unsigned k = rnd(&g->rng, 3); k > 0; --k) {
            gen_filler(g);
        }
        ADD("mov %s, %s", gpr(s, w), a);
        break;
    case 1:   // load, gap, load
        ADD("mov %s, %s", gpr(r, w), a);
        for (unsigned k = rnd(&g->rng, 3); k > 0; --k) {
            gen_filler(g);
        }
        ADD("mov %s, %s", gpr(chance(&g->rng, 50) ? r : s, w), a);
        break;
    case 2:   // store, gap, store
        ADD("mov %s, %s", a, gpr(r, w));
        for (unsigned k = rnd(&g->rng, 3); k > 0; --k) {
            gen_filler(g);
        }
        ADD("mov %s, %s", a, gpr(chance(&g->rng, 50) ? r : s, w));
        break;
    case 3:   // load, store back
        ADD("mov %s, %s", gpr(r, w), a);
        if (chance(&g->rng, 50)) {
            gen_filler(g);
        }
        ADD("mov %s, %s", a, gpr(r, w));
        break;
    case 4: { // bit-cast
        int x = (int) rnd(&g->rng, 8);
        frame_slot(g, w, a, sizeof(a), NULL);
        const char *mv = w == 64 ? "movq" : "movd";
        if (chance(&g->rng, 50)) {
            ADD("mov %s, %s", a, gpr(r, w));
            if (chance(&g->rng, 30)) {
                gen_filler(g);
            }
            ADD("%s xmm%d, %s", chance(&g->rng, 50) ? mv :
                w == 64 ? "movsd" : "movss", x, a);
        } else {
            ADD("%s %s, xmm%d", chance(&g->rng, 50) ? mv :
                w == 64 ? "movsd" : "movss", a, x);
            if (chance(&g->rng, 30)) {
                gen_filler(g);
            }
            ADD("mov %s, %s", gpr(r, w), a);
        }
        break;
    }
    case 5: { // constant store, store again
        char b[48];
        imm_text(g, 32, b, sizeof(b));
        ADD("mov %s, %s", a, b);
        if (chance(&g->rng, 50)) {
            gen_filler(g);
        }
        ADD("mov %s, %s", a, chance(&g->rng, 50) ? b : gpr(r, w));
        break;
    }
    default: { // the same slot spelled through the other base
        int off;
        frame_slot(g, w, a, sizeof(a), &off);
        char other[48];
        if (strstr(a, "rsp") != NULL) {
            snprintf(other, sizeof(other), "%s ptr [rbp-%d]", size_word(w),
                     FRAME_SIZE - off);
        } else {
            snprintf(other, sizeof(other), "%s ptr [rsp+%d]", size_word(w),
                     off);
        }
        ADD("mov %s, %s", a, gpr(r, w));
        ADD("mov %s, %s", other, gpr(s, w));
        ADD("mov %s, %s", gpr(body_reg(g), w), a);
        break;
    }
    }
}

static void plant_flags(struct gen *g)
{
    char a[48];
    int r = body_reg(g), s = body_reg(g);
    int w = rand_width(g);
    switch (rnd(&g->rng, 16)) {
    case 14:  // SETcc, TEST, JE/JNE
        ADD("set%s %s", rand_cc(g), gpr(r, 8));
        ADD("test %s, %s", gpr(r, 8), gpr(r, 8));
        gen_branch_cc(g, chance(&g->rng, 50) ? "e" : "ne");
        return;
    case 15:  // SETcc, XOR 1
        ADD("set%s %s", rand_cc(g), gpr(r, 8));
        ADD("xor %s, 1", gpr(r, 8));
        break;
    case 0:   // zeroing, test, consumer
        ADD("%s %s, %s", chance(&g->rng, 70) ? "xor" : "sub", gpr(r, 32),
            gpr(r, 32));
        if (chance(&g->rng, 40)) {
            gen_filler(g);
        }
        ADD("test %s, %s", gpr(r, w), gpr(r, w));
        break;
    case 1:   // immediate, compare, consumer
        imm_text(g, w == 64 ? 32 : w, a, sizeof(a));
        ADD("mov %s, %s", gpr(r, w), a);
        imm_text(g, w == 64 ? 32 : w, a, sizeof(a));
        if (chance(&g->rng, 50)) {
            ADD("cmp %s, %s", gpr(r, w), a);
        } else {
            ADD("test %s, %s", gpr(r, w), gpr(r, w));
        }
        break;
    case 2: { // ALU, test
        static const char *const OPS[] = {"add", "sub", "and", "or", "xor",
                                          "inc", "dec", "neg"};
        const char *op = OPS[rnd(&g->rng, 8)];
        if (strcmp(op, "inc") == 0 || strcmp(op, "dec") == 0 ||
            strcmp(op, "neg") == 0) {
            ADD("%s %s", op, gpr(r, w));
        } else {
            ADD("%s %s, %s", op, gpr(r, w), gpr(s, w));
        }
        ADD("test %s, %s", gpr(r, w), gpr(r, w));
        break;
    }
    case 3:   // shift, test
        ADD("%s %s, %u", chance(&g->rng, 50) ? "shl" : "shr", gpr(r, w),
            1 + rnd(&g->rng, (unsigned) w - 1));
        ADD("test %s, %s", gpr(r, w), gpr(r, w));
        break;
    case 4:   // compare against one
        ADD("cmp %s, 1", gpr(r, w));
        gen_branch_cc(g, chance(&g->rng, 50) ? "b" : "ae");
        return;
    case 5:
        ADD("mov %s, 0", gpr(r, chance(&g->rng, 50) ? 32 : 64));
        break;
    case 6:
        ADD("and %s, %s", gpr(r, w == 8 ? 32 : w),
            chance(&g->rng, 50) ? "0xff" : "0xffff");
        break;
    case 7: {
        static const char *const OPS[] = {"and", "xor", "test", "add", "sub",
                                          "or", "cmp"};
        static const char *const IMM[] = {"-1", "0", "1", "128", "-128"};
        ADD("%s %s, %s", OPS[rnd(&g->rng, 7)], gpr(r, w),
            IMM[rnd(&g->rng, 5)]);
        break;
    }
    case 8:
        ADD("%s %s, %s", chance(&g->rng, 50) ? "or" : "and", gpr(r, w),
            gpr(r, w));
        break;
    case 9:
        ADD("shl %s, 1", gpr(r, w));
        break;
    case 10:
        ADD("shl %s, %u", gpr(r, w), w == 64 ? 32u : w == 32 ? 24u : 8u);
        ADD("%s %s, %u", chance(&g->rng, 50) ? "sar" : "shr", gpr(r, w),
            w == 64 ? 32u : w == 32 ? 24u : 8u);
        break;
    case 11:
        ADD("neg %s", gpr(r, w));
        ADD("%s %s, %s", chance(&g->rng, 50) ? "add" : "sub", gpr(s, w),
            gpr(r, w));
        break;
    case 12:
        switch (rnd(&g->rng, 4)) {
        case 0:
            ADD("shr %s, %u", gpr(r, 32), 24 + rnd(&g->rng, 8));
            ADD("movzx %s, %s", gpr(r, 32), gpr(r, 8));
            break;
        case 1:
            any_mem(g, 8, a, sizeof(a));
            ADD("movzx %s, %s", gpr(r, chance(&g->rng, 50) ? 32 : 16), a);
            ADD("movzx %s, %s", gpr(r, chance(&g->rng, 50) ? 32 : 64),
                gpr(r, 8));
            break;
        case 2:
            ADD("movsx %s, %s", gpr(r, chance(&g->rng, 50) ? 32 : 64),
                gpr(s, 8));
            ADD("movsx %s, %s", gpr(r, chance(&g->rng, 50) ? 32 : 64),
                gpr(r, chance(&g->rng, 50) ? 8 : 16));
            break;
        default:
            ADD("movsx %s, %s", gpr(r, 64), gpr(s, chance(&g->rng, 50) ? 8
                : 16));
            ADD("movsxd %s, %s", gpr(r, 64), gpr(r, 32));
            break;
        }
        break;
    default:
        ADD("set%s %s", rand_cc(g), gpr(r, 8));
        if (chance(&g->rng, 50)) {
            ADD("and %s, 1", gpr(r, 8));
        } else {
            ADD("movzx %s, %s", gpr(r, 32), gpr(r, 8));
        }
        break;
    }
    // A consumer for the flags, often; one that does not read OF after a
    // shift.
    const char *last = g->p->it[g->p->n - 1].text;
    bool shifted = strncmp(last, "sh", 2) == 0 || strncmp(last, "sa", 2) == 0;
    const char *cc = shifted ? rand_cc_no_of(g) : rand_cc(g);
    unsigned c = rnd(&g->rng, 4);
    if (c == 0) {
        gen_branch_cc(g, cc);
    } else if (c == 1) {
        ADD("cmov%s %s, %s", cc, gpr(s, 32), gpr(body_reg(g), 32));
    } else if (c == 2) {
        ADD("set%s %s", cc, gpr(s, 8));
    }
}

static void plant_fold(struct gen *g)
{
    char a[48], b[48];
    int r = body_reg(g), s = body_reg_other(g, r), t = body_reg(g);
    int w = chance(&g->rng, 60) ? 64 : 32;
    static const char *const ALU[] = {"add", "sub", "and", "or", "xor", "cmp",
                                      "test", "mov"};
    switch (rnd(&g->rng, 14)) {
    case 13: { // BMI and MOVBE shapes
        int bw = chance(&g->rng, 50) ? 64 : 32;
        switch (rnd(&g->rng, 4)) {
        case 0:
            ADD("not %s", gpr(r, bw));
            ADD("and %s, %s", gpr(r, bw), gpr(chance(&g->rng, 80) ? s : r,
                bw));
            break;
        case 1:
            ADD("lea %s, [%s-1]", gpr(r, bw), gpr(s, 64));
            ADD("%s %s, %s", chance(&g->rng, 50) ? "and" : "xor", gpr(r, bw),
                gpr(s, bw));
            break;
        case 2:
            ADD("mov %s, %s", gpr(r, bw), gpr(s, bw));
            ADD("neg %s", gpr(r, bw));
            ADD("and %s, %s", gpr(r, bw), gpr(s, bw));
            break;
        default:
            any_mem(g, bw, a, sizeof(a));
            ADD("mov %s, %s", gpr(r, bw), a);
            ADD("bswap %s", gpr(r, bw));
            break;
        }
        if (chance(&g->rng, 50)) {
            gen_flag_definer(g);
        }
        break;
    }
    case 0: { // LEA into memory
        int start = g->p->n;
        ADD("lea %s, [r14+%d]", gpr(r, chance(&g->rng, 85) ? 64 : 32),
            (int) rnd(&g->rng, 32) * 8);
        ADD("mov %s, %s ptr [%s+%d]", gpr(s, w), size_word(w), gpr(r, 64),
            (int) rnd(&g->rng, 8) * 8);
        seal_last(g, g->p->n - start);
        break;
    }
    case 1: { // ADD into memory
        int start = g->p->n;
        ADD("lea %s, [r14+%d]", gpr(r, 64), (int) rnd(&g->rng, 32) * 8);
        if (chance(&g->rng, 70)) {
            ADD("%s %s, %d", chance(&g->rng, 70) ? "add" : "sub", gpr(r,
                chance(&g->rng, 85) ? 64 : 32), (int) rnd(&g->rng, 8) * 8);
        } else {
            ADD("%s %s", chance(&g->rng, 50) ? "inc" : "dec", gpr(r, 64));
        }
        ADD("mov %s, %s ptr [%s+%d]", gpr(s, w), size_word(w), gpr(r, 64),
            (int) rnd(&g->rng, 8) * 8);
        seal_last(g, g->p->n - start);
        break;
    }
    case 2:   // ADD into LEA
        ADD("lea %s, [%s+%d]", gpr(r, w), gpr(s, 64), (int) rnd(&g->rng, 64));
        switch (rnd(&g->rng, 3)) {
        case 0:
            ADD("add %s, %d", gpr(r, w), (int) rnd(&g->rng, 64) - 32);
            break;
        case 1:
            ADD("add %s, %s", gpr(r, w), gpr(t, w));
            break;
        default:
            ADD("add %s, %s", gpr(t, w), gpr(r, w));
            break;
        }
        break;
    case 3:   // MOV + ADD
        ADD("mov %s, %s", gpr(r, w), gpr(s, w));
        if (chance(&g->rng, 50)) {
            ADD("%s %s, %d", chance(&g->rng, 50) ? "add" : "sub", gpr(r, w),
                (int) rnd(&g->rng, 100));
        } else {
            ADD("add %s, %s", gpr(r, w), gpr(t, w));
        }
        break;
    case 4:   // MOV constant into its consumer
        if (w == 64 && chance(&g->rng, 30)) {
            ADD("mov %s, %" PRId64, gpr(r, 64), (int64_t) edge_value(&g->rng));
        } else {
            imm_text(g, 32, a, sizeof(a));
            ADD("mov %s, %s", gpr(r, chance(&g->rng, 50) ? 32 : 64), a);
        }
        ADD("%s %s, %s", ALU[rnd(&g->rng, 8)], gpr(s, w), gpr(r, w));
        if (chance(&g->rng, 60)) {
            ADD("mov %s, 7", gpr(r, 32));
        }
        break;
    case 5:   // load into ALU
        any_mem(g, w, a, sizeof(a));
        ADD("mov %s, %s", gpr(r, w), a);
        ADD("%s %s, %s", ALU[rnd(&g->rng, 7)], gpr(s, w), gpr(r, w));
        if (chance(&g->rng, 60)) {
            ADD("mov %s, 7", gpr(r, 32));
        }
        break;
    case 6:   // load into compare
        any_mem(g, w, a, sizeof(a));
        ADD("mov %s, %s", gpr(r, w), a);
        if (chance(&g->rng, 50)) {
            imm_text(g, w, b, sizeof(b));
            ADD("cmp %s, %s", gpr(r, w), b);
        } else {
            ADD("test %s, %s", gpr(r, w), gpr(r, w));
        }
        if (chance(&g->rng, 60)) {
            ADD("mov %s, 7", gpr(r, 32));
        }
        gen_branch(g);
        break;
    case 7: { // load into extend
        int nw = chance(&g->rng, 40) ? 8 : chance(&g->rng, 50) ? 16 : 32;
        any_mem(g, nw, a, sizeof(a));
        ADD("mov %s, %s", gpr(r, nw), a);
        if (nw == 32) {
            ADD("movsxd %s, %s", gpr(r, 64), gpr(r, 32));
        } else {
            ADD("%s %s, %s", chance(&g->rng, 50) ? "movzx" : "movsx",
                gpr(r, chance(&g->rng, 50) ? 32 : 64), gpr(r, nw));
        }
        break;
    }
    case 8: { // vector load into op
        int x = (int) rnd(&g->rng, 8), y = (int) rnd(&g->rng, 8);
        any_mem(g, 128, a, sizeof(a));
        static const char *const LOADS[] = {"movups", "movdqu", "movaps",
                                            "movdqa", "movapd"};
        ADD("%s xmm%d, %s", LOADS[rnd(&g->rng, 5)], x, a);
        static const char *const OPS[] = {"addps", "paddd", "pxor", "xorps",
                                          "pand", "mulps"};
        ADD("%s xmm%d, xmm%d", OPS[rnd(&g->rng, 6)], y, x);
        if (chance(&g->rng, 60)) {
            ADD("xorps xmm%d, xmm%d", x, x);
        }
        break;
    }
    case 9: { // load into vector transfer
        int x = (int) rnd(&g->rng, 8);
        any_mem(g, w, a, sizeof(a));
        ADD("mov %s, %s", gpr(r, w), a);
        ADD("%s xmm%d, %s", chance(&g->rng, 30) ? "cvtsi2sd" :
            w == 64 ? "movq" : "movd", x, gpr(r, w));
        if (chance(&g->rng, 60)) {
            ADD("mov %s, 7", gpr(r, 32));
        }
        break;
    }
    case 10: { // constants again
        imm_text(g, 32, a, sizeof(a));
        ADD("mov %s, %s", gpr(r, w), a);
        for (unsigned k = rnd(&g->rng, 3); k > 0; --k) {
            gen_filler(g);
        }
        ADD("mov %s, %s", gpr(chance(&g->rng, 50) ? r : s, w), a);
        break;
    }
    case 11: { // narrow moves and merges
        int x = (int) rnd(&g->rng, 8), y = (int) rnd(&g->rng, 8);
        if (chance(&g->rng, 50)) {
            int nw = chance(&g->rng, 50) ? 8 : 16;
            ADD("mov %s, %s", gpr(r, nw), gpr(s, nw));
            ADD("mov %s, %s", gpr(t, 64), gpr(r, 64));
        } else {
            ADD("%s xmm%d, xmm%d", chance(&g->rng, 50) ? "movss" : "movsd",
                x, y);
            ADD("movq %s, xmm%d", gpr(t, 64), x);
        }
        break;
    }
    default: { // shift by CL; bit scans
        static const char *const SH[] = {"shl", "shr", "sar"};
        ADD("%s %s, cl", SH[rnd(&g->rng, 3)], gpr(r, w));
        if (chance(&g->rng, 50)) {
            // A bit scan's zero-source default, set by hand: at each width,
            // from a source that may be the destination itself or memory,
            // and from a MOV wider than the scan.
            int bw = chance(&g->rng, 20) ? 16 : w;
            int mw = bw == 16 && chance(&g->rng, 50) ? 32 : bw;
            const char *scan = chance(&g->rng, 70) ? "tzcnt" : "lzcnt";
            if (chance(&g->rng, 20)) {
                ADD("mov %s, %d", gpr(s, mw), bw);
                any_mem(g, bw, a, sizeof(a));
                ADD("%s %s, %s", scan, gpr(s, bw), a);
            } else {
                ADD("mov %s, %d", gpr(s, mw), bw);
                ADD("%s %s, %s", scan, gpr(s, bw),
                    gpr(chance(&g->rng, 25) ? s : t, bw));
            }
            gen_flag_definer(g);
        }
        break;
    }
    }
}

// Place the pending labels at random later points of the body.
static void place_labels(struct gen *g, int body_start, int body_end)
{
    for (int k = 0; k < g->npending; ++k) {
        int l = g->pending[k];
        // The branch defining it.
        int src = -1;
        char needle[16];
        snprintf(needle, sizeof(needle), "@%d", l);
        for (int i = body_start; i < body_end; ++i) {
            const char *at = strstr(g->p->it[i].text, needle);
            if (at != NULL && at[strlen(needle)] == '\0') {
                src = i;
                break;
            }
        }
        assert(src >= 0);
        // Somewhere after the branch, not inside a group, and not on an
        // item already labelled; the epilogue's first item takes the rest.
        int dst = body_end;
        for (int tries = 0; tries < 8; ++tries) {
            int span = body_end - src;
            int cand = src + 1 + (int) rnd(&g->rng, (unsigned) span);
            if (cand >= body_end) {
                break;
            }
            if (!g->p->it[cand].sealed && g->p->it[cand].label < 0) {
                dst = cand;
                break;
            }
        }
        if (g->p->it[dst].label >= 0) {
            // Share the existing label: re-spell the branch.
            int existing = g->p->it[dst].label;
            char *at = strstr(g->p->it[src].text, needle);
            snprintf(at, (size_t) (TEXTLEN - (at - g->p->it[src].text)), "@%d",
                     existing);
        } else {
            g->p->it[dst].label = (short) l;
        }
    }
}

static void generate(struct prog *p, uint64_t seed, enum mode mode)
{
    struct gen g = {.rng = seed, .p = p, .mode = mode};
    memset(p, 0, sizeof(*p));
    p->nlabels = 1;   // label 0 is the stub
    emit_prologue(p);
    int body_start = p->n;
    int count = 30 + (int) rnd(&g.rng, 40);
    while (p->n - body_start < count && p->n < MAXITEMS - 120) {
        unsigned pick = rnd(&g.rng, 100);
        bool frame = mode == MODE_ALL || mode == MODE_FRAME;
        bool flags = mode == MODE_ALL || mode == MODE_FLAGS;
        bool fold = mode == MODE_ALL || mode == MODE_FOLD;
        unsigned planted = mode == MODE_ALL ? 45 : 40;
        if (pick < planted) {
            unsigned which = rnd(&g.rng, 3);
            if (which == 0 && frame) {
                plant_frame(&g);
            } else if (which == 1 && flags) {
                plant_flags(&g);
            } else if (which == 2 && fold) {
                plant_fold(&g);
            } else if (frame && mode == MODE_FRAME) {
                plant_frame(&g);
            } else if (flags && mode == MODE_FLAGS) {
                plant_flags(&g);
            } else if (fold && mode == MODE_FOLD) {
                plant_fold(&g);
            } else {
                gen_filler(&g);
            }
        } else {
            gen_filler(&g);
        }
    }
    int body_end = p->n;
    emit_epilogue(p);
    place_labels(&g, body_start, body_end);
}

// ------------------------------------------------------------- assemble ---

static const char *cc_driver = "cc";
static char workdir[256];

struct code {
    uint8_t *bytes;
    size_t size;
    size_t *off;      // per item: offset of its instruction (or of the next)
    uint8_t *len;     // per item: instruction length, 0 for a bare label
    int n;
};

static void code_free(struct code *c)
{
    free(c->bytes);
    free(c->off);
    free(c->len);
    memset(c, 0, sizeof(*c));
}

static void emit_prog_text(FILE *f, const struct prog *p, int tag, int *line)
{
    fprintf(f, "rwfuzz_p%d:\n", tag);
    ++*line;
    for (int i = 0; i < p->n; ++i) {
        const struct item *it = &p->it[i];
        if (it->label >= 0) {
            fprintf(f, ".L%d_%d:\n", tag, it->label);
            ++*line;
        }
        if (it->text[0] == '\0') {
            continue;
        }
        const char *at = strchr(it->text, '@');
        if (at != NULL) {
            fprintf(f, "\t%.*s.L%d_%s\n", (int) (at - it->text), it->text, tag,
                    at + 1);
        } else {
            fprintf(f, "\t%s\n", it->text);
        }
        ++*line;
    }
}

static uint8_t *read_file(const char *path, size_t *size)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc((size_t) n);
    if (buf == NULL || fread(buf, 1, (size_t) n, f) != (size_t) n) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *size = (size_t) n;
    return buf;
}

// The .text of an ELF relocatable, which must carry no relocations.
static uint8_t *elf_text(const uint8_t *elf, size_t size, size_t *text_size)
{
    if (size < sizeof(Elf64_Ehdr) || memcmp(elf, ELFMAG, SELFMAG) != 0) {
        return NULL;
    }
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *) elf;
    const Elf64_Shdr *sh = (const Elf64_Shdr *) (elf + eh->e_shoff);
    const char *names = (const char *) (elf + sh[eh->e_shstrndx].sh_offset);
    const uint8_t *text = NULL;
    for (int k = 0; k < eh->e_shnum; ++k) {
        const char *name = names + sh[k].sh_name;
        if (strcmp(name, ".text") == 0) {
            text = elf + sh[k].sh_offset;
            *text_size = sh[k].sh_size;
        } else if (strcmp(name, ".rela.text") == 0 && sh[k].sh_size != 0) {
            fprintf(stderr, "rwfuzz: the assembler left relocations\n");
            exit(2);
        }
    }
    if (text == NULL) {
        return NULL;
    }
    uint8_t *out = malloc(*text_size + 1);
    memcpy(out, text, *text_size);
    return out;
}

static void decode_init(xed_decoded_inst_t *x)
{
    xed_decoded_inst_zero(x);
    xed_decoded_inst_set_mode(x, XED_MACHINE_MODE_LONG_64,
                              XED_ADDRESS_WIDTH_64b);
}

// Assemble n programs as one batch. A program whose text the assembler
// refuses has ok[k] cleared and no code; the batch is retried without it.
static void assemble(struct prog *const *progs, int n, struct code *out,
                     bool *ok)
{
    for (int k = 0; k < n; ++k) {
        ok[k] = true;
    }
    for (;;) {
        char spath[300], opath[300], epath[300];
        snprintf(spath, sizeof(spath), "%s/b.s", workdir);
        snprintf(opath, sizeof(opath), "%s/b.o", workdir);
        snprintf(epath, sizeof(epath), "%s/b.err", workdir);
        FILE *f = fopen(spath, "w");
        if (f == NULL) {
            perror(spath);
            exit(2);
        }
        int line = 1;
        fprintf(f, "\t.intel_syntax noprefix\n");
        ++line;
        fprintf(f, "\t.text\n");
        ++line;
        int *first = calloc((size_t) n + 1, sizeof(int));
        for (int k = 0; k < n; ++k) {
            first[k] = line;
            if (ok[k]) {
                emit_prog_text(f, progs[k], k, &line);
            }
        }
        first[n] = line;
        fclose(f);

        char cmd[1200];
        snprintf(cmd, sizeof(cmd),
                 "%s -c -x assembler -o '%s' '%s' 2> '%s'", cc_driver, opath,
                 spath, epath);
        int rc = system(cmd);
        if (rc != 0) {
            // Find the programs the errors name and drop them.
            size_t esize;
            char *err = (char *) read_file(epath, &esize);
            bool dropped = false;
            if (err != NULL) {
                err = realloc(err, esize + 1);
                err[esize] = '\0';
                for (char *p = err; (p = strstr(p, "b.s:")) != NULL; ++p) {
                    int l = atoi(p + 4);
                    for (int k = 0; k < n; ++k) {
                        if (ok[k] && l >= first[k] && l < first[k + 1]) {
                            ok[k] = false;
                            dropped = true;
                        }
                    }
                }
            }
            if (getenv("RWFUZZ_DEBUG") != NULL && err != NULL) {
                fprintf(stderr, "%s", err);
            }
            if (!dropped) {
                fprintf(stderr, "rwfuzz: the assembler failed:\n%s\n",
                        err != NULL ? err : "(no output)");
                exit(2);
            }
            free(err);
            free(first);
            continue;
        }
        free(first);

        size_t osize, tsize;
        uint8_t *obj = read_file(opath, &osize);
        uint8_t *text = obj != NULL ? elf_text(obj, osize, &tsize) : NULL;
        free(obj);
        if (text == NULL) {
            fprintf(stderr, "rwfuzz: no .text in %s\n", opath);
            exit(2);
        }
        size_t at = 0;
        for (int k = 0; k < n; ++k) {
            memset(&out[k], 0, sizeof(out[k]));
            if (!ok[k]) {
                continue;
            }
            const struct prog *p = progs[k];
            out[k].n = p->n;
            out[k].off = calloc((size_t) p->n + 1, sizeof(size_t));
            out[k].len = calloc((size_t) p->n + 1, 1);
            size_t start = at;
            for (int i = 0; i < p->n; ++i) {
                out[k].off[i] = at - start;
                if (p->it[i].text[0] == '\0') {
                    continue;
                }
                xed_decoded_inst_t x;
                decode_init(&x);
                if (at >= tsize || xed_decode(&x, text + at,
                        (unsigned) (tsize - at)) != XED_ERROR_NONE) {
                    fprintf(stderr, "rwfuzz: cannot decode `%s`\n",
                            p->it[i].text);
                    exit(2);
                }
                out[k].len[i] = (uint8_t) xed_decoded_inst_get_length(&x);
                at += out[k].len[i];
            }
            out[k].off[p->n] = at - start;
            out[k].size = at - start;
            out[k].bytes = malloc(out[k].size);
            memcpy(out[k].bytes, text + start, out[k].size);
        }
        free(text);
        return;
    }
}

// -------------------------------------------------------------- analysis ---

// A decoded view of one assembled program.
struct view {
    const struct prog *p;
    const struct code *c;
    xed_decoded_inst_t *dec;   // per item; zeroed for a bare label
};

static void view_build(struct view *v, const struct prog *p,
                       const struct code *c)
{
    v->p = p;
    v->c = c;
    v->dec = calloc((size_t) p->n, sizeof(xed_decoded_inst_t));
    for (int i = 0; i < p->n; ++i) {
        if (c->len[i] == 0) {
            continue;
        }
        decode_init(&v->dec[i]);
        xed_decode(&v->dec[i], c->bytes + c->off[i], c->len[i]);
    }
}

static void view_free(struct view *v)
{
    free(v->dec);
}

static int item_at_offset(const struct code *c, size_t off)
{
    for (int i = 0; i < c->n; ++i) {
        if (c->len[i] != 0 && c->off[i] == off) {
            return i;
        }
    }
    return -1;
}

// Does item i write GPR `num` (at any width)? A call clobbers the
// caller-saved registers.
static bool writes_gpr(const struct view *v, int i, int num)
{
    if (v->c->len[i] == 0) {
        return false;
    }
    const xed_decoded_inst_t *x = &v->dec[i];
    if (xed_decoded_inst_get_category(x) == XED_CATEGORY_CALL) {
        for (size_t k = 0; k < sizeof(CLOBBERED) / sizeof(CLOBBERED[0]); ++k) {
            if (CLOBBERED[k] == num) {
                return true;
            }
        }
    }
    const xed_inst_t *xi = xed_decoded_inst_inst(x);
    for (unsigned k = 0; k < xed_inst_noperands(xi); ++k) {
        const xed_operand_t *op = xed_inst_operand(xi, k);
        xed_operand_enum_t name = xed_operand_name(op);
        if (!xed_operand_is_register(name)) {
            continue;
        }
        if (!xed_operand_written(op)) {
            continue;
        }
        xed_reg_enum_t r = xed_decoded_inst_get_reg(x, name);
        if (xed_reg_class(r) != XED_REG_CLASS_GPR) {
            continue;
        }
        xed_reg_enum_t big = xed_get_largest_enclosing_register(r);
        if ((int) (big - XED_REG_RAX) == num) {
            return true;
        }
    }
    return false;
}

// Does item i read or write GPR `num` at any width, through any operand?
static bool touches_gpr(const struct view *v, int i, int num)
{
    if (v->c->len[i] == 0) {
        return false;
    }
    if (writes_gpr(v, i, num)) {
        return true;
    }
    const xed_decoded_inst_t *x = &v->dec[i];
    const xed_inst_t *xi = xed_decoded_inst_inst(x);
    for (unsigned k = 0; k < xed_inst_noperands(xi); ++k) {
        xed_operand_enum_t name = xed_operand_name(xed_inst_operand(xi, k));
        xed_reg_enum_t r = XED_REG_INVALID;
        if (xed_operand_is_register(name)) {
            r = xed_decoded_inst_get_reg(x, name);
        } else if (name == XED_OPERAND_MEM0 || name == XED_OPERAND_AGEN) {
            if ((int) (xed_get_largest_enclosing_register(
                    xed_decoded_inst_get_base_reg(x, 0)) - XED_REG_RAX) ==
                    num ||
                (int) (xed_get_largest_enclosing_register(
                    xed_decoded_inst_get_index_reg(x, 0)) - XED_REG_RAX) ==
                    num) {
                return true;
            }
            continue;
        }
        if (xed_reg_class(r) == XED_REG_CLASS_GPR &&
            (int) (xed_get_largest_enclosing_register(r) - XED_REG_RAX) ==
                num) {
            return true;
        }
    }
    return false;
}

static bool writes_xmm(const struct view *v, int i, int num)
{
    if (v->c->len[i] == 0) {
        return false;
    }
    const xed_decoded_inst_t *x = &v->dec[i];
    if (xed_decoded_inst_get_category(x) == XED_CATEGORY_CALL) {
        return num < 8;
    }
    const xed_inst_t *xi = xed_decoded_inst_inst(x);
    for (unsigned k = 0; k < xed_inst_noperands(xi); ++k) {
        const xed_operand_t *op = xed_inst_operand(xi, k);
        xed_operand_enum_t name = xed_operand_name(op);
        if (!xed_operand_is_register(name) || !xed_operand_written(op)) {
            continue;
        }
        xed_reg_enum_t r = xed_decoded_inst_get_reg(x, name);
        if (r >= XED_REG_XMM0 && r <= XED_REG_XMM15 &&
            (int) (r - XED_REG_XMM0) == num) {
            return true;
        }
    }
    return false;
}

// The arithmetic flags that may be undefined when the epilogue reads them,
// over every path of the original program. *reads_undefined is set when a
// body instruction reads a flag that may be undefined there: such a program
// depends on what the hardware leaves, which a rewrite need not keep.
static uint32_t flags_undefined_at_end(const struct view *v,
                                       bool *reads_undefined)
{
    *reads_undefined = false;
    const struct prog *p = v->p;
    uint32_t *incoming = calloc((size_t) p->n + 1, sizeof(uint32_t));
    bool *reached = calloc((size_t) p->n + 1, sizeof(bool));
    uint32_t cur = 0;
    bool live = true;
    uint32_t result = FL_ARITH;
    for (int i = 0; i < p->n; ++i) {
        if (reached[i]) {
            cur = (live ? cur : 0) | incoming[i];
            live = true;
        }
        if (p->it[i].region == R_EPI) {
            result = cur;
            break;
        }
        if (v->c->len[i] == 0 || !live) {
            continue;
        }
        const xed_decoded_inst_t *x = &v->dec[i];
        xed_category_enum_t cat = xed_decoded_inst_get_category(x);
        if (cat == XED_CATEGORY_CALL) {
            cur = 0;   // the stub's ADD defines them all
            continue;
        }
        const xed_simple_flag_t *fi = xed_decoded_inst_get_rflags_info(x);
        if (fi != NULL) {
            uint32_t rd = xed_simple_flag_get_read_flag_set(fi)->flat;
            if ((rd & cur & FL_COMPARED) != 0) {
                *reads_undefined = true;
                if (getenv("RWFUZZ_DEBUG") != NULL) {
                    fprintf(stderr, "undefined read by `%s` (%#x)\n",
                            p->it[i].text, rd & cur);
                }
            }
            uint32_t w = xed_simple_flag_get_written_flag_set(fi)->flat;
            uint32_t u = xed_simple_flag_get_undefined_flag_set(fi)->flat;
            if (xed_simple_flag_get_may_write(fi)) {
                cur |= u;   // a shift by CL may leave the old flags
            } else {
                cur = (cur & ~(w | u)) | u;
            }
        }
        if (xed_decoded_inst_get_branch_displacement_width_bits(x) != 0) {
            int64_t t = (int64_t) v->c->off[i] + v->c->len[i] +
                        xed_decoded_inst_get_branch_displacement(x);
            int ti = -1;
            for (int j = i + 1; j <= p->n; ++j) {
                if ((int64_t) v->c->off[j] == t) {
                    ti = j;
                    break;
                }
            }
            if (ti > i) {
                incoming[ti] |= cur;
                reached[ti] = true;
            }
            if (cat == XED_CATEGORY_UNCOND_BR) {
                live = false;
            }
        }
    }
    free(incoming);
    free(reached);
    return result & FL_ARITH;
}

// --------------------------------------------------------------- flags ---

struct fl {
    bool cf, zf, sf, of, pf;
};

static bool parity(uint64_t v)
{
    return (__builtin_popcountll(v & 0xff) & 1) == 0;
}

static struct fl flags_logic(uint64_t r, int bits)
{
    r &= width_mask(bits);
    struct fl f = {false, r == 0, (r >> (bits - 1)) & 1, false, parity(r)};
    return f;
}

static struct fl flags_sub(uint64_t a, uint64_t b, int bits)
{
    uint64_t m = width_mask(bits);
    a &= m;
    b &= m;
    uint64_t r = (a - b) & m;
    struct fl f;
    f.cf = a < b;
    f.zf = r == 0;
    f.sf = (r >> (bits - 1)) & 1;
    f.of = (((a ^ b) & (a ^ r)) >> (bits - 1)) & 1;
    f.pf = parity(r);
    return f;
}

// A condition code's number (the low nibble of its Jcc opcode), or -1.
static int cc_code(const char *cc)
{
    static const struct {
        const char *name;
        int code;
    } names[] = {
        {"o", 0}, {"no", 1}, {"b", 2}, {"c", 2}, {"nae", 2}, {"ae", 3},
        {"nb", 3}, {"nc", 3}, {"e", 4}, {"z", 4}, {"ne", 5}, {"nz", 5},
        {"be", 6}, {"na", 6}, {"a", 7}, {"nbe", 7}, {"s", 8}, {"ns", 9},
        {"p", 10}, {"pe", 10}, {"np", 11}, {"po", 11}, {"l", 12},
        {"nge", 12}, {"ge", 13}, {"nl", 13}, {"le", 14}, {"ng", 14},
        {"g", 15}, {"nle", 15},
    };
    for (size_t k = 0; k < sizeof(names) / sizeof(names[0]); ++k) {
        if (strcmp(cc, names[k].name) == 0) {
            return names[k].code;
        }
    }
    return -1;
}

// Condition codes by suffix; -1 for an unknown one.
static int cc_eval(const char *cc, struct fl f)
{
    static const struct {
        const char *name;
        int code;
    } names[] = {
        {"o", 0}, {"no", 1}, {"b", 2}, {"c", 2}, {"nae", 2}, {"ae", 3},
        {"nb", 3}, {"nc", 3}, {"e", 4}, {"z", 4}, {"ne", 5}, {"nz", 5},
        {"be", 6}, {"na", 6}, {"a", 7}, {"nbe", 7}, {"s", 8}, {"ns", 9},
        {"p", 10}, {"pe", 10}, {"np", 11}, {"po", 11}, {"l", 12},
        {"nge", 12}, {"ge", 13}, {"nl", 13}, {"le", 14}, {"ng", 14},
        {"g", 15}, {"nle", 15},
    };
    for (size_t k = 0; k < sizeof(names) / sizeof(names[0]); ++k) {
        if (strcmp(cc, names[k].name) != 0) {
            continue;
        }
        bool r;
        switch (names[k].code >> 1) {
        case 0: r = f.of; break;
        case 1: r = f.cf; break;
        case 2: r = f.zf; break;
        case 3: r = f.cf || f.zf; break;
        case 4: r = f.sf; break;
        case 5: r = f.pf; break;
        case 6: r = f.sf != f.of; break;
        default: r = f.zf || f.sf != f.of; break;
        }
        return (names[k].code & 1) ? !r : r;
    }
    return -1;
}

// ------------------------------------------------------------ rewriters ---

// A rewriter applies its row's rewrite to `out`, a copy of the program, for
// a finding at item i. It returns false, with a reason, when the shape its
// row names is not there.
typedef bool (*rewrite_fn)(const struct view *v, int i, struct prog *out,
                           char *why, size_t whylen);

#define FAIL(...) do { snprintf(why, whylen, __VA_ARGS__); return false; } \
    while (0)

static int next_insn(const struct view *v, int i)
{
    for (int j = i + 1; j < v->p->n; ++j) {
        if (v->c->len[j] != 0) {
            return j;
        }
    }
    return -1;
}

static void delete_item(struct prog *out, int i)
{
    out->it[i].text[0] = '\0';
}

static bool reg_op(const char *op, int *num, int *bits)
{
    return gpr_parse(op, num, bits);
}

static bool rw_delete_compare(const struct view *v, int i, struct prog *out,
                              char *why, size_t whylen)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    if ((strcmp(in.mn, "cmp") != 0 && strcmp(in.mn, "test") != 0) ||
        is_mem(in.op[0]) || is_mem(in.op[1])) {
        FAIL("not a register CMP/TEST");
    }
    delete_item(out, i);
    return true;
}

// The rows whose advice is "delete it", each with the mnemonics it names.
static bool rw_delete_if(const struct view *v, int i, struct prog *out,
                         char *why, size_t whylen, const char *const *mns)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    for (const char *const *m = mns; *m != NULL; ++m) {
        if (strcmp(in.mn, *m) == 0) {
            delete_item(out, i);
            return true;
        }
    }
    FAIL("`%s` is not what the row deletes", v->p->it[i].text);
}

#define DELETER(fn, ...)                                                     \
    static bool fn(const struct view *v, int i, struct prog *out, char *why, \
                   size_t whylen)                                            \
    {                                                                        \
        static const char *const mns[] = {__VA_ARGS__, NULL};                \
        return rw_delete_if(v, i, out, why, whylen, mns);                    \
    }

static bool rw_mov_self(const struct view *v, int i, struct prog *out,
                        char *why, size_t whylen)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    if ((strcmp(in.mn, "mov") != 0 && strncmp(in.mn, "cmov", 4) != 0) ||
        strcmp(in.op[0], in.op[1]) != 0) {
        FAIL("not a MOV/CMOVcc onto itself");
    }
    delete_item(out, i);
    return true;
}

static bool rw_shift_zero(const struct view *v, int i, struct prog *out,
                          char *why, size_t whylen)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    int64_t imm;
    if (in.nop < 2 || !imm_parse(in.op[in.nop - 1], &imm) || imm != 0) {
        FAIL("not a shift by an immediate zero");
    }
    delete_item(out, i);
    return true;
}

static bool rw_branch_next(const struct view *v, int i, struct prog *out,
                           char *why, size_t whylen)
{
    if (v->p->it[i].text[0] != 'j') {
        FAIL("not a branch");
    }
    delete_item(out, i);
    return true;
}

static bool rw_delete_test(const struct view *v, int i, struct prog *out,
                           char *why, size_t whylen)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    if (strcmp(in.mn, "test") != 0 || strcmp(in.op[0], in.op[1]) != 0) {
        FAIL("not TEST reg, reg");
    }
    delete_item(out, i);
    return true;
}

DELETER(rw_delete_ext, "movzx", "movsx", "movsxd", "and", "mov")

static bool rw_delete_mov_imm(const struct view *v, int i, struct prog *out,
                              char *why, size_t whylen)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    int r, bits;
    int64_t x;
    if (strcmp(in.mn, "mov") != 0 || in.nop != 2 ||
        !reg_op(in.op[0], &r, &bits) || !imm_parse(in.op[1], &x)) {
        FAIL("not MOV reg, imm");
    }
    delete_item(out, i);
    return true;
}

static bool frame_operand(const char *op, struct mem *m)
{
    return mem_parse(op, m) && m->index[0] == '\0' &&
           (strcmp(m->base, "rsp") == 0 || strcmp(m->base, "rbp") == 0);
}

static bool rw_delete_frame_load(const struct view *v, int i, struct prog *out,
                                 char *why, size_t whylen)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    struct mem m;
    int num, bits;
    if (strcmp(in.mn, "mov") != 0 || !reg_op(in.op[0], &num, &bits) ||
        !frame_operand(in.op[1], &m)) {
        FAIL("not a frame-slot load");
    }
    delete_item(out, i);
    return true;
}

static bool rw_delete_frame_store(const struct view *v, int i,
                                  struct prog *out, char *why, size_t whylen)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    struct mem m;
    if (in.nop != 2 || !frame_operand(in.op[0], &m)) {
        FAIL("not a frame-slot store");
    }
    delete_item(out, i);
    return true;
}

static bool rw_mov_zero(const struct view *v, int i, struct prog *out,
                        char *why, size_t whylen)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    int num, bits;
    int64_t imm;
    if (strcmp(in.mn, "mov") != 0 || !reg_op(in.op[0], &num, &bits) ||
        bits < 32 || !imm_parse(in.op[1], &imm) || imm != 0) {
        FAIL("not MOV r32/r64, 0");
    }
    item_set(&out->it[i], "xor %s, %s", gpr(num, 32), gpr(num, 32));
    return true;
}

// op reg, imm with reg a plain register, its immediate truncated to width.
static bool reg_imm(const struct view *v, int i, const char *mn, int *num,
                    int *bits, uint64_t *imm)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    int64_t x;
    if (strcmp(in.mn, mn) != 0 || in.nop != 2 ||
        !reg_op(in.op[0], num, bits) || !imm_parse(in.op[1], &x)) {
        return false;
    }
    *imm = (uint64_t) x & width_mask(*bits);
    return true;
}

static bool rw_and_imm_movzx(const struct view *v, int i, struct prog *out,
                             char *why, size_t whylen)
{
    int num, bits;
    uint64_t imm;
    if (!reg_imm(v, i, "and", &num, &bits, &imm) || bits < 32 ||
        (imm != 0xff && imm != 0xffff)) {
        FAIL("not AND r32/r64, 0xff/0xffff");
    }
    item_set(&out->it[i], "movzx %s, %s", gpr(num, 32),
             gpr(num, imm == 0xff ? 8 : 16));
    return true;
}

static bool rw_to_test_self(const struct view *v, int i, struct prog *out,
                            char *why, size_t whylen, const char *const *mns,
                            bool need_imm, uint64_t want, bool want_mask)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    int num, bits;
    bool mn_ok = false;
    for (const char *const *m = mns; *m != NULL; ++m) {
        mn_ok |= strcmp(in.mn, *m) == 0;
    }
    if (!mn_ok || in.nop != 2 || !reg_op(in.op[0], &num, &bits)) {
        FAIL("`%s` is not the row's shape", v->p->it[i].text);
    }
    if (need_imm) {
        int64_t x;
        if (!imm_parse(in.op[1], &x)) {
            FAIL("no immediate");
        }
        uint64_t e = (uint64_t) x & width_mask(bits);
        if (e != (want_mask ? width_mask(bits) : want)) {
            FAIL("immediate %#" PRIx64 " is not the row's", e);
        }
    } else if (strcmp(in.op[0], in.op[1]) != 0) {
        FAIL("operands differ");
    }
    item_set(&out->it[i], "test %s, %s", in.op[0], in.op[0]);
    return true;
}

#define TO_TEST(fn, imm, want, mask, ...)                                     \
    static bool fn(const struct view *v, int i, struct prog *out, char *why,  \
                   size_t whylen)                                             \
    {                                                                         \
        static const char *const mns[] = {__VA_ARGS__, NULL};                 \
        return rw_to_test_self(v, i, out, why, whylen, mns, imm, want, mask); \
    }

TO_TEST(rw_and_minus_one, true, 0, true, "and")
TO_TEST(rw_test_minus_one, true, 0, true, "test")
TO_TEST(rw_add_sub_zero, true, 0, false, "add", "sub")
TO_TEST(rw_or_xor_zero, true, 0, false, "or", "xor")
TO_TEST(rw_cmp_zero, true, 0, false, "cmp")
TO_TEST(rw_or_and_self, false, 0, false, "or", "and")

static bool rw_and_zero(const struct view *v, int i, struct prog *out,
                        char *why, size_t whylen)
{
    int num, bits;
    uint64_t imm;
    if (!reg_imm(v, i, "and", &num, &bits, &imm) || imm != 0) {
        FAIL("not AND reg, 0");
    }
    item_set(&out->it[i], "xor %s, %s", gpr(num, bits), gpr(num, bits));
    return true;
}

static bool rw_sub_self(const struct view *v, int i, struct prog *out,
                        char *why, size_t whylen)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    if (strcmp(in.mn, "sub") != 0 || strcmp(in.op[0], in.op[1]) != 0) {
        FAIL("not SUB reg, reg");
    }
    item_set(&out->it[i], "xor %s, %s", in.op[0], in.op[0]);
    return true;
}

static bool rw_xor_not(const struct view *v, int i, struct prog *out,
                       char *why, size_t whylen)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    int64_t x;
    if (strcmp(in.mn, "xor") != 0 || in.nop != 2 ||
        !imm_parse(in.op[1], &x)) {
        FAIL("not XOR x, imm");
    }
    item_set(&out->it[i], "not %s", in.op[0]);
    return true;
}

static bool rw_inc_dec(const struct view *v, int i, struct prog *out,
                       char *why, size_t whylen)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    int64_t x;
    bool add = strcmp(in.mn, "add") == 0, sub = strcmp(in.mn, "sub") == 0;
    if ((!add && !sub) || in.nop != 2 || !imm_parse(in.op[1], &x) ||
        (x != 1 && x != -1)) {
        FAIL("not ADD/SUB x, +-1");
    }
    bool inc = (add && x == 1) || (sub && x == -1);
    item_set(&out->it[i], "%s %s", inc ? "inc" : "dec", in.op[0]);
    return true;
}

static bool rw_add_sub_128(const struct view *v, int i, struct prog *out,
                           char *why, size_t whylen)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    int64_t x;
    bool add = strcmp(in.mn, "add") == 0, sub = strcmp(in.mn, "sub") == 0;
    if ((!add && !sub) || in.nop != 2 || !imm_parse(in.op[1], &x) ||
        x != 128) {
        FAIL("not ADD/SUB x, 128");
    }
    item_set(&out->it[i], "%s %s, -128", add ? "sub" : "add", in.op[0]);
    return true;
}

static bool rw_shl_one(const struct view *v, int i, struct prog *out,
                       char *why, size_t whylen)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    int num, bits;
    int64_t x;
    if (strcmp(in.mn, "shl") != 0 || !reg_op(in.op[0], &num, &bits) ||
        (in.nop == 2 && (!imm_parse(in.op[1], &x) || x != 1))) {
        FAIL("not SHL reg, 1");
    }
    item_set(&out->it[i], "add %s, %s", in.op[0], in.op[0]);
    return true;
}

static bool rw_imul(const struct view *v, int i, struct prog *out, char *why,
                    size_t whylen)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    int d, dbits, s, sbits;
    int64_t x;
    if (strcmp(in.mn, "imul") != 0 || in.nop != 3 ||
        !reg_op(in.op[0], &d, &dbits) || !reg_op(in.op[1], &s, &sbits) ||
        !imm_parse(in.op[2], &x)) {
        FAIL("not IMUL reg, reg, imm");
    }
    uint64_t e = (uint64_t) x & width_mask(dbits);
    const char *D = in.op[0];
    const char *S64 = gpr(s, 64);
    if (e == 0) {
        item_set(&out->it[i], "xor %s, %s", D, D);
    } else if (e == 1) {
        item_set(&out->it[i], "mov %s, %s", D, in.op[1]);
    } else if (e == width_mask(dbits) && d == s) {
        item_set(&out->it[i], "neg %s", D);
    } else if (e == 2 || e == 3 || e == 5 || e == 9) {
        item_set(&out->it[i], "lea %s, [%s+%s*%d]", D, S64, S64,
                 (int) e - 1);
    } else if ((e & (e - 1)) == 0 && d == s) {
        item_set(&out->it[i], "shl %s, %d", D, __builtin_ctzll(e));
    } else if ((e == 4 || e == 8) && d != s) {
        item_set(&out->it[i], "lea %s, [%s*%d]", D, S64, (int) e);
    } else {
        FAIL("multiplier %" PRIu64 " has no single-instruction spelling", e);
    }
    return true;
}

static bool rw_lea(const struct view *v, int i, struct prog *out, char *why,
                   size_t whylen)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    int d, dbits;
    struct mem m;
    if (strcmp(in.mn, "lea") != 0 || !reg_op(in.op[0], &d, &dbits) ||
        !mem_parse(in.op[1], &m)) {
        FAIL("not LEA");
    }
    int b, bbits, x, xbits;
    if (m.index[0] == '\0' && m.disp == 0 && gpr_parse(m.base, &b, &bbits)) {
        item_set(&out->it[i], "mov %s, %s", in.op[0], gpr(b, dbits));
        return true;
    }
    if (m.index[0] != '\0' && m.scale == 1 && m.disp == 0 &&
        gpr_parse(m.base, &b, &bbits) && gpr_parse(m.index, &x, &xbits)) {
        int other = b == d ? x : b;
        item_set(&out->it[i], "add %s, %s", in.op[0], gpr(other, dbits));
        return true;
    }
    FAIL("LEA is neither [base] nor [base+index]");
}

static bool rw_lea_width(const struct view *v, int i, struct prog *out,
                         char *why, size_t whylen)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    int d, dbits;
    if (strcmp(in.mn, "lea") != 0 || !reg_op(in.op[0], &d, &dbits) ||
        dbits != 64) {
        FAIL("not a 64-bit LEA");
    }
    item_set(&out->it[i], "lea %s, %s", gpr(d, 32), in.op[1]);
    return true;
}

static bool rw_movsx_implicit(const struct view *v, int i, struct prog *out,
                              char *why, size_t whylen)
{
    const char *t = v->p->it[i].text;
    if (strcmp(t, "movsxd rax, eax") == 0) {
        item_set(&out->it[i], "cdqe");
    } else if (strcmp(t, "movsx eax, ax") == 0) {
        item_set(&out->it[i], "cwde");
    } else if (strcmp(t, "movsx ax, al") == 0) {
        item_set(&out->it[i], "cbw");
    } else {
        FAIL("not an accumulator sign extension");
    }
    return true;
}

static bool rw_lane0(const struct view *v, int i, struct prog *out, char *why,
                     size_t whylen)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    int64_t x;
    if (in.nop != 3 || !imm_parse(in.op[2], &x) || x != 0) {
        FAIL("not a lane-0 extract");
    }
    if (strcmp(in.mn, "pextrd") == 0) {
        item_set(&out->it[i], "movd %s, %s", in.op[0], in.op[1]);
    } else if (strcmp(in.mn, "pextrq") == 0) {
        item_set(&out->it[i], "movq %s, %s", in.op[0], in.op[1]);
    } else if (strcmp(in.mn, "extractps") == 0) {
        item_set(&out->it[i], "%s %s, %s", is_mem(in.op[0]) ? "movss" : "movd",
                 in.op[0], in.op[1]);
    } else {
        FAIL("not PEXTRD/PEXTRQ/EXTRACTPS");
    }
    return true;
}

static bool rw_sse_mov(const struct view *v, int i, struct prog *out,
                       char *why, size_t whylen)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    const char *to;
    if (strcmp(in.mn, "movapd") == 0 || strcmp(in.mn, "movdqa") == 0) {
        to = "movaps";
    } else if (strcmp(in.mn, "movupd") == 0 || strcmp(in.mn, "movdqu") == 0) {
        to = "movups";
    } else {
        FAIL("not MOVAPD/MOVDQA/MOVUPD/MOVDQU");
    }
    item_set(&out->it[i], "%s %s, %s", to, in.op[0], in.op[1]);
    return true;
}

static bool rw_sse_zero(const struct view *v, int i, struct prog *out,
                        char *why, size_t whylen)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    if ((strcmp(in.mn, "pxor") != 0 && strcmp(in.mn, "xorpd") != 0) ||
        strcmp(in.op[0], in.op[1]) != 0) {
        FAIL("not a PXOR/XORPD zeroing idiom");
    }
    item_set(&out->it[i], "xorps %s, %s", in.op[0], in.op[0]);
    return true;
}

static bool rw_narrow_move(const struct view *v, int i, struct prog *out,
                           char *why, size_t whylen)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    int d, dbits;
    if (strcmp(in.mn, "mov") != 0 || !reg_op(in.op[0], &d, &dbits) ||
        dbits > 16) {
        FAIL("not an 8/16-bit register MOV");
    }
    int s, sbits;
    int64_t x;
    if (imm_parse(in.op[1], &x)) {
        item_set(&out->it[i], "mov %s, %" PRIu64, gpr(d, 32),
                 (uint64_t) x & width_mask(dbits));
    } else if (reg_op(in.op[1], &s, &sbits) || is_mem(in.op[1])) {
        item_set(&out->it[i], "movzx %s, %s", gpr(d, 32), in.op[1]);
    } else {
        FAIL("unknown source");
    }
    return true;
}

static bool rw_shlx(const struct view *v, int i, struct prog *out, char *why,
                    size_t whylen)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    int d, dbits;
    const char *to = strcmp(in.mn, "shl") == 0 ? "shlx" :
                     strcmp(in.mn, "shr") == 0 ? "shrx" :
                     strcmp(in.mn, "sar") == 0 ? "sarx" : NULL;
    if (to == NULL || !reg_op(in.op[0], &d, &dbits) || dbits < 32 ||
        strcmp(in.op[1], "cl") != 0) {
        FAIL("not SHL/SHR/SAR r32/r64, cl");
    }
    item_set(&out->it[i], "%s %s, %s, %s", to, in.op[0], in.op[0],
             gpr(1, dbits));
    return true;
}

static bool rw_insert_xor(const struct view *v, int i, struct prog *out,
                          char *why, size_t whylen)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    int d, dbits;
    if (!reg_op(in.op[0], &d, &dbits)) {
        FAIL("no register destination");
    }
    char t[TEXTLEN];
    snprintf(t, sizeof(t), "xor %s, %s", gpr(d, 32), gpr(d, 32));
    if (!prog_insert(out, i, t)) {
        FAIL("program full");
    }
    return true;
}

// The encoding rows the generator's text can reach: a 64-bit MOV of a small
// immediate, which the assembler spells with a modrm byte (C7) or a full
// imm64, and a TEST whose mask fits the low byte.
static bool rw_mov_imm_short(const struct view *v, int i, struct prog *out,
                             char *why, size_t whylen)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    int r, bits;
    int64_t x;
    if (strcmp(in.mn, "mov") != 0 || in.nop != 2 ||
        !reg_op(in.op[0], &r, &bits) || !imm_parse(in.op[1], &x)) {
        FAIL("not MOV reg, imm");
    }
    if (bits == 64 && x >= 0 && (uint64_t) x <= UINT32_MAX) {
        // The B8+r form at 32 bits zero-extends.
        item_set(&out->it[i], "mov %s, %" PRId64, gpr(r, 32), x);
    } else if (bits == 64 && x >= INT32_MIN && x <= INT32_MAX) {
        // The sign-extended imm32 (C7) form.
        item_set(&out->it[i], "mov %s, %" PRId64, gpr(r, 64), x);
    } else if (bits < 64) {
        item_set(&out->it[i], "mov %s, %" PRId64, gpr(r, bits), x);
    } else {
        FAIL("the immediate needs 64 bits");
    }
    return true;
}

static bool rw_test_imm8(const struct view *v, int i, struct prog *out,
                         char *why, size_t whylen)
{
    int r, bits;
    uint64_t imm;
    if (!reg_imm(v, i, "test", &r, &bits, &imm) || (imm & ~0x7full) != 0) {
        FAIL("not TEST reg, imm with a low-byte mask");
    }
    item_set(&out->it[i], "test %s, %" PRIu64, gpr(r, 8), imm);
    return true;
}

// --- SETcc pairs ---

static bool rw_setcc_test(const struct view *v, int i, struct prog *out,
                          char *why, size_t whylen)
{
    struct ins a, t, b;
    ins_parse(v->p->it[i].text, &a);
    int code = strncmp(a.mn, "set", 3) == 0 ? cc_code(a.mn + 3) : -1;
    int j = next_insn(v, i);
    int k = j >= 0 ? next_insn(v, j) : -1;
    if (code < 0 || k < 0) {
        FAIL("not SETcc, TEST, Jcc");
    }
    ins_parse(v->p->it[j].text, &t);
    ins_parse(v->p->it[k].text, &b);
    if (strcmp(t.mn, "test") != 0 || strcmp(t.op[0], a.op[0]) != 0 ||
        strcmp(t.op[1], a.op[0]) != 0) {
        FAIL("`%s` does not test the SETcc's register", v->p->it[j].text);
    }
    bool je = strcmp(b.mn, "je") == 0 || strcmp(b.mn, "jz") == 0;
    bool jne = strcmp(b.mn, "jne") == 0 || strcmp(b.mn, "jnz") == 0;
    if (!je && !jne) {
        FAIL("`%s` is not JE/JNE", v->p->it[k].text);
    }
    delete_item(out, j);
    item_set(&out->it[k], "j%s %s", CC[je ? code ^ 1 : code], b.op[0]);
    return true;
}

static bool rw_setcc_xor(const struct view *v, int i, struct prog *out,
                         char *why, size_t whylen)
{
    struct ins a, x;
    ins_parse(v->p->it[i].text, &a);
    int code = strncmp(a.mn, "set", 3) == 0 ? cc_code(a.mn + 3) : -1;
    int j = next_insn(v, i);
    if (code < 0 || j < 0) {
        FAIL("not SETcc then XOR");
    }
    ins_parse(v->p->it[j].text, &x);
    int64_t imm;
    if (strcmp(x.mn, "xor") != 0 || strcmp(x.op[0], a.op[0]) != 0 ||
        !imm_parse(x.op[1], &imm) || imm != 1) {
        FAIL("`%s` is not XOR of the SETcc's register with 1",
             v->p->it[j].text);
    }
    item_set(&out->it[i], "set%s %s", CC[code ^ 1], a.op[0]);
    delete_item(out, j);
    return true;
}

// --- BMI and MOVBE folds ---

static bool rw_andn(const struct view *v, int i, struct prog *out, char *why,
                    size_t whylen)
{
    struct ins a, b;
    ins_parse(v->p->it[i].text, &a);
    int j = next_insn(v, i);
    if (strcmp(a.mn, "not") != 0 || j < 0) {
        FAIL("not NOT then AND");
    }
    ins_parse(v->p->it[j].text, &b);
    if (strcmp(b.mn, "and") != 0 || strcmp(b.op[0], a.op[0]) != 0) {
        FAIL("`%s` is not an AND of the NOT's register", v->p->it[j].text);
    }
    item_set(&out->it[j], "andn %s, %s, %s", a.op[0], a.op[0], b.op[1]);
    delete_item(out, i);
    return true;
}

// lea D, [S-1] ; and/xor D, S  ->  blsr/blsmsk D, S
static bool rw_lea_bmi(const struct view *v, int i, struct prog *out,
                       char *why, size_t whylen, const char *op,
                       const char *to)
{
    struct ins a, b;
    ins_parse(v->p->it[i].text, &a);
    int d, dbits, s, sbits;
    struct mem m;
    int j = next_insn(v, i);
    if (strcmp(a.mn, "lea") != 0 || !reg_op(a.op[0], &d, &dbits) ||
        !mem_parse(a.op[1], &m) || m.index[0] != '\0' || m.disp != -1 ||
        !gpr_parse(m.base, &s, &sbits) || j < 0) {
        FAIL("not LEA D, [S-1]");
    }
    ins_parse(v->p->it[j].text, &b);
    int bs, bbits;
    if (strcmp(b.mn, op) != 0 || strcmp(b.op[0], a.op[0]) != 0 ||
        !reg_op(b.op[1], &bs, &bbits) || bs != s) {
        FAIL("`%s` is not %s D, S", v->p->it[j].text, op);
    }
    item_set(&out->it[j], "%s %s, %s", to, a.op[0], gpr(s, dbits));
    delete_item(out, i);
    return true;
}

static bool rw_blsr(const struct view *v, int i, struct prog *out, char *why,
                    size_t whylen)
{
    return rw_lea_bmi(v, i, out, why, whylen, "and", "blsr");
}

static bool rw_blsmsk(const struct view *v, int i, struct prog *out,
                      char *why, size_t whylen)
{
    return rw_lea_bmi(v, i, out, why, whylen, "xor", "blsmsk");
}

// mov D, S ; neg D ; and D, S  ->  blsi D, S
static bool rw_blsi(const struct view *v, int i, struct prog *out, char *why,
                    size_t whylen)
{
    struct ins a, b, c;
    ins_parse(v->p->it[i].text, &a);
    int j = next_insn(v, i);
    int k = j >= 0 ? next_insn(v, j) : -1;
    if (strcmp(a.mn, "mov") != 0 || k < 0) {
        FAIL("not MOV, NEG, AND");
    }
    ins_parse(v->p->it[j].text, &b);
    ins_parse(v->p->it[k].text, &c);
    if (strcmp(b.mn, "neg") != 0 || strcmp(b.op[0], a.op[0]) != 0 ||
        strcmp(c.mn, "and") != 0 || strcmp(c.op[0], a.op[0]) != 0 ||
        strcmp(c.op[1], a.op[1]) != 0) {
        FAIL("not MOV D, S ; NEG D ; AND D, S");
    }
    item_set(&out->it[k], "blsi %s, %s", a.op[0], a.op[1]);
    delete_item(out, i);
    delete_item(out, j);
    return true;
}

static bool rw_movbe(const struct view *v, int i, struct prog *out, char *why,
                     size_t whylen)
{
    struct ins a, b;
    ins_parse(v->p->it[i].text, &a);
    int j = next_insn(v, i);
    if (strcmp(a.mn, "mov") != 0 || !is_mem(a.op[1]) || j < 0) {
        FAIL("not a load");
    }
    ins_parse(v->p->it[j].text, &b);
    if (strcmp(b.mn, "bswap") != 0 || strcmp(b.op[0], a.op[0]) != 0) {
        FAIL("`%s` does not swap the loaded register", v->p->it[j].text);
    }
    item_set(&out->it[j], "movbe %s, %s", a.op[0], a.op[1]);
    delete_item(out, i);
    return true;
}

// --- the constant conditions ---

// The value a straight-line producer leaves in register `num`, known in
// bits [0, *known). Walks back from item i; stops at a label.
static bool known_value(const struct view *v, int i, int num, uint64_t *val,
                        int *known)
{
    for (int j = i - 1; j >= 0; --j) {
        if (v->p->it[j + 1].label >= 0) {
            return false;   // a merge between the producer and the reader
        }
        if (v->c->len[j] == 0 || !writes_gpr(v, j, num)) {
            continue;
        }
        struct ins in;
        ins_parse(v->p->it[j].text, &in);
        int r, bits;
        int64_t x;
        if ((strcmp(in.mn, "xor") == 0 || strcmp(in.mn, "sub") == 0) &&
            in.nop == 2 && strcmp(in.op[0], in.op[1]) == 0 &&
            reg_op(in.op[0], &r, &bits) && r == num) {
            *val = 0;
            *known = bits == 32 ? 64 : bits;
            return true;
        }
        if (strcmp(in.mn, "mov") == 0 && in.nop == 2 &&
            reg_op(in.op[0], &r, &bits) && r == num &&
            imm_parse(in.op[1], &x)) {
            *val = (uint64_t) x & width_mask(bits);
            if (bits == 64) {
                *val = (uint64_t) x;
            }
            *known = bits == 32 ? 64 : bits;
            return true;
        }
        return false;
    }
    return false;
}

static bool rw_const_condition(const struct view *v, int i, struct prog *out,
                               char *why, size_t whylen)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    int r, bits;
    if ((strcmp(in.mn, "test") != 0 && strcmp(in.mn, "cmp") != 0) ||
        in.nop != 2 || !reg_op(in.op[0], &r, &bits)) {
        FAIL("not TEST/CMP reg, x");
    }
    uint64_t val;
    int known;
    if (!known_value(v, i, r, &val, &known) || known < bits) {
        FAIL("no producer of a known value for %s", in.op[0]);
    }
    struct fl f;
    int64_t imm;
    if (strcmp(in.mn, "test") == 0) {
        int r2, b2;
        if (!reg_op(in.op[1], &r2, &b2) || r2 != r) {
            FAIL("TEST of two registers");
        }
        f = flags_logic(val, bits);
    } else if (imm_parse(in.op[1], &imm)) {
        f = flags_sub(val, (uint64_t) imm, bits);
    } else {
        FAIL("CMP against a non-constant");
    }
    // The consumer: the first instruction reading flags.
    for (int j = i + 1; j < v->p->n; ++j) {
        if (v->c->len[j] == 0) {
            continue;
        }
        struct ins c;
        ins_parse(v->p->it[j].text, &c);
        const char *cc = NULL;
        if (c.mn[0] == 'j' && strcmp(c.mn, "jmp") != 0) {
            cc = c.mn + 1;
        } else if (strncmp(c.mn, "cmov", 4) == 0) {
            cc = c.mn + 4;
        } else if (strncmp(c.mn, "set", 3) == 0) {
            cc = c.mn + 3;
        }
        if (cc == NULL) {
            const xed_simple_flag_t *fi =
                xed_decoded_inst_get_rflags_info(&v->dec[j]);
            if (fi != NULL && xed_simple_flag_get_read_flag_set(fi)->flat) {
                FAIL("the flags reader `%s` is no consumer", c.mn);
            }
            continue;
        }
        int taken = cc_eval(cc, f);
        if (taken < 0) {
            FAIL("unknown condition %s", cc);
        }
        delete_item(out, i);
        if (c.mn[0] == 'j') {
            if (taken) {
                item_set(&out->it[j], "jmp %s", c.op[0]);
            } else {
                delete_item(out, j);
            }
        } else if (c.mn[0] == 'c') {
            int dr, db;
            reg_op(c.op[0], &dr, &db);
            if (taken) {
                item_set(&out->it[j], "mov %s, %s", c.op[0], c.op[1]);
            } else if (db == 32) {
                item_set(&out->it[j], "mov %s, %s", c.op[0], c.op[0]);
            } else {
                delete_item(out, j);
            }
        } else {
            item_set(&out->it[j], "mov %s, %d", c.op[0], taken);
        }
        return true;
    }
    FAIL("no consumer");
}

// --- the frame-slot rows ---

struct slot_access {
    bool store;
    bool xmm;       // the data register is an xmm
    int reg;        // GPR or xmm number; -1 for an immediate store
    int bits;       // access width
};

// Classify item j as a MOV-family access to a frame slot.
static bool frame_access_of(const struct view *v, int j, struct mem *m,
                            struct slot_access *a)
{
    struct ins in;
    ins_parse(v->p->it[j].text, &in);
    if (in.nop != 2) {
        return false;
    }
    static const char *const MOVS[] = {"mov", "movd", "movq", "movss",
                                       "movsd", "movups", "movaps", "movdqu",
                                       "movdqa", NULL};
    bool ok = false;
    for (const char *const *k = MOVS; *k != NULL; ++k) {
        ok |= strcmp(in.mn, *k) == 0;
    }
    if (!ok) {
        return false;
    }
    int idx = is_mem(in.op[0]) ? 0 : is_mem(in.op[1]) ? 1 : -1;
    if (idx < 0 || !frame_operand(in.op[idx], m)) {
        return false;
    }
    const char *data = in.op[1 - idx];
    a->store = idx == 0;
    a->bits = m->bits;
    int bits;
    if (reg_op(data, &a->reg, &bits)) {
        a->xmm = false;
    } else if (xmm_parse(data, &a->reg)) {
        a->xmm = true;
    } else {
        a->reg = -1;
        a->xmm = false;
    }
    return true;
}

static bool same_slot(const struct mem *a, const struct mem *b)
{
    return strcmp(a->base, b->base) == 0 && a->disp == b->disp &&
           a->bits == b->bits;
}

static bool slot_overlaps(const struct mem *a, const struct mem *b)
{
    if (strcmp(a->base, b->base) != 0) {
        return false;
    }
    int64_t a0 = a->disp, a1 = a->disp + a->bits / 8;
    int64_t b0 = b->disp, b1 = b->disp + b->bits / 8;
    return a0 < b1 && b0 < a1;
}

static bool reg_written_between(const struct view *v, int from, int to,
                                int reg, bool xmm)
{
    for (int j = from + 1; j < to; ++j) {
        if (xmm ? writes_xmm(v, j, reg) : writes_gpr(v, j, reg)) {
            return true;
        }
    }
    return false;
}

static bool label_between(const struct view *v, int from, int to)
{
    for (int j = from + 1; j <= to; ++j) {
        if (v->p->it[j].label >= 0) {
            return true;
        }
    }
    return false;
}

// The partner of a frame-slot load at item i: the nearest earlier access
// to the slot whose data register still holds what it moved. The walk
// stops at the slot's last store, at a label and at the body's start.
static int frame_partner(const struct view *v, int i, const struct mem *slot,
                         bool want_xmm)
{
    for (int j = i - 1; j >= 0 && v->p->it[j].region == R_BODY; --j) {
        if (label_between(v, j, i)) {
            return -1;
        }
        struct mem m;
        struct slot_access a;
        if (v->c->len[j] == 0) {
            continue;
        }
        struct ins in;
        ins_parse(v->p->it[j].text, &in);
        bool is_access = frame_access_of(v, j, &m, &a);
        if (is_access && same_slot(&m, slot) && a.reg >= 0 &&
            a.xmm == want_xmm &&
            !reg_written_between(v, j, i, a.reg, a.xmm)) {
            return j;
        }
        if (is_access && a.store && slot_overlaps(&m, slot)) {
            return -1;   // the slot's last store, and it is no partner
        }
        if (in.nop >= 1 && is_mem(in.op[0]) && mem_parse(in.op[0], &m) &&
            slot_overlaps(&m, slot) && strcmp(in.mn, "cmp") != 0 &&
            strcmp(in.mn, "test") != 0) {
            return -1;   // some other write of the slot
        }
    }
    return -1;
}

static bool rw_frame_forward(const struct view *v, int i, struct prog *out,
                             char *why, size_t whylen)
{
    struct mem slot;
    struct slot_access a;
    if (!frame_access_of(v, i, &slot, &a) || a.store || a.xmm || a.reg < 0) {
        FAIL("not a GPR frame-slot load");
    }
    int j = frame_partner(v, i, &slot, false);
    if (j < 0) {
        FAIL("no register holds the slot");
    }
    struct mem m;
    struct slot_access b;
    frame_access_of(v, j, &m, &b);
    item_set(&out->it[i], "mov %s, %s", gpr(a.reg, a.bits),
             gpr(b.reg, a.bits));
    return true;
}

static bool rw_frame_bitcast(const struct view *v, int i, struct prog *out,
                             char *why, size_t whylen)
{
    struct mem slot;
    struct slot_access a;
    if (!frame_access_of(v, i, &slot, &a) || a.store || a.reg < 0 ||
        (a.bits != 32 && a.bits != 64)) {
        FAIL("not a 32/64-bit frame-slot load");
    }
    int j = frame_partner(v, i, &slot, !a.xmm);
    if (j < 0) {
        FAIL("no register of the other file holds the slot");
    }
    struct mem m;
    struct slot_access b;
    frame_access_of(v, j, &m, &b);
    const char *mv = a.bits == 64 ? "movq" : "movd";
    if (a.xmm) {
        item_set(&out->it[i], "%s xmm%d, %s", mv, a.reg, gpr(b.reg, a.bits));
    } else {
        item_set(&out->it[i], "%s %s, xmm%d", mv, gpr(a.reg, a.bits), b.reg);
    }
    return true;
}

// --- constants ---

// The full value a register holds after item j, if j is a constant
// producer for it: known in bits [0, *known).
static bool const_producer(const struct view *v, int j, int *reg,
                           uint64_t *val, int *known)
{
    struct ins in;
    ins_parse(v->p->it[j].text, &in);
    int bits;
    int64_t x;
    if (strcmp(in.mn, "mov") == 0 && in.nop == 2 &&
        reg_op(in.op[0], reg, &bits) && imm_parse(in.op[1], &x)) {
        *val = bits == 64 ? (uint64_t) x : (uint64_t) x & width_mask(bits);
        *known = bits == 32 ? 64 : bits;
        return true;
    }
    if ((strcmp(in.mn, "xor") == 0 || strcmp(in.mn, "sub") == 0) &&
        in.nop == 2 && strcmp(in.op[0], in.op[1]) == 0 &&
        reg_op(in.op[0], reg, &bits)) {
        *val = 0;
        *known = bits == 32 ? 64 : bits;
        return true;
    }
    return false;
}

static bool rw_remat(const struct view *v, int i, struct prog *out, char *why,
                     size_t whylen)
{
    int d, known;
    uint64_t want;
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    int dbits;
    if (!const_producer(v, i, &d, &want, &known) ||
        !reg_op(in.op[0], &d, &dbits)) {
        FAIL("not a constant MOV");
    }
    // The bits the MOV decides: the zero-extension for 32.
    int need = dbits == 32 ? 64 : dbits;
    for (int j = i - 1; j >= 0 && v->p->it[j].region == R_BODY; --j) {
        if (label_between(v, j, i)) {
            break;
        }
        int s, sknown;
        uint64_t sval;
        if (v->c->len[j] == 0 ||
            !const_producer(v, j, &s, &sval, &sknown) || s == d) {
            continue;
        }
        // A 32-bit copy zero-extends, so it needs only the low 32.
        int cmp_bits = dbits == 32 ? 32 : need;
        if (sknown < cmp_bits ||
            ((sval ^ want) & width_mask(cmp_bits)) != 0) {
            continue;
        }
        if (reg_written_between(v, j, i, s, false)) {
            continue;
        }
        item_set(&out->it[i], "mov %s, %s", in.op[0], gpr(s, dbits));
        return true;
    }
    FAIL("no register holds the constant");
}

// --- folds of adjacent pairs ---

static bool rw_mov_const_fold(const struct view *v, int i, struct prog *out,
                              char *why, size_t whylen)
{
    int r, known;
    uint64_t val;
    if (!const_producer(v, i, &r, &val, &known)) {
        FAIL("not a constant MOV");
    }
    int j = next_insn(v, i);
    if (j < 0) {
        FAIL("no consumer");
    }
    struct ins c;
    ins_parse(v->p->it[j].text, &c);
    int s, sbits;
    // The source operand, or either operand of the commutative TEST.
    int other = 0;
    if (c.nop == 2 && strcmp(c.mn, "test") == 0 &&
        reg_op(c.op[0], &s, &sbits) && s == r &&
        !(reg_op(c.op[1], &s, &sbits) && s == r)) {
        reg_op(c.op[0], &s, &sbits);
        other = 1;
    } else if (c.nop != 2 || !reg_op(c.op[1], &s, &sbits) || s != r) {
        FAIL("`%s` does not read the constant as its source",
             v->p->it[j].text);
    }
    if (sbits > known) {
        FAIL("`%s` reads bits the MOV did not set", v->p->it[j].text);
    }
    int64_t imm = sign_extend(val, sbits);
    item_set(&out->it[j], "%s %s, %" PRId64, c.mn, c.op[other], imm);
    delete_item(out, i);
    return true;
}

// Fold an address into the consumer's memory operand, replacing base `reg`.
static bool fold_address(const char *consumer, const char *reg64,
                         const struct mem *addr, char *out, size_t n,
                         char *why, size_t whylen)
{
    struct ins c;
    ins_parse(consumer, &c);
    int idx = -1;
    for (int k = 0; k < c.nop; ++k) {
        if (is_mem(c.op[k])) {
            idx = k;
        }
    }
    struct mem m;
    if (idx < 0 || !mem_parse(c.op[idx], &m) || strcmp(m.base, reg64) != 0) {
        FAIL("the consumer `%s` does not address through %s", consumer, reg64);
    }
    struct mem f = *addr;
    f.bits = m.bits;
    f.disp += m.disp;
    if (m.index[0] != '\0') {
        if (f.index[0] != '\0') {
            FAIL("two indexes");
        }
        snprintf(f.index, sizeof(f.index), "%s", m.index);
        f.scale = m.scale;
    }
    if (f.base[0] == '\0' && f.index[0] != '\0' && f.scale == 1) {
        snprintf(f.base, sizeof(f.base), "%s", f.index);
        f.index[0] = '\0';
    }
    char memtext[64];
    mem_format(&f, f.bits, memtext, sizeof(memtext));
    int k = snprintf(out, n, "%s ", c.mn);
    for (int o = 0; o < c.nop; ++o) {
        k += snprintf(out + k, n - (size_t) k, "%s%s", o ? ", " : "",
                      o == idx ? memtext : c.op[o]);
    }
    return true;
}

static bool rw_lea_into_mem(const struct view *v, int i, struct prog *out,
                            char *why, size_t whylen)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    int d, dbits;
    struct mem a;
    if (strcmp(in.mn, "lea") != 0 || !reg_op(in.op[0], &d, &dbits) ||
        !mem_parse(in.op[1], &a)) {
        FAIL("not LEA");
    }
    int j = next_insn(v, i);
    if (j < 0) {
        FAIL("no consumer");
    }
    char t[TEXTLEN];
    if (!fold_address(v->p->it[j].text, gpr(d, 64), &a, t, sizeof(t), why,
                      whylen)) {
        return false;
    }
    item_set(&out->it[j], "%s", t);
    delete_item(out, i);
    return true;
}

static bool rw_add_into_mem(const struct view *v, int i, struct prog *out,
                            char *why, size_t whylen)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    int d, dbits;
    if (!reg_op(in.op[0], &d, &dbits)) {
        FAIL("no register destination");
    }
    struct mem a;
    memset(&a, 0, sizeof(a));
    snprintf(a.base, sizeof(a.base), "%s", gpr(d, 64));
    a.scale = 1;
    int64_t x;
    int t, tbits;
    if (strcmp(in.mn, "inc") == 0) {
        a.disp = 1;
    } else if (strcmp(in.mn, "dec") == 0) {
        a.disp = -1;
    } else if (strcmp(in.mn, "add") == 0 && imm_parse(in.op[1], &x)) {
        a.disp = x;
    } else if (strcmp(in.mn, "sub") == 0 && imm_parse(in.op[1], &x)) {
        a.disp = -x;
    } else if (strcmp(in.mn, "add") == 0 && reg_op(in.op[1], &t, &tbits)) {
        snprintf(a.index, sizeof(a.index), "%s", gpr(t, 64));
    } else {
        FAIL("not ADD/SUB/INC/DEC");
    }
    int j = next_insn(v, i);
    if (j < 0) {
        FAIL("no consumer");
    }
    char text[TEXTLEN];
    if (!fold_address(v->p->it[j].text, gpr(d, 64), &a, text, sizeof(text),
                      why, whylen)) {
        return false;
    }
    item_set(&out->it[j], "%s", text);
    delete_item(out, i);
    return true;
}

// An ADD/SUB/INC/DEC's term, as a displacement or a register.
static bool add_term(const struct ins *in, int64_t *disp, int *reg)
{
    int64_t x;
    int b;
    *reg = -1;
    *disp = 0;
    if (strcmp(in->mn, "inc") == 0) {
        *disp = 1;
    } else if (strcmp(in->mn, "dec") == 0) {
        *disp = -1;
    } else if (strcmp(in->mn, "add") == 0 && imm_parse(in->op[1], &x)) {
        *disp = x;
    } else if (strcmp(in->mn, "sub") == 0 && imm_parse(in->op[1], &x)) {
        *disp = -x;
    } else if (strcmp(in->mn, "add") == 0 && reg_op(in->op[1], reg, &b)) {
        ;
    } else {
        return false;
    }
    return true;
}

static bool rw_add_into_lea(const struct view *v, int i, struct prog *out,
                            char *why, size_t whylen)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    int d, dbits;
    struct mem a;
    if (strcmp(in.mn, "lea") != 0 || !reg_op(in.op[0], &d, &dbits) ||
        !mem_parse(in.op[1], &a)) {
        FAIL("not LEA");
    }
    int j = next_insn(v, i);
    if (j < 0) {
        FAIL("no ADD");
    }
    struct ins c;
    ins_parse(v->p->it[j].text, &c);
    int cd, cbits, term;
    int64_t disp;
    if (!reg_op(c.op[0], &cd, &cbits) || !add_term(&c, &disp, &term)) {
        FAIL("`%s` is not an ADD", v->p->it[j].text);
    }
    int dest = d;
    if (cd == d) {
        if (term < 0) {
            a.disp += disp;
        }
    } else if (term == d) {
        term = cd;
        dest = cd;
    } else {
        FAIL("the ADD neither writes nor reads the LEA's register");
    }
    if (term >= 0) {
        if (a.index[0] != '\0' && a.base[0] != '\0') {
            FAIL("no free address slot");
        }
        if (a.base[0] == '\0') {
            snprintf(a.base, sizeof(a.base), "%s", gpr(term, 64));
        } else {
            snprintf(a.index, sizeof(a.index), "%s", gpr(term, 64));
            a.scale = 1;
        }
    }
    char mt[64];
    mem_format(&a, 0, mt, sizeof(mt));
    item_set(&out->it[j], "lea %s, %s", gpr(dest, cbits), mt);
    delete_item(out, i);
    return true;
}

static bool rw_mov_add_lea(const struct view *v, int i, struct prog *out,
                           char *why, size_t whylen)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    int d, dbits, s, sbits;
    if (strcmp(in.mn, "mov") != 0 || !reg_op(in.op[0], &d, &dbits) ||
        !reg_op(in.op[1], &s, &sbits)) {
        FAIL("not MOV reg, reg");
    }
    // The ADD: the next instruction touching the copy, past a gap that
    // does not.
    int j = next_insn(v, i);
    while (j >= 0 && !touches_gpr(v, j, d)) {
        j = next_insn(v, j);
    }
    if (j < 0) {
        FAIL("no ADD");
    }
    struct ins c;
    ins_parse(v->p->it[j].text, &c);
    int cd, cbits, term;
    int64_t disp;
    if (!reg_op(c.op[0], &cd, &cbits) || cd != d ||
        !add_term(&c, &disp, &term)) {
        FAIL("`%s` is not an ADD to the copy", v->p->it[j].text);
    }
    struct mem a;
    memset(&a, 0, sizeof(a));
    snprintf(a.base, sizeof(a.base), "%s", gpr(s, 64));
    a.scale = 1;
    a.disp = disp;
    if (term >= 0) {
        snprintf(a.index, sizeof(a.index), "%s", gpr(term == d ? s : term,
                 64));
    }
    char mt[64];
    mem_format(&a, 0, mt, sizeof(mt));
    item_set(&out->it[j], "lea %s, %s", gpr(d, cbits), mt);
    delete_item(out, i);
    return true;
}

// mov R, [m] ; consumer reading R  ->  consumer reading [m]
static bool load_fold(const struct view *v, int i, struct prog *out,
                      char *why, size_t whylen, int src_operand,
                      bool compare)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    int r, rbits;
    struct mem m;
    if (strcmp(in.mn, "mov") != 0 || !reg_op(in.op[0], &r, &rbits) ||
        !mem_parse(in.op[1], &m)) {
        FAIL("not a load");
    }
    int j = next_insn(v, i);
    if (j < 0) {
        FAIL("no consumer");
    }
    struct ins c;
    ins_parse(v->p->it[j].text, &c);
    int s, sbits;
    char mt[64];
    if (compare) {
        int s1, s1bits;
        if (reg_op(c.op[0], &s, &sbits) && s == r) {
            mem_format(&m, sbits, mt, sizeof(mt));
            if (strcmp(c.mn, "test") == 0 && strcmp(c.op[0], c.op[1]) == 0) {
                item_set(&out->it[j], "cmp %s, 0", mt);
            } else {
                item_set(&out->it[j], "%s %s, %s", c.mn, mt, c.op[1]);
            }
        } else if (c.nop == 2 && reg_op(c.op[1], &s1, &s1bits) && s1 == r) {
            mem_format(&m, s1bits, mt, sizeof(mt));
            item_set(&out->it[j], "%s %s, %s", c.mn, c.op[0], mt);
        } else {
            FAIL("`%s` does not compare the loaded register",
                 v->p->it[j].text);
        }
    } else {
        if (c.nop <= src_operand ||
            !reg_op(c.op[src_operand], &s, &sbits) || s != r) {
            FAIL("`%s` does not read the loaded register",
                 v->p->it[j].text);
        }
        mem_format(&m, strncmp(c.mn, "movsxd", 6) == 0 ? 32 : sbits, mt,
                   sizeof(mt));
        char t[TEXTLEN];
        int k = snprintf(t, sizeof(t), "%s ", c.mn);
        for (int o = 0; o < c.nop; ++o) {
            k += snprintf(t + k, sizeof(t) - (size_t) k, "%s%s", o ? ", " : "",
                          o == src_operand ? mt : c.op[o]);
        }
        item_set(&out->it[j], "%s", t);
    }
    delete_item(out, i);
    return true;
}

static bool rw_load_alu(const struct view *v, int i, struct prog *out,
                        char *why, size_t whylen)
{
    return load_fold(v, i, out, why, whylen, 1, false);
}

static bool rw_load_cmp(const struct view *v, int i, struct prog *out,
                        char *why, size_t whylen)
{
    return load_fold(v, i, out, why, whylen, 0, true);
}

static bool rw_load_ext(const struct view *v, int i, struct prog *out,
                        char *why, size_t whylen)
{
    return load_fold(v, i, out, why, whylen, 1, false);
}

static bool rw_load_vec_transfer(const struct view *v, int i,
                                 struct prog *out, char *why, size_t whylen)
{
    return load_fold(v, i, out, why, whylen, 1, false);
}

static bool rw_load_vecop(const struct view *v, int i, struct prog *out,
                          char *why, size_t whylen)
{
    struct ins in;
    ins_parse(v->p->it[i].text, &in);
    int x;
    struct mem m;
    if (!xmm_parse(in.op[0], &x) || !mem_parse(in.op[1], &m)) {
        FAIL("not a vector load");
    }
    int j = next_insn(v, i);
    if (j < 0) {
        FAIL("no consumer");
    }
    struct ins c;
    ins_parse(v->p->it[j].text, &c);
    if (c.nop != 2 || strcmp(c.op[1], in.op[0]) != 0) {
        FAIL("`%s` does not read the loaded register", v->p->it[j].text);
    }
    item_set(&out->it[j], "%s %s, %s", c.mn, c.op[0], in.op[1]);
    delete_item(out, i);
    return true;
}

static bool rw_shift_pair(const struct view *v, int i, struct prog *out,
                          char *why, size_t whylen)
{
    struct ins a, b;
    ins_parse(v->p->it[i].text, &a);
    int j = next_insn(v, i);
    if (j < 0) {
        FAIL("no second shift");
    }
    ins_parse(v->p->it[j].text, &b);
    int r, bits;
    int64_t k1, k2;
    if (strcmp(a.mn, "shl") != 0 || !reg_op(a.op[0], &r, &bits) ||
        !imm_parse(a.op[1], &k1) || strcmp(b.op[0], a.op[0]) != 0 ||
        !imm_parse(b.op[1], &k2) || k1 != k2) {
        FAIL("not SHL then a shift back by the same count");
    }
    int m = bits - (int) k1;
    bool sar = strcmp(b.mn, "sar") == 0;
    if (!sar && strcmp(b.mn, "shr") != 0) {
        FAIL("not SAR/SHR");
    }
    if (m == 32 && bits == 64) {
        if (sar) {
            item_set(&out->it[j], "movsxd %s, %s", gpr(r, 64), gpr(r, 32));
        } else {
            item_set(&out->it[j], "mov %s, %s", gpr(r, 32), gpr(r, 32));
        }
    } else if (m == 8 || m == 16) {
        item_set(&out->it[j], "%s %s, %s", sar ? "movsx" : "movzx",
                 a.op[0], gpr(r, m));
    } else {
        FAIL("kept width %d is no register", m);
    }
    delete_item(out, i);
    return true;
}

static bool rw_cmp_one(const struct view *v, int i, struct prog *out,
                       char *why, size_t whylen)
{
    struct ins a, b;
    ins_parse(v->p->it[i].text, &a);
    int r, bits;
    int64_t x;
    if (strcmp(a.mn, "cmp") != 0 || !reg_op(a.op[0], &r, &bits) ||
        !imm_parse(a.op[1], &x) || x != 1) {
        FAIL("not CMP reg, 1");
    }
    int j = next_insn(v, i);
    if (j < 0) {
        FAIL("no branch");
    }
    ins_parse(v->p->it[j].text, &b);
    const char *to;
    if (strcmp(b.mn, "jb") == 0 || strcmp(b.mn, "jc") == 0 ||
        strcmp(b.mn, "jnae") == 0) {
        to = "jz";
    } else if (strcmp(b.mn, "jae") == 0 || strcmp(b.mn, "jnc") == 0 ||
               strcmp(b.mn, "jnb") == 0) {
        to = "jnz";
    } else {
        FAIL("the branch is not JB/JAE");
    }
    item_set(&out->it[i], "test %s, %s", a.op[0], a.op[0]);
    item_set(&out->it[j], "%s %s", to, b.op[0]);
    return true;
}

static bool rw_neg_fold(const struct view *v, int i, struct prog *out,
                        char *why, size_t whylen)
{
    struct ins a, b;
    ins_parse(v->p->it[i].text, &a);
    int r, bits;
    if (strcmp(a.mn, "neg") != 0 || !reg_op(a.op[0], &r, &bits)) {
        FAIL("not NEG reg");
    }
    int j = next_insn(v, i);
    if (j < 0) {
        FAIL("no ADD/SUB");
    }
    ins_parse(v->p->it[j].text, &b);
    if (b.nop != 2 || strcmp(b.op[1], a.op[0]) != 0) {
        FAIL("`%s` does not take the negated register as its source",
             v->p->it[j].text);
    }
    if (strcmp(b.mn, "add") == 0) {
        item_set(&out->it[j], "sub %s, %s", b.op[0], b.op[1]);
    } else if (strcmp(b.mn, "sub") == 0) {
        item_set(&out->it[j], "add %s, %s", b.op[0], b.op[1]);
    } else {
        FAIL("not ADD/SUB");
    }
    delete_item(out, i);
    return true;
}

// ---------------------------------------------------------------- table ---

struct kind {
    const char *name;
    rewrite_fn fn;
    enum mode family;
};

static const struct kind KINDS[] = {
    {"dead compare", rw_delete_compare, MODE_FLAGS},
    {"suboptimal MOV zero", rw_mov_zero, MODE_FLAGS},
    {"oversized MOV encoding", rw_mov_imm_short, MODE_FOLD},
    {"oversized immediate", rw_mov_imm_short, MODE_FOLD},
    {"oversized TEST immediate", rw_test_imm8, MODE_FLAGS},
    {"suboptimal AND immediate", rw_and_imm_movzx, MODE_FLAGS},
    {"redundant AND immediate", rw_and_minus_one, MODE_FLAGS},
    {"suboptimal AND zero", rw_and_zero, MODE_FLAGS},
    {"suboptimal XOR immediate", rw_xor_not, MODE_FLAGS},
    {"redundant ADD/SUB zero", rw_add_sub_zero, MODE_FLAGS},
    {"redundant OR/XOR zero", rw_or_xor_zero, MODE_FLAGS},
    {"oversized ADD/SUB one", rw_inc_dec, MODE_FLAGS},
    {"oversized ADD/SUB 128", rw_add_sub_128, MODE_FLAGS},
    {"suboptimal CMP zero", rw_cmp_zero, MODE_FLAGS},
    {"redundant TEST immediate", rw_test_minus_one, MODE_FLAGS},
    {"suboptimal OR/AND reg, reg", rw_or_and_self, MODE_FLAGS},
    {"suboptimal SUB reg, reg", rw_sub_self, MODE_FLAGS},
    {"redundant MOV reg, reg", rw_mov_self, MODE_FLAGS},
    {"redundant CMOVcc reg, reg", rw_mov_self, MODE_FLAGS},
    {"redundant shift/rotate by zero", rw_shift_zero, MODE_FLAGS},
    {"branch to the next instruction", rw_branch_next, MODE_FLAGS},
    {"suboptimal SHL one", rw_shl_one, MODE_FLAGS},
    {"suboptimal IMUL constant", rw_imul, MODE_FLAGS},
    {"suboptimal LEA", rw_lea, MODE_FOLD},
    {"oversized LEA width", rw_lea_width, MODE_FOLD},
    {"unneeded MOVSXD", rw_movsx_implicit, MODE_FLAGS},
    {"unneeded MOVSX", rw_movsx_implicit, MODE_FLAGS},
    {"suboptimal lane-0 extract", rw_lane0, MODE_FOLD},
    {"suboptimal SSE MOV opcode", rw_sse_mov, MODE_FOLD},
    {"suboptimal SSE zero idiom", rw_sse_zero, MODE_FOLD},
    {"redundant TEST after flags", rw_delete_test, MODE_FLAGS},
    {"redundant TEST after shift", rw_delete_test, MODE_FLAGS},
    {"constant condition after zeroing", rw_const_condition, MODE_FLAGS},
    {"constant condition after immediate", rw_const_condition, MODE_FLAGS},
    {"suboptimal CMP one", rw_cmp_one, MODE_FLAGS},
    {"redundant TEST after SETcc", rw_setcc_test, MODE_FLAGS},
    {"suboptimal SETcc inversion", rw_setcc_xor, MODE_FLAGS},
    {"missing ANDN", rw_andn, MODE_FOLD},
    {"missing BLSR", rw_blsr, MODE_FOLD},
    {"missing BLSMSK", rw_blsmsk, MODE_FOLD},
    {"missing BLSI", rw_blsi, MODE_FOLD},
    {"missing MOVBE", rw_movbe, MODE_FOLD},
    {"shift pair foldable into extend", rw_shift_pair, MODE_FLAGS},
    {"NEG foldable into ADD/SUB", rw_neg_fold, MODE_FLAGS},
    {"redundant zero-extension", rw_delete_ext, MODE_FLAGS},
    {"redundant re-extension", rw_delete_ext, MODE_FLAGS},
    {"redundant MOV constant", rw_delete_mov_imm, MODE_FOLD},
    {"rematerialized constant", rw_remat, MODE_FOLD},
    {"redundant bit-scan default", rw_delete_mov_imm, MODE_FOLD},
    {"MOV constant foldable", rw_mov_const_fold, MODE_FOLD},
    {"LEA foldable into memory", rw_lea_into_mem, MODE_FOLD},
    {"ADD foldable into memory", rw_add_into_mem, MODE_FOLD},
    {"ADD foldable into LEA", rw_add_into_lea, MODE_FOLD},
    {"MOV+ADD foldable to LEA", rw_mov_add_lea, MODE_FOLD},
    {"load foldable into ALU", rw_load_alu, MODE_FOLD},
    {"load foldable into compare", rw_load_cmp, MODE_FOLD},
    {"load foldable into extend", rw_load_ext, MODE_FOLD},
    {"load foldable into vector op", rw_load_vecop, MODE_FOLD},
    {"load foldable into vector transfer", rw_load_vec_transfer, MODE_FOLD},
    {"merging narrow move", rw_narrow_move, MODE_FOLD},
    {"missing SHLX/SHRX/SARX", rw_shlx, MODE_FOLD},
    {"missing POPCNT dependency break", rw_insert_xor, MODE_FOLD},
    {"redundant reload", rw_frame_forward, MODE_FRAME},
    {"load of a just-stored value", rw_frame_forward, MODE_FRAME},
    {"load of a value the register still holds", rw_delete_frame_load,
     MODE_FRAME},
    {"store of a value the slot already holds", rw_delete_frame_store,
     MODE_FRAME},
    {"dead store to a frame slot", rw_delete_frame_store, MODE_FRAME},
    {"bit-cast routed through a frame slot", rw_frame_bitcast, MODE_FRAME},
};
#define NKINDS ((int) (sizeof(KINDS) / sizeof(KINDS[0])))

static int kind_of(const char *name)
{
    for (int k = 0; k < NKINDS; ++k) {
        if (strcmp(KINDS[k].name, name) == 0) {
            return k;
        }
    }
    return -1;
}

// ---------------------------------------------------------------- stats ---

struct stat_row {
    const char *name;
    long findings, run, mismatches, not_applied, harness, unmapped;
    long control_tried, control_changed;
};

#define MAXNAMES 160
static struct stat_row stats[MAXNAMES];
static int nstats;

static struct stat_row *stat_for(const char *name)
{
    for (int k = 0; k < nstats; ++k) {
        if (strcmp(stats[k].name, name) == 0) {
            return &stats[k];
        }
    }
    assert(nstats < MAXNAMES);
    stats[nstats].name = name;
    return &stats[nstats++];
}

// ------------------------------------------------------------ execution ---

static sigjmp_buf run_jmp;
static volatile sig_atomic_t in_run;

static void on_signal(int sig)
{
    if (in_run) {
        in_run = 0;
        siglongjmp(run_jmp, sig);
    }
    signal(sig, SIG_DFL);
    raise(sig);
}

static uint8_t *exec_mem;
#define EXEC_SIZE (1 << 16)

typedef void (*prog_fn)(struct rstate *);

// Every run uses the same state block and the same stack depth, since the
// body can leave a pointer into either in a register.
static struct rstate exec_state;

static int run_code_at(const struct code *c, struct rstate *st);

static int run_code(const struct code *c, struct rstate *st)
{
    exec_state = *st;
    int sig = run_code_at(c, &exec_state);
    *st = exec_state;
    return sig;
}

static int run_code_at(const struct code *c, struct rstate *st)
{
    if (c->size > EXEC_SIZE) {
        return -1;
    }
    memcpy(exec_mem, c->bytes, c->size);
    __builtin___clear_cache((char *) exec_mem, (char *) exec_mem + c->size);
    int sig = sigsetjmp(run_jmp, 1);
    if (sig != 0) {
        return sig;
    }
    in_run = 1;
    alarm(2);
    ((prog_fn) (void *) exec_mem)(st);
    alarm(0);
    in_run = 0;
    return 0;
}

static void init_signals(void)
{
    static uint8_t altstack[1 << 16];
    stack_t ss = {.ss_sp = altstack, .ss_size = sizeof(altstack)};
    sigaltstack(&ss, NULL);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sa.sa_flags = SA_ONSTACK | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    int sigs[] = {SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGTRAP, SIGALRM};
    for (size_t k = 0; k < sizeof(sigs) / sizeof(sigs[0]); ++k) {
        sigaction(sigs[k], &sa, NULL);
    }
}

static void random_state(struct rstate *st, uint64_t *s)
{
    memset(st, 0, sizeof(*st));
    for (int k = 0; k < 16; ++k) {
        st->in_gpr[k] = edge_value(s);
        st->stub[k] = edge_value(s);
    }
    for (int x = 0; x < 8; ++x) {
        for (int b = 0; b < 16; b += 8) {
            uint64_t q = edge_value(s);
            memcpy(&st->in_xmm[x][b], &q, 8);
        }
    }
    st->in_flags = 0x2 | (rng_next(s) & FL_ARITH);
    for (int k = 0; k < FRAME_SIZE; k += 8) {
        uint64_t q = edge_value(s);
        memcpy(&st->frame[k], &q, 8);
    }
    for (int k = 0; k < SCRATCH_SIZE; k += 8) {
        uint64_t q = edge_value(s);
        memcpy(&st->scratch[k], &q, 8);
    }
}

// What differs between two final states, or NULL.
static const char *state_diff(const struct rstate *a, const struct rstate *b,
                              uint32_t flag_mask, char *buf, size_t n)
{
    for (int k = 0; k < NBODY; ++k) {
        int r = BODY[k];
        if (a->out_gpr[r] != b->out_gpr[r]) {
            snprintf(buf, n, "%s: %#" PRIx64 " vs %#" PRIx64, gpr(r, 64),
                     a->out_gpr[r], b->out_gpr[r]);
            return buf;
        }
    }
    for (int x = 0; x < 8; ++x) {
        if (memcmp(a->out_xmm[x], b->out_xmm[x], 16) != 0) {
            uint64_t a0, a1, b0, b1;
            memcpy(&a0, a->out_xmm[x], 8);
            memcpy(&a1, a->out_xmm[x] + 8, 8);
            memcpy(&b0, b->out_xmm[x], 8);
            memcpy(&b1, b->out_xmm[x] + 8, 8);
            snprintf(buf, n, "xmm%d: %016" PRIx64 "%016" PRIx64 " vs %016"
                     PRIx64 "%016" PRIx64, x, a1, a0, b1, b0);
            return buf;
        }
    }
    if (((a->out_flags ^ b->out_flags) & flag_mask) != 0) {
        snprintf(buf, n, "flags: %#" PRIx64 " vs %#" PRIx64 " (compared %#x)",
                 a->out_flags & FL_ARITH, b->out_flags & FL_ARITH, flag_mask);
        return buf;
    }
    for (int k = 0; k < SCRATCH_SIZE; ++k) {
        if (a->scratch[k] != b->scratch[k]) {
            snprintf(buf, n, "scratch byte %d: %#x vs %#x", k, a->scratch[k],
                     b->scratch[k]);
            return buf;
        }
    }
    return NULL;
}

// ------------------------------------------------------------------ main ---

struct finding_rec {
    const char *name;
    uint64_t off;
};

struct finding_list {
    struct finding_rec f[512];
    int n;
};

static void on_finding(void *ctx, const char *name, uint64_t vaddr,
                       const xed_decoded_inst_t *xedd, const uint8_t *bytes)
{
    (void) xedd;
    (void) bytes;
    struct finding_list *l = ctx;
    if (l->n < (int) (sizeof(l->f) / sizeof(l->f[0]))) {
        l->f[l->n].name = name;
        l->f[l->n].off = vaddr;
        ++l->n;
    }
}

struct variant {
    int prog;          // index in the batch
    int item;
    int kind;          // KINDS index
    const char *name;  // finding name
    bool control;
    struct prog *p;
};

// Does q change the prologue, epilogue or stub of p? Compares them in
// order, so an insertion into the body shifts nothing.
static bool touches_harness(const struct prog *p, const struct prog *q)
{
    int i = 0, j = 0;
    for (;;) {
        while (i < p->n && p->it[i].region == R_BODY) {
            ++i;
        }
        while (j < q->n && q->it[j].region == R_BODY) {
            ++j;
        }
        if (i >= p->n || j >= q->n) {
            return (i >= p->n) != (j >= q->n);
        }
        if (strcmp(p->it[i].text, q->it[j].text) != 0) {
            return true;
        }
        ++i;
        ++j;
    }
}

static void print_prog(const struct prog *p, int mark, const struct prog *q)
{
    for (int i = 0; i < p->n; ++i) {
        if (p->it[i].region != R_BODY) {
            continue;
        }
        if (p->it[i].label >= 0) {
            fprintf(stderr, "    @%d:\n", p->it[i].label);
        }
        bool changed = q != NULL && strcmp(p->it[i].text, q->it[i].text) != 0;
        fprintf(stderr, "  %s %-40s%s%s\n", i == mark ? ">>" : "  ",
                p->it[i].text[0] ? p->it[i].text : "(label)",
                changed ? "  =>  " : "",
                changed ? (q->it[i].text[0] ? q->it[i].text : "(deleted)")
                        : "");
    }
}

// The generator's seed for a program, and for each redraw of it.
static uint64_t prog_seed(uint64_t seed, long number, int round)
{
    return seed * 0x100000001b3ull + (uint64_t) number * 2 + 1 +
           (uint64_t) round * 0x9e3779b97f4a7c15ull;
}

static void usage(void)
{
    fprintf(stderr,
            "usage: rwfuzz [-n PROGRAMS] [-s SEED] [-f NAME] [-k KINDS] "
            "[-t TARGET] MODE\n");
    fprintf(stderr, "modes:");
    for (int m = 0; m < NMODES; ++m) {
        fprintf(stderr, " %s", MODE_NAMES[m]);
    }
    fprintf(stderr, "\n");
}

#define BATCH 128
#define RUNS 4
#define CONTROLS_PER_PROG 3

int main(int argc, char **argv)
{
    long nprogs = 10000;
    uint64_t seed = 0;
    const char *only = NULL;
    long min_kinds = 0;
    enum x86lint_target target = X86LINT_TARGET_ZEN;
    int opt;
    while ((opt = getopt(argc, argv, "n:s:f:k:t:")) != -1) {
        switch (opt) {
        case 'n':
            nprogs = atol(optarg);
            break;
        case 's':
            seed = strtoull(optarg, NULL, 0);
            break;
        case 'f':
            only = optarg;
            break;
        case 'k':
            min_kinds = atol(optarg);
            break;
        case 't':
            if (!x86lint_target_parse(optarg, &target)) {
                fprintf(stderr, "rwfuzz: unknown target %s\n", optarg);
                return 2;
            }
            break;
        default:
            usage();
            return 2;
        }
    }
    if (optind + 1 != argc) {
        usage();
        return 2;
    }
    enum mode mode = NMODES;
    for (int m = 0; m < NMODES; ++m) {
        if (strcmp(argv[optind], MODE_NAMES[m]) == 0) {
            mode = (enum mode) m;
        }
    }
    if (mode == NMODES) {
        usage();
        return 2;
    }
    if (only != NULL && kind_of(only) < 0) {
        fprintf(stderr, "rwfuzz: no rewriter for \"%s\"\n", only);
        return 2;
    }
    if (getenv("RWFUZZ_CC") != NULL) {
        cc_driver = getenv("RWFUZZ_CC");
    }

    uint32_t extensions = 0;
    __builtin_cpu_init();
    if (__builtin_cpu_supports("bmi")) {
        extensions |= X86LINT_EXT_BMI1;
    }
    if (__builtin_cpu_supports("bmi2")) {
        extensions |= X86LINT_EXT_BMI2;
    }
    {
        // MOVBE: CPUID.1:ECX bit 22.
        unsigned eax = 1, ebx, ecx = 0, edx;
        __asm__("cpuid" : "+a"(eax), "=b"(ebx), "+c"(ecx), "=d"(edx));
        if (ecx & (1u << 22)) {
            extensions |= X86LINT_EXT_MOVBE;
        }
    }

    const char *tmp = getenv("TMPDIR") != NULL ? getenv("TMPDIR") : "/tmp";
    snprintf(workdir, sizeof(workdir), "%s/rwfuzz.XXXXXX", tmp);
    if (mkdtemp(workdir) == NULL) {
        perror("mkdtemp");
        return 2;
    }
    exec_mem = mmap(NULL, EXEC_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (exec_mem == MAP_FAILED) {
        perror("mmap");
        return 2;
    }
    init_signals();
    xed_tables_init();

    long programs = 0, orig_faults = 0, printed = 0, skipped_progs = 0;
    long undefined_progs = 0;
    long total_runs = 0;
    struct prog *progs = malloc(sizeof(struct prog) * BATCH);
    struct prog **pp = malloc(sizeof(struct prog *) * BATCH);
    struct code *codes = calloc(BATCH, sizeof(struct code));
    bool *ok = malloc(BATCH);
    int *retry = malloc(sizeof(int) * BATCH);
    struct prog **rp = malloc(sizeof(struct prog *) * BATCH);
    struct code *rcodes = calloc(BATCH, sizeof(struct code));
    bool *rok = malloc(BATCH);

    for (long base = 0; base < nprogs; base += BATCH) {
        int nb = (int) (nprogs - base < BATCH ? nprogs - base : BATCH);
        for (int k = 0; k < nb; ++k) {
            generate(&progs[k], prog_seed(seed, base + k, 0), mode);
            pp[k] = &progs[k];
        }
        assemble(pp, nb, codes, ok);
        // A program that reads a flag the SDM leaves undefined depends on
        // what this core computes there; draw another in its place.
        for (int round = 1; round <= 8; ++round) {
            int nt = 0;
            for (int k = 0; k < nb; ++k) {
                if (!ok[k]) {
                    continue;
                }
                struct view tv;
                view_build(&tv, &progs[k], &codes[k]);
                bool reads_undefined;
                flags_undefined_at_end(&tv, &reads_undefined);
                view_free(&tv);
                if (reads_undefined) {
                    code_free(&codes[k]);
                    generate(&progs[k], prog_seed(seed, base + k, round),
                             mode);
                    retry[nt++] = k;
                }
            }
            if (getenv("RWFUZZ_DEBUG") != NULL) {
                fprintf(stderr, "round %d: %d redrawn\n", round, nt);
            }
            if (nt == 0) {
                break;
            }
            for (int j = 0; j < nt; ++j) {
                rp[j] = &progs[retry[j]];
            }
            assemble(rp, nt, rcodes, rok);
            for (int j = 0; j < nt; ++j) {
                codes[retry[j]] = rcodes[j];
                ok[retry[j]] = rok[j];
            }
        }

        // Findings and their rewrites.
        int cap = nb * 64;
        struct variant *vars = calloc((size_t) cap, sizeof(*vars));
        int nv = 0;
        struct view *views = calloc((size_t) nb, sizeof(*views));
        uint32_t *flag_mask = calloc((size_t) nb, sizeof(uint32_t));
        for (int k = 0; k < nb; ++k) {
            if (!ok[k]) {
                fprintf(stderr, "rwfuzz: program %ld did not assemble\n",
                        base + k);
                ++skipped_progs;
                continue;
            }
            ++programs;
            view_build(&views[k], &progs[k], &codes[k]);
            bool reads_undefined;
            flag_mask[k] = FL_COMPARED & ~flags_undefined_at_end(&views[k],
                &reads_undefined);
            if (reads_undefined) {
                ++undefined_progs;
                ok[k] = false;
                --programs;
                view_free(&views[k]);
                continue;
            }
            struct finding_list fl = {.n = 0};
            check_instructions(codes[k].bytes, codes[k].size, 0, false, NULL,
                               extensions, target, X86LINT_CLASS_REWRITE,
                               on_finding, &fl);
            bool *flagged = calloc((size_t) progs[k].n * NKINDS, 1);
            for (int f = 0; f < fl.n; ++f) {
                const char *name = fl.f[f].name;
                int kind = kind_of(name);
                if (only != NULL && strcmp(only, name) != 0) {
                    continue;
                }
                struct stat_row *st = stat_for(name);
                ++st->findings;
                int item = item_at_offset(&codes[k], fl.f[f].off);
                if (item < 0) {
                    ++st->unmapped;
                    continue;
                }
                if (kind >= 0) {
                    flagged[item * NKINDS + kind] = true;
                }
                if (progs[k].it[item].region != R_BODY) {
                    ++st->harness;
                    continue;
                }
                if (kind < 0) {
                    continue;   // no rewriter: counted, not run
                }
                struct prog *q = malloc(sizeof(*q));
                *q = progs[k];
                char why[160] = "";
                if (!KINDS[kind].fn(&views[k], item, q, why, sizeof(why))) {
                    ++st->not_applied;
                    if (printed < 20) {
                        fprintf(stderr, "NOT APPLIED %s (program %ld, item "
                                "%d): %s\n", name, base + k, item, why);
                        print_prog(&progs[k], item, NULL);
                        ++printed;
                    }
                    free(q);
                    continue;
                }
                // A rewrite that touches the harness is left alone.
                if (touches_harness(&progs[k], q)) {
                    ++st->harness;
                    free(q);
                    continue;
                }
                if (nv < cap) {
                    vars[nv++] = (struct variant){k, item, kind, name, false,
                                                  q};
                } else {
                    free(q);
                }
            }
            // Controls: the mode's rewriters where x86lint was silent.
            uint64_t cs = seed ^
                          ((uint64_t) (base + k) * 0x9e3779b97f4a7c15ull);
            int made = 0;
            for (int tries = 0; tries < 40 && made < CONTROLS_PER_PROG;
                 ++tries) {
                int kind = (int) rnd(&cs, NKINDS);
                if (only != NULL && strcmp(only, KINDS[kind].name) != 0) {
                    continue;
                }
                if (mode != MODE_ALL && KINDS[kind].family != mode) {
                    continue;
                }
                int item = (int) rnd(&cs, (unsigned) progs[k].n);
                if (progs[k].it[item].region != R_BODY ||
                    codes[k].len[item] == 0 ||
                    flagged[item * NKINDS + kind]) {
                    continue;
                }
                struct prog *q = malloc(sizeof(*q));
                *q = progs[k];
                char why[160];
                if (!KINDS[kind].fn(&views[k], item, q, why, sizeof(why)) ||
                    nv >= cap) {
                    free(q);
                    continue;
                }
                if (touches_harness(&progs[k], q)) {
                    free(q);
                    continue;
                }
                vars[nv++] = (struct variant){k, item, kind, KINDS[kind].name,
                                              true, q};
                ++made;
            }
            free(flagged);
        }

        // Assemble the rewrites.
        struct prog **vp = malloc(sizeof(struct prog *) * (size_t) (nv + 1));
        struct code *vcodes = calloc((size_t) nv + 1, sizeof(struct code));
        bool *vok = malloc((size_t) nv + 1);
        for (int k = 0; k < nv; ++k) {
            vp[k] = vars[k].p;
        }
        if (nv > 0) {
            assemble(vp, nv, vcodes, vok);
        }
        for (int k = 0; k < nv; ++k) {
            if (!vok[k] && !vars[k].control) {
                struct stat_row *st = stat_for(vars[k].name);
                ++st->not_applied;
                if (printed < 20) {
                    fprintf(stderr, "NOT APPLIED %s (program %ld, item %d): "
                            "the assembler refused the rewrite\n",
                            vars[k].name, base + vars[k].prog, vars[k].item);
                    print_prog(&progs[vars[k].prog], vars[k].item, vars[k].p);
                    ++printed;
                }
            }
        }

        // Run.
        bool *changed = calloc((size_t) nv + 1, 1);
        bool *mismatched = calloc((size_t) nv + 1, 1);
        for (int k = 0; k < nb; ++k) {
            if (!ok[k]) {
                continue;
            }
            for (int r = 0; r < RUNS; ++r) {
                uint64_t ss = (seed + 0x5bd1e995ull) * 0x2545f4914f6cdd1dull ^
                              ((uint64_t) (base + k) << 8 | (uint64_t) r);
                struct rstate in, want, got;
                random_state(&in, &ss);
                want = in;
                if (run_code(&codes[k], &want) != 0) {
                    ++orig_faults;
                    continue;
                }
                ++total_runs;
                for (int x = 0; x < nv; ++x) {
                    if (vars[x].prog != k || !vok[x] || mismatched[x]) {
                        continue;
                    }
                    got = in;
                    int sig = run_code(&vcodes[x], &got);
                    char buf[200];
                    const char *d = sig != 0 ? (snprintf(buf, sizeof(buf),
                        "the rewrite died of signal %d", sig), buf) :
                        state_diff(&want, &got, flag_mask[k], buf,
                                   sizeof(buf));
                    if (vars[x].control) {
                        if (d != NULL) {
                            changed[x] = true;
                        }
                        continue;
                    }
                    if (r == 0) {
                        ++stat_for(vars[x].name)->run;
                    }
                    if (d != NULL) {
                        mismatched[x] = true;
                        ++stat_for(vars[x].name)->mismatches;
                        if (printed < 40) {
                            fprintf(stderr, "MISMATCH %s (program %ld, item "
                                    "%d, run %d): %s\n", vars[x].name,
                                    base + k, vars[x].item, r, d);
                            print_prog(&progs[k], vars[x].item, vars[x].p);
                            ++printed;
                        }
                    }
                }
            }
        }
        for (int x = 0; x < nv; ++x) {
            if (vars[x].control && vok[x]) {
                struct stat_row *st = stat_for(vars[x].name);
                ++st->control_tried;
                st->control_changed += changed[x];
            }
            free(vars[x].p);
            code_free(&vcodes[x]);
        }
        for (int k = 0; k < nb; ++k) {
            if (ok[k]) {
                view_free(&views[k]);
            }
            code_free(&codes[k]);
        }
        free(changed);
        free(mismatched);
        free(vp);
        free(vcodes);
        free(vok);
        free(vars);
        free(views);
        free(flag_mask);
    }

    // Report.
    long mism = 0, notap = 0, kinds_run = 0, run_total = 0;
    printf("rwfuzz %s: %ld programs, seed %" PRIu64 ", %ld runs\n",
           MODE_NAMES[mode], programs, seed, total_runs);
    for (int k = 0; k < nstats; ++k) {
        for (int j = k + 1; j < nstats; ++j) {
            if (strcmp(stats[j].name, stats[k].name) < 0) {
                struct stat_row t = stats[k];
                stats[k] = stats[j];
                stats[j] = t;
            }
        }
    }
    long tried = 0, chg = 0;
    for (int k = 0; k < nstats; ++k) {
        struct stat_row *s = &stats[k];
        bool has = kind_of(s->name) >= 0;
        if (s->findings == 0 && s->control_tried == 0) {
            continue;
        }
        printf("  %-44s %7ld found", s->name, s->findings);
        if (has) {
            printf(", %7ld run, %ld mismatched", s->run, s->mismatches);
        } else {
            printf(", no rewriter");
        }
        if (s->not_applied) {
            printf(", %ld NOT APPLIED", s->not_applied);
        }
        if (s->harness) {
            printf(", %ld in the harness", s->harness);
        }
        if (s->unmapped) {
            printf(", %ld unmapped", s->unmapped);
        }
        if (s->control_tried) {
            printf("; control %ld/%ld changed", s->control_changed,
                   s->control_tried);
        }
        printf("\n");
        mism += s->mismatches;
        notap += s->not_applied;
        run_total += s->run;
        tried += s->control_tried;
        chg += s->control_changed;
        if (s->run > 0) {
            ++kinds_run;
        }
    }
    printf("  %ld findings run, %ld kinds; %ld mismatched, %ld not applied\n",
           run_total, kinds_run, mism, notap);
    printf("  control: %ld refused rewrites run, %ld changed the result\n",
           tried, chg);
    printf("  %ld programs read a flag left undefined and were skipped",
           undefined_progs);
    if (orig_faults || skipped_progs) {
        printf("; %ld original runs faulted; %ld programs did not assemble",
               orig_faults, skipped_progs);
    }
    printf("\n");

    char cmd[400];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", workdir);
    if (system(cmd) != 0) {
        fprintf(stderr, "rwfuzz: could not remove %s\n", workdir);
    }

    if (programs == 0 || run_total == 0) {
        fprintf(stderr, "rwfuzz: nothing was tested\n");
        return 1;
    }
    if (mism || notap || skipped_progs) {
        return 1;
    }
    if (min_kinds > 0 && kinds_run < min_kinds) {
        fprintf(stderr, "rwfuzz: %ld kinds run, fewer than %ld\n", kinds_run,
                min_kinds);
        return 1;
    }
    return 0;
}

#endif
