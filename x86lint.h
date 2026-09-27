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

#ifndef X86LINT_H
#define X86LINT_H

#include <stdbool.h>
#include "xed/xed-interface.h"

// return false if instruction sequence contains multiple adjacent no ops
// (an undecodable byte ends the NOP run without a finding)
bool check_suboptimal_nops(const uint8_t *inst, size_t len);

// return false if instruction has an oversized immediate
bool check_oversized_immediate(const xed_decoded_inst_t *xedd);

// return false if test reg, imm carries an imm16/imm32 whose mask fits the
// low seven bits -- the byte-register form (test al, 1 etc.) sets identical
// flags in 2-4 fewer bytes
bool check_oversized_test_immediate(const xed_decoded_inst_t *xedd);

// return false if test reg, -1 (an all-ones mask at the operand width) could
// be test reg, reg, which sets identical flags in fewer bytes
bool check_test_minus_one(const xed_decoded_inst_t *xedd);

// return false if instruction encodes ADD REG, 128 / SUB REG, 128 (5-6 bytes)
// instead of the negated SUB REG, -128 / ADD REG, -128 (3 bytes)
bool check_oversized_add_sub_128(const xed_decoded_inst_t *xedd);

// return false if a 66 operand-size prefix narrows the instruction's
// immediate to 16 bits (add cx, 0x1234) -- a length-changing prefix, which
// stalls Intel's pre-decoder ~3 cycles per visit through the Skylake era.
// Advisory: the clean fix (32-bit operands) writes bits 16-31, which no
// liveness here tracks
bool check_lcp_imm16(const xed_decoded_inst_t *xedd);

// The MOV half of the same stall, whose cost is per-core. See x86lint.c.
bool check_lcp_imm16_mov(const xed_decoded_inst_t *xedd);

// return false if instruction has an unneeded rex prefix
bool check_unneeded_rex(const xed_decoded_inst_t *xedd);

// return false if instruction uses CMP 0 instead of TEST
bool check_cmp_zero(const xed_decoded_inst_t *xedd);

// return false if instruction zeros a register with mov instead of xor
bool check_mov_zero(const xed_decoded_inst_t *xedd);

// return false if instruction could use an implicit register encoding
bool check_implicit_register(const xed_decoded_inst_t *xedd);

// return false if instruction could use an implicit immediate encoding
bool check_implicit_immediate(const xed_decoded_inst_t *xedd);

// return false if instruction could use movzbl or movzwl instead of AND REG, IMM
bool check_and_strength_reduce(const xed_decoded_inst_t *xedd);

// return false if and reg, -1 (an all-ones mask at the operand width) could be
// test reg, reg, which sets identical flags in fewer bytes. The 32-bit form
// also zero-extends (GCC's fused zero-extend-and-test idiom), so the
// dispatcher gates it on upper-32 register liveness (cf. check_mov_self)
bool check_and_minus_one(const xed_decoded_inst_t *xedd);

// return false if xor r/m, -1 could be not r/m, one byte shorter (valid
// when the arithmetic flags are dead, since NOT writes none)
bool check_xor_to_not(const xed_decoded_inst_t *xedd);

// return false if instruction should not have a LOCK prefix
bool check_superfluous_lock_prefix(const xed_decoded_inst_t *xedd);

// return false if a near RET carries the ignored F3 (REP) prefix -- the
// obsolete AMD K8/K10 branch-predictor workaround gcc emitted until GCC 8;
// dropping it saves the byte unconditionally. F2 (MPX's bnd ret) is not
// matched
bool check_rep_ret(const xed_decoded_inst_t *xedd);

// return false for an indirect near CALL carrying the CET NOTRACK prefix
// (3E): the call site is exempt from indirect-branch tracking, a deliberate
// hole in IBT coverage. Indirect JMPs are not matched -- NOTRACK there is
// the compilers' read-only switch-table idiom. A security review flag
// rather than a rewrite suggestion
bool check_notrack_call(const xed_decoded_inst_t *xedd);

// return false if xchg with an accumulator uses the modrm form (87 /r)
// when the one-byte 90+r form would do
bool check_xchg_accumulator(const xed_decoded_inst_t *xedd);

// return false if a JMP or Jcc uses rel32 when rel8 would reach the target
bool check_oversized_branch(const xed_decoded_inst_t *xedd);

// A direct rel8 branch whose displacement is zero: control arrives at the
// same instruction taken or not, so it is a pure no-op. See x86lint.c.
bool check_branch_to_next(const xed_decoded_inst_t *xedd);

// return false if instruction is a no-op mov reg, reg. The 8/16/64-bit forms
// are pure no-ops; the mov r32, r32 form is a no-op only when its incidental
// zero-extension into the upper 32 bits is dead, which the dispatcher gates on
// register liveness (reg_upper32_live_after)
bool check_mov_self(const xed_decoded_inst_t *xedd);

// CMOVcc naming one register twice: a conditional move onto itself. See
// x86lint.c.
bool check_cmov_self(const xed_decoded_inst_t *xedd);

// PEXTR/EXTRACTPS of lane 0, which MOVD/MOVQ/MOVSS spell more cheaply.
bool check_lane0_extract(const xed_decoded_inst_t *xedd);

// return false if instruction is add reg, 0 or sub reg, 0 (use TEST
// reg, reg instead for the flag side-effect, or remove the instruction
// if flags are unused). The 32-bit form also zero-extends, so the
// dispatcher gates it on upper-32 register liveness (cf. check_mov_self)
bool check_add_sub_zero(const xed_decoded_inst_t *xedd);

// return false if instruction is or reg, 0 or xor reg, 0 (no-ops that only
// set flags; use TEST reg, reg instead, or remove when flags are unused).
// The 32-bit form also zero-extends, so the dispatcher gates it on upper-32
// register liveness (cf. check_mov_self)
bool check_or_xor_zero(const xed_decoded_inst_t *xedd);

// return false if instruction is and reg, 0, which zeroes the register --
// xor reg, reg does the same with identical flags in fewer bytes
bool check_and_zero(const xed_decoded_inst_t *xedd);

// return false if add r/m, 1 / sub r/m, 1 (or the -1 forms, register or
// memory destination) could be inc / dec, which is one byte shorter (valid
// when CF is dead, since inc/dec leave CF unchanged)
bool check_inc_dec(const xed_decoded_inst_t *xedd);

// return false if a mov reg, imm uses the c6/c7 modrm form with a
// register destination when the b0/b8 +r form would be one byte shorter
bool check_mov_modrm_imm(const xed_decoded_inst_t *xedd);

// return false if instruction has a SIB byte that could be elided by
// encoding the addressing mode directly in modrm
bool check_unneeded_sib(const xed_decoded_inst_t *xedd);

// return false if instruction encodes a zero displacement that could be
// shortened (disp32=0 -> disp8=0, or disp8=0 -> no displacement)
bool check_unneeded_zero_displacement(const xed_decoded_inst_t *xedd);

// return false if instruction encodes a nonzero displacement as disp32
// when its value fits in a signed disp8 (EVEX instructions are skipped:
// their disp8 is compressed by a scale factor, so most small disp32
// values have no disp8 form)
bool check_oversized_displacement(const xed_decoded_inst_t *xedd);

// return false if movsxd rax, eax could be cdqe (cltq in AT&T)
bool check_unneeded_movsxd(const xed_decoded_inst_t *xedd);

// return false if movsx eax, ax could be cwde or movsx ax, al could be cbw
bool check_unneeded_movsx(const xed_decoded_inst_t *xedd);

// return false if sub reg, reg is used as a zero idiom -- xor reg, reg is
// the canonical form that CPUs recognize as dependency-breaking
bool check_sub_self(const xed_decoded_inst_t *xedd);

// return false if or reg, reg or and reg, reg is used as a flag test --
// test reg, reg is the canonical form and does not write the register.
// The 32-bit form's write also zero-extends, so the dispatcher gates it on
// upper-32 register liveness (cf. check_mov_self)
bool check_or_and_self(const xed_decoded_inst_t *xedd);

// return false if IMUL by a constant in {2,3,5,9} or a power of two could be
// replaced by a single LEA or SHL, or if the multiplier is degenerate:
// 0 -> XOR, 1 -> MOV (or removal when destination and source coincide,
// gated on upper-32 register liveness by the dispatcher), -1 in place -> NEG
bool check_imul_to_lea(const xed_decoded_inst_t *xedd);

// return false if lea dst, [base] (no index, zero displacement, base width
// matching the destination) could be mov dst, base
bool check_lea_to_mov(const xed_decoded_inst_t *xedd);

// return false if lea dst, [reg + reg2] (unit scale, no displacement,
// destination one of the two address registers) could be add dst, reg2, which
// is a byte shorter and issues on more ports (flag-gated: add writes flags)
bool check_lea_to_add(const xed_decoded_inst_t *xedd);

// return false if lea r64, [...] could be lea r32: the address's low 32 bits
// come out identical and dropping REX.W saves its byte (flagged only when W
// is the sole REX payload, so the prefix disappears). The narrowed form
// zeroes bits 32-63 of the destination where the original stores the
// address's upper half, so the dispatcher gates the finding on those bits
// being dead -- with no backward zero-extension escape: a predecessor's
// zeroing of the destination says nothing about the new address's upper half
bool check_oversized_lea_width(const xed_decoded_inst_t *xedd);

// return false if a shift or rotate instruction has an immediate count of 0
// (value- and flag-preserving per the Intel SDM; hardware still zero-extends
// a 32-bit destination even at count 0, so the dispatcher gates that form on
// upper-32 register liveness, cf. check_mov_self). Memory destinations are
// excluded: deleting the instruction deletes a memory access, whose faults,
// MMIO side effects, and write-back are observable regardless of the value
bool check_shift_zero(const xed_decoded_inst_t *xedd);

// return false if shl reg, 1 could be add reg, reg -- the same value with
// identical flags (CF and OF included) in the same or fewer bytes, on more
// execution ports; unconditional
bool check_shl_one(const xed_decoded_inst_t *xedd);

// return false if a variable shift (shl/shr/sar reg, cl) could be the
// flagless BMI2 form (shlx/shrx/sarx), which takes its count in any register
// and drops the flag-merge cost of CL shifts on Intel cores. The dispatcher
// runs this only when the caller enabled BMI2 and gates it on the arithmetic
// flags being dead (the CL form writes them all for a nonzero count; the
// BMI2 forms write none) and, for 32-bit forms, on upper-32 register
// liveness (per the SDM a count-0 shift may leave the destination unwritten,
// where shlx always zero-extends; cf. check_shift_zero)
bool check_missing_shlx(const xed_decoded_inst_t *xedd);

// return false if a legacy-encoded movapd/movdqa/movupd/movdqu could be
// movaps/movups, the identical copy without the one-byte 66/F3 prefix
bool check_sse_mov_opcode(const xed_decoded_inst_t *xedd);

// return false if a legacy-encoded self-XOR zeroing idiom -- pxor xmm, xmm or
// xorpd xmm, xmm -- could be xorps xmm, xmm, the identical zeroing without the
// one-byte 66 prefix.
//
// What makes the swap free is that the three are interchangeable to the
// hardware, not that they cost nothing: every microarchitecture that
// recognizes a self-XOR as independent of the register's prior value lists
// PXOR, XORPS and XORPD together, so the dependency break survives the
// rewrite. Whether the idiom also skips an execution unit varies and is the
// same for all three either way -- resolved at the register allocation stage
// through Broadwell, executing on a vector port from Skylake (Agner Fog,
// microarchitecture.pdf) -- so it does not distinguish them. The
// integer-versus-FP domain question that qualifies the sibling SSE MOV check
// is weaker here because the value produced is a constant zero rather than
// forwarded data
bool check_sse_zero_idiom(const xed_decoded_inst_t *xedd);

// return false if an EVEX-encoded instruction uses no EVEX-only feature
// (opmask, broadcast, rounding/SAE, 512-bit length, xmm16-31) and a VEX
// re-encoding is strictly shorter
bool check_oversized_evex(const xed_decoded_inst_t *xedd);

// return false if a VEX-encoded instruction uses the three-byte (C4) prefix
// where the two-byte (C5) form would do -- opcode map 0F, VEX.W clear, and no
// r8-r15 base/index/rm operand -- which wastes one byte
bool check_oversized_vex(const xed_decoded_inst_t *xedd);

// return false if the bytes at `offset` do not begin with an ENDBR64
// instruction. For a caller with outside evidence that an indirect branch can
// land at `offset` -- an ELF relocation, an init_array slot, an exported
// function, the entry point -- a false return in a CET IBT-marked binary is a
// runtime fault: with indirect branch tracking enforced, an indirect JMP or
// CALL landing anywhere but an ENDBR64 raises #CP. The evidence is the
// caller's job precisely because the instruction stream cannot supply it:
// nothing in the bytes distinguishes an indirect target from fallthrough
// code, so a streamwise "missing ENDBR64" check would be guessing (and its
// inverse -- flagging a superfluous ENDBR64 -- would be unsound, since a
// target materialized by LEA leaves no relocation behind)
bool check_endbr64_target(const uint8_t *inst, size_t len, size_t offset);

// Overwrite every instruction whose encoding a relocation will rewrite, so
// that the scan neither reads a placeholder as a value nor suggests a rewrite
// the link would undo. `field_starts` is one byte per byte of `inst`, nonzero
// where a relocation field begins; the caller supplies it because only the
// container knows, exactly as with check_endbr64_target above. Returns the
// number of instructions masked.
//
// An unlinked object's immediates and displacements are not values. They are
// zero, or a bare addend, waiting for the linker, and a peephole that reads
// one is reasoning about a number that will not be there at run time. On a
// Fedora kernel module (amt.ko, 8,441 instructions) 275 of 314 findings were
// this: 143 relocated `e9 00000000` -- every return in a
// -mfunction-return=thunk-extern build -- whose rel32 placeholder reads as a
// branch to the next instruction and as a displacement that would fit rel8,
// and 132 `mov r64, imm32` carrying R_X86_64_32S, where the narrower encoding
// the finding asks for cannot express the sign-extended kernel address the
// linker is about to write. Both are worse than noise: applying either
// corrupts the relocation.
//
// The masked bytes become 0x06, an opcode invalid in 64-bit mode, which is
// what the ELF driver already writes over bytes outside the function symbols.
// That spelling is load-bearing rather than decorative: the scan's
// decode-and-resync loop skips the instruction, tallies its bytes as
// undecodable so the excluded volume stays visible in the report, and -- the
// part a value-level suppression could not give -- treats it as a barrier, so
// no multi-instruction window reasons across a placeholder either.
//
// Returns the number of instructions masked, and through `bytes_masked` (when
// non-NULL) how many bytes they held, so a caller can say how much of the
// report's undecodable-byte count is this exclusion rather than data in the
// code section -- on that kernel module it is 5,061 of 5,061.
size_t x86lint_mask_relocated(uint8_t *inst, size_t len,
                              const uint8_t *field_starts,
                              size_t *bytes_masked);

// A by-type tally of findings accumulated across one or more
// check_instructions runs, so a driver can print a by-prevalence summary.
// Opaque; created and destroyed by the caller. A NULL summary is accepted
// everywhere (tallying is simply skipped).
typedef struct x86lint_summary x86lint_summary;

x86lint_summary *x86lint_summary_create(void);
void x86lint_summary_destroy(x86lint_summary *summary);

// Print the findings grouped by type, most prevalent first.
void x86lint_summary_print(const x86lint_summary *summary);

// Total instructions decoded across the runs tallied into this summary.
// Returns 0 for a NULL summary.
size_t x86lint_summary_instructions(const x86lint_summary *summary);

// Total undecodable bytes skipped across the runs tallied into this summary.
// Nonzero means the input interleaves data with code (common in Go binaries
// and jump tables), so coverage was incomplete. Returns 0 for a NULL summary.
size_t x86lint_summary_skipped(const x86lint_summary *summary);

// A named function's address range, for attributing findings to the
// function that contains them.
typedef struct {
    uint64_t start;     // vaddr, inclusive
    uint64_t end;       // vaddr, exclusive
    const char *name;
} x86lint_func_range;

// Install the function ranges consulted when a finding is tallied: each
// finding's address (the scan's vaddr plus the finding's offset) is
// looked up here, verbose finding lines gain a "(name+0xoff)" suffix,
// and the summary prints a by-function table beside the by-type one.
// `funcs` must be sorted by start, non-overlapping, and outlive the
// summary along with the names it points to; the summary does not copy
// or free them. NULL/0 (the default) disables attribution.
void x86lint_summary_set_functions(x86lint_summary *summary,
                                   const x86lint_func_range *funcs,
                                   size_t count);

// Findings attributed to funcs[idx] of the installed table. Always 0
// when no table is installed.
size_t x86lint_summary_function_findings(const x86lint_summary *summary,
                                         size_t idx);

// A by-extension tally of every instruction decoded, mapped onto the x86-64
// psABI micro-architecture levels, for auditing what a binary was compiled
// for: x86-64-v2 (CMPXCHG16B, LAHF-SAHF, POPCNT, SSE3, SSSE3, SSE4.1,
// SSE4.2), x86-64-v3 (adds AVX, AVX2, BMI1, BMI2, F16C, FMA, LZCNT, MOVBE,
// XSAVE), x86-64-v4 (adds AVX-512 F/BW/CD/DQ/VL). Extensions outside the
// levels (AES-NI, SHA, ADX, CET, the post-v4 AVX-512 families, ...) are
// tallied separately and never raise the level verdict.
//
// The census reports presence, not requirement: code behind IFUNC or branch
// dispatch (glibc's memcpy variants, Go's runtime feature checks) counts
// even though the binary still runs on CPUs without the extension.
// Reachability is not decidable from the instruction stream, so the census
// answers "was the compiler allowed to use this anywhere"; the driver
// prints the binary's IFUNC resolver count alongside so dispatch-heavy
// binaries are recognizable as such. Opaque; NULL is accepted everywhere.
typedef struct x86lint_census x86lint_census;

x86lint_census *x86lint_census_create(void);
void x86lint_census_destroy(x86lint_census *census);

// Linear-sweep decode of `len` bytes, tallying each instruction by XED
// isa-set. An undecodable byte is skipped and the sweep resyncs, tallied
// like the lint scan's skipped count. `vaddr` is the virtual address of
// inst[0], used for the sample addresses verbose mode prints.
void x86lint_census_scan(x86lint_census *census, const uint8_t *inst,
                         size_t len, uint64_t vaddr);

// Print the census: totals, per-level breakdowns by descending count, the
// highest level used, and in verbose mode up to four sample addresses per
// extension (to tell real use from data decoded as code).
void x86lint_census_print(const x86lint_census *census, bool verbose);

size_t x86lint_census_instructions(const x86lint_census *census);
size_t x86lint_census_skipped(const x86lint_census *census);

// Instructions tallied at one psABI level: 1 = baseline x86-64, 2..4 =
// x86-64-v2..v4, 0 = extensions outside the levels.
size_t x86lint_census_level_count(const x86lint_census *census, int level);

// The x87 line is a cross-cutting annotation: x87-family instructions
// (isa-sets X87, FCMOV, FCOMI, and SSE3X87's FISTTP) keep their psABI
// level in the counts above -- x87 IS baseline -- and are additionally
// split three ways here. Control/env covers the FPU-state instructions
// (FLDCW, FNSTSW, FNSAVE, ...) that ordinary fenv manipulation emits;
// 80-bit covers any instruction touching a ten-byte memory operand,
// the long-double traffic the SysV ABI legitimately routes through x87.
// The split exists because intent is only judgeable per binary, not per
// instruction: legitimate long-double code is dominated by bare
// register-stack arithmetic between its FLDT/FSTPT edges, so "other"
// beside 80-bit traffic reads as long-double implementation, while
// "other" in a binary with ZERO 80-bit operands cannot be long double
// and reads as -mfpmath=387 leakage or ported 32-bit assembly.
enum x86lint_x87_kind {
    X86LINT_X87_CONTROL,     // FPU environment/state management
    X86LINT_X87_EIGHTY_BIT,  // touches an 80-bit (tbyte) memory operand
    X86LINT_X87_OTHER,       // register-stack arithmetic, narrow loads, ...
};

size_t x86lint_census_x87_count(const x86lint_census *census,
                                enum x86lint_x87_kind kind);

// Code-evidence labeling. The census cannot tell a real instruction from
// a phantom decode of data-in-text (tools/cohere measured every cheap
// coherence heuristic failing at exactly that), but the toolchain often
// recorded which bytes it meant as code: sized STT_FUNC symbols,
// .eh_frame FDE pc-ranges, and Go pclntab function boundaries (which
// survive `strip`). With evidence installed, every tally is also
// counted as evidenced or not, and the report annotates families whose
// hits fall outside all evidence. The semantics are asymmetric by
// design: inside evidence lends trust; outside means only "no toolchain
// claim" -- GHC emits no FDEs for Haskell code, some builds strip unwind
// tables -- never "phantom".
typedef struct {
    uint64_t start;     // vaddr, inclusive
    uint64_t end;       // vaddr, exclusive
} x86lint_evidence_range;

// Install the evidence ranges consulted by subsequent scans. `ranges`
// must be sorted by start, non-overlapping, and outlive the census; the
// census does not copy or free them. NULL/0 (the default) disables
// labeling: nothing is counted unevidenced and no annotations print.
void x86lint_census_set_evidence(x86lint_census *census,
                                 const x86lint_evidence_range *ranges,
                                 size_t count);

// Instructions tallied at one psABI level (same buckets as
// x86lint_census_level_count) whose site lay outside every evidence
// range. Always 0 when no evidence is installed.
size_t x86lint_census_level_unevidenced(const x86lint_census *census,
                                        int level);

// Highest of levels 2..4 with a nonzero tally, else 1 (baseline).
int x86lint_census_highest_level(const x86lint_census *census);

// Called once per finding, in the order findings are reported, when passed
// to check_instructions. The summary answers "how many of each kind"; this
// answers "which instruction, at what address" -- the form a consumer needs
// to join findings against something else keyed by address, such as an
// execution profile that weights each finding by how often the instruction
// it names actually runs.
//
// name is the finding's stable string literal, the same pointer the summary
// tallies under and verbose mode prints, so it may be compared by identity
// as well as by strcmp. vaddr is the offending instruction's absolute
// address: check_instructions' vaddr argument plus the finding's offset.
// xedd and bytes are that instruction's decoded form and its raw encoding,
// both valid only for the duration of the call -- a consumer that keeps
// either must copy it.
//
// A multi-instruction peephole matches a window but reports one instruction
// of it, the one its rewrite removes, and that is the instruction named
// here; the rest of the window is not reported. Two checks can therefore
// fire at the same vaddr, and a finding can name an instruction the scan has
// not reached yet, so findings do not arrive in strictly increasing address
// order.
typedef void (*x86lint_finding_fn)(void *ctx, const char *name, uint64_t vaddr,
                                   const xed_decoded_inst_t *xedd,
                                   const uint8_t *bytes);

// Instruction-set extensions the scanned code's target is known to support.
// Checks whose suggested replacement is an instruction from one of these sets
// run only when the caller enables that set: on a target without it the
// "missed opportunity" is not actionable (the compiler was not allowed to use
// the instruction), and code built for mixed dispatch -- glibc keeps baseline
// and BMI-rich ifunc variants in one .text -- makes inferring availability
// from the surrounding bytes unsound. The bits are independent, matching
// their CPUID feature flags: bmi2 does not imply bmi1.
enum x86lint_extensions {
    X86LINT_EXT_BMI1 = 1u << 0,  // ANDN, BLSI, BLSMSK, BLSR, TZCNT, ...
    X86LINT_EXT_BMI2 = 1u << 1,  // BZHI, MULX, PDEP, PEXT, RORX, SHLX, ...
    X86LINT_EXT_MOVBE = 1u << 2, // MOVBE (byte-swapping load/store)
    X86LINT_EXT_APX = 1u << 3,   // EVEX-promoted NDD three-operand forms, ...
    // V8 differs in kind from the ISA bits above: it asserts a runtime
    // invariant of the scanned code rather than a hardware capability -- that
    // R14 holds V8's pointer-compression cage base (kPtrComprCageBaseRegister),
    // which is 4 GB aligned so its low 32 bits are zero. V8 decompresses a
    // tagged field with `mov r32, [obj+off]; or r64, r14`, and the OR equals an
    // ADD only because the two operands share no set bits. The checks it gates
    // (OR foldable into memory) are unsound for arbitrary code and stay silent
    // without it. The armlint twin is -m v8 (ARMLINT_FEATURE_V8, whose cage
    // half is ARMLINT_FEATURE_V8CAGE).
    X86LINT_EXT_V8 = 1u << 4,
};

// The microarchitecture the scanned code is tuned for. This is a different
// axis from the extensions above: those say whether an encoding *exists* on
// the target, where this says whether a rewrite is *worth making* there, and
// several of x86lint's are not worth it everywhere.
//
// A three-component LEA costs 3 cycles on port 1 alone from Sandy Bridge
// through Cascade Lake, where each two-component form is 1 cycle on two
// ports, so folding a fast LEA and an ADD into a slow one trades a cycle for
// three or four bytes. Ice Lake and later drop the penalty and Zen never had
// it, and on those the same fold wins on size, uops and latency at once.
// POPCNT treats its destination as a phantom input from Sandy Bridge through
// Cascade Lake and not after. The length-changing prefix stall applies to MOV
// on the Pentium 4 through Nehalem, not on Sandy Bridge through Skylake, and
// again from Ice Lake -- non-monotonic, which is why this is a set of named
// cores rather than a version number. And SUB r, r is recognized as a
// zeroing idiom independent of its input everywhere except the low-power
// line, so the rewrite to XOR buys nothing on a big core.
//
// GENERIC is the default and assumes every penalty applies at once, which is
// the conservative reading: it reports the rewrites that are safe everywhere
// and withholds the ones that are only sometimes worth it.
enum x86lint_target {
    X86LINT_TARGET_GENERIC = 0,
    X86LINT_TARGET_SANDYBRIDGE,   // Sandy Bridge, Ivy Bridge, Haswell, Broadwell
    X86LINT_TARGET_SKYLAKE,       // Skylake, Cascade Lake
    X86LINT_TARGET_ICELAKE,       // Ice Lake, Tiger Lake and later
    X86LINT_TARGET_ZEN,           // Zen 1 through Zen 5
    X86LINT_TARGET_SILVERMONT,    // the low-power line
};

// What kind of thing a finding is, which decides whether it is reported at
// all. Most of x86lint's checks state a verified byte-level rewrite: the
// replacement is equivalent, the tool proved the conditions, and applying it
// is mechanical. Those are the default, and they are what makes the exit
// status meaningful for gating a compiler test suite.
//
// Two other kinds do not fit that description and, until now, were reported
// beside it as though they did.
//
// ADVISORY is a real improvement whose fix the tool cannot verify or cannot
// even see. The SETcc zero-extension's rewrite belongs upstream of the
// flag-setter, whose surroundings a peephole cannot prove safe; the
// length-changing prefix stall's clean fix is 32-bit operands, which needs
// upper-16 liveness this tool does not track. Both say as much in their own
// documentation. A build should not fail on advice the tool cannot check.
//
// SECURITY is not a rewrite at all. The IBT-bypassing NOTRACK call is a
// review item -- dropping the prefix without padding the target trades the
// bypass for a #CP fault -- so the reader is being asked to look, not to
// patch. armlint keeps the same kind behind its own opt-in flag (-a pac).
//
// The bits are independent, so a caller can ask for advisories without
// security review items or the other way round. Enabling a class makes its
// findings count like any other, exit status included: you asked for them.
enum x86lint_classes {
    X86LINT_CLASS_REWRITE = 1u << 0,   // the default; a verified rewrite
    X86LINT_CLASS_ADVISORY = 1u << 1,  // a fix the tool cannot verify
    X86LINT_CLASS_SECURITY = 1u << 2,  // a review item, not a rewrite
};

// The name accepted by the driver's -c, or NULL for an unknown class.
const char *x86lint_class_name(uint32_t klass);

// Parse a -c name into its bit; returns false for an unknown one. "all"
// yields every class.
bool x86lint_class_parse(const char *name, uint32_t *out);

// The name accepted by the driver's -t, or NULL for an unknown target.
const char *x86lint_target_name(enum x86lint_target target);

// Parse a -t name; returns false and leaves *out alone if it is not one.
bool x86lint_target_parse(const char *name, enum x86lint_target *out);

// A tally of how a binary's jumps fall against 32-byte boundaries, for
// auditing whether it was built with the JCC-erratum mitigation (the driver's
// -j). Opaque; NULL is accepted everywhere.
//
// Skylake-derived cores cannot cache a jump in the decoded-icache when the
// jump's bytes cross a 32-byte boundary or its last byte is the last byte of
// one. Fetch falls back to legacy decode, and the cost is per execution, so a
// hot loop pays it every iteration. The affected population is a list of
// models and steppings rather than a range -- V8 enumerates it in
// src/base/cpu/cpu-x86.cc, and it comes to Skylake through Comet Lake with
// Cascade Lake among them. Ice Lake and later do not have the erratum and no
// AMD core ever did.
//
// This is a verdict rather than a check because the fix is padding. Every
// other analysis here reads an instruction and says its bytes could have been
// better; here the bytes are fine and what is wrong is where they landed.
// Moving a jump off a boundary means inserting NOPs or prefixes *earlier*,
// which shifts everything after it, so the actionable advice is one build
// flag and not a rewrite: gas's -mbranches-within-32B-boundaries (that is,
// -malign-branch-boundary=32 -malign-branch=jcc+fused+jmp), LLVM's flag of
// the same name, Go's assembler (padJump in
// src/cmd/internal/obj/x86/asm6.go, on for compiler output and off for
// hand-written assembly), V8's Assembler::AlignForJCCErratum. So the report
// is one verdict for the whole binary, not a finding per site -- which is
// also the only honest shape, since 10-13% of the jumps in an unmitigated
// binary touch a boundary and no one of them is individually at fault.
//
// What makes the verdict sound without a calibrated threshold is that
// unmitigated code is exactly uniform with respect to the boundary. A jump of
// length L occupies [s, s+L-1] and touches a boundary precisely when
// s mod 32 >= 32 - L, which is L of the 32 residues: it contributes L/32
// expected witnesses, and the expectation for a whole scan is therefore its
// jump bytes over 32 -- an arithmetic null hypothesis, not a fitted one.
// Measured against it on 2026-09-26: bash, glibc, libcrypto, ld.so and libxul
// all land within 5% of the expectation (10.7-12.9% of their Jcc and JMP), a
// gas-mitigated object reports 0 of 2,366, and /bin/go reports 92 of 165,353
// against an expected 16,582, because Go pads what its compiler emits and not
// what its runtime hand-writes.
//
// The evidence is asymmetric, and the verdicts below are shaped accordingly:
// a single witness proves the mitigation did not cover the code that holds
// it, while the absence of witnesses means nothing until enough jumps have
// been examined for chance to have produced one.
typedef struct x86lint_jcc x86lint_jcc;

// What kind of transfer a tally counts. The verdict rests on COND and UNCOND
// alone: those are what every mitigation pads and their count is unambiguous.
// CALL and RET are padded by Go's assembler and not by gas, and which
// compare+Jcc pairs actually macro-fuse depends on the core and on operand
// shape -- an approximate predicate must not be allowed to manufacture a
// witness. Both are reported beside the verdict and neither decides it.
enum x86lint_jcc_kind {
    X86LINT_JCC_COND,     // Jcc -- XED's COND_BR, which also holds the LOOPs
                          // and JRCXZ that compilers do not emit
    X86LINT_JCC_UNCOND,   // JMP, direct or indirect
    X86LINT_JCC_CALL,     // CALL, direct or indirect
    X86LINT_JCC_RET,      // RET
    // A macro-fusible compare immediately followed by a Jcc, measured as one
    // unit because the pair can straddle a boundary when neither instruction
    // does. Its Jcc is also counted under X86LINT_JCC_COND.
    X86LINT_JCC_FUSED,
};

#define X86LINT_JCC_KINDS (X86LINT_JCC_FUSED + 1)

enum x86lint_jcc_verdict {
    // No jumps, or too few for the absence of witnesses to mean anything.
    X86LINT_JCC_UNKNOWN,
    X86LINT_JCC_MITIGATED,  // no witness, over a scan large enough to expect one
    X86LINT_JCC_PARTIAL,    // witnesses, but far below what chance predicts:
                            // some of the code was padded and some was not,
                            // which is what a mixed link looks like -- and
                            // what Go's own binaries look like
    X86LINT_JCC_ABSENT,     // witnesses at the rate chance predicts
};

x86lint_jcc *x86lint_jcc_create(void);
void x86lint_jcc_destroy(x86lint_jcc *jcc);

// Linear-sweep decode of `len` bytes, tallying every transfer by kind and by
// whether it touches a 32-byte boundary. An undecodable byte is skipped and
// the sweep resyncs, tallied like the lint scan's skipped count.
//
// `vaddr` must be the address inst[0] will hold when it runs, since the
// boundaries are absolute: a linked executable's sh_addr (a PIE's load bias
// is page-aligned, so it cannot change any address mod 32), or the real
// address a JIT reported for its code. An ordinary relocatable object's
// section satisfies this only if the section is at least 32-byte aligned,
// which gas raises .text to precisely so that the padding it just inserted
// survives the link; below that the linker may place the section at 16 mod 32
// and half the analysis is wrong. Deciding that is the caller's job.
void x86lint_jcc_scan(x86lint_jcc *jcc, const uint8_t *inst, size_t len,
                      uint64_t vaddr);

// Print the audit: the scope, the witnesses against the expectation, the
// verdict, and the classes that do not decide it. Returns what
// x86lint_jcc_findings would.
int x86lint_jcc_print(const x86lint_jcc *jcc, enum x86lint_target target,
                      bool verbose);

// The findings this audit contributes: 1 when the mitigation is missing and
// `target` is a core that has the erratum, 0 otherwise. The erratum is one
// named group of cores, which makes this the only place a -t value decides
// whether something is a finding at all rather than which rewrite is worth
// making -- -t skylake is what turns the audit into something a build can fail
// on. Every other target leaves it informational, the conservative GENERIC
// default included: GENERIC assumes every penalty applies, and applied here
// that would fail every binary on a system that may never run on an affected
// core.
int x86lint_jcc_findings(const x86lint_jcc *jcc, enum x86lint_target target);

enum x86lint_jcc_verdict x86lint_jcc_verdict(const x86lint_jcc *jcc);

size_t x86lint_jcc_count(const x86lint_jcc *jcc, enum x86lint_jcc_kind kind);
size_t x86lint_jcc_touching(const x86lint_jcc *jcc,
                            enum x86lint_jcc_kind kind);
size_t x86lint_jcc_instructions(const x86lint_jcc *jcc);
size_t x86lint_jcc_skipped(const x86lint_jcc *jcc);

// Witnesses expected in the verdict's scope if the code were laid out with no
// regard to the boundary: the scope's jump bytes over 32 (see above), scaled
// by 100 so the caller needs no floating point.
uint64_t x86lint_jcc_expected_centi(const x86lint_jcc *jcc);

// A tally of how a binary's returns and indirect branches leave, for auditing
// whether it was built to route them through the Spectre-v2 and Retbleed
// thunks (the driver's -s). Opaque; NULL is accepted everywhere.
//
// A retpoline replaces an indirect branch with a call to a thunk that returns
// to the intended target, so the branch predictor never sees an indirect
// transfer to mistrain. A return thunk does the same for RET, which is what
// Retbleed and SRSO attack. Both are whole-build decisions --
// -mindirect-branch=thunk[-extern] and -mfunction-return=thunk[-extern] in
// GCC, -mretpoline in clang -- and both are verdicts here for the same
// reasons the JCC audit is: the transformation is not an encoding a peephole
// could suggest, no single unrouted return is at fault, and reported per site
// it would be one finding per return in the binary.
//
// The signal is as close to binary as this tool gets, and it is positive on
// both sides rather than inferred from absence. A routed build names the thunk
// -- in its relocations while it is still an object, in its symbol table once
// linked -- and contains none of the instruction the thunk replaces. Measured
// on Fedora's own kernel: amt.ko has **zero** RET in 150 functions, every exit
// a relocated `jmp __x86_return_thunk`, where /bin/bash has 3,032 RET and
// names no thunk at all.
//
// So the two errors are not alike here either, and the verdicts say so. A
// bare RET in an image that names a return thunk is a hole in a mitigation
// the build asked for -- hand-written assembly the conversion missed is
// exactly how that happens -- and is the only thing this audit reports as a
// finding. A binary that names no thunk never opted in, and saying so is
// describing a build rather than judging one: userspace does not use these,
// and there is no -t value that would change that, because what decides is
// what the binary *is* and not which CPU runs it.
typedef struct x86lint_thunk x86lint_thunk;

// Which transfer a tally counts, and whether it goes through a thunk.
enum x86lint_thunk_kind {
    X86LINT_THUNK_RET_BARE,         // a RET instruction
    X86LINT_THUNK_RET_ROUTED,       // a branch relocated against a return thunk
    X86LINT_THUNK_INDIRECT_BARE,    // an indirect CALL or JMP
    X86LINT_THUNK_INDIRECT_ROUTED,  // a branch relocated against an indirect thunk
};

#define X86LINT_THUNK_KINDS (X86LINT_THUNK_INDIRECT_ROUTED + 1)

// The two independent halves: a build can route its indirect branches and not
// its returns, which is what -mindirect-branch=thunk alone produces.
enum x86lint_thunk_axis {
    X86LINT_THUNK_RETURNS,
    X86LINT_THUNK_INDIRECT,
};

enum x86lint_thunk_verdict {
    X86LINT_THUNK_NONE,     // no transfer of the kind: nothing to judge
    X86LINT_THUNK_ROUTED,   // the image names a thunk and no bare transfer is left
    X86LINT_THUNK_PARTIAL,  // it names one and bare transfers remain: a hole
    X86LINT_THUNK_BARE,     // it names none; this build did not opt in
};

x86lint_thunk *x86lint_thunk_create(void);
void x86lint_thunk_destroy(x86lint_thunk *thunk);

// Linear-sweep decode of `len` bytes, counting the RETs and the indirect
// CALLs and JMPs -- the instructions a routed build does not contain. An
// undecodable byte is skipped and the sweep resyncs.
//
// `thunk_bodies`, when non-NULL, is one byte per byte of `inst`, nonzero
// inside a thunk's own code, and instructions there are decoded but not
// counted. That exclusion is not a refinement, it is required for the audit
// to mean anything: a thunk necessarily contains the instruction it exists to
// replace -- a retpoline ends in `jmp *%rax`, and a return trampoline in a
// RET -- so an image that defines its thunks rather than importing them would
// otherwise always report a hole, and the one it reported would be the
// mitigation itself. Only the container can say where they are.
void x86lint_thunk_scan(x86lint_thunk *thunk, const uint8_t *inst, size_t len,
                        const uint8_t *thunk_bodies);

// The evidence the bytes cannot carry, since a thunk is named rather than
// spelled: how many branches a relocation routes to each family, and whether
// the image names a thunk of each at all. The counts are exact only while the
// object is relocatable; a linked image has resolved them into ordinary
// direct branches, and the presence flags carry the verdict there.
void x86lint_thunk_set_evidence(x86lint_thunk *thunk, size_t routed_returns,
                                size_t routed_indirects, bool returns_named,
                                bool indirects_named);

// Print the audit: each axis's counts, its verdict, and what the verdict
// rests on. Returns what x86lint_thunk_findings would.
int x86lint_thunk_print(const x86lint_thunk *thunk, bool verbose);

// 1 when either axis is PARTIAL -- a mitigation the build asked for with a
// hole left in it -- and 0 otherwise. A BARE verdict is never a finding: see
// the block comment above.
int x86lint_thunk_findings(const x86lint_thunk *thunk);

enum x86lint_thunk_verdict x86lint_thunk_verdict(const x86lint_thunk *thunk,
                                                 enum x86lint_thunk_axis axis);

size_t x86lint_thunk_count(const x86lint_thunk *thunk,
                           enum x86lint_thunk_kind kind);
size_t x86lint_thunk_instructions(const x86lint_thunk *thunk);

// How many instructions the copy folds -- missing APX NDD and MOV+ADD
// foldable to LEA, which divide the same pairs by flag liveness -- may
// examine, counting the copy and its consumer: 2 matches only adjacent
// pairs, 3 sees through one independent instruction between them, and so
// on. Overridable at build time (-DAPX_NDD_WINDOW=16) to measure other
// widths; soundness never depends on the value -- every instruction looked
// through must prove independence (see apx_ndd_gap_independent in
// x86lint.c) -- and neither, measurably, does scan time. The default of 8
// is the measured knee: one gap captures about half of the non-adjacent
// population, window 8 nearly all of it (96-99% of the window-16 ceiling
// on bash/git/glibc/libcrypto), and consumers further out essentially do
// not occur. Lives here rather than in x86lint.c so the tests can size
// their window fixtures' expectations to the build's value.
#ifndef APX_NDD_WINDOW
#define APX_NDD_WINDOW 8
#endif

// return number of failed checks. An undecodable byte is not fatal: linear
// sweep skips it and resyncs (executable sections routinely embed data).
// Skipped bytes are only tallied into the summary, never printed -- a stripped
// binary with data in its code section can skip hundreds of thousands of
// bytes. In verbose mode each finding is printed as a one-line summary
// followed by its offending encoding; otherwise nothing is printed per finding
// (the caller's summary is the whole report). vaddr is the address of
// inst[0], added to finding offsets when attributing them against the
// summary's installed function table (pass 0 when addresses do not
// matter). If summary is non-NULL, every finding is tallied into it by
// type and function and the decoded-instruction and skipped-byte counts
// are accumulated. extensions is a bitwise OR of
// enum x86lint_extensions values; 0 restricts the scan to baseline x86-64
// checks. target names the microarchitecture being tuned for, which decides
// the rewrites whose worth is per-core rather than universal;
// X86LINT_TARGET_GENERIC assumes every documented penalty applies. classes
// is a bitwise OR of enum x86lint_classes values saying which kinds of
// finding to report; X86LINT_CLASS_REWRITE alone is the verified-rewrite
// scan. If on_finding is non-NULL it is invoked once per finding with ctx
// as its first argument; it is independent of both summary and verbose, so a
// consumer wanting only the per-finding stream passes NULL for the summary
// and false for verbose.
int check_instructions(const uint8_t *inst, size_t len, uint64_t vaddr,
                       bool verbose, x86lint_summary *summary,
                       uint32_t extensions, enum x86lint_target target,
                       uint32_t classes, x86lint_finding_fn on_finding,
                       void *ctx);

#endif
