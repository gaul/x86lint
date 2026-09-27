# x86lint

x86lint examines x86-64 machine code to find suboptimal encodings and sequences.
For example, `add eax, 1` can encode with either an 8- or 32-bit immediate:

```
83C0 01
81C0 01000000
```

Using the former can result in smaller and faster code.  x86lint can help
compiler writers generate better code and documents the complexity of x86.

## Design and soundness model

x86lint is a peephole analyzer. It walks the machine code in a single linear
sweep -- decoding one instruction at a time in 64-bit long mode with Intel
XED, with every instruction set XED knows enabled (XED_CHIP_ALL), so a
chip-gated encoding like LZCNT decodes as itself rather than as its legacy
alias (BSR under a stray REP prefix) -- and matches each decoded instruction
against a table of checks, every
one recognizing a single suboptimal encoding by its opcode, operands, and
immediate. Matching works on XED's decoded form, so aliases and alternate
encodings of the same operation are all caught. Most checks inspect a single
instruction; a few peepholes match a short window of adjacent instructions --
like its AArch64 sibling [armlint](https://github.com/gaul/armlint) -- such as
a redundant test folded into the flag-setting ALU before it or a LEA folded
into the memory operand after it. The soundness gates below then look a bounded
distance forward (and, for the 32-bit identity rewrites, one instruction back)
to prove a flag or register value dead.

**Linear sweep with resync.** Executable sections routinely interleave data
with code -- jump tables, alignment islands, GHC info tables, Go's
BoringCrypto signature. When XED cannot decode the bytes at the cursor,
x86lint skips a single byte and resynchronizes instead of abandoning the rest
of the section. Skipped bytes are counted (`x86lint_summary_skipped`) so that
partial coverage of a data-laden region is not mistaken for a clean scan.

A first pass over the same sweep also collects every direct branch and call
target. A multi-instruction peephole rewrites a *window* of instructions,
which is sound only if control cannot enter the window's interior -- an
incoming edge executes just the tail. The canonical trap is the scan loop
`mov rbx, rax ; L: add rbx, 1 ; cmp byte [rbx], '-' ; je L` (this exact shape
appears in bash and git), where folding the pair into `lea rbx, [rax + 1]`
would turn the loop increment into a per-iteration reset. Each
multi-instruction finding is therefore suppressed when a collected target
lands inside its window; a target on the window's head is fine, since that
edge executes the whole pattern. An `ENDBR64` is marked as a target too:
under IBT it is the only place an indirect branch may land, so it is the
binary's own declaration of an incoming edge -- the one indirect edge the
sweep can see -- and a window it sits inside is suppressed like any other.
Edges the sweep cannot see -- indirect branches in code without landing pads,
`notrack` jump tables, entries from another section -- remain a residual risk
of judging raw bytes, accepted and documented here.

**Soundness over recall.** For a tool that suggests code changes, a false
positive -- flagging an instruction whose replacement would change behavior --
is the worst failure, so every check errs toward false negatives: a missed
opportunity is cheaper than a wrong one. Most rewrites are unconditionally
equivalent (a shorter immediate, a dropped REX prefix, `movaps` for `movdqa`)
and need no further proof. But two side effects are invisible in the lone
instruction and would make an otherwise-redundant rewrite unsound if a later
instruction observed them; each is guarded by a bounded forward scan (up to 16
instructions) starting at the successor.

* **Flag liveness.** Some rewrites change which flags an instruction writes:
  `mov eax, 0` -> `xor eax, eax` saves bytes but clobbers the arithmetic flags
  `mov` left untouched, and `add [rbx], 1` -> `inc [rbx]` reproduces every flag
  except CF, which `add` writes and `inc` leaves alone. The rewrite is sound
  only when the affected flags are dead, so a check declares the flags it
  perturbs (`flag_concerns`) and `flags_live_after` suppresses the finding if
  any is read before being overwritten. A `RET` ends the scan as dead --
  neither the SysV nor Win64 ABI preserves flags across a call -- while a
  branch, call, or interrupt whose path the scan cannot follow ends it
  conservatively live.

  The model covers CF, PF, ZF, SF and OF. AF is deliberately outside it, and
  three rewrites do diverge there, each replacing an instruction that defines
  AF with one that leaves it undefined: `CMP reg, 0` and `ADD reg, 0` to
  `TEST reg, reg`, and `SUB reg, reg` to `XOR reg, reg`. Nothing gates them,
  because `flag_concerns` has no bit for AF and adding one would suppress
  findings on a flag that 64-bit code cannot read without `LAHF` or `PUSHF`
  and that no compiler emits a dependence on. Recorded rather than assumed:
  the divergence is real, it runs toward *undefined*, and it is accepted.
  The reverse direction is harmless and appears once, in `SHL reg, 1` to
  `ADD reg, reg`, which gives AF a definition the shift did not have.

* **Register (upper-32) liveness.** Writing a 32-bit register zero-extends
  into the upper half of its 64-bit parent, so a 32-bit identity operation
  whose rewrite writes nothing -- `mov eax, eax` removed; `add eax, 0`,
  `or eax, eax`, or `and eax, -1` turned into `test`; `shl eax, 0` removed
  (hardware zero-extends even at count 0, whatever the SDM's count-0
  pseudocode suggests) -- is redundant only when that zero-extension is dead.
  This is not hypothetical: GCC emits `and ebx, -1` as a fused
  zero-extend-and-test whose full 64-bit register is read right after the
  branch, so the ungated rewrite would corrupt it. A check names the 64-bit
  register at stake (`reg_concern`) and `reg_upper32_live_after` suppresses
  the finding if bits 63:32 are read -- as an explicit operand or a memory
  base/index -- before an unconditional 32- or 64-bit write redefines them.
  Here `RET` is conservatively live: the value can escape as a return value
  or in a callee-saved register, which a linear walk cannot rule out. One
  backward escape reinstates the finding: when the immediately preceding
  instruction already zero-extended the register, the identity op changes
  nothing regardless of downstream reads. The escape holds only if every
  path to the instruction runs through that predecessor, so a direct branch
  targeting the instruction itself -- arriving with unknown upper bits --
  cancels it. The escape is licensed per check, because it is sound only for
  rewrites that *delete* the write: narrowing `lea rax, [...]` to
  `lea eax, [...]` (oversized LEA width) still writes the register, swapping
  the address's upper half for zeros, so a predecessor's zeroing of the
  destination -- overwritten either way -- proves nothing, and that check
  runs the forward gate alone. The boundary also parameterizes: the merging
  narrow move check runs the same walk at bit 8 or 16
  (`reg_bits_above_live_after`), where a high-byte register read observes
  bits 15:8 and a same-register 32/64-bit XOR or SUB counts as the kill it
  is rather than the read XED records -- compilers end a value's life with
  exactly that idiom.

Both scans share one bias: reads count inclusively and redefinitions
exclusively, so every uncertainty -- a decode error, an unfollowable branch,
running past the 16-instruction window, or the end of the buffer -- resolves
toward *live*, and thus toward suppressing the finding. A branch ends the walk
at that conservative answer, so the analysis stays within a basic block: it
never suggests a rewrite whose soundness would hinge on a fact about a branch
target it cannot see. The one boundary it reads through is a function return,
and only for flags -- the ABI guarantees they do not survive it.

## Implemented analyses

Each row links to its full description -- the encoding or sequence it
matches, what the rewrite saves, and the soundness argument that licenses
it -- in [analyses.md](analyses.md). Candidate checks not yet implemented,
with the corpus populations that argue for or against each, live in
[TODO.md](TODO.md).

| Analysis | Rewrite |
| --- | --- |
| [ADD foldable into LEA](analyses.md#add-foldable-into-lea) | one `LEA` carrying the ADD's term, where the result stays within two components |
| [ADD foldable into memory](analyses.md#add-foldable-into-memory) | fold the pointer arithmetic into the consumer's `base+index*scale+disp` |
| [AVX-SSE transition](analyses.md#avx-sse-transition) | `VZEROUPPER` after the last 256-bit use, or the VEX spelling of the SSE code |
| [branch to the next instruction](analyses.md#branch-to-the-next-instruction) | delete; control arrives there either way |
| [CAS loop foldable into LOCK op](analyses.md#cas-loop-foldable-into-lock-op) | `LOCK OR`/`AND`/`XOR` |
| [constant condition after immediate](analyses.md#constant-condition-after-immediate) | delete the compare; the `Jcc`/`CMOVcc`/`SETcc` reading it has one outcome |
| [constant condition after zeroing](analyses.md#constant-condition-after-zeroing) | same, the tested register being provably zero at any width |
| [IBT-bypassing NOTRACK call](analyses.md#ibt-bypassing-notrack-call) | review item: a deliberately untracked forward edge, not a rewrite |
| [LEA foldable into memory](analyses.md#lea-foldable-into-memory) | fold the address into the consumer's memory operand |
| [length-changing prefix stall](analyses.md#length-changing-prefix-stall) | 32-bit operands; advisory, and the imm8 narrowing removes it by itself |
| [load foldable into ALU](analyses.md#load-foldable-into-alu) | `ADD reg, [mem]` and the rest of the two-operand forms |
| [load foldable into compare](analyses.md#load-foldable-into-compare) | `CMP [mem], imm` / `TEST` |
| [load foldable into extend](analyses.md#load-foldable-into-extend) | `MOVZX`/`MOVSX reg, byte [mem]` |
| [load foldable into vector op](analyses.md#load-foldable-into-vector-op) | fold the load into the SIMD instruction's source operand |
| [load foldable into vector transfer](analyses.md#load-foldable-into-vector-transfer) | `MOVD`/`MOVQ`/`CVTSI2SD xmm, [mem]` |
| [NEG foldable into ADD/SUB](analyses.md#neg-foldable-into-addsub) | `SUB`/`ADD` of the original |
| [missing ANDN (only with `-m bmi1`)](analyses.md#missing-andn-only-with--m-bmi1) | `ANDN` |
| [missing APX NDD (only with `-m apx`)](analyses.md#missing-apx-ndd-only-with--m-apx) | the EVEX new-data-destination form, dropping the copy |
| [missing APX SETZU (only with `-m apx`)](analyses.md#missing-apx-setzu-only-with--m-apx) | the zero-upper `SETcc`, dropping the `MOVZX` |
| [missing BLSI (only with `-m bmi1`)](analyses.md#missing-blsi-only-with--m-bmi1) | `BLSI` |
| [missing BLSMSK (only with `-m bmi1`)](analyses.md#missing-blsmsk-only-with--m-bmi1) | `BLSMSK` |
| [missing BLSR (only with `-m bmi1`)](analyses.md#missing-blsr-only-with--m-bmi1) | `BLSR` |
| [missing MOVBE (only with `-m movbe`)](analyses.md#missing-movbe-only-with--m-movbe) | `MOVBE` |
| [missing MULX (only with `-m bmi2`)](analyses.md#missing-mulx-only-with--m-bmi2) | `MULX`, dropping the move out of the fixed register |
| [missing POPCNT dependency break](analyses.md#missing-popcnt-dependency-break) | insert `XOR dst, dst` ahead of it |
| [missing SSE dependency break](analyses.md#missing-sse-dependency-break) | insert `XORPS dst, dst` ahead of it |
| [stale VEX merge operand](analyses.md#stale-vex-merge-operand) | name the data source, or a dead register, as the merge operand |
| [merging scalar move](analyses.md#merging-scalar-move) | `MOVAPS` |
| [merging narrow move](analyses.md#merging-narrow-move) | `MOVZX`, or `MOVSX` where the sign is wanted |
| [missing SHLX/SHRX/SARX (only with `-m bmi2`)](analyses.md#missing-shlxshrxsarx-only-with--m-bmi2) | `SHLX`/`SHRX`/`SARX`, which write no flags |
| [MOV constant foldable](analyses.md#mov-constant-foldable) | fold the constant into the consumer's immediate |
| [MOV+ADD foldable to LEA](analyses.md#movadd-foldable-to-lea) | one non-destructive `LEA` |
| [OR foldable into memory (only with `-m v8`)](analyses.md#or-foldable-into-memory-only-with--m-v8) | fold V8's decompressed pointer into the consumer's addressing mode |
| [oversized ADD/SUB 128](analyses.md#oversized-addsub-128) | the imm8 form of the opposite operation |
| [oversized ADD/SUB one](analyses.md#oversized-addsub-one) | `INC`/`DEC`, while CF is dead |
| [oversized branch displacement](analyses.md#oversized-branch-displacement) | the rel8 form |
| [oversized displacement](analyses.md#oversized-displacement) | the disp8 form |
| [oversized EVEX encoding](analyses.md#oversized-evex-encoding) | the VEX encoding of the same operation |
| [oversized immediates](analyses.md#oversized-immediates) | the sign-extended imm8 form |
| [oversized LEA width](analyses.md#oversized-lea-width) | drop the REX.W, while bits 63:32 are dead |
| [oversized MOV encoding](analyses.md#oversized-mov-encoding) | the `B8+r` immediate-to-register form |
| [oversized TEST immediate](analyses.md#oversized-test-immediate) | `TEST AL, imm8` |
| [oversized VEX encoding](analyses.md#oversized-vex-encoding) | the two-byte VEX prefix |
| [oversized XCHG encoding](analyses.md#oversized-xchg-encoding) | the one-byte `90+r` accumulator form |
| [redundant ADD/SUB zero](analyses.md#redundant-addsub-zero) | `TEST`, or remove |
| [redundant CMOVcc reg, reg](analyses.md#redundant-cmovcc-reg-reg) | remove; a conditional move onto itself |
| [redundant AND immediate](analyses.md#redundant-and-immediate) | `TEST reg, reg` |
| [redundant bit-scan default](analyses.md#redundant-bit-scan-default) | delete the MOV; needs `-t skylake` or later |
| [redundant MOV constant](analyses.md#redundant-mov-constant) | delete; the destination already holds it |
| [redundant MOV reg, reg](analyses.md#redundant-mov-reg-reg) | remove |
| [redundant OR/XOR zero](analyses.md#redundant-orxor-zero) | `TEST`, or remove |
| [redundant zero-extension](analyses.md#redundant-zero-extension) | drop it; the producer already zeroed those bits |
| [redundant re-extension](analyses.md#redundant-re-extension) | remove the second extension |
| [redundant shift/rotate by zero](analyses.md#redundant-shiftrotate-by-zero) | remove |
| [redundant TEST after flags](analyses.md#redundant-test-after-flags) | delete the `TEST`; the ALU before it already set the flags |
| [redundant TEST after SETcc](analyses.md#redundant-test-after-setcc) | branch on the compare's flags directly |
| [redundant TEST after shift](analyses.md#redundant-test-after-shift) | branch on the shift's flags directly |
| [redundant TEST immediate](analyses.md#redundant-test-immediate) | `TEST reg, reg` |
| [shift pair foldable into extend](analyses.md#shift-pair-foldable-into-extend) | `MOVSX`/`MOVZX` |
| [rematerialized constant](analyses.md#rematerialized-constant) | `MOV rD, rS`; needs `-t skylake` or `-t zen` |
| [suboptimal AND immediate](analyses.md#suboptimal-and-immediate) | `MOVZX` |
| [suboptimal AND zero](analyses.md#suboptimal-and-zero) | `XOR reg, reg` |
| [suboptimal CMP zero](analyses.md#suboptimal-cmp-zero) | `TEST reg, reg` |
| [suboptimal CMP one](analyses.md#suboptimal-cmp-one) | `TEST reg, reg` with the equality branch |
| [suboptimal IMUL constant](analyses.md#suboptimal-imul-constant) | `LEA`, `SHL`, `MOV`, `NEG` or `XOR`, by the multiplier |
| [suboptimal lane-0 extract](analyses.md#suboptimal-lane-0-extract) | `MOVD`/`MOVQ`/`MOVSS` |
| [suboptimal LEA](analyses.md#suboptimal-lea) | `MOV`, or `ADD` while the flags are dead |
| [suboptimal MOV zero](analyses.md#suboptimal-mov-zero) | `XOR reg, reg`, while the flags are dead |
| [suboptimal OR/AND reg, reg](analyses.md#suboptimal-orand-reg-reg) | `TEST reg, reg` |
| [suboptimal SETcc inversion](analyses.md#suboptimal-setcc-inversion) | the complementary `SETcc` |
| [suboptimal SETcc zero-extension](analyses.md#suboptimal-setcc-zero-extension) | zero the register ahead of the flag-setter; advisory |
| [suboptimal SHL one](analyses.md#suboptimal-shl-one) | `ADD reg, reg` |
| [suboptimal SSE MOV opcode](analyses.md#suboptimal-sse-mov-opcode) | `MOVAPS`/`MOVUPS` |
| [suboptimal SSE zero idiom](analyses.md#suboptimal-sse-zero-idiom) | `XORPS` |
| [suboptimal SUB reg, reg](analyses.md#suboptimal-sub-reg-reg) | `XOR reg, reg`, which every core recognizes as independent |
| [suboptimal XOR immediate](analyses.md#suboptimal-xor-immediate) | `NOT`, while the flags are dead |
| [unneeded explicit immediate](analyses.md#unneeded-explicit-immediate) | the implied-operand form |
| [unneeded explicit register](analyses.md#unneeded-explicit-register) | the accumulator form |
| [unneeded LOCK prefix on XCHG](analyses.md#unneeded-lock-prefix-on-xchg) | drop the prefix; `XCHG` with memory is already atomic |
| [unneeded MOVSX](analyses.md#unneeded-movsx) | `CWDE`/`CBW` |
| [unneeded MOVSXD](analyses.md#unneeded-movsxd) | `CDQE` |
| [unneeded REP prefix on RET](analyses.md#unneeded-rep-prefix-on-ret) | drop the prefix |
| [unneeded REX prefix](analyses.md#unneeded-rex-prefix) | drop the prefix |
| [unneeded SIB byte](analyses.md#unneeded-sib-byte) | the plain modrm form |
| [unneeded zero displacement](analyses.md#unneeded-zero-displacement) | drop the displacement |
| ~~suboptimal NOP sequence~~ | multiple `90` instead of a single `66 90`; never implemented, see [#9](https://github.com/gaul/x86lint/issues/9) |

## Compilation

First install the Intel x86 encoder decoder:

```
git clone https://github.com/intelxed/xed.git xed
git clone https://github.com/intelxed/mbuild.git mbuild
cd xed
./mfile.py install --install-dir=kits/xed-install
```

Next build x86lint:

```
git clone https://github.com/gaul/x86lint.git x86lint
cd x86lint
XED_PATH=/path/to/xed make all
```

Run the unit suite and the ELF-driver smoke test with
`XED_PATH=/path/to/xed make check`.

The suite has three layers. `x86lint_test.c` assembles byte sequences and
asserts the exact category and total each one produces, which is where a
check's soundness gates are pinned. `driver_test.sh` builds small ELF fixtures
with the system toolchain and asserts one stated fact per line about the
report: what each flag turns on, which exit code a path returns, what `--json`
must not contain. The same script then snapshots each fixture's whole report
into `snapshots/`, which catches everything the assertions do not name --
column widths, ordering, a stray extra finding, a count on a line nobody wrote
a grep for. Values the linker chooses (section index, load address, sample and
target addresses) are normalized away so the files are portable. Rewrite them
with `XED_PATH=/path/to/xed make snapshots` and read the diff: a change you can
explain is a new check or a deliberate edit, and one you cannot is the
regression the layer exists to catch. The script never skips itself; an
environment that cannot build the fixtures exits 2, because a skip that exits 0
is indistinguishable from a pass.

## Usage

x86lint is intended to be part of compiler test suites, which should
`#include "x86lint.h"` and link `libx86lint.a`. Pass the just-emitted machine
code to `check_instructions`; its return value is the number of opportunities
found, which a test can assert is zero:

```c
#include "x86lint.h"

// inst/len: the x86-64 bytes to check (e.g. a function the compiler just
// emitted). Returns the opportunity count (0 == clean). An undecodable byte
// is skipped and the scan resyncs rather than failing, since executable input
// can interleave data with code.
int lint(const uint8_t *inst, size_t len)
{
    xed_tables_init();
    return check_instructions(inst, len, /*vaddr=*/0, /*verbose=*/false,
                              /*summary=*/NULL, /*extensions=*/0,
                              /*on_finding=*/NULL, /*ctx=*/NULL);
}
```

The optional `summary` accumulates a by-type tally across one or more runs
(`x86lint_summary_create` / `_print` / `_destroy`; pass `NULL` to skip it),
and `verbose` controls whether each opportunity is printed as it is found.
`x86lint_summary_skipped` reports how many undecodable bytes were skipped, so
incomplete coverage of a data-laden section is not mistaken for a clean scan.
`extensions` is a bitwise OR of `enum x86lint_extensions` values
(`X86LINT_EXT_BMI1`, `X86LINT_EXT_BMI2`) declaring which instruction-set
extensions the code's target supports; checks that suggest an instruction
from one of those sets run only when its bit is enabled, and 0 keeps the scan
to baseline x86-64.

The optional `on_finding` callback is called once per opportunity, with `ctx`
as its first argument, the finding's name, the absolute address of the
offending instruction (the `vaddr` argument plus the finding's offset), and
that instruction's decoded form and raw encoding. Where the summary answers
"how many of each kind", the callback answers "which instruction, at what
address" -- the form needed to join findings against anything else keyed by
address, such as an execution profile that weights each opportunity by how
often the instruction it names actually runs. It is independent of both
`summary` and `verbose`, so a consumer wanting only the per-finding stream
passes `NULL` for the summary and `false` for verbose. The driver's `--json`
mode is built on it.

x86lint can also read arbitrary 64-bit ELF executables directly. When the
binary kept its symbol table (`.symtab`), the scan is restricted to the byte
ranges of its function symbols: executable sections routinely interleave
non-code that *decodes* cleanly -- GHC info tables, LLVM's constexpr tables,
jump tables -- which linear sweep would otherwise report pseudo-instruction
findings from, and which the undecodable-bytes counter cannot flag. Excluded
bytes are tallied into that skipped count, and a summary line reports the
restriction; pass `-a` to scan every byte anyway. The dynamic symbol table is
never used for this -- it survives stripping but lists only exports, and
scanning just those would silently miss almost all code -- so stripped
binaries scan whole sections exactly as before. An unsized assembly label
extends to the next function's start, keeping coverage conservative.

An instruction whose bytes a relocation will rewrite is excluded whatever the
symbols say, because its immediate or displacement is not a value. It is zero,
or a bare addend, waiting for the linker, and a peephole that reads one is
reasoning about a number that will not be there at run time. Two findings on
a Fedora kernel module show the stakes: 143 relocated `e9 00000000` -- every
return in a `-mfunction-return=thunk-extern` build -- whose rel32 placeholder
reads as a displacement that would fit `rel8`, and 132 `mov r64, imm32`
carrying `R_X86_64_32S`, where the shorter encoding the finding asks for
cannot express the sign-extended kernel address the linker is about to write.
Acting on either corrupts the relocation, which makes these worse than noise;
they were 275 of that module's 314 findings, and excluding them leaves 31.
The whole instruction goes, not the field, since an opcode with its immediate
cut out decodes as something else entirely -- so the exclusion also stops any
multi-instruction window from reasoning across a placeholder. A linked binary
has no relocations into `.text` (only `.rela.dyn` and `.rela.plt`, neither of
which names a target section), so this costs nothing there and the summary
line appears only when something was actually excluded.

The dynamic linker's import glue is skipped whatever the symbols say: the
ELF `.plt`, `.iplt` and `.plt.*` sections are emitted from a fixed template
by `ld`, so their shape is the dynamic-linking ABI's business and no source
change reaches it. The noise this removes is a constant: a lazy-binding PLT
entry pushes its relocation index with the 5-byte `push imm32`, so every
entry whose index fits a signed imm8 draws an oversized-immediate finding and
the count saturates at exactly 128 -- libstdc++ (1,105 PLT entries),
`/bin/bash` (236) and libcrypto (161) each reported those 128 plus 7
oversized branch displacements from the resolver jumps, 135 apiece regardless
of size, none of them fixable and all of them enough to fail the non-zero
exit a compiler test suite gates on. The exclusion is by section rather than
by symbol because the symbol restriction already hid it wherever `.symtab`
survived (glibc reported none) and could not where it did not, so the noise
appeared only on stripped binaries -- which is how a distro library is
usually scanned. `-a` keeps its contract and scans the glue too, for anyone
auditing a linker rather than a compiler. The `-e` verification is a separate
pass and deliberately unaffected: PLT entries really are indirect-branch
targets under IBT, so whether they carry landing pads is the one thing about
them worth checking. armlint excludes the same family, adding Mach-O's
`__stubs`, `__stub_helper` and `__objc_stubs`.

By default x86lint prints only a summary -- the opportunities grouped by type
and sorted by prevalence -- followed by a total and the number of
instructions scanned:

```console
$ ./x86lint /bin/ls
Optimization opportunities by type:
     169  oversized ADD/SUB one
     105  oversized immediate
       8  oversized branch displacement

282 optimization opportunities in 22705 instructions
```

Pass `-v` to also print each opportunity -- its one-line disassembly plus the
offending encoding -- ahead of the summary:

```console
$ ./x86lint -v /bin/ls
== section 5 .text: vaddr 0x2100, 1077514 bytes ==
oversized immediate at offset: 0x14: push 0x0
  68 00 00 00 00
...
```

Offsets are relative to the section being scanned, so the banner names each
one and gives the address to add to place a finding in a disassembly. A
binary can hold several executable sections -- a BOLT-processed library keeps
the functions it did not move in `.bolt.org.text` beside those it moved into
`.text` -- and without the banner their offsets are indistinguishable.

When the binary kept its symbols, findings are also attributed to the
function that holds them: each `-v` line gains a `(name+0xoff)` suffix
that jumps straight to the site in a disassembler, and the summary adds
a by-function companion table -- the top ten offenders, the tail summed
into a residue line -- so a whole-binary count reads as "and here is
where to start":

```console
Optimization opportunities by function:
     356  __strcasecmp_l_sse2
     356  __strncasecmp_l_sse2
     252  __strcmp_sse2
     ...
   49334  in 32480 more functions
```

Attribution uses sized function symbols only; a finding in code reached
through an unsized assembly label lands in an honest
`outside every function range` row rather than the wrong neighbor.

Pass `-f NAME` to restrict the scan to the one function named NAME --
"lint just this function". Unlike the default restriction, `-f` also
draws on the dynamic symbol table, so naming an exported function of a
stripped library works; every sized symbol spelled NAME is scanned (a
versioned export like glibc's two `memcpy`s has several sites), and the
count line reflects only their instructions. `-f` combines with `-i`
for a per-function census; see that section.

Pass `-m bmi1`, `-m bmi2`, `-m movbe`, and/or `-m apx` to declare that the
binary's target supports those instruction-set extensions, enabling the
checks that suggest replacing a baseline sequence with an instruction from
that set (missing ANDN, missing BLSI, missing BLSMSK, missing BLSR, missing
SHLX/SHRX/SARX, missing MOVBE, missing APX NDD, missing APX
SETZU). These
are opt-in because the finding is only actionable when the target guarantees
the extension: a distro binary built for x86-64-v2 could not have used ANDN
however clear the opportunity, and inferring availability from the
surrounding bytes is unsound for binaries like glibc that keep baseline code
and CPU-dispatched BMI-rich variants in the same section. The flags are
independent, matching their CPUID feature bits: `-m bmi2` does not imply
`-m bmi1`.

`-m v8` is a knowledge bit rather than an ISA bit, and is armlint's flag
of the same name: it asserts a runtime invariant of the scanned code,
that R14 holds V8's pointer-compression cage base, which is 4 GB aligned
so its low 32 bits are zero. It enables OR foldable into memory, which is
unsound for arbitrary code and stays silent without it. Pass it when
scanning V8's JIT output or its embedded builtins; never for an ordinary
binary.

Pass `-t generic|sandybridge|skylake|icelake|zen|silvermont` to name the
microarchitecture the code is tuned for. This is a different axis from `-m`:
that says whether an encoding *exists* on the target, where `-t` says whether
a rewrite is *worth making* there, and several of x86lint's are not worth it
everywhere. The default, `generic`, assumes every documented penalty applies
at once, so it reports the rewrites that pay on every core and withholds the
ones that only sometimes do.

Four behaviours move with it, and they move in both directions:

* A **three-component LEA** costs 3 cycles on port 1 alone from Sandy Bridge
  through Cascade Lake, where each two-component form is 1 cycle on two
  ports, so folding a fast LEA and an ADD into a slow one trades a cycle for
  three or four bytes. Agner Fog's tables give Ice Lake and Tiger Lake no
  separate row for the three-component form, and Zen 3 through Zen 5 two
  cycles as two ops, which is what the pair already costs. On libxul,
  `-t icelake` takes "ADD foldable into LEA" from **2,678 findings to
  28,064**: 25,386 sound folds that the default is right to withhold and a
  modern target is right to want.
* **POPCNT's destination is a phantom input** from Sandy Bridge through
  Cascade Lake and not after, so on `icelake` and `zen` the dependency-break
  check goes silent rather than advising an XOR that is pure cost. That is
  6,431 findings on libxul the default reports and Ice Lake does not.
* The **length-changing prefix stall** applies to MOV on the Pentium 4
  through Nehalem, not on Sandy Bridge through Skylake, and again from Ice
  Lake. MOV is most of what that check fires on -- 92% of the findings on
  librustc_driver -- so on a Sandy-Bridge-through-Skylake target the bulk of
  its output was reporting a cost that is not paid. The arithmetic and logic
  forms pay on every Intel big core and are never gated.
* **SUB r, r is recognized as a zeroing idiom** independent of its input
  everywhere except the low-power line, where "SUB, SBB and CMP instructions
  are not recognized in this way" (Agner Fog). The rewrite to XOR therefore
  fires under `generic` and `silvermont` and nowhere else.

`sandybridge` and `skylake` currently differ in no gated behaviour and are
named separately because they differ on an axis no check reads yet: the
bit-scan false dependency ends at Broadwell where POPCNT's runs to Cascade
Lake. An unknown name is a usage error rather than a silent fallback to the
default, since a typo that quietly changed which findings appear would be
worse than a refusal.

Pass `-c advisory`, `-c security` or `-c all` to report kinds of finding the
default scan withholds. Most checks state a verified byte-level rewrite: the
replacement is equivalent, the tool proved the conditions, and applying it is
mechanical. Those are the default, and they are what makes a non-zero exit
mean "there is something here to fix". Two other kinds do not fit that
description and were, until now, reported beside them as though they did.

* **advisory** is a real improvement whose fix the tool cannot verify or
  cannot even see. The SETcc zero-extension's rewrite belongs upstream of the
  flag-setter, whose surroundings a peephole cannot prove safe; the
  length-changing prefix stall's clean fix is 32-bit operands, which needs
  upper-16 liveness this tool does not track. Both said so in their own
  documentation before they had a class to sit in. A build should not fail on
  advice the tool cannot check.
* **security** is not a rewrite at all. The IBT-bypassing NOTRACK call is a
  review item, since dropping the prefix without padding the target trades
  the bypass for a `#CP` fault, so the reader is being asked to look rather
  than to patch. armlint keeps the same kind behind its own opt-in flag,
  `-a pac`.

The bits are independent, so advisories can be asked for without review items
or the other way round, and an unknown name is a usage error rather than a
silent default. Enabling a class makes its findings count like any other,
exit status included: you asked for them. On glibc the default scan reports
7,130 findings and `-c advisory` reports 7,464, the difference being 194
SETcc zero-extensions and 140 prefix stalls.

One finding changes class rather than appearing: under `-m apx` the SETcc
pair is reported as "missing APX SETZU" instead, and that *is* a verified
rewrite -- the zero-upper form replaces the pair in place -- so it stays in
the default scan.

Pass `--json` to replace the human report with the findings as a JSON
document, one object per line inside a `findings` array:

```console
$ ./x86lint --json /bin/ls
{"file": "/bin/ls",
  "findings": [
    {"vaddr": 8468, "check": "oversized immediate", "section": ".text", "length": 5, "bytes": "6800000000", "text": "push 0x0"},
    ...
  ],
  "instructions": 22705,
  "skipped": 0,
  "opportunities": 282
}
```

`vaddr` is the offending instruction's **absolute** address -- not the
section-relative offset `-v` prints -- and is a number rather than a hex
string so that it composes with arithmetic. That is the point of the mode:
findings become joinable against anything else keyed by address, and the
join worth making is an execution profile, which turns a static count of
opportunities into a dynamic one. How often a compiler *emits* a suboptimal
encoding is a poor proxy for what it costs; one inside an interpreter
dispatch loop outweighs thousands in cold initialization code, and only a
profile can tell the two apart. `function` and `function_offset` appear when
the binary kept symbols to attribute against, and `restriction` carries what
narrowed the scan -- `{"symbols": N}` by default, `{"function": ..., "sites":
N, "bytes": N}` under `-f`, and absent under `-a` -- so that a partial scan
is not read as a clean sweep of the whole file.

Findings are written as they are found rather than collected first, so a
large binary streams instead of accumulating tens of thousands of objects in
memory; the totals close the document because the scan only knows them then.
Section and symbol names are copied from the file verbatim, so a binary whose
string tables are not UTF-8 yields strings that are not either. The exit
status is unchanged, and a file the driver rejects leaves stdout empty rather
than half a document. `--json` describes the peephole scan alone: `-v`, `-i`,
`-e`, `-j`, `-s` and `-p` are separate reports whose output would interleave
with it, and the driver refuses the combination rather than choosing for the
caller.

Pass `-e` to also verify the binary's CET indirect-branch-tracking landing
pads, `-i` to replace the lint scan with an ISA census of the binary, `-j` to
replace it with a JCC-erratum verdict, `-s` with a speculation-thunk verdict,
and `-p` with a per-function build-property audit; see the next sections.

The exit status follows the grep convention -- 0 for a clean scan, 1 when any
opportunity is found, 2 on a tool failure (unreadable or malformed input) --
so x86lint can gate a compiler test suite and CI can tell a dirty scan from a
broken run. `-e` findings set the exit status like any other; the `-i` census
never sets it, the `-j` audit sets it only under `-t skylake` (the one target
that has the erratum), the `-s` audit only for a mitigation left incomplete,
and the `-p` audit never.

## ENDBR64 (CET IBT) verification

With Intel CET's indirect branch tracking enforced, an indirect `JMP` or
`CALL` must land on an `ENDBR64` instruction or the CPU raises a
control-protection fault (#CP). The loader turns enforcement on when the
binary's GNU property note (`.note.gnu.property`) carries the IBT bit, so a
binary makes two claims that can drift apart: the note says "every indirect
target is padded," and the code either honors that or does not. `x86lint -e`
cross-checks them.

Which addresses an indirect branch can reach is not a property of the
instruction stream -- nothing in the bytes distinguishes a landing site from
fallthrough code, which is why this is a driver (`-e`) pass over the ELF
metadata rather than an entry in the check table above. A linked binary
evidences a checkable subset of its indirect targets:

* the entry point (`e_entry`) of a program with a `PT_INTERP` interpreter --
  ld.so transfers to it with an indirect jump (`_dl_start_user`'s
  `jmp *%r12`). A kernel-entered binary -- static, static-PIE, ld.so itself
  -- starts with the tracker idle and owes no pad there, and ld.so's own
  `_start` indeed has none, deliberately;
* `.init` and `.fini` (`DT_INIT`/`DT_FINI`) -- called through pointers;
* every `.preinit_array`/`.init_array`/`.fini_array` slot;
* `R_X86_64_JUMP_SLOT` and `R_X86_64_GLOB_DAT` relocations resolving to a
  definition in the same binary -- the slot's runtime value is that entry;
* `R_X86_64_IRELATIVE` -- the loader calls the ifunc resolver indirectly;
* every defined dynamic function symbol -- a cross-object call always
  arrives through the caller's PLT or GOT, an indirect branch landing here;
* absolute-address relocations (`R_X86_64_RELATIVE`, `R_X86_64_64`, and the
  packed `SHT_RELR` form) whose baked pointer lands in an executable
  section -- vtables and callback tables.

The last class proves only that the address is *taken*, not that it is
branched to: glibc bakes pointers to bracket labels
(`__syscall_cancel_arch_start`) that are only ever compared against
interrupted PCs, and hand-written assembly omits their pads deliberately.
Address-relocation evidence therefore counts only when the pointer addresses
a function entry known to `.symtab` or `.dynsym` -- a compare-only label is
`NOTYPE` and drops out, and a stripped binary loses this one evidence class
(the tool's usual trade: a false negative over a false claim). The converse
check -- flagging a *superfluous* `ENDBR64` -- is not attempted at all,
since a target materialized by a RIP-relative `LEA` leaves no relocation
behind and absence of evidence proves nothing.

Four verdicts, reconciling the pads against the note:

* IBT declared, all targets padded -- clean;
* IBT declared, some target bare -- each miss is printed with its address,
  symbol, and evidence (`#CP` fault the moment tracking is enforced);
* IBT not declared, but the targets carry pads -- the compiler emitted CET
  and the link lost it: the linker ANDs the property across all inputs, so
  a single object built without `-fcf-protection` silently disarms
  enforcement for the whole binary. One finding; `-v` lists any targets
  without pads (in a poisoned link, usually the culprit object's);
* no declaration, no pads -- not an IBT binary; nothing to hold it to, no
  findings.

The same `FEATURE_1_AND` word carries the shadow-stack bit, so `-e` reports
it in the same pass: `-fcf-protection=full` emits both, and an asymmetric
declaration earns a line. The asymmetries are real and directional: of
3,203 `/usr/lib64` library files, 3,120 declare both bits, none declare IBT
alone, and 18 declare SHSTK alone -- all media/JIT libraries (the ffmpeg
family, dav1d, x264, libass, LuaJIT) whose hand-written assembly emits an
SHSTK-only property note, since its returns stay call-paired but its entry
points carry no pads. Under the linker's AND an SHSTK-only *output* proves
every input object declared SHSTK while at least one withheld IBT, so each
of the 18 pairs this line with the annotation-lost verdict: the two
together read "the C was compiled with full CET, the assembly could claim
only the return half, and the AND kept exactly what everything agreed on."
The SHSTK line is informational and never sets the exit status, because
SHSTK, unlike IBT, leaves nothing in the instruction stream to hold the
binary to; even a shadow-stack-*incompatible* idiom is not statically
recognizable -- glibc's own `setcontext`/`swapcontext` end in the classic
`push`-and-`ret`, legitimately, because a runtime branch takes an
`RSTORSSP`-based path first whenever a shadow stack is live, a feature gate
no instruction matcher can see. So the declared bit is reported and the
instructions are not judged. In the annotation-lost verdict the pads
evidence branch protection only -- a lost `FEATURE_1_AND` takes IBT and
SHSTK down together, but whether return protection was ever compiled in is
unknowable, so there the line states the bit's absence without claiming a
loss.

Verified against a Fedora system where CET is on by default: `bash` (1,767
evidenced targets), `libc.so.6` (2,500), `libcrypto.so.3` (5,867, including
OpenSSL's perlasm), `ld-linux-x86-64.so.2`, and `git` all reconcile
cleanly, and a Go binary -- Go does not emit IBT -- produces no noise. The
sweep also caught a real specimen of the third verdict: Fedora's
`libzstd.so.1` ships all 598 evidenced targets padded but its property note
carries no `FEATURE_1_AND` at all -- the hand-written Huffman assembly ate
the declaration at link, so the fully padded library runs unenforced.
Relocatable objects are rejected: their address-taken evidence dissolves
into the final link, so the question is only answerable for executables and
shared objects. The library exports the single-site predicate
(`check_endbr64_target`); the evidence collection lives in the driver.

## ISA census (`-i`)

`x86lint -i` replaces the lint scan with a census: every instruction in the
binary's executable sections, tallied by the XED isa-set it belongs to and
mapped onto the x86-64 psABI micro-architecture levels -- x86-64-v2
(CMPXCHG16B, LAHF-SAHF, POPCNT, SSE3, SSSE3, SSE4.1, SSE4.2), x86-64-v3
(adds AVX, AVX2, BMI1, BMI2, F16C, FMA, LZCNT, MOVBE, XSAVE), x86-64-v4
(adds AVX-512 F/BW/CD/DQ/VL). This answers "what was this binary compiled
for": a distro package built with `-march=x86-64-v3` shows AVX and BMI woven
through ordinary functions, while a baseline build shows none.

```console
$ ./x86lint -i /usr/lib64/libc.so.6
ISA census: 356358 instructions, 0 undecodable bytes skipped
  baseline x86-64 (v1): 341217
  x86-64-v2: SSSE3 (315), SSE4.2 (206), SSE4.1 (11)
  x86-64-v3: AVX2 (3368), AVX (3015), BMI1 (532), BMI2 (146), LZCNT (27), MOVBE (16)
  x86-64-v4: AVX512F (2038), AVX512BW (1709), AVX512DQ (3)
  outside the psABI levels: CET (3706), RTM (46), PKU (3)
  x87 legacy FP: 428 (control/env 34, 80-bit operands 124, other 270)
  highest psABI level: x86-64-v4
  code evidence: 9899 function symbols + 3791 .eh_frame FDEs + 0 Go pclntab functions covering 1481413 of 1514109 executable bytes
  GNU property ISA note: needed = x86-64-baseline, used = x86-64-baseline+x86-64-v2+x86-64-v3+x86-64-v4
  IFUNC resolvers defined: 141 (runtime CPU dispatch present)
```

The census reports presence, not requirement. glibc above runs on any
x86-64 CPU: its AVX-512 lives in IFUNC-dispatched `memcpy` variants selected
at load time, which is why the IFUNC resolver count is printed alongside --
a high level plus many resolvers reads as "baseline binary with dispatched
fast paths," a high level with none as "compiled wholesale for that level"
(or, as in OpenSSL and Go binaries, dispatch by plain branches on a
runtime-probed feature word, which no static count can see). Deciding what
the binary *requires* would mean proving which instructions execute
unconditionally on the path from entry, which the instruction stream cannot
evidence; the census states what the compiler was allowed to emit anywhere,
and reports the note that can state requirement when the toolchain recorded
one: the `GNU property ISA note` line prints the
`GNU_PROPERTY_X86_ISA_1_NEEDED` word (authoritative -- the loader refuses to
run the binary below that level) and the `_USED` word (the linker's union of
what its inputs were allowed to emit -- the same quantity the census
measures from the bytes, and a cross-check on it). glibc above declares
`needed = baseline`: it requires only v1, everything higher being reached
through dispatch, exactly as the resolver count suggests.

`-f NAME` narrows the census to the one named function, which turns
"dispatch is present" into "and here is what each target actually uses"
-- the per-target level question a whole-binary census cannot answer,
one command per IFUNC variant:

```console
$ for fn in __memmove_avx512_unaligned_erms __memmove_avx_unaligned_erms \
            __memmove_sse2_unaligned_erms; do
>   ./x86lint -i -f $fn /usr/lib64/libc.so.6 | grep highest
> done
  highest psABI level: x86-64-v4
  highest psABI level: x86-64-v3
  highest psABI level: baseline x86-64 (v1)
```

The coverage figure on the `code evidence` line is clipped to the
scanned slices, and the file-level lines (the property note, the
resolver count) keep reporting the whole binary they describe.

Extensions outside the levels -- AES-NI, PCLMULQDQ, SHA, ADX, CET, RTM, the
post-v4 AVX-512 families (VNNI, VBMI, VAES, ...), APX -- are tallied on
their own line and never raise the level verdict, since no `-march=x86-64-vN`
implies them.

The `x87 legacy FP` line is a cross-cutting annotation, not a level: the
x87-family instructions (isa-sets X87, FCMOV, FCOMI, plus SSE3's FISTTP)
keep their place in the level counts -- x87 *is* baseline -- and are
additionally split into FPU control/environment instructions (`FLDCW`,
`FNSTSW`, ..., what ordinary `fesetround` compiles to), instructions
touching an 80-bit `tbyte` memory operand, and everything else. The split
exists because intent is only judgeable per binary, never per instruction:
the SysV ABI deliberately keeps `long double` on x87, and a legitimate
long-double function is dominated by bare register-stack arithmetic
between its `FLDT`/`FSTPT` edges (glibc's own line above reads exactly so:
`strtold` and `printf %%Lf` machinery). "Other" *beside* 80-bit traffic is
long-double implementation; "other" in a binary with **zero** 80-bit
operands cannot be long double, and reads as `-mfpmath=387` leakage or
assembly ported from 32-bit habits -- Fedora's `libavutil` is a live
specimen (`x87 legacy FP: 19 (control/env 4, 80-bit operands 0, other
15)`), and `-v`'s `x87 other at ...` samples lead straight to the sites. The v4 line folds XED's per-width isa-sets into their CPUID
feature (`AVX512F_512`, `AVX512F_128` and the mask ops all count as
`AVX512F`); levels with no hits print `none` so two censuses diff
line-for-line. The census always scans every executable byte (the
`.symtab` restriction does not apply): a handful of hits can be data
misdecoded as code, so `-v` prints up to four sample addresses per
extension to check at a disassembler prompt before trusting a small count,
and the zero-`none` shape plus the skipped-bytes counter bound how much
could have been misread.

The census also labels every tally against the bytes the toolchain
recorded as code -- sized function symbols from `.symtab` and `.dynsym`
(stripped distro libraries keep the latter), `.eh_frame` FDE
pc-ranges, and Go `pclntab` function boundaries, the runtime's own
table, kept through `strip` because traceback needs it: a stripped
pure-Go binary loses both symbol tables and has no unwind data worth
the name, yet keeps every function boundary this way (all four header
eras back to Go 1.2 parse; the table is found by section name or by
scanning the data sections, and believed only after the whole functab
validates against the executable sections and the entry point --
modern linkers store a dead `textStart` word, so the base is recovered
from the section layout, and when external linking makes every
candidate wrong the table is honestly dropped) -- because no property
of the instruction stream itself can
tell a real instruction from a phantom: `tools/cohere` measured run
length, gap adjacency, and self-synchronization consensus all failing
at exactly that (a GHC binary's phantom x87 reaches 92% consensus;
junk converges onto its own stable decode chain). A family with hits
outside all evidence prints as `FAM (n, u unevidenced)`, and the
`code evidence` line reports what backed the labels. The semantics are
deliberately asymmetric: *inside* evidence lends trust -- OpenSSL's
`XOP (88)` carries no annotation because every hit sits in a real
function, and they are indeed its Bulldozer SHA-1 paths -- while
*unevidenced* means only "no toolchain claim", never "phantom": GHC
emits no FDEs for Haskell code, so a shellcheck census flags all 30864
x87 hits (correctly: they are info tables), but real Haskell code is
equally unlabeled there. Evidence quality varies by build; when a
binary has none at all, nothing is labeled and the line says so.

## JCC erratum audit (`-j`)

Skylake-derived cores cannot cache a jump in the decoded-icache when the
jump's bytes cross a 32-byte boundary or its last byte is the last byte of
one; fetch falls back to legacy decode, and the cost is paid per execution,
so a hot loop pays it every iteration. `x86lint -j` reports whether a binary
was built with the assembler padding that avoids it.

This is the one report here that is a verdict rather than a finding. Every
check in the table above reads an instruction and says its bytes could have
been better; here the bytes are fine and what is wrong is where they landed,
so the fix is padding something *earlier* -- one build flag, not a rewrite --
and no single one of the 10-13% of jumps that touch a boundary is
individually at fault.

```console
$ ./x86lint -j /bin/bash
JCC erratum audit: 254073 instructions, 0 undecodable bytes skipped
  Jcc 30799 + JMP 12442: 5458 touch a 32-byte boundary (12.6%), 5688.50 expected unpadded
  verdict: mitigation absent (witnesses at the rate chance predicts)
  not in the verdict's scope: 29266 fused compare+Jcc pairs (6428 touching), 19612 CALL (3018), 3032 RET (92)
  informational: the erratum is Skylake through Comet Lake, Cascade Lake included; pass -t skylake to count it
```

What makes the verdict sound without a calibrated threshold is that
unmitigated code is *exactly* uniform with respect to the boundary. A jump of
length L occupies `[s, s+L-1]` and touches a boundary precisely when
`s mod 32 >= 32 - L`, which is L of the 32 residues, so each jump contributes
L/32 expected witnesses and the expectation for a whole scan is its jump
bytes over 32. That is arithmetic, not a fit, and the corpus lands on it:
bash, glibc, libcrypto, ld.so and libxul report 10.7-12.9% of their `Jcc` and
`JMP` on a boundary, every one of them within 5% of its own expectation. An
object assembled with `cc -Wa,-mbranches-within-32B-boundaries` reports 0 of
2,366, for 2.6% more text.

The evidence is asymmetric, and the four verdicts say so. One witness is
proof that whatever produced the code holding it did not pad, so `mitigation
absent` needs no minimum sample; the absence of witnesses means nothing until
enough jumps have been seen for chance to have produced one, so `mitigation
present` requires a scan expecting at least eight. Between them,
`partially mitigated` is a real configuration rather than a hedge -- a
mixed link, or a toolchain that pads compiler output and not hand-written
assembly, which is exactly what Go's own binaries are:

```console
$ ./x86lint -j /bin/go | sed -n '2,3p'
  Jcc 113255 + JMP 52098: 92 touch a 32-byte boundary (0.1%), 16581.65 expected unpadded
  verdict: partially mitigated (witnesses far below chance -- mixed objects, or a toolchain that pads compiler output and not hand-written assembly)
```

Go pads what its compiler emits and not what its runtime hand-writes
(`padJump` and `isJump` in `src/cmd/internal/obj/x86/asm6.go`, which
`makePjcCtx` turns off for `ctxt.IsAsm`), and those 92 are the hand-written
half. Its scope is also wider than gas's: `CALL` and `RET` come out at 55 of
104,059 and 8 of 28,022, where gas's `-malign-branch=jcc+fused+jmp` leaves
both alone. Reading the out-of-scope line beside the verdict is what
identifies which toolchain was at work, which is why those classes are
printed and why they never decide the verdict -- that and the fact that
whether a given compare and `Jcc` really macro-fuse depends on the core and
on operand shape, so an approximate predicate must not be allowed to
manufacture a witness.

Only `-t skylake` makes a missing mitigation a finding (exit 1); every other
target, the conservative `-t generic` default included, leaves the report
informational. The erratum is one named group of cores -- V8 enumerates the
affected models and steppings in `src/base/cpu/cpu-x86.cc` -- so unlike every
other per-core question here, the pessimistic reading is not the safe one:
applied by default it would fail every binary on a system that may never run
on an affected core.

The audit needs the address each jump will run at, which is why a
*relocatable* object is judged only when the section holding it is at least
32-byte aligned. That is not a formality: gas raises `.text` to 32-byte
alignment precisely when it pads, so that the padding it just inserted is not
undone by a linker placing the section at 16 mod 32. Sections below that are
counted and reported as skipped rather than guessed at. Sections with a real
address -- a linked executable's, or the JIT addresses
`tools/jitdump2elf.py` records -- are judged exactly.

The JIT case is the one this cannot be measured any other way. V8 implements
the mitigation (`Assembler::AlignForJCCErratum`) and SpiderMonkey implements
nothing, but V8's is gated on the host CPU actually having the erratum, so a
dump's verdict describes the machine that produced it and not the engine: on
an AMD host a V8 corpus reports `mitigation absent`, correctly, because
nothing there needed padding.

## Speculation thunk audit (`-s`)

A retpoline replaces an indirect branch with a call to a thunk that returns to
the intended target, so the branch predictor never sees an indirect transfer to
mistrain; a return thunk does the same for `RET`, which is what Retbleed and
SRSO attack. `x86lint -s` reports whether a binary was built that way --
`-mindirect-branch=thunk[-extern]` and `-mfunction-return=thunk[-extern]` in
GCC, `-mretpoline` in clang.

Like the JCC audit this is a verdict: the transformation is not an encoding a
peephole could suggest, no one unrouted return is at fault, and per site it
would be one finding per return in the binary. The signal is about as close to
binary as this tool gets, and it is positive on both sides rather than inferred
from absence -- a routed build *names* the thunk, in its relocations while it
is still an object and in its symbol table once linked, and contains none of
the instruction the thunk replaces.

```console
$ xzcat /lib/modules/$(uname -r)/kernel/drivers/net/amt.ko.xz > amt.ko
$ ./x86lint -s amt.ko
speculation thunk audit: 8441 instructions, 0 undecodable bytes skipped
  returns: 0 bare, 75 routed through a thunk -- routed (the image names a return thunk and holds no RET)
  indirect branches: 0 bare -- none in this image

$ ./x86lint -s /bin/bash | sed -n '2,3p'
  returns: 3032 bare -- not routed (the image names no return thunk)
  indirect branches: 239 bare -- not routed (the image names no indirect thunk)
```

Fedora's own kernel is the proof that this is worth checking: across 60 shipped
modules, 59 report `routed` and one has no returns at all to judge. Not one
reports a hole, which is the calibration -- a verdict that fired spuriously on
real input would be useless for the audit it exists for.

**The one thing reported as a finding is a hole, not an absence.** A bare `RET`
in an image that names a return thunk means the build asked for the mitigation
and something escaped it -- hand-written assembly the conversion missed is
exactly how that happens -- so that exits 1. A binary that names no thunk never
opted in, and saying so is describing a build rather than judging one: these
are kernel and hypervisor mitigations, userspace does not use them, and unlike
the JCC erratum there is no `-t` value that would change the answer, because
what decides is what the binary *is* and not which CPU runs it.

**A thunk's own body is excluded, and it has to be.** The trampoline GCC emits
ends in the very `RET` it exists to replace, and a retpoline's ends in a `RET`
that jumps to the target it pushed. Without excluding those bodies, an image
that defines its thunks rather than importing them would always report a hole,
and the hole it reported would be the mitigation itself. GCC also emits both
symbols with `st_size` 0, so the extent comes from the next symbol in the
section -- the same rule the scan applies to an unsized assembly label.

Two limits worth stating. The routed *count* is exact only while the object is
relocatable, since a linked image has resolved those branches into ordinary
direct ones; there the symbol's presence carries the verdict and the count
reads zero. And a linked image is judged whole, passengers included: a
retpoline-built program linked against an ordinary libc reports `INCOMPLETE`
because libc's returns really are unrouted, which is accurate but says more
about the link than about the code. A kernel module has no such passengers,
which is why it is the case with clean semantics.

## Build-property audit (`-p`)

`x86lint -p` reports build properties that a function's own code reveals, as
fractions of the functions rather than facts about the image. That makes the
symbol table part of the measurement rather than an optimization: a stripped
binary has no denominator, which is the one contract this shares with nothing
else here.

So far it answers one question -- what fraction of functions carry a stack
canary -- and the fraction is the point. `checksec` and `hardening-check` read
the symbol table and report whether `__stack_chk_fail` is *present*, which is
a yes or no; counting the functions that actually load the guard separates
*none* from *some* from *every one*, which is what distinguishes the three
flag settings. Verified against all three: 0% with no flag, 25% under
`-fstack-protector-strong` for the one function of four with an escaping
array, 100% under `-fstack-protector-all`.

```console
$ ./x86lint -p /usr/lib64/libc.so.6 | sed -n '2,3p'
  stack protector: 1513 of 6943 functions (21.8%) -- -fstack-protector or -strong
  measured over the function symbols in .symtab

$ ./x86lint -p /usr/lib64/ld-linux-x86-64.so.2 | sed -n '2p'
  stack protector: 1 of 474 functions (0.2%) -- no stack protector (the guard is read but no handler is named, so this is where it gets set up)
```

The loader is why the verdict rests on two signals and not one. Reading the
guard is not being protected by it: `ld.so` touches `%fs:0x28` in exactly one
function, that being where the guard is established for everyone else, and it
names no `__stack_chk_fail` at all. An earlier version called that binary
`-fstack-protector` on the strength of one initializer. A protected function
must be able to fail, so with no handler named anywhere the verdict is
`no stack protector` however many functions touch the slot.

Which functions `-strong` protects is not decidable from the bytes -- it turns
on having a local array or an address-taken local -- so the partial verdict
names both flags and does not choose between them. The audit is informational
and never sets the exit status: coverage is a policy choice rather than a
defect at any level, and partial coverage is precisely what `-strong` means.

Two things to know about the denominator. `.symtab` is preferred; where it has
been stripped -- most distro binaries -- the audit measures over `.dynsym`
instead and says so, because exported functions are a biased sample of a
library's but a biased fraction still answers the question where no sample
answers nothing. And the guard load is not a prologue-only phenomenon: GCC
schedules it wherever the register pressure allows, and the first version of
this measured only the first dozen instructions of each function, which
undercounted `/bin/bash` by 35%.

## Mining tools

`tools/` holds the research utilities that feed x86lint's check backlog,
built separately with `XED_PATH=/path/to/xed make tools`:

* `tools/shapescan` sizes a *named* candidate with the rewrite's own
  conditions applied, and says what refused the rest. Where pairscan ranks
  shapes to find what is frequent, a TODO row turns on whether a specific
  rewrite is available at a site, and measuring that ad hoc is what this
  exists to stop: the 2026-09 armlint port was sized four times with
  throwaway scripts and was wrong four times, three of them overstating the
  rewrite by 20x or more because a condition went unapplied. Candidates are
  therefore C predicates rather than patterns -- each needed operand-role
  matching, branch arithmetic, encodability through XED or a liveness walk --
  and the file includes `x86lint.c` to call the shipped checks themselves, so
  a shipped candidate is measured by the code that realizes it and an
  unshipped one is a draft check that moves rather than being rewritten. Each
  reports three things: how often the pattern matched, how often the rewrite
  was available, and which gate refused the difference. The third is the
  point -- "18,236 sites become 583" is a puzzle, while "9,126 read the
  loaded register again and 5,743 have no memory form in that operand slot"
  is an answer. `-e NAME` prints example sites
* `tools/pairscan` counts adjacent-instruction pairs by normalized shape
  across the executable sections of an ELF binary, surfacing frequent
  patterns worth a new check. Registers collapse to a class and width
  (with RAX, RCX, RDX, RSP, and RBP kept distinct), immediates to
  `#0`/`#1`/`#-1`/`#i`, memory to `[base+index*scale+disp]:width`, and the
  Jcc, SETcc, and CMOVcc families to one token each. Every pair is tagged
  with how the two instructions couple: `dep` and `waw` on registers,
  `fdep` and `fdead` on the flags -- the last being the gate that decides
  whether a flag-disturbing rewrite is legal. `-e SUBSTR` prints example
  sites for matching shapes.
* `tools/defuse` profiles block-local def-to-use distances -- how far a
  value's sole consumer sits from its producer, bucketed so a window can
  be sized against it -- and the multi-instruction redundancies no pair
  statistic can see: dead definitions, redundant reloads of one address,
  re-materialized constants, and zero compares of a value whose producer
  already set the flags.
* `tools/cohere` measured whether cheap per-instruction "coherence"
  signals -- run length between undecodable gaps, gap adjacency, and
  three-walk self-synchronization consensus -- can separate real
  instructions from phantom decodes of data-in-text, toward gating the
  census. All three fail on ground truth (a GHC binary's phantom x87
  reaches 92% consensus: self-sync is a decoder property, and junk
  converges onto its own stable chain); what separates every tested
  case instead is toolchain evidence, `.symtab` ranges and `.eh_frame`
  FDEs. The tool's header records the measurements; the census's
  evidence labeling (the `unevidenced` annotations and `code evidence`
  line) is what they argued into existence.

All of them restrict the scan to the symbol table's function ranges and skip
the dynamic linker's import glue exactly as the driver does, so no pair or
distance spans two functions, none is mined from the non-code that executable
sections interleave, and none counts the PLT's one fixed template as though a
compiler had emitted it; `-a` scans every byte. The workflow behind several
current checks: run `pairscan` over a
representative corpus, classify the top shapes as by-design or foldable,
then use `defuse` to decide whether a candidate needs adjacency only or a
liveness window -- the measurement `APX_NDD_WINDOW`'s default rests on.

Both lean on XED's operand model, which is exact about the compare
aliases where Capstone is not, but reports `CMOVcc` as a plain write to
its destination. That is right about the encoding and wrong about the
dataflow -- the prior value survives a not-taken move -- so the tools
add a conditional writer's destination to its read set, the same
correction `reg_kill_iclass` embodies in `x86lint.c`.

## JIT output

A JIT has no object file: its code lives in an anonymous mapping that
disappears with the process, which is why every measurement in this project's
backlog that mentions a JavaScript engine was made by reading disassembly text
rather than by running the tool. `tools/` converts what an engine can be made
to hand over into an ELF object x86lint scans like any other, so the whole
check table applies to JIT output:

* `tools/v8dump2elf.py` reads a V8 `--print-opt-code` listing, which already
  carries the encoding bytes, so nothing has to be patched. `d8
  --print-opt-code bench.js | python3 tools/v8dump2elf.py - -o v8.elf` and
  then `./x86lint -m v8 v8.elf`; the `-m v8` flag is what tells the linter
  that R13 holds a 4 GB-aligned pointer-compression cage base, which is the
  invariant the `OR`-into-address fold rests on.
* `tools/jitdump2elf.py` reads a container of raw code blobs --
  `"X86J" | u64 address | u32 code size | u32 name size | name | code`,
  concatenated with no file header, so a dump from a process that was killed
  still parses up to its truncation. `tools/spidermonkey-jitdump.patch` adds
  the eighty lines to `jit::Linker::newCode` that write it, covering Ion,
  Baseline, RegExp and the trampolines; JavaScriptCore's `LinkBuffer` takes
  the same few lines, and the record is the whole interface. `--raw` reads a
  bare blob, which is what SpiderMonkey's `disnative(f, "file")` writes for
  one function with nothing patched at all.

Both write one section per code object at the address the engine compiled it
to, so a finding cross-references straight back into the dump, and separate
sections stop a window peephole from walking off one code object into the
next. Each section gets an `STT_FUNC` symbol naming the tier and, where the
engine reveals it, the JS function -- so the by-function table is a per-tier
breakdown and `-v` names the holder.

What they found, over Octane 9 and ARES-6 on both engines -- 10.4M
instructions of JIT output, against the same engines' own compiled code --
is written up as "JIT corpora" in [TODO.md](TODO.md). The headline is that
JIT code carries six to nine times the findings per instruction that AOT
code does, and that **one check is nearly all of the difference**: oversized
branch displacement runs 33-59 per thousand instructions against 0.12-0.42
in compiled binaries. Every one of those 464,860 findings is a *forward*
branch and none is backward, because both assemblers shorten a jump to an
already-bound label and neither can know the distance to one that is not yet
bound. Take that class out and JIT and AOT code are within a factor of two
of each other, which is the reassuring half: the check table needs no JIT
dialect.

## References

* [Agner Fog optimization guide](https://www.agner.org/optimize/)
* [Intel instruction set reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf)
* [Intel optimization manual](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-optimization-manual.pdf)
* [uops.info](https://uops.info/) — machine-measured latency/throughput/port data per instruction and microarchitecture
* [Intel x86 encoder decoder](https://github.com/intelxed/xed) - library to parse instructions
* [armlint](https://github.com/gaul/armlint) - AArch64 equivalent of x86lint

## License

Copyright (C) 2018 Andrew Gaul

Licensed under the Apache License, Version 2.0
