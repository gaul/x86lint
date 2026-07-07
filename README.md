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
XED -- and matches each decoded instruction against a table of checks, every
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
edge executes the whole pattern. Edges the sweep cannot see -- indirect
branches, jump tables, entries from another section -- remain a residual risk
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
  nothing regardless of downstream reads.

Both scans share one bias: reads count inclusively and redefinitions
exclusively, so every uncertainty -- a decode error, an unfollowable branch,
running past the 16-instruction window, or the end of the buffer -- resolves
toward *live*, and thus toward suppressing the finding. A branch ends the walk
at that conservative answer, so the analysis stays within a basic block: it
never suggests a rewrite whose soundness would hinge on a fact about a branch
target it cannot see. The one boundary it reads through is a function return,
and only for flags -- the ABI guarantees they do not survive it.

## Implemented analyses

* LEA foldable into memory
  - `488D04B7 488B00` (LEA RAX, [RDI+RSI*4]; MOV RAX, [RAX]) -- the address
    computation folds into the load's own base+index*scale+disp, so the LEA
    disappears: MOV RAX, [RDI+RSI*4]. Fires when the LEA's register is dead
    after the fold (overwritten or unused) and the combined address still fits
    one index and a 32-bit displacement (gated by register liveness)
* load foldable into extend
  - `8A06 0FB6C0` (MOV AL, [RSI]; MOVZX EAX, AL) -- a narrow load then an
    in-place sign/zero-extension is a single extending load: MOVZX EAX, byte
    [RSI]. Removes the load and its partial-register write; also MOVSX and the
    MOVSXD (32->64) form
* missing LOCK prefix on CMPXCHG and XADD
* MOV constant foldable
  - `B905000000 01C8` (MOV ECX, 5; ADD EAX, ECX) -- the constant folds into the
    next instruction's immediate: ADD EAX, 5. Applies to ADD/SUB/ADC/SBB/AND/OR/
    XOR/CMP/TEST/MOV that use the register as a source, when it is dead after the
    fold and the constant fits the immediate (gated by register liveness)
* MOV+ADD foldable to LEA
  - `89F2 01FA` (MOV EDX, ESI; ADD EDX, EDI) -- the two are the non-destructive
    three-operand LEA EDX, [RSI+RDI], saving the MOV, when the arithmetic flags
    ADD would set are dead (gated by flag liveness)
  - `89F2 83C205` (MOV EDX, ESI; ADD EDX, 5) -- an immediate addend folds the
    same way, as LEA EDX, [RSI+5]; SUB negates the displacement and INC/DEC
    are the implied +/-1 forms, which -- like LEA -- leave CF untouched, so
    only the flags they do write gate them
* oversized ADD/SUB 128
  - `05 80000000` instead of `83E8 80` (ADD EAX, 128 -> SUB EAX, -128)
  - `2D 80000000` instead of `83C0 80` (SUB EAX, 128 -> ADD EAX, -128)
* oversized ADD/SUB one
  - `83C0 01` instead of `FFC0` (ADD EAX, 1 -> INC EAX, when CF is unused)
  - `836B10 01` instead of `FF4B10` (SUB DWORD [RBX+0x10], 1 -> DEC DWORD [RBX+0x10])
* oversized branch displacement
  - `E9 00000000` instead of `EB 03` (JMP rel32 that fits in rel8)
* oversized displacement
  - `8B 83 10000000` instead of `8B 43 10` (MOV EAX, [RBX+0x10]; disp32 that fits in disp8)
* oversized EVEX encoding
  - `62F1FD286FCA` instead of `C5FD6FCA` (VMOVDQA64 YMM1, YMM2 -> VMOVDQA;
    without an opmask, broadcast, rounding, 512-bit length, or xmm16-31,
    the 4-byte EVEX prefix wastes 1-2 bytes over VEX)
* oversized immediates
  - `81C0 01000000` instead of `83C0 01` (ADD EAX, 1)
  - `68 01000000` instead of `6A 01` (PUSH 1)
* oversized MOV encoding
  - `C7C0 01000000` instead of `B8 01000000` (MOV EAX, 1)
  - `48 C7C0 01000000` instead of `B8 01000000` (MOV RAX, 1; the 32-bit form zero-extends)
* oversized TEST immediate
  - `A9 01000000` instead of `A8 01` (TEST EAX, 1 -> TEST AL, 1; TEST has no
    sign-extended imm8 form, and a mask within the low seven bits sets
    identical flags at byte width)
* oversized VEX encoding
  - `C4E17D6FCA` instead of `C5FD6FCA` (VMOVDQA YMM1, YMM2; the three-byte VEX
    prefix wastes a byte when the two-byte form's map/W/register constraints
    are met)
* oversized XCHG encoding
  - `87C8` instead of `91` (XCHG EAX, ECX; the 90+r accumulator form is one byte)
* redundant ADD/SUB zero
  - `83C0 00` (ADD EAX, 0) -- use TEST or remove (flag-exact; the 32-bit
    form's zero-extension is gated by register liveness)
* redundant AND immediate
  - `83E0 FF` instead of `85C0` (AND EAX, -1 -> TEST EAX, EAX; an all-ones mask
    sets identical flags; the 32-bit form's zero-extension -- GCC's fused
    zero-extend-and-test -- is gated by register liveness)
* redundant MOV reg, reg
  - `4889C0` (MOV RAX, RAX)
  - `89C0` (MOV EAX, EAX) -- the 8/16/64-bit forms are pure no-ops; the 32-bit
    form clears the upper 32 bits, so it is flagged when those bits are dead
    downstream or already zero from the preceding 32-bit write (both gated by
    register liveness)
* redundant OR/XOR zero
  - `83C8 00` (OR EAX, 0) -- no-op that sets flags; use TEST or remove (the
    32-bit form's zero-extension is gated by register liveness)
* redundant shift/rotate by zero
  - `C1E0 00` (SHL EAX, 0) -- value and flags unchanged; hardware still
    zero-extends the 32-bit form even at count 0, so it is gated by register
    liveness
* redundant TEST after flags
  - `21D8 85C0` (AND EAX, EBX; TEST EAX, EAX) -- the AND already set SF/ZF/PF,
    so the TEST is dead. AND/OR/XOR match TEST's flags exactly (CF/OF cleared)
    and fire unconditionally; ADD/SUB/INC/DEC and friends diverge only on CF/OF
    and are flagged only when those are dead downstream (gated by flag liveness)
* redundant TEST after SETcc
  - `0F94C0 84C0 74xx` (SETZ AL; TEST AL, AL; JE) -- SETcc preserves the
    compare's flags, so the TEST only recomputes a condition they still hold;
    branch on them directly (JE -> negated Jcc, JNE -> same). Drop the TEST
    always, and the SETcc too when AL is dead. Only JE/JNE and an exact-width
    TEST AL, AL match, gated on every arithmetic flag being dead on both
    successors (a direct branch's target is a known offset, so both are scanned)
* redundant TEST immediate
  - `A9 FFFFFFFF` instead of `85C0` (TEST EAX, -1 -> TEST EAX, EAX; an all-ones
    mask sets identical flags)
* suboptimal AND immediate
  - `25 FF000000` (AND EAX, 0xFF) -- use MOVZBL
* suboptimal AND zero
  - `83E0 00` (AND EAX, 0) -- use XOR EAX, EAX (same flags, fewer bytes)
* suboptimal CMP zero
  - `83F8 00` instead of `85C0` (CMP EAX, 0 -> TEST EAX, EAX)
* suboptimal IMUL constant
  - `6BC0 03` (IMUL EAX, EAX, 3) -- use LEA
  - `6BC0 10` (IMUL EAX, EAX, 16) -- use SHL (any power of two, same register)
* suboptimal LEA
  - `488D03` (LEA RAX, [RBX]) -- use MOV RAX, RBX (more ports, no AGU)
  - `488D0408` (LEA RAX, [RAX+RCX]) -- an in-place two-register LEA is ADD RAX,
    RCX, a byte shorter (no SIB) and on more ports, when the arithmetic flags
    are dead (gated by flag liveness)
* suboptimal MOV zero
  - `B8 00000000` (MOV EAX, 0) -- use XOR EAX, EAX (fewer bytes, breaks the
    dependency chain); flagged only when the arithmetic flags XOR would clobber
    are dead, so the deliberate flag-preserving MOV before a CMOV
    ([#7](https://github.com/gaul/x86lint/issues/7)) is not flagged
* ~~suboptimal NOP sequence~~, see [#9](https://github.com/gaul/x86lint/issues/9)
  - multiple `90` instead of a single `66 90`, etc.
* suboptimal OR/AND reg, reg
  - `09C0` (OR EAX, EAX) -- use TEST EAX, EAX (same flags, no register write;
    the 32-bit form's zero-extension is gated by register liveness)
* suboptimal SSE MOV opcode
  - `660F6FCA` instead of `0F28CA` (MOVDQA XMM1, XMM2 -> MOVAPS; the legacy
    66/F3-prefixed copies movapd/movdqa/movupd/movdqu waste a byte over
    movaps/movups)
* suboptimal SUB reg, reg
  - `29C0` (SUB EAX, EAX) -- use XOR for dependency-breaking
* suboptimal XOR immediate
  - `83F0 FF` instead of `F7D0` (XOR EAX, -1 -> NOT EAX, when flags are unused)
* unneeded explicit immediate
  - `C1D0 01` instead of `D1D0` (RCL EAX, 1)
* unneeded explicit register
  - `81C0 00010000` instead of `05 00010000` (ADD EAX, 0x100)
* unneeded LOCK prefix on XCHG
* unneeded MOVSX
  - `0FBFC0` instead of `98` (MOVSX EAX, AX -> CWDE)
  - `66 0FBEC0` instead of `66 98` (MOVSX AX, AL -> CBW)
* unneeded MOVSXD
  - `48 63 C0` instead of `48 98` (MOVSXD RAX, EAX -> CDQE)
* unneeded REX prefix
  - XOR RAX, RAX `4831C0` instead of XOR EAX, EAX `31C0`
  - `40C9` instead of `C9` (LEAVE)
  - `48 0FB6C3` instead of `0FB6C3` (MOVZX RAX, BL -> MOVZX EAX, BL; the r32 form zero-extends to 64)
* unneeded SIB byte
  - `C64465 04 05` instead of `C645 04 05` (MOV byte [RBP+4], 5)
* unneeded zero displacement
  - `017E 00` instead of `013E` (ADD [RSI], EDI)

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
    return check_instructions(inst, len, /*verbose=*/false, /*summary=*/NULL);
}
```

The optional `summary` accumulates a by-type tally across one or more runs
(`x86lint_summary_create` / `_print` / `_destroy`; pass `NULL` to skip it),
and `verbose` controls whether each opportunity is printed as it is found.
`x86lint_summary_skipped` reports how many undecodable bytes were skipped, so
incomplete coverage of a data-laden section is not mistaken for a clean scan.

x86lint can also read arbitrary 64-bit ELF executables directly. By default it
prints only a summary -- the opportunities grouped by type and sorted by
prevalence -- followed by a total and the number of instructions scanned:

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
oversized immediate at offset: 0x14: push 0x0
  68 00 00 00 00
...
```

The exit status follows the grep convention -- 0 for a clean scan, 1 when any
opportunity is found, 2 on a tool failure (unreadable or malformed input) --
so x86lint can gate a compiler test suite and CI can tell a dirty scan from a
broken run.

## References

* [Agner Fog optimization guide](https://www.agner.org/optimize/optimizing_assembly.pdf)
* [Intel instruction set reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf)
* [Intel optimization manual](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-optimization-manual.pdf)
* [Intel x86 encoder decoder](https://github.com/intelxed/xed) - library to parse instructions
* [armlint](https://github.com/gaul/armlint) - AArch64 equivalent of armlint

## License

Copyright (C) 2018 Andrew Gaul

Licensed under the Apache License, Version 2.0
