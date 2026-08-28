# TODO: candidate analyses

The research-backed backlog of checks considered but not yet
implemented. Implemented checks are documented in the "Implemented
analyses" section of [README.md](README.md); the soundness model every
candidate here has to satisfy is in "Design and soundness model" there.
Sources: the Intel optimization manual, Agner Fog's guides, uops.info,
gaps noted while building the existing checks, and the shipped-check
backlog of [armlint](https://github.com/gaul/armlint), whose
`TODO.md` and `analyses.md` this file mirrors.

Population figures marked **2026-08 sweep** come from `tools/pairscan`
and `tools/defuse` over six ELF binaries totalling 33.5M instructions:
Firefox `libxul.so` opt (C++/Rust, 30.08M), `go` 1.26 (1.65M),
OpenSSL 3.5.7 `libcrypto` (C + perlasm, 828k), `libstdc++` 6.0.36
(357k), glibc `libc.so.6` (351k) and `/bin/bash` (254k). libxul is 90%
of that total, so read the per-binary rate per million instructions,
not the sum -- three of the rows below look large only because libxul
is large, and one of them (the dead `mov rbp, rsp` row) is a property
of libxul's build flags rather than of any compiler.

Both tools restrict the scan to the symbol table's function ranges, so
no pair or def-use distance spans two functions or is mined from the
non-code that executable sections interleave. Only libxul, go and libc
kept a `.symtab`; bash, libstdc++ and libcrypto were swept with `-a`,
which scans every byte and therefore admits data-in-text. Treat their
numbers as upper bounds.

Distances are `defuse`'s: **d1** is an adjacent pair, and every
population below is quoted at d1 unless it says otherwise, because the
distance histograms show d1 dominating every sole-use producer family
in this corpus -- strict adjacency is the right default here, as it is
in armlint.

A population is not a prediction. armlint learned this twice over: a
prediction is exact only when it is made by the machinery that will
realize it, and a shape counted without the rewrite's own conditions
applied is an upper bound, sometimes by two orders of magnitude. Every
non-zero row below was spot-checked against real disassembly, and
every candidate was also measured against what x86lint *already
reports* on the same binary -- which is what closed the MOV-immediate
row and opened the LEA row in "Coverage gaps" below.

## Memory-operand folds

x86's two-operand forms take a memory operand directly, so a
sole-use load feeding an ALU or compare is one instruction the
encoding already offers to delete. This is the largest and most
uniform family in the corpus: 229,302 adjacent sites, present at
3,834-7,214 per Minsn in *every* binary, independent of language.

| Pattern | Rewrite | 2026-08 sweep (d1, rate/Minsn) |
| --- | --- | --- |
| ~~sole-use load + `CMP`/`TEST` of the loaded register~~ | ~~fold the load into the compare~~ | **Done: "load foldable into compare".** Swept population 81,510; realized **6,245** (libc 73, libstdc++ 69, bash 105, libcrypto 58, libxul 5,854, go 286). See the realized-vs-predicted note below |
| sole-use load + `ADD`/`SUB`/`ADC`/`SBB` reading it | fold into the ALU: `MOV RAX, [M]` ; `ADD RBX, RAX` -> `ADD RBX, [M]` | **122,714.** libc 1,593 (4534), libstdc++ 1,662 (4649), bash 830 (3267), libcrypto 2,155 (2603), libxul 107,747 (3581), go 8,727 (5286) |
| sole-use load + `AND`/`OR`/`XOR` reading it | same | **22,326.** libc 294 (837), libstdc++ 296 (828), bash 322 (1267), libcrypto 464 (560), libxul 20,461 (680), go 489 (296) |
| sole-use load + `IMUL`/`MUL` reading it | same | **2,752**, concentrated in libcrypto (338) and go (260) |

The zero-test arm shipped first, and not because it is the largest: it
is the only one that needs no flag argument at all.
`TEST r, r` and `CMP m, 0` agree exactly -- both set SF/ZF/PF from the
value and clear CF/OF, since subtracting zero neither borrows nor
overflows -- so the sole-use gate is the whole proof. The other three
arms inherit the consumer's own flag semantics unchanged, which is
also exact, but they must additionally match the load's width to the
ALU operand's width: `MOV EAX, [M]` ; `ADD RBX, RAX` is not
`ADD RBX, [M]`.

Real sites, both from one glibc function:

```
mov eax, dword ptr [rdx+0x4] ; test eax, eax      ->  cmp dword ptr [rdx+0x4], 0
mov rdi, qword ptr [r12]     ; cmp dword ptr [rdi+0xc0], 0x0   (already folded)
```

The second line is the rewrite the first line wants, emitted by the
same compiler in the same function a few instructions earlier. That is
the strongest evidence a candidate can carry: the toolchain already
considers the folded form idiomatic and merely fails to reach it
consistently.

**Microarchitectural caveat, to be documented rather than gated on.**
`CMP mem, imm` cannot macro-fuse with a following `Jcc` on Intel,
where `TEST r, r` + `Jcc` does. The trade is uop-neutral -- three
instructions fusing to two, against two instructions that do not fuse
-- and strictly positive on code size (7 bytes to 5 in the shape
above). It belongs in the check's documentation, not in its gate.

This is the generalization of the shipped "load foldable into extend",
which fires **49** times on libxul and **0** on libc.

**Realized against predicted, and what the gap is made of.** The shipped
check reports 6,245 findings where the sweep counted 81,510 adjacent
sites -- 13x on libxul, 5x on libc. armlint's rule explains the shape
of that: a prediction is exact only when it is made by the machinery
that will realize it, and this one was not. `defuse`'s "sole use" is
its own region-local dataflow; the check has to *prove* the value dead
through `reg_live_after`'s 16-instruction walk, which ends LIVE at the
second control transfer, plus the side-entry gate. The residue is that
proof's conservatism, not a defect, and it is the same residue the LEA
fold shows in "Coverage gaps" below.

One part of the gap was a defect, and it is the reason this row is
worth reading twice. The first working build reported **1** finding
across all of glibc. `reg_live_after` stops at any control transfer,
and for this family that transfer is the very next instruction --
the whole point of a compare is the branch that reads its flags -- so
the gate suppressed essentially the entire population while looking
like a check that worked. A conditional branch reads flags, not GPRs,
so `reg_live_after_branch` splits at a direct Jcc and requires the
value dead on both successors. That took libc from 1 to 73. A check
whose population is three orders of magnitude below its shape is
reporting on an accident of its gate, and the only way to see it is to
measure the check against the sweep that motivated it.

## Address folds

The x86 twin of armlint's highest-yield shipped checks
(`check_add_ldr_imm_offset`, 8,428 findings; `check_add_ldr_str_multi_fold`,
3,804). x86lint folds `LEA` into a memory operand but not `ADD`.

| Pattern | Rewrite | 2026-08 sweep (d1, rate/Minsn) |
| --- | --- | --- |
| `ADD`/`SUB`/`INC`/`DEC` whose sole use is as the base of a following access | fold into the addressing mode: `ADD RCX, 1` ; `MOVZX EAX, BYTE [RCX]` -> `MOVZX EAX, BYTE [RCX+1]` | **219,285.** libc 630 (1793), libstdc++ 2,190 (6126), bash 498 (1960), libcrypto 1,774 (2142), libxul 213,679 (7103), go 514 (311) |
| `LEA` + `ADD`/`SUB` reading its result | one `LEA`: `LEA RAX, [RBX+8]` ; `ADD RDX, RAX` -> `LEA RDX, [RDX+RBX+8]` | **45,779.** libc 176 (501), libstdc++ 128 (358), bash 36 (142), libcrypto 103 (124), libxul 44,761 (1488), go 575 (348) |

Both reuse the register-liveness machinery behind "LEA foldable into
memory", plus the same encodability condition (the combined address
must still fit one index and a 32-bit displacement). Both need one
gate that check does not: `LEA` writes no flags and `ADD`/`SUB` do, so
the fold is legal only where the flags are dead past it. `SUB` by an
immediate folds as a negated displacement; `SUB` by a register does
not fold at all, since an addressing mode cannot negate its index.

Real sites, from glibc:

```
add rcx, 0x1  ; movzx eax, byte ptr [rcx]        ->  movzx eax, byte ptr [rcx+1]
add rax, rcx  ; mov r14, qword ptr [rax]         ->  mov r14, qword ptr [rax+rcx]
add r14, rbx  ; movsx eax, byte ptr [r14+0x18]   ->  movsx eax, byte ptr [r14+rbx+0x18]
```

go's rate (311) is an order of magnitude below the C and C++ binaries;
this is a clang/gcc shape, and the gc backend largely does not emit it.

## Constants

| Pattern | Rewrite | 2026-08 sweep (d1, rate/Minsn) |
| --- | --- | --- |
| `MOV r, imm` of a constant still live in another register | `MOV rD, rS` -- 3 bytes against up to 10 for a `MOVABS`, and eliminated at rename where the immediate form is not | **27,796.** libc 113 (322), libstdc++ 126 (352), bash 90 (354), libcrypto 124 (150), libxul 26,982 (897), go 361 (219) |

The usual counter-argument to un-rematerializing a constant is
register pressure, and it does not apply: the measurement's
precondition is that the value is already live in another register, so
the rewrite frees a register rather than pinning one. armlint has the
same candidate open from its own pairscan sweep. `defuse`'s
`remat|movimm` row is the population; a check needs the liveness proof
that the source register still holds the constant at the use.

## Coverage gaps in shipped checks

A population counted independently says nothing about which spellings
a *shipped check's* decoder chain accepts. armlint found two real
holes this way, both of which had been reporting plausible numbers off
a fraction of their own population. Measuring each x86lint check
against the shape it claims found one gap worth investigating and one
that closed itself.

| Check | Reports | Population at d1 | Notes |
| --- | --- | --- | --- |
| LEA foldable into memory | libxul 1,215; go 153; libc **0** | libxul 14,923; go 658; libc 254 | A 12x gap on libxul and a 254-to-zero gap on libc. Some of the residue is legitimately unfoldable -- a LEA that already carries base+index feeding `[reg]` would need two indices -- but the split has not been measured. Do it armlint's way: lower the check's own gates and count what comes back through its real liveness proof, rather than counting the shape from outside |
| redundant TEST after flags | libxul 556; libc 7; go 4 | `cmp0` d1: logic 329, arith 1,637, **test-width 405** | The logic and arith rows are covered (the check searches a window, not just d1, and arith is an upper bound gated on CF/OF deadness, exactly as documented). The test-width row -- 405 sites, 357 of them libxul -- is the check's exact-register match refusing a TEST that names a different width of the producer's register. That refusal is deliberate and sound (`AND EAX, EBX` clears bits 63:32 where `TEST RAX, RAX` reads a sign bit the narrow form never sees); the open question is whether the narrowing direction, where the producer is the *wider* one, is admissible |

## Investigated and closed (2026-08 sweep)

Candidates measured and rejected, recorded so they are not
re-investigated. The first two are the sharper warnings: one looked
like a 20x coverage gap until the sites were dumped, and the other
looked like the largest dead-code population in the corpus until it
was traced to a build flag.

| Pattern | Rewrite | Measured |
| --- | --- | --- |
| `MOV r, imm` + `CMP`/ALU reading it, beyond what "MOV constant foldable" reports | fold the constant into the consumer's immediate | **Closed.** pairscan shows ~7,000 `mov rcx, imm ; cmp rax, rcx` pairs in libxul against 365 findings, which reads as a 20x hole. Dumping the sites closes it: the constants are genuinely 64-bit (`0x7fffffffe`, `0x1fffffffffffe`, `0xfff9800000000000`) and not imm32-encodable, which is *why* the compiler materialized them. The check is right and the gap is not a gap -- the shape count was measuring the population of an encoding condition it had not applied |
| dead `MOV RBP, RSP` | delete | **Rejected. 34,930 sites in libxul, ~0 in the other five** (libc 1, libcrypto 17, go 10). Provable by register liveness -- `PUSH RBP` ; `MOV RBP, RSP` ; ... ; `POP RBP` in empty and leaf functions, 2,901 of them with the kill literally adjacent -- and unsound anyway: the write is what an asynchronous unwinder's RBP frame chain reads, and deleting it contradicts the CFI. It is also an artifact of one binary's `-fno-omit-frame-pointer`, not a compiler behaviour. The largest-looking dead-code row in the corpus is not a finding |
| `ADD r, imm` + `ADD r, imm` chain (armlint ships this as `check_add_sub_imm_chain`) | one `ADD` | **0 real.** 16,002 pairscan hits, every dumped one on *different* registers (`add r10, 0x4 ; add r9, 0x3`) -- interleaved JIT-style sequences, which the shape key cannot separate from a chain because it collapses register identity. The coupled spelling (`dep,fdead`) is empty |
| `LEA` + `CMOVcc` reading its result | fold the address into the CMOV's memory operand | **Unsound**, 10,679 sites. `CMOVcc r, m` loads unconditionally regardless of the condition; the LEA does not load at all. Any site where the address is only conditionally valid would fault |
| sole-use load + shift reading it | fold into the shift | **Not encodable**, 19,729 sites. A shift takes a memory operand only as its destination, and these consume the loaded value as the shifted operand with a register destination |
| redundant reload of one address (`reload\|same`, `reload\|copy`) | reuse the first value | **7,237** across the corpus (libc 196/Minsn, bash 205, libxul 228, go 108) -- real, and an order of magnitude below every family in the sections above. Worth revisiting only after those ship |
| `XOR r32, r32` + `XOR r32, r32` | -- | **28,516 sites and nothing to fix.** The most frequent flag-coupled pair in the corpus after the compare/branch families, and it is two independent zeroing idioms; the `fdead` tag says only that the first's flag write is dead, which is true of every zeroing idiom |

## Not yet measured

Ideas carried over from armlint's backlog or noted while reading the
corpus, with no population attached. Each needs a sweep before it
earns a row above.

| Item | Notes |
| --- | --- |
| `MOV r, imm` + `TZCNT`/`LZCNT` | 1,375 pairscan sites tagged `waw` (the mov's value overwritten unread), and the split across the family is the whole point: **BSR 1,067, TZCNT 305, BSF 3**. `BSF`/`BSR` leave the destination undefined for a zero source, so the preceding `MOV` is what gives it a defined value and is not dead. `TZCNT`/`LZCNT` define it as the operand size, so for those the `MOV` is dead outright -- a 305-site candidate, not a 1,375-site one. Counting the shape without splitting it would have overstated this by 4.5x |
| one-operand `MUL` whose low half is dead | 415 `dep,waw` sites (`mul rdx ; mov rax, rdx`, the low half in RAX overwritten unread). `MULX` (BMI2) produces the high half without writing RAX/RDX, so this is a `-m bmi2` candidate alongside the shipped SHLX/SHRX/SARX and ANDN checks. MULX is unsigned-only, so the 517 one-operand `IMUL` sites in the same shape do not qualify |
| `MOV r, r` + shift/ALU (the APX NDD shape) | 270,543 adjacent sites, the second-largest family in the corpus. Already covered by "missing APX NDD" under `-m apx`; recorded here only so the size of the population is not mistaken for an uncovered one |
| split macro-fusion pairs | Informational, the class armlint files under its `-a` audit idea: a `CMP`/`TEST` separated from its `Jcc` cannot fuse. Needs the per-core fusion tables from the optimization manual, and has no rewrite -- it is a scheduling complaint, not a peephole |
| constant-condition `Jcc` after a zero test | `TEST r, r` and `CMP r, 0` both clear CF and OF, so `JB`/`JO` are never taken and `JAE`/`JNO` always are. armlint's equivalent row measured empty on AArch64; unmeasured here |
