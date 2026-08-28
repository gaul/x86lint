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
encoding already offers to delete. By shape this is the largest and
most uniform family in the corpus: 229,302 adjacent sites, present at
3,834-7,214 per Minsn in *every* binary, independent of language.

Both halves have now shipped, and the shape count held for one and not
the other -- 6,245 realized of 81,510 for the compare fold, 1,631 of
147,792 for the ALU fold. The two notes below say why, and the second
is the more useful lesson: the uniformity above is a property of the
*shape*, and the ALU half loses it entirely once the rewrite's own
operand condition is applied.

| Pattern | Rewrite | 2026-08 sweep (d1, rate/Minsn) |
| --- | --- | --- |
| ~~sole-use load + `CMP`/`TEST` of the loaded register~~ | ~~fold the load into the compare~~ | **Done: "load foldable into compare".** Swept population 81,510; realized **6,245** (libc 73, libstdc++ 69, bash 105, libcrypto 58, libxul 5,854, go 286). See the realized-vs-predicted note below |
| ~~sole-use load + `ADD`/`SUB`/`ADC`/`SBB` reading it~~ | ~~fold into the ALU~~ | **Done: "load foldable into ALU"**, with the logic and multiply rows below. Swept population 147,792 across the three rows; realized **1,631** (go 1,150, libxul 470, libcrypto 5, libc 4, bash 2, libstdc++ 0, ld.so 0). The sweep overcounted by 90x, for a reason worth reading: see the operand-role note below |
| ~~sole-use load + `AND`/`OR`/`XOR` reading it~~ | ~~same~~ | **Done**, same check. 22,326 swept |
| ~~sole-use load + `IMUL`/`MUL` reading it~~ | ~~same~~ | **Done**, same check, including the one-operand MUL/IMUL forms. 2,752 swept |

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

These are the generalization of the shipped "load foldable into extend",
which fires **49** times on libxul and **0** on libc.

**The operand-role overcount.** `defuse`'s `load->addsub` row counts a
load whose sole use is an arithmetic instruction. It does not ask WHICH
operand of that instruction the loaded register is, and only one of the
two roles folds. When the loaded register is the source
(`mov rcx, [m] ; add rbx, rcx`) it folds to `add rbx, [m]`. When it is
the destination (`mov rcx, [m] ; add rcx, rbx`) it is read and written,
so it is not dead, and the only fold with the memory in the other slot
is `add [m], rbx`, which stores where the original did not.

An independent objdump pass over libc splits the adjacent pairs
**634 destination-is-loaded, 122 source-is-loaded** -- the unfoldable
role is 5x the foldable one, and the C and C++ compilers prefer it
because accumulating into the loaded register is what their register
allocators produce. Applying deadness to those 122 leaves **4**, which
is exactly what the check reports. Two independent counts agreeing on 4
is the strongest confirmation available that neither is wrong.

So the ALU family's 147,792 swept sites are a 90x overcount of a 1,631
finding population, where the compare family's 81,510 was a 13x
overcount of 6,245. Same tools, same corpus, same discipline, and an
order of magnitude difference in how much the shape overstated the
rewrite -- because the compare fold's consumer reads its operand and
the ALU fold's consumer usually writes it. A shape count is an upper
bound whose tightness is a property of the specific rewrite, and cannot
be guessed from another rewrite's experience.

The realized population also inverts by language. go supplies 1,150 of
the 1,631 (697/Minsn against libxul's 15.6), nearly all of it in
`crypto/internal/fips140`'s field arithmetic, where the gc backend
spills a bignum limb to the stack and reloads it into an ADC chain
without ever folding the reload. That is one backend's habit, not a
cross-language family like the compare fold.

**Realized against predicted, and what the gap is made of.** The shipped
compare check reports 6,245 findings where the sweep counted 81,510
adjacent sites -- 13x on libxul, 5x on libc. armlint's rule explains the shape
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
3,804). x86lint folded `LEA` into a memory operand but not `ADD`; it
now does both, and the ADD half turned out to be two orders of
magnitude smaller than its AArch64 model, for a reason worth the
paragraphs below.

| Pattern | Rewrite | 2026-08 sweep (d1, rate/Minsn) |
| --- | --- | --- |
| ~~`ADD`/`SUB`/`INC`/`DEC` whose sole use is as the base of a following access~~ | ~~fold into the addressing mode~~ | **Done: "ADD foldable into memory".** Swept population 219,285; realized **710** (libxul 706, go 2, bash 1, libstdc++ 1, libc 0, libcrypto 0, ld.so 0) -- a 309x overcount, and the reason is the sharpest of the three. See the LEA-displacement note below |
| ~~`LEA` + `ADD` reading its result~~ | ~~one `LEA`~~ | **Done: "ADD foldable into LEA".** Swept population 45,779; **39,715 sound folds** in libxul alone, of which **2,678** are reported (go 1, everything else 0). The 37,037 excluded are not unsound -- they are not improvements. See the slow-LEA note below. `SUB` reading the result never folds at all |

Both reuse the register-liveness machinery behind "LEA foldable into
memory", plus the same encodability condition (the combined address
must still fit one index and a 32-bit displacement). Both need one
gate that check does not: `LEA` writes no flags and `ADD`/`SUB` do, so
the fold is legal only where the flags are dead past it. `SUB` by an
immediate folds as a negated displacement; `SUB` by a register does
not fold at all, since an addressing mode cannot negate its index.

**Why the ADD fold is nearly empty on x86, and why armlint's twin is
not.** 710 findings against 219,285 swept sites is the largest
overcount in this file, and unlike the ALU fold's it is not an operand
role that explains it. It is that **x86 has LEA and AArch64 does
not**. An AArch64 compiler with no three-operand address instruction
must materialize a scratch address with `add x8, x0, #16`, and x8 then
dies into the single access that uses it -- which is exactly the shape
`check_add_ldr_imm_offset` folds 8,428 times. An x86 compiler reaches
for `LEA` in that role, where x86lint already folds it, and emits
`ADD` almost only to advance a pointer in place, where the destination
stays live by construction because the next iteration needs it.

An independent objdump pass over libc makes this concrete. Of **716**
adjacent ADD-then-memory-base pairs: **378** have the destination
provably live, **311** end at a control transfer within sixteen
instructions, and the **27** that are dead are every one of them
`sub rD, rS`, which no addressing mode can spell. libc's true
population is **0**, which is what the check reports. The most
instructive site is the one the compiler had already solved:

```
add r12, 0x1 ; mov BYTE PTR [r12-0x1], al
```

The `-1` is already folded into the store's displacement, and the
increment survives because r12 is the live loop pointer. That is the
opposite of a fold opportunity, and it is the modal shape of the
219,285.

What is left is a C++ and Rust check: **706 of the 710 are libxul**,
across 523 functions, in naga, webrender, neqo, `core::slice::sort`
and SpiderMonkey -- rustc and clang at -O2 emitting `add reg, imm`
into a value that dies in one access. It is the third family in a row
whose realized population inverts by language, and the third whose
shape count said nothing useful about its size. A borrowed check needs
its host architecture's own measurement, not the donor's finding
count: armlint's 8,428 predicted nothing here, because the fact that
made it large on AArch64 -- no LEA -- is false on x86.

Real sites, from glibc:

```
add rcx, 0x1  ; movzx eax, byte ptr [rcx]        ->  movzx eax, byte ptr [rcx+1]
add rax, rcx  ; mov r14, qword ptr [rax]         ->  mov r14, qword ptr [rax+rcx]
add r14, rbx  ; movsx eax, byte ptr [r14+0x18]   ->  movsx eax, byte ptr [r14+rbx+0x18]
```

go's rate (311) is an order of magnitude below the C and C++ binaries;
this is a clang/gcc shape, and the gc backend largely does not emit it.

**The slow-LEA exclusion.** This is the first row in this file whose
binding constraint is neither soundness nor shape but *desirability*,
and it is the one that changed what shipped. All 39,715 libxul folds
compute the identical value and pass the flag gate. But an LEA using
base, index and displacement together is the "slow LEA": 3 cycles on
port 1 alone from Sandy Bridge onward, where every two-component form
is 1 cycle on two ports. Folding a fast LEA plus an ADD -- 2 cycles
across two ports -- into a slow one buys a uop and three or four bytes
for a cycle of latency and a port. That is a trade, not an
improvement, and **99.6% of the sound folds land on it**: the modal
site is `lea rcx, [rax+r13] ; add rcx, 8`, a two-component LEA that an
ADD of a field offset would turn slow.

So the check reports only folds whose result stays within two
components, which is 2,678 of the 39,715. What survives is a single
clean shape -- `lea rax, [rdx*8] ; add rax, r13` -> `lea rax, [r13+rdx*8]`
-- that wins on all three axes at once: one instruction instead of
two, one uop instead of two, and **one cycle instead of two**, since
the result has no displacement and stays fast. LLVM emits it
constantly for `x * 3`, `x * 5` and `x * 9` strength reduction and for
struct-array indexing, and never rejoins the halves.

Recording the 37,037 here rather than reporting them is the point of
the row. A sound rewrite that may cost a cycle on a dependency chain
is not what this tool emits, and the only way to know which side of
that line a family falls on is to measure the result's encoding rather
than the input's shape.


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
| ~~LEA foldable into memory~~ | libxul **1,326**; go 153; libc 0 | libxul 14,923; go 658; libc 254 | **Investigated and mostly closed.** The 12x figure was the wrong measurement: `defuse`'s `lea->addr` counts a LEA whose sole use is an address and asks nothing about whether the combined address is *encodable* or the register provably dead. See the breakdown below; the check gained 111 findings from one real fix and the rest of the residue is refusals it should be making |
| redundant TEST after flags | libxul 556; libc 7; go 4 | `cmp0` d1: logic 329, arith 1,637, **test-width 405** | The logic and arith rows are covered (the check searches a window, not just d1, and arith is an upper bound gated on CF/OF deadness, exactly as documented). The test-width row -- 405 sites, 357 of them libxul -- is the check's exact-register match refusing a TEST that names a different width of the producer's register. That refusal is deliberate and sound (`AND EAX, EBX` clears bits 63:32 where `TEST RAX, RAX` reads a sign bit the narrow form never sees); the open question is whether the narrowing direction, where the producer is the *wider* one, is admissible |

**Breaking down the LEA fold's residue.** Classifying every adjacent
LEA-then-memory-base pair in libc with an independent objdump pass,
against the 542 the shape count admits:

```
235  the LEA is RIP-relative        (218 of them feed an indexed consumer)
111  two indexes between the pair   unfoldable: one addressing mode, one index
  1  a segment override on the consumer
195  candidates needing only liveness -- of which 9 are actually dead
```

So libc's true population is about **10**, not 254, and the check
reporting 0 was nearly right rather than 254x wrong. One real fix came
out of the investigation and shipped: the deadness walk used
`reg_live_after`, which ends at every control transfer, and a folded
address is very often consumed by a compare or a load the next
instruction branches on. Switching to `reg_live_after_branch` -- the
both-successors split written for the compare fold -- took libxul from
1,215 to **1,326**, 111 gained and none lost, all of them the shape
`lea rdi, [rsi+rdi*4] ; cmp [rdi], r14d ; je`. It did nothing for libc,
whose residue is encodability rather than liveness.

The **RIP-relative arm** is the one piece still unimplemented, and it
is small. `lea rax, [rip+X] ; mov r14, [rax]` is `mov r14, [rip+X']`,
which the assembler resolves; but RIP-relative addressing admits no
index, and **95% of the RIP pairs feed an indexed consumer** -- the
jump-table and global-array shape `lea rax, [rip+X] ; mov ecx,
[rax+rdx*4]`, which has no one-instruction spelling. What is left is
**89 sites** (libxul 88, libc 1), and it carries the actionability
caveat armlint records for `adrp`+`add`: the LEA usually carries a
relocation, so this is a codegen suggestion rather than a byte patch.

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
