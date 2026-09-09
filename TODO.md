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

Figures marked **2026-09 Rust sweep** add three binaries totalling
3.2M instructions, mined for what a Rust-heavy corpus shows that a C
and C++ one does not: `geckodriver` (rustc, 715k) and `http3server`
(rustc, 549k) from the Firefox tree, and uutils `coreutils` 0.11.0
(1.98M), the only one of the three built outside this tree. uutils
ships stripped, so it was swept with `-a`; treat its absolute numbers
as upper bounds, though `geckodriver`'s symbol-restricted run
reproduces the same ranking.

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

The line is drawn per core, which turns the exclusion into a
target-axis question rather than a closed one. Agner Fog's instruction
tables (read 2026-09) give the three-component form 3 cycles on port 1
on Skylake, no separate row at all on Ice Lake and Tiger Lake -- their
"with index" form is 1 cycle on p15, the same as two components -- and
2 cycles as 2 ops on Zen 3 through Zen 5. On Ice Lake and later the
37,037 win on every axis the check measures. Filed as [#28](https://github.com/gaul/x86lint/issues/28),
together with the other per-core caveats a `-t` knob would gate.


## Constants

| Pattern | Rewrite | 2026-08 sweep (d1, rate/Minsn) |
| --- | --- | --- |
| `MOV r, imm` of a constant still live in another register | `MOV rD, rS` -- 2-3 bytes against the 5-6 the immediate form costs | **27,796** at d1, of 41,108 at all distances. libc 113 (322), libstdc++ 126 (352), bash 90 (354), libcrypto 124 (150), libxul 26,982 (897), go 361 (219) |

This is the one row in this file whose population may survive contact
with the rewrite, and the reason is worth stating. Every count that
collapsed was defined by *shape*: `lea->addr` never asked whether the
combined address was encodable, `load->addsub` never asked which
operand the loaded register was. `defuse`'s `remat|movimm` row is
defined by the rewrite's own precondition -- the constant still being
live in another register is exactly what makes the copy legal -- so the
erosion here should be the check's proof being stricter than defuse's
block-local model, not a condition the count ignored.

Two corrections to an earlier draft of this row, both from measuring
the sites rather than the shape:

* **The size claim was wrong.** It read "3 bytes against up to 10 for a
  `MOVABS`". Every constant in the population fits imm32 -- **zero
  `movabs` sites in libc or libxul** -- so the saving is a uniform 2-3
  bytes (`mov edi, 0x2` at 5 bytes becomes `mov edi, r10d` at 3), never
  the 7 a 64-bit immediate would give.
* **16% of the population is the constant zero** (6,239 of libxul's
  39,777), and those must be excluded rather than reported. The shipped
  "suboptimal MOV zero" check already covers them, and its advice --
  `XOR r, r` -- is strictly better than a copy, since XOR is eliminated
  at rename *and* breaks the dependency where a copy creates one.

Three costs, in decreasing order of how much they should worry a
future implementer:

* **It serializes two independent instructions.** The dominant shape is
  glibc's `mov r10d, 0x2 ; mov edi, 0x2`, two constant materializations
  with no dependency between them, each 1 cycle, free to issue in
  parallel. The rewrite makes the second depend on the first. Whether
  that costs anything turns entirely on **move elimination**, and this
  is the piece to settle first: a `MOV r64, r64` handled at rename is 0
  latency and 0 ports, which would make the copy better than the
  immediate on every axis, but GPR move elimination is reportedly
  *disabled* from Ice Lake onward. Agner Fog's tables (read 2026-09)
  settle it per core: `MOV r32/64, r32/64` is latency 0 by renaming on
  Zen 1 through Zen 5, 0-1 and "may be eliminated" on Ivy Bridge
  through Coffee Lake, and a full cycle on p0156 with no elimination on
  Ice Lake and Tiger Lake, as on Sandy Bridge. The tables have no Alder
  Lake section, so Golden Cove and later stay unverified. On Ice Lake,
  then, this is the slow-LEA situation: sound, tens of thousands of
  sites, and trading a cycle for two bytes -- which makes the row a
  client of the target axis in [#28](https://github.com/gaul/x86lint/issues/28),
  reportable where the copy is free and refused where it is not.
* **Compilers do this deliberately, in reverse.** Rematerialization is
  a standard register-allocator technique, and LLVM marks `MOV32ri` and
  `MOV64ri` trivially rematerializable precisely so the allocator can
  duplicate a constant rather than keep it live; a fresh constant is
  also the canonical way to break a dependency. So a finding here is
  often the compiler's choice rather than its oversight, which is not
  true of anything that shipped this session.
* **Live-range extension, but only at distance.** The copy needs its
  source live at the use, which can add register pressure. At d1 the
  objection is vacuous -- the definition is one instruction away -- and
  d1 is 68% of the population. It grows with distance, so an
  adjacency-only v1 mostly escapes it. (An earlier draft of this row
  claimed the rewrite "frees a register rather than pinning one". It
  does neither.)

The proof burden is also new in kind. Every shipped check proves a
register **dead**; this one must prove a register holds a **specific
value**, which needs a small constant-tracking state that resets at
branch targets, calls and any write to the source, with width traps
(`mov ecx, 5` establishes RCX = 5; `mov cl, 5` does not). More
machinery than any existing check, and more places to be wrong.

armlint has the same candidate open from its own pairscan sweep.

## Constant conditions (both arms shipped, 2026-09)

A flag producer whose result is known at assembly time makes its
consumer's condition a constant, so the `Jcc`, `CMOVcc` or `SETcc`
reading it has one outcome and the compare feeding it is pure waste.
Two arms, both found by the 2026-09 Rust sweep, both counted with the
side-entry gate described below. Site counts come from an independent
whole-binary disassembly pass, quoted against the symbol-restricted
instruction counts the rest of this file uses.

**This family is done.** Both arms ship as checks -- "constant condition
after zeroing" and "constant condition after immediate" -- for **1,543
findings** across the corpus against the sweep's predicted 1,330, sharing
a consumer search (`constant_condition_consumed`), a gap rule
(`known_reg_gap_transparent`) and a bit-range model (`gpr_bit_range`).
Nothing here is left open. What follows is kept for the measurements,
and for the ways the counting went wrong on the way to them -- the
transferable part:

| Pattern | Rewrite | 2026-09 sweep (d1, rate/Minsn) |
| --- | --- | --- |
| ~~zeroing idiom (`XOR r, r` / `SUB r, r`) + `TEST r, r` of any width of that register~~ | ~~delete the `TEST`; `CMOVE` -> `MOV`, `JE` -> `JMP`, `JNE`/`CMOVNE` deleted~~ | **Done: "constant condition after zeroing".** Swept population 809 (uutils 521, libxul 276, geckodriver 7, http3server 5, and 0 in go, libc, bash, ld.so, libcrypto and libstdc++); realized **914** (uutils 562, libxul 338, geckodriver 9, http3server 5, 0 everywhere else). The first row in this file to realize *more* than its sweep predicted -- see the note below |
| ~~`MOV r, imm` + `TEST r, r` or `CMP r, imm2`~~ | ~~same, with the outcome decided by the two immediates~~ | **Done: "constant condition after immediate".** Swept population 521 (libxul 457, uutils 52, geckodriver 6, and 0 in every C binary); realized **629** (libxul 520, uutils 79, geckodriver 20, http3server 9, libcrypto 1, 0 everywhere else) -- see the note below on what the sweep got wrong in both directions |

**What the immediate arm's sweep got wrong, in both directions.** Its raw
count was 457 libxul sites, its realized count 520, and the two numbers
agree by accident: three separate errors, two of them large and pulling
opposite ways. The census took *any* third instruction as the consumer,
which cost nothing here (455 of the 457 do read the condition) but was
luck, not method. Against that, it counted only an adjacent compare,
where the check searches `APX_NDD_WINDOW`: 65 of libxul's 520 have a gap
instruction between the load and the compare, and the site sets agree
exactly otherwise (census-only 0). The third error was the interesting
one, and it was mine rather than the census's. The first draft of the
check copied the zeroing arm's rule and refused 8- and 16-bit producers,
on the argument that `mov cl, 5` leaves bits 63:8 unknown -- true of a
wider compare, and irrelevant to `test cl, cl`, which reads exactly the
bits the load wrote. That draft found 172. Splitting the census showed
the refusal was throwing away **323 of 455** libxul sites, so the check
carries a bit-range model (`gpr_bit_range`) instead of a width test, and
gets the high-byte names right while it is there: AH covers bits 15:8,
so `mov al, 5 ; test ah, ah` proves nothing. A gate that looks like a
detail is worth measuring before it is believed.

The zeroing arm now carries the same model, for symmetry rather than for
yield. It costs nothing and gains nothing on real code: a census of
narrow zeroing idioms (`xor cl, cl` and the like) followed by a
same-width `TEST` and a consumer finds **0 sites in both libxul and
uutils**, since compilers zero with `xor r32, r32`, and the corpus
output is byte-identical across all ten binaries before and after. What
it buys is that one rule now decides both arms, stated as bits rather
than as widths, and that the high-byte names are right in both:
`xor al, al` proves nothing about `test ah, ah`.

**Realized above predicted, for once, and why.** Every other row in this
file overstated its rewrite by between 5x and 300x. The zeroing arm
understated it, by 13%: 914 findings against 809 swept sites, with no
site the sweep found and the check misses. The sweep was an objdump pass that matched
the `TEST` **immediately** after the zeroing instruction, because that is
what a quick census can express; the check searches `APX_NDD_WINDOW` past
instructions that leave the tested register alone. Classifying libxul's
338: 287 adjacent, 44 with one intervening instruction, 7 with more. The
gaps are exactly what the shape suggests -- a second zeroing
(`xor r8d, r8d ; xor eax, eax ; test r8d, r8d`), a spill of the zero, an
alignment NOP. So the discipline that every other row demonstrates in one
direction holds in the other too: a shape count is not the rewrite's
count, and the sign of the error is not predictable either.

The 16 libxul sites where a zeroing producer met a same-width `TEST` were
already reported as "redundant TEST after flags" (556 there before, 540
after); they now carry the stronger claim instead. All six C and Go
binaries are byte-identical to the previous build's output.

The first arm is `defuse`'s `cmp0|test-width` row, which the
"Coverage gaps" table below had recorded as an open question about
whether the narrowing direction is admissible. Dumping the sites
answers it by dissolving it: **559 of 559 uutils sites at d1 are a
zeroing idiom**, and the width mismatch is not a width problem at all.

```
xor   ecx, ecx
test  rcx, rcx        <- tests a register just proven zero
cmove rbx, rax        <- ZF is 1, so this always moves
```

A zeroed register is zero in every width, so every flag is a constant
-- ZF=1, SF=0, CF=OF=0, PF=1 -- independent of the `TEST`'s operand
size. That is why the width mismatch that makes "redundant TEST after
flags" refuse the site is exactly what hides it, and why the claim
available here is stronger than that check's: the condition is decided,
not merely recomputed, which also covers the `CMOVcc` and `SETcc`
consumers that a redundant-compare framing cannot reach. uutils'
consumers are 328 `CMOVE`, 135 `JE`, 44 `JNE` and 11 `CMOVNE`;
libxul's are 168 `JNE`, 95 `JE`, 5 `CMOVNE` and 4 `SETcc`.

Real sites, from libxul and from uutils:

```
xor edx, edx  ; test dl, dl   ; jne  +0xf     (never taken; cdef_filter_block_c)
mov r10d, 0x3f; test r10d,r10d; jg   -0x70    (always taken; VP8EnterCritical)
mov ecx, 0x10 ; cmp  rcx,0x28 ; ja   +0x79    (never taken; wasm2c bounds check)
```

**The side-entry gate is the whole check.** Raw adjacency counts the
first arm at 1,096 on uutils, 1,381 on libxul and 704 on go. Most of
those are unsound: the `TEST` is a branch target reached from paths
where the register is not zero, the shape being a block that falls into
a shared join. **All 704 of go's are side entries**, so go's true
population is zero, and the arm is absent from every C binary in the
corpus. The gate has a second edge that is easy to get backwards: a
site where the *zeroing instruction* is the branch target is still
sound, since every entry there executes it, and rejecting those drops
uutils from 521 to 189. Between the two errors this family can be
counted as anything from 189 to 1,096.

Neither arm is concentrated in one file: 250 libxul functions for the
zeroing arm, 242 for the immediate arm -- though wasm2c's generated
dispatcher supplies 93 of that arm's 457, so the row carries a smaller
version of the `mov rbp, rsp` caveat.

Distance is not needed: uutils' histogram is 559 at d1 against 32 at
d2 and 13 beyond, so adjacency plus the existing flag-producer walk
covers the population.

The proof burden was the lightest of any row in this file. The first arm needs
no constant model at all -- a zeroing idiom is recognized by its two
operands naming one register -- and the second needs a single
immediate, where the `remat|movimm` row above needs a tracked constant
per register. What both needed beyond the shipped machinery was a flag
*consumer* search: `flags_live_after` already walks forward sixteen
instructions, but it answers whether the flags are read, not by which
condition, and these checks have to name the consumer and see that it
reads one.

The shipped "redundant TEST after flags" reported 28 on uutils and 9 on
geckodriver, so this was a gap rather than a re-count of covered ground.
It stayed one: on libxul the zeroing arm took over 16 sites that check
had been reporting (556 to 540) and added 322 it could not see.

Two cautions were written here for an implementer, and both survived
into the shipped checks. The rewrite deletes instructions, so as a byte
patch it would be a `NOP` fill plus a `Jcc`-to-`JMP` opcode swap (same
length for both rel8 and rel32); as a codegen report it is one finding
per site, which is what both checks emit. And a never-taken branch means
the code it guards is unreachable, a stronger statement about the
compiler's output than any other row in this file makes -- said outright
in both README entries rather than implied.

## Coverage gaps in shipped checks

A population counted independently says nothing about which spellings
a *shipped check's* decoder chain accepts. armlint found two real
holes this way, both of which had been reporting plausible numbers off
a fraction of their own population. Measuring each x86lint check
against the shape it claims found one gap worth investigating and one
that closed itself.

| Check | Reports | Population at d1 | Notes |
| --- | --- | --- | --- |
| ~~LEA foldable into memory~~ | libxul **1,359**; go **184**; libc **2** | libxul 14,923; go 658; libc 254 | **Investigated and mostly closed.** The 12x figure was the wrong measurement: `defuse`'s `lea->addr` counts a LEA whose sole use is an address and asks nothing about whether the combined address is *encodable* or the register provably dead. See the breakdown below; the check gained 111 findings from a liveness fix and 87 more from the RIP-relative arm, and the rest of the residue is refusals it should be making |
| redundant TEST after flags | libxul 556; libc 7; go 4 | `cmp0` d1: logic 329, arith 1,637, **test-width 405** | The logic and arith rows are covered (the check searches a window, not just d1, and arith is an upper bound gated on CF/OF deadness, exactly as documented). The test-width row -- 405 sites, 357 of them libxul -- is the check's exact-register match refusing a TEST that names a different width of the producer's register. That refusal is deliberate and sound (`AND EAX, EBX` clears bits 63:32 where `TEST RAX, RAX` reads a sign bit the narrow form never sees); the question this row left open -- whether the narrowing direction, with the producer the *wider* one, is admissible -- is now answered, and not in the terms it was asked: **the test-width row is almost entirely the zeroing idiom**, where every width agrees because the register is zero. See "Constant conditions" above, which supersedes this row -- the sites it names are not a widening puzzle but a decided condition, and are now reported as one by "constant condition after zeroing" (338 findings on libxul) |

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

The **RIP-relative arm** has since shipped, and it is the one
prediction in this file that landed. `lea rax, [rip+X] ; mov r14, [rax]`
is `mov r14, [rip+X']`, which the assembler resolves; but RIP-relative
addressing admits no index, and **95% of the RIP pairs feed an indexed
consumer** -- the jump-table and global-array shape `lea rax, [rip+X] ;
mov ecx, [rax+rdx*4]`, which has no one-instruction spelling. Sizing it
that way, through the condition the *rewrite* imposes rather than the
shape, predicted **89 sites**; the check reports **87** (libxul 33, go
31, libstdc++ 13, libcrypto 8, libc 2). Every earlier row in this file
overstated its rewrite by between 5x and 300x, and the difference is
not the tools -- it is that this estimate applied the encodability
condition before counting, and the others did not.

It carries the actionability caveat armlint records for `adrp`+`add`:
where the LEA holds a relocation this is a codegen suggestion rather
than a byte patch.

## Investigated and closed (2026-08 sweep)

Candidates measured and set aside, recorded so they are not
re-investigated. Most are rejected outright; one is sound and
merely blocked on a knob the tool does not have. The first two are the
sharper warnings: one looked like a 20x coverage gap until the sites
were dumped, and the other looked like the largest dead-code population
in the corpus until it was traced to a build flag.

| Pattern | Rewrite | Measured |
| --- | --- | --- |
| `MOV r, imm` + `CMP`/ALU reading it, beyond what "MOV constant foldable" reports | fold the constant into the consumer's immediate | **Closed.** pairscan shows ~7,000 `mov rcx, imm ; cmp rax, rcx` pairs in libxul against 365 findings, which reads as a 20x hole. Dumping the sites closes it: the constants are genuinely 64-bit (`0x7fffffffe`, `0x1fffffffffffe`, `0xfff9800000000000`) and not imm32-encodable, which is *why* the compiler materialized them. The check is right and the gap is not a gap -- the shape count was measuring the population of an encoding condition it had not applied |
| dead `MOV RBP, RSP` | delete | **Rejected. 34,930 sites in libxul, ~0 in the other five** (libc 1, libcrypto 17, go 10). Provable by register liveness -- `PUSH RBP` ; `MOV RBP, RSP` ; ... ; `POP RBP` in empty and leaf functions, 2,901 of them with the kill literally adjacent -- and unsound anyway: the write is what an asynchronous unwinder's RBP frame chain reads, and deleting it contradicts the CFI. It is also an artifact of one binary's `-fno-omit-frame-pointer`, not a compiler behaviour. The largest-looking dead-code row in the corpus is not a finding |
| `ADD r, imm` + `ADD r, imm` chain (armlint ships this as `check_add_sub_imm_chain`) | one `ADD` | **0 real.** 16,002 pairscan hits, every dumped one on *different* registers (`add r10, 0x4 ; add r9, 0x3`) -- interleaved JIT-style sequences, which the shape key cannot separate from a chain because it collapses register identity. The coupled spelling (`dep,fdead`) is empty |
| `LEA` + `CMOVcc` reading its result | fold the address into the CMOV's memory operand | **Unsound**, 10,679 sites. `CMOVcc r, m` loads unconditionally regardless of the condition; the LEA does not load at all. Any site where the address is only conditionally valid would fault |
| sole-use load + shift reading it | fold into the shift | **Not encodable**, 19,729 sites. A shift takes a memory operand only as its destination, and these consume the loaded value as the shifted operand with a register destination |
| redundant reload of one address (`reload\|same`, `reload\|copy`) | reuse the first value | **7,237** across the 2026-08 corpus (libc 196/Minsn, bash 205, libxul 228, go 108), about 7,700 with the Rust sweep. **Dissected 2026-09 and filed as [#29](https://github.com/gaul/x86lint/issues/29).** The heap, global and TLS sites are atomics, `volatile` signal flags and wasm2c sandbox memory: a plain load that survives -O2 CSE with no store between is one the source forbade merging, so for those addresses the shape selects for the unsound case. The stack sites are spill reloads -- **2,666** in libxul, 365 in uutils, 65 in libc, 2 in go -- and sound as thread-private memory, about 2,900 of them within the check window. Blocked on the tool's standard that no finding changes the set of memory accesses; see the note below |
| `MOV r, imm` + `TZCNT`/`LZCNT` (the defensive default) | delete the `MOV` | **Sound, 305 sites, and blocked on a knob the tool does not have.** See the note below; the knob is filed as [#28](https://github.com/gaul/x86lint/issues/28) |
| ~~one-operand `MUL` whose low half is dead~~ | ~~`MULX`~~ | **Done: "missing MULX" (`-m bmi2`).** The row said 415 sites; the operand condition takes it to **101**, and the check reports **94**, all in libxul. See the note below -- this is the second estimate in this file to land, and for the same reason as the first |
| `XOR r32, r32` + `XOR r32, r32` | -- | **28,516 sites and nothing to fix.** The most frequent flag-coupled pair in the corpus after the compare/branch families, and it is two independent zeroing idioms; the `fdead` tag says only that the first's flag write is dead, which is true of every zeroing idiom |
| `PUSH r` + `POP r` of one register (an [#24](https://github.com/gaul/x86lint/issues/24) candidate) | delete the pair | **Rejected: the shape is a stack-clash probe.** 0 sites in compiled code across eight binaries (libxul, geckodriver, uutils, go, bash, libc, libcrypto) except **89** in libstdc++, every one GCC's `-fstack-clash-protection` probe in a function whose only frame activity is a call to a `noreturn` function -- `endbr64 ; push rax ; pop rax ; mov edi, 8 ; sub rsp, 8 ; call g`, reproduced with gcc 16 at `-O2 -fstack-clash-protection` and gone under `-fno-stack-clash-protection`. The push touches the page below the return address so a guard page faults before the callee runs; deleting the pair removes the protection. The shape selects for the intentional case, as the reload row's heap half does |
| adjacent `ADD`/`SUB rsp, imm` pairs (an [#24](https://github.com/gaul/x86lint/issues/24) candidate) | one adjustment | **Rejected: 3 real sites.** 38 adjacent pairs across the same eight binaries: **29** have a direct branch onto the second, a join point the incoming-edge gate refuses anyway; **6** are crti/crtn's empty `.fini` (`sub rsp, 8 ; add rsp, 8` with nothing between); and 3 are LLVM's post-call argument-area pop ahead of the epilogue's own adjustment, in Rust `Debug::fmt` (geckodriver 2, libxul 1) |

**MULX: the operand condition the shape count missed.** One-operand
`MUL` is pinned to fixed registers -- RAX times its operand, product to
RDX:RAX -- so a widening multiply wanting only the high half spends a
second instruction moving it out. MULX is not pinned: one multiplicand
implicitly from RDX, the other from any r/m, both halves named, no flags
written. `mul rdx ; mov rax, rdx` is `mulx rax, rdx, rax`.

The row originally read "415 `dep,waw` sites", and that number was the
shape's, not the rewrite's. **MULX's implicit multiplicand is RDX where
MUL's is RAX**, so the fold needs RDX to hold a multiplicand already --
the instruction must literally be `mul rdx`. Splitting the corpus by
that one condition:

```
mul rdx        182   MULX-eligible; 101 with the `mov rax, rdx` consumer
mul r64        246   needs a `mov rdx, ...` in front: back to two instructions
mul rcx        110   same
memory operand  33   same
32-bit forms    47   same
```

The check reports **94 of that 101**, across 80 libxul functions and
zero everywhere else -- a 93% survival rate against the 1-10% every
population in this file's earlier rows managed. The difference is not
the tools. It is that this estimate applied the encodability condition
before counting, exactly as the RIP-relative arm's did, and those two
are the only estimates here that landed.

Almost every site is the magic-number division idiom, `movabs rdx,
0x20c49ba5e353f7cf ; mul rdx ; mov rax, rdx ; shr rax, 4` -- Firefox
dividing by 1000 and 1000000 for time conversion, 94 times.

Two conditions beyond the operand one: RDX must be dead after the pair,
since MULX has no discard encoding for the low half and RDX is the only
home available without register allocation; and every arithmetic flag
must be dead, since MUL defines CF and OF and MULX writes nothing. IMUL
never qualifies -- MULX is unsigned-only, which is what excludes the 517
one-operand `IMUL` sites in the same shape, including the signed magic
divisions sitting beside these in libxul.

What the check leaves on the table: the MUL is often preceded by a
`mov rax, src` that exists only because MUL demands its multiplicand in
RAX, and MULX would take that operand from any r/m -- three instructions
to one. Only **2 of the 94** have that shape adjacent (the rest reach
RAX through a shift), so anchoring on the MUL and noting the bonus in
the check's documentation was the right trade rather than a backward
window.

**The bit-scan defensive default: right answer, wrong core.** A compiler
writing `mov r8d, 0x40 ; tzcnt r8, rsi` is providing the zero-source
answer, an idiom that exists because `BSF`/`BSR` leave their destination
*undefined* when the source is zero (real silicon preserves it, which is
what the sequence relies on). `TZCNT`/`LZCNT` have no such hole: they
are defined to return the operand size and they write the destination
unconditionally, so for those spellings the `MOV` is dead outright.

The family splits **BSR 1,067, TZCNT 305, BSF 3** across 1,375 pairscan
sites, so counting the shape unsplit overstates the candidate by 4.5x.
The discriminator is mechanical, and the constant itself carries it:

```
mov  r8d, 0x40      0x40 == 64 == the operand size TZCNT already returns.  Dead.
tzcnt r8, rsi

mov  ecx, 0x7f      0x7f is a sentinel, not an answer.
bsr  rcx, rdx
xor  ecx, 0x3f      127^63 = 64 for the zero case; index^63 = 63-index otherwise.
```

Every dumped TZCNT site in libxul -- **108 of 108**, 81 at 64 and 27 at
32 -- has the constant exactly equal to the operand size, with no
exceptions. So the check would be easy to write and easy to gate.

**What blocks it is that the same `MOV` is the false-dependency break.**
`TZCNT` and `LZCNT` treat their destination as a phantom input through
Broadwell, the same erratum class as `POPCNT`, and a `mov r32, imm32` is
a full write with no input, so it cuts the chain. The shipped
"missing POPCNT dependency break" check says exactly this: it declines
to flag a site "when the preceding instruction already redefined the
register -- the mitigation gcc and clang emit", and it names LZCNT and
TZCNT as affected through Broadwell. The motivating site makes the
conflict concrete:

```
mov   r8d, DWORD PTR [rdi+0x20]     <- R8 written
add   r8d, 0xfffffff0               <- and again
mov   QWORD PTR gs:[r8+0x8], rsi
mov   r8d, 0x40                     <- dead value, live mitigation
tzcnt r8, rsi
```

Without the `MOV` the TZCNT inherits a false dependency on that
load-and-add chain, and x86lint would flag the same address with the
opposite advice. Two shipped checks fighting over one instruction is
worse than either finding.

So the fold is correct **only on Skylake and later**, where the phantom
input is gone and the `MOV` is 5-6 bytes and a uop of pure waste. That
makes it a target-microarchitecture-gated check, and `-m` is not that
axis: it selects ISA features -- whether an encoding exists -- not which
core is being tuned for. Adding a target axis for one 305-site check is
a poor trade. Adding it for the family may not be: this row, the
POPCNT/LZCNT/TZCNT dependency break, the length-changing prefix stall,
and the **37,037 slow-LEA folds excluded from "ADD foldable into LEA"**
all carry per-core caveats that currently live in prose. A `-t` knob
would turn several of them into gates at once, and would make this row
and the slow-LEA folds reportable on the same day. That is the argument
for building the axis rather than the check. Filed as [#28](https://github.com/gaul/x86lint/issues/28),
with Agner's per-core LEA and `MOV r,r` rows attached: the slow-LEA
exclusion is Skylake-class only, and the constants row's
move-elimination question is the same axis.

**The reload row, dissected.** `defuse` records a reload when a `MOV`
loads an address the same block already loaded -- same base, index,
scale, displacement, width and segment -- with no store, call or `LOCK`
between and no write to the base or index, and it resets at every
branch target, so its counts already carry the side-entry gate. It
splits sites by what the first load left behind: *same* (the value is
still in the register this load targets, so the load is a duplicate),
*copy* (still in another register, so the load becomes a register
copy) and *clobbered* (gone, which is register allocation rather than a
peephole). libxul's 6,867 same-and-copy sites, by where the address
lives:

```
3,111  heap, dword, same register    atomic loads, 14 of 14 sampled: Glean's EventMetric
                                     re-reading a flags word in hundreds of monomorphized
                                     copies, HarfBuzz refcounts read twice before lock decl,
                                     an nsHttpChannel load before lock cmpxchg
2,666  stack slots                   spill reloads: jpeg_idct_11x11 reloading its loop
                                     index before each of eleven indexed accesses, dav1d's
                                     sgr_5x5_c, libwebp's NearLossless; 2,661 through rbp
  408  gs: segment                   wasm2c RLBox sandbox memory
  211  RIP-relative globals          unsampled in libxul; bash's are terminating_signal
                                     and _rl_caught_signal, volatile signal flags
  471  heap, other widths and copy   unsampled
```

The heap and global halves are unsound by construction: a plain load
that survives -O2 CSE with no store between it and its twin is one the
source told the compiler not to merge, and the binary cannot show the
atomic, the `volatile` or the compiler fence that did it. armlint
reached the same conclusion for its twin row. The stack half is spill
code, created after IR-level optimization and never merged afterwards,
and its rate is ordinary compiled code's: 89/Minsn in libxul, 184 in
uutils, 185 in glibc, 147 in geckodriver, 1 in go. That rules out a
frame-pointer artifact -- libxul, built with frame pointers, has the
lowest rate of the LLVM binaries -- and one backend's habit, though gc
does not produce it. 2,346 of libxul's 2,666 and 315 of uutils' 365 sit
within eight instructions. Two things the check would need beyond the
shipped machinery: a gap rule that permits conditional branches, since
the rewrite lives on the fall-through path and most uutils sites have a
`Jcc` between the loads, where `known_reg_gap_transparent` refuses
every control transfer and permits the memory writes this check must
refuse; and a decision on `rbp`, which is a frame slot only in
functions whose prologue makes it one. What blocks it is not proof but
the standard `check_shift_zero` records -- no finding changes the set
of memory accesses -- and [#29](https://github.com/gaul/x86lint/issues/29)
leaves the choice between a carve-out for thread-private frame slots
and an informational class open. It needs no target axis: deleting a
reload wins bytes, a load-port uop and the cache latency on every core.

The store-to-load form of the same row -- a `MOV` store followed at once
by a `MOV` load of the identical operand, another #24 candidate -- is
outside `defuse`'s census, whose reload category is load-after-load. An
adjacent, exact-operand count over the objdump dumps (a lower bound)
gives **3,328** sites: libxul 2,732 (1,842 frame slots; 813 `gs:` wasm2c
sandbox words; 77 heap; no RIP-relative), libstdc++ 261, uutils 94,
geckodriver 60, libcrypto 60, go 58, libc 33, bash 30, with nine in ten
of the non-libxul, non-go sites on frame slots. The value is still in the
store's source register, so the rewrite is a register copy, or a deletion
when the load targets that register, and the adjacency leaves no gap to
rule on. It is the same spill phenomenon behind the same policy line,
and is recorded on [#29](https://github.com/gaul/x86lint/issues/29) as a
sibling shape.

## Not yet measured

Ideas carried over from armlint's backlog or noted while reading the
corpus, with no population attached. Each needs a sweep before it
earns a row above.

| Item | Notes |
| --- | --- |
| `MOV r, r` + shift/ALU (the APX NDD shape) | 270,543 adjacent sites, the second-largest family in the corpus. Already covered by "missing APX NDD" under `-m apx`; recorded here only so the size of the population is not mistaken for an uncovered one |
| split macro-fusion pairs | Informational, the class armlint files under its `-a` audit idea: a `CMP`/`TEST` separated from its `Jcc` cannot fuse. Needs the per-core fusion tables from the optimization manual, and has no rewrite -- it is a scheduling complaint, not a peephole. The tables are the target axis of [#28](https://github.com/gaul/x86lint/issues/28) |
| ~~constant-condition `Jcc` after a zero test~~ | **Done.** Measured, moved to "Constant conditions" above, and shipped there as both arms: 1,543 findings against the 1,330 the sweep predicted. The CF/OF half this row described (`JB`/`JO` after a zero test) is a subset of the general case |
