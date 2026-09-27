# TODO: candidate analyses

The research-backed backlog of checks considered but not yet
implemented. Implemented checks are documented in
[analyses.md](analyses.md), which [README.md](README.md) indexes; the
soundness model every candidate here has to satisfy is in "Design and
soundness model" there.
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
| ~~`MOV r, imm` of a constant still live in another register~~ | ~~`MOV rD, rS`~~ | **Done, 2026-09-15: "rematerialized constant", gated on move elimination (`-t skylake`, `-t zen`).** 33,218 findings of a 33,456 shape, libxul 32,168. A second, ungated finding came out of the same walk: "redundant MOV constant", 238 sites where the register already holding the value is the destination, so the move is dead rather than replaceable |

**This is the one row in this file whose population survived contact with
the rewrite**, and it was predicted to, for the right reason. Every count that
collapsed was defined by *shape*: `lea->addr` never asked whether the
combined address was encodable, `load->addsub` never asked which
operand the loaded register was. `defuse`'s `remat|movimm` row is
defined by the rewrite's own precondition -- the constant still being
live in another register is exactly what makes the copy legal -- so the
erosion here should be the check's proof being stricter than defuse's
block-local model, not a condition the count ignored.

**Measured, and it held.** Every other candidate this session collapsed
under its own conditions -- the CAS loop 614 to 19, the vector fold 18,236 to
583, the scalar siblings 470 to 12. This one goes 34,155 to **33,248**, which
is 97%, and its adjacent half comes in 11% *above* defuse's d1 estimate rather
than below it. The reason is the one the paragraph above gives: the row's
population was defined by the rewrite's own precondition -- the constant still
being live in another register -- and not by a shape that the conditions would
later cut down. A count defined that way is the count.

The shipped-check machinery is what makes the figure trustworthy rather than
another estimate: the candidate tracks a value per register, records only the
32- and 64-bit `mov r, imm` forms (a 32-bit write zero-extends, so `mov eax,
5` really does establish RAX = 5, where `mov al, 5` establishes nothing about
the other 56 bits), clears every register an instruction writes, and clears
the whole map at a call, at any control transfer, at a branch target and at a
decode error. libc's 116 adjacent sites against defuse's 113 is the
independent corroboration.

Two things the measurement found that the row did not say:

* **238 sites are a stronger finding than this row describes.** The register
  that already holds the value is the destination itself, so the `mov` is not
  a copy opportunity but dead outright -- libxul 188, libstdc++ 31, go 18.
  Those want deleting, not rewriting, and no target question arises, so they
  ship ungated.
* **The zero fraction is about 2%, not the 16% recorded below**, and those
  sites now defer to the shipped "suboptimal MOV zero" rather than being
  counted here at all: its XOR is two bytes against the copy's three and
  breaks the dependency the copy would create. The 16% came from counting a
  population that included the XOR zeroing idiom, where this rewrite needs a
  `mov r, imm` to replace and compilers do not spell zero that way.
* **The first measurement of this row was 2% high, from a false positive the
  check itself then reproduced.** The three MOV-immediate forms leave three
  different values behind: a 32-bit write zero-extends, so `mov edx,
  0xffffffff` leaves `0x00000000ffffffff`, where the 64-bit imm32 form
  sign-extends and `mov rdx, -1` leaves all ones. Reading the raw immediate
  for both made them compare equal, and glibc's `__isoc23_strtoul` clamp --
  which uses exactly that pair -- was reported as a redundant move of a value
  the register does not hold. Every one of libc's 7 "already holds it" sites
  was that bug. It was caught by disassembling a finding rather than by any
  count looking wrong, which is the second time this file has needed that.

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

## Ported from armlint (2026-09 cross-project audit)

armlint's shipped check table was walked against x86lint's and every
member with an x86 spelling was counted, in the other direction from
the rest of this file: the candidates here are things armlint already
*ships*, so the question is not whether the rewrite is sound but
whether the shape exists on x86 and survives its own conditions.

Figures marked **2026-09 port sweep** are whole-binary `objdump`
adjacency counts over libxul (32.1M decoded instructions, against the
30.08M x86lint's symbol-restricted scan reports), go 1.92M, libcrypto
828k, libstdc++ 358k, libc 356k and bash 254k. The sweep applies no
liveness proof and no side-entry gate and is not symbol-restricted, so
every figure is an upper bound admitting data-in-text -- the same
standing this file gives its `-a`-swept binaries.

| Pattern | Rewrite | 2026-09 port sweep |
| --- | --- | --- |
| ~~`LOCK CMPXCHG` retry loop whose body is one bitwise op~~ | ~~`LOCK OR`/`AND`/`XOR`~~ | **Done: "CAS loop foldable into LOCK op".** Shape 614 in libxul (466 OR, 132 AND, 16 XOR), 3 libc, 0 elsewhere; realized **19**, all libxul. See the note below -- a 32x collapse with a single cause |
| ~~vector load whose sole use is the next vector op's source~~ | ~~fold into that operand~~ | **Done: "load foldable into vector op".** Shape 9,298 in libxul, of which 541 were predicted to survive a deadness proof; realized **583** (libcrypto 176, and 0 in libc, libstdc++, go and bash). See the note below -- the 17x gap between shape and finding is the register allocator being right, not the proof being timid. Two scalar siblings are measured in their own row below |
| ~~GPR load whose sole use is a transfer into the vector file~~ | ~~fold into that transfer~~ | **Done: "load foldable into vector transfer".** `mov r, [m] ; movd/movq xmm, r` and `mov r, [m] ; cvtsi2sd/ss xmm, r`. Shape 470 in libxul and 34 in go; an estimate put the survivors at 16 and 13, and the check reports **10 and 2**, with 0 in libc, libstdc++, libcrypto and bash. The originally published figures were the bare shape (370 and 100). See the note below |
| adjacent immediate-zero stores at consecutive addresses | one wider store | **Filed as [#30](https://github.com/gaul/x86lint/issues/30).** Re-counted by maximal run rather than by pair: libxul **20,870** runs covering 45,626 stores; libstdc++ 396 runs, libcrypto 339, go 331, libc 91, bash 78. `tools/shapescan` now carries the candidate and sharpens the yield to **7,225** libxul runs that merge to a single store with no new register and no side entry, against the 11,788 the issue quotes -- a different unit (instructions rather than runs) and, more to the point, no side-entry gate, where 1,765 runs turn out to have a branch entering them. Blocked on a policy question, not on proof -- see below |

**The CAS fold, and why its shape overstated it 32x.** The check
ships, and the collapse from 5,192 `LOCK CMPXCHG` + `JNE` pairs to 614
fetch-op-shaped loops to **19 findings** has one cause worth recording:
LLVM already lowers an `atomic_fetch_or` whose result is *discarded*
straight to `LOCK OR`, so a CAS loop that survives to the binary is
usually the value-returning form, which no single x86 instruction
spells. dav1d's two dominant tails say it outright -- `jne L ; test
eax, eax` and `jne L ; or eax, ecx` both read the old value the fold
would discard. That also explains the **zero ADD and SUB loops
anywhere in the corpus**: `LOCK XADD` is the one value-returning locked
form, so the compiler reaches for it directly and the CAS spelling
never appears. The 19 that remain are real and concentrated:
`HttpBaseChannel`'s constructor sets eight bitfield flags in a row,
each its own five-instruction CAS loop, each old value killed by the
next loop's reload. This is the fourth row in this file whose
population is a property of what the compiler *already* optimizes, and
the first where measuring the tail of the loop rather than its head was
what showed it.

**The vector fold, and the 17x its shape overstated.** It now ships. It is the
"load foldable into ALU" family with the consumer set widened past the
GPR ALU. The alignment condition is unusually clean for x86: a
`movaps`/`movdqa` producer *proves* its address 16-byte aligned,
because the instruction faults otherwise, so folding into a legacy-SSE
memory operand inherits that proof -- the instruction the fold deletes
is the one carrying the evidence for the instruction that survives. A
`movups`/`movdqu` producer proves nothing and may fold only into a VEX
consumer, which carries no alignment requirement, which is why the two
arms are counted separately above.

The first draft of this row read "9,279 libxul sites, several times the
1,631 the scalar arm realized", and that was a shape count with the
rewrite's own deadness condition not applied -- the mistake this file
exists to stop. Applying it:

```
reuse    6,670  (72%)  the loaded register is read again
window   1,889  (20%)  the 12-instruction scan reached no verdict
xfer       198  ( 2%)  a control transfer ended the scan
dead       541  ( 6%)  foldable
```

**The 72% is the register allocator being right, not the proof being
timid.** A vector constant is loaded into a register precisely because
it is used more than once, and folding would turn one load into N; the
unrolled-accumulator shape, one mask applied to four or eight
accumulators, is most of that mass. Only the window and transfer rows
are recoverable by a sharper proof, so the ceiling is under 800. What
survives is concentrated -- `mulps` is 350 of the 541, and **539 of the
541 are RIP-relative constant-pool loads**, so this is "a constant used
once", not pointer traffic. The modal site is a vectorized polynomial
kernel reloading its coefficients one at a time through one scratch,
where the next constant's load is itself what proves the previous one
dead:

```
movaps xmm2, [rip+A] ; mulps xmm8, xmm2 ; divps xmm8, xmm10
movaps xmm2, [rip+B] ; addps xmm8, xmm2
```

libcrypto's 176 are a different population with the same cause: OpenSSL's
hand-written AES-NI perlasm loads a round key per round and uses it once,
which is what a fold the compiler already performs leaves behind.

Everything else is the existing family's machinery: sole use, register
deadness, adjacency. **Realized 583 against the 541 predicted**, the
closest estimate in this file and the second to land high rather than
low. The overshoot is understood and has the same shape as the zeroing
arm's: the estimate counted a fixed list of consumers and only the
alignment-proving producers, where the check asks XED whether the
consumer has a memory form at all and carries the unaligned-into-VEX arm
besides. Against that it scans only symbol ranges where the estimate read
whole sections. Two conditions the estimate never applied, both pushing
the same way. The both-successors split is deliberately not used: 198 of
the 9,298 end at a control transfer, so it would buy under 2% for the
machinery it costs.

**The two scalar siblings are the same fold with a general-purpose
register as the waypoint**, and their published figures were the bare
shape:

```
mov eax, [rip+X] ; cvtsi2ss xmm0, eax  ->  cvtsi2ss xmm0, dword ptr [rip+X]
mov r12, [rax+4] ; movq     xmm0, r12  ->  movq     xmm0, qword ptr [rax+4]
```

MOVD/MOVQ and CVTSI2SD/SS all take a memory source, so the integer
register is a pure waypoint. Beyond the instruction and the register
this deletes a cross-domain transfer, which costs bypass latency on
every core; the folded form never touches the integer file. The
deadness gate takes libxul's 470 to **16** and go's 34 to **13**, with
4 sites and 0 findings elsewhere -- 6% of the shape, a 20x overstatement
by the same mistake the vector row made.

`movd`/`movq` collapses hardest, and the reason is specific: **275 of
its 370, or 74%, read the integer register again**, which is the value
being wanted in *both* files. That is exactly why it was loaded into a
GPR rather than straight into the xmm, so folding would load the same
memory twice. The `cvtsi2s` half fails differently, mostly at a control
transfer inside the window, which is why this check does take the
both-successors split the vector one declines: 115 of the 470 end that
way against 2% for the vector fold. What survives is the RIP-relative
global read once and converted -- Firefox reading integer preference
mirrors into floats, where the next load of the same register is what
proves the previous one dead.

One thing that looks like a conflict and is not: CVTSI2SD merges into
its destination's upper bits, which is the shipped "missing SSE
dependency break" finding, and the fold does not change that. Both fire
on the same site, independently and correctly -- one says fold the load,
the other says insert the XORPS. The unit fixture pins the pair at two
findings rather than hiding it.

**Realized 10 and 2 against the 16 and 13 estimated**, and this is the
one row here whose estimate ran *high*. The cause is the same rule that
explains every other miss, applied in the other direction: the estimate
was made by weaker machinery than the one that realized it. Its
read-detection was a regular expression over disassembly text, where
`inst_reads_reg64` also sees implicit operands and memory base and index
registers, so the estimate under-counted reads and therefore
over-counted deaths. go's 34-site shape falling to 2 rather than 13 is
almost entirely that. A shape count is an upper bound, but so is a
liveness estimate built on a cruder reader than the check's own.

**The zero-store merge needs a policy decision before it needs code**, and
is filed as [#30](https://github.com/gaul/x86lint/issues/30) with the
measurement and the argument. The rewrite is armlint's
(`check_ldp_stp_coalesce`'s zero arm and `check_stp_wzr_to_str_xzr`), and
the dword run is the clean case -- `C7 /0 imm32` twice is 14 bytes against
one `48 C7 /0 imm32` at 8, a store uop saved as well, and `MOV r/m64,
imm32` sign-extends so zero costs the same immediate at either width. But
it changes the *granularity* of a memory access, which the standing rule
behind `check_shift_zero` and
[#29](https://github.com/gaul/x86lint/issues/29) -- no finding changes
the set of memory accesses -- was written to forbid. Merging is not
deleting, nothing stops being written, and every compiler's store-merging
pass does exactly this, so the rule may simply be about deletion; that is
the call to make.

**Counting by run rather than by pair is what made the row honest.** An
eight-store run is one opportunity, not seven, and the pair count also
missed every mixed-width run: libxul's ~6,000 same-width pairs are really
20,870 maximal runs covering 45,626 stores. Bucketing those by the bytes
they span says what each would merge into -- 284 at 2 bytes, 1,057 at 4,
6,927 at 8, and 12,602 above 8 -- so about 8,000 collapse to a single
store outright and the rest collapse partially. The small binaries look
empty (21 in libstdc++, 28 in libcrypto) for a reason worth keeping:
their runs are overwhelmingly *pairs of qword stores* spanning 16 bytes,
which the no-new-register model cannot improve at all. That is not the
shape being absent, it is the cheap half of the rewrite not applying.

Two x86-only wrinkles if it proceeds: a 2-byte span must not be merged,
since a `66`-prefixed `imm16` store is this tool's own
length-changing-prefix finding and its fix would create another, so byte
stores merge four at a time rather than two; and above 8 bytes the merge
wants a zeroed XMM the surrounding code may not have, spelled `MOVUPS`
rather than `MOVAPS` since byte and dword stores prove nothing about
alignment. That register is the whole difference from armlint, where
`xzr` exists and the wider store needs nothing allocated.

**Measured and near-dead, with one exception that was neither.** Every
remaining armlint check with an x86 spelling, now carried by
`tools/shapescan` so the figures are the gates' own and re-runnable. Shape
and realized are corpus-wide over libxul, go, libcrypto, libstdc++, libc and
bash:

| armlint check | x86 spelling | shape | realized |
| --- | --- | --- | --- |
| compare whose flags are overwritten unread | delete the `CMP`/`TEST` | 2,327,914 | 396 |
| ~~`neg` + `add`/`sub`~~ | ~~`neg r ; add r2, r` -> `sub r2, r`~~ | **Done: "NEG foldable into ADD/SUB", 16** |
| ~~redundant zero-extension by producer threshold~~ | ~~generalized past extension-after-extension~~ | **Done: "redundant zero-extension", 54** (libxul 48, go 6) |
| `shift` foldable into shifted-register form | `shl r, k<=3 ; add r2, r` -> `lea` | 17 | 0 |
| ~~`umov` of lane 0~~ | ~~`pextrd/q ..., 0` -> `movd/movq`~~ | **Done: "suboptimal lane-0 extract", 10** |
| `mov #C` + variable shift | `mov ecx, imm ; shl r, cl` | 6 | 0 |
| ~~`csel Rd, Rn, Rn`~~ | ~~same-register `CMOVcc`~~ | **Done: "redundant CMOVcc reg, reg", 3** |
| vector self-op identity | `pand`/`por`/`psub` with one source | 0 | 0 |
| `and xd, xn, #0xffffffff` | `and r64, 0xffffffff` -> `mov r32, r32` | 0 | 0 |
| widening extend + `scvtf` | `movsxd` + `cvtsi2sd` -> 32-bit convert | 0 | 0 |

**The vector self-op row is zero, and was 3 for an unsound reason.** All
three of libxul's sites were `subps xmm1, xmm1`, and the floating-point
self-subtract is not a zeroing idiom: `x - x` is `+0.0` only for a finite
`x` and NaN for an infinity or a NaN, so rewriting it to `XORPS` would change
the result. Excluding `SUBPS` and `SUBPD` -- the integer `PSUB` and the
signed `PCMPGT` really are always zero -- empties the row. It was the only
candidate here whose shape count came from a rewrite that does not hold, and
it was caught by writing the exclusion down rather than by any measurement.

**The branch-to-next row was recorded here as zero, and it shipped
instead.** It is **964** findings -- libxul 909, libcrypto 47, go 8 -- every
one realized, since neither form writes a register and both outcomes fall
through so there is nothing to gate. The earlier census parsed each
instruction's address out of `objdump` with its trailing colon still
attached, so `strtonum` returned 0 and every "is the target the next
instruction" test compared against zero. It reported a plausible number --
none -- and nothing looked wrong, which is the silent-failure mode armlint's
`--selftest` was built for and the reason a candidate belongs in a tool
rather than in a shell pipeline.

What the sites are is worth keeping too: hand-written SIMD, not compiler
output. libjpeg-turbo's `jsimd_ycc_rgb_convert_avx2` emits `jmp` to a NASM
macro label that lands on the very next instruction, most of libxul's 909,
with 47 more in libcrypto's perlasm. That is exactly the population armlint
documents for its own version -- compilers emit none, and the catch is
assembly and JIT emitters. See
[analyses.md](analyses.md#branch-to-the-next-instruction) for why only the
rel8 spelling is matched, which is a relocation argument rather than a size
one and costs 40 libxul sites and 5 in glibc.

Two rows shifted on better gates rather than on a bug. The dead compare rose
from 291 to 396 because `flags_live_after` reads a `RET` as flag death where
the census did not, and the zero-extension row is quoted here as the
*generalization alone*: counting extension-after-extension too put it at 285
against the shipped "redundant re-extension" check's own 254, which is
re-reporting covered ground rather than sizing a candidate.

## Parity gaps with armlint (2026-09 cross-check)

Driver, tooling and reporting rather than analyses. armlint's check table is
roughly half the size of this one's and its ELF driver has grown past it in
these seven ways; the eighth row is the one the audit found already broken
rather than merely missing.

| Item | Notes |
| --- | --- |
| ~~Linker import glue scanned as if it were compiler output~~ | **Done, 2026-09-15 (833a433).** The `.plt`, `.iplt` and `.plt.*` sections were linted, contributing a constant 135 unfixable findings per stripped binary: a lazy-binding entry pushes its relocation index with the 5-byte `push imm32`, so every entry whose index fits a signed imm8 draws an oversized-immediate finding and the count saturates at exactly 128, plus 7 from the resolver jumps. Identical in libstdc++ (1,105 PLT entries), bash (236) and libcrypto (161), and enough on their own to fail the non-zero exit a compiler test suite gates on. Excluded by section rather than by symbol, because the symbol restriction already hid it wherever `.symtab` survived and could not where it did not, so the noise appeared only on stripped binaries. `-a` still scans the glue; `-e` is untouched, PLT entries being real IBT targets. The fix also had to read the section-name table for every run rather than only under `-v`, `-e`, `-i` and `--json` -- a first version left that alone and silently did nothing in exactly the plain invocation it exists for |
| Mach-O and universal-binary support | The driver reads ELF only: `main.c` contains no Mach-O or PE constant at all. armlint reads ELF, thin Mach-O and fat binaries, walking every ARM64-family slice. The direct gain is macOS Intel binaries, but the larger one is that **every cross-project figure in this file compares a Linux ELF corpus against armlint's macOS Mach-O one** and has to caveat it; a shared format would let the two tools measure the same binaries for the first time. What it needs: the `LC_SEGMENT_64`/`LC_SYMTAB` parse, `LC_FUNCTION_STARTS` for the scan restriction on stripped binaries (ELF has no equivalent and simply gives up there), the fat-header walk, and the `__stubs`/`__stub_helper`/`__objc_stubs` exclusion that pairs with the PLT row above. Most of this is architecture-independent and already written in armlint's `main.c`, the cputype filter aside |
| ~~Durable candidate sizing~~ | **Done, 2026-09-15: `tools/shapescan`.** Sizes a named candidate with the rewrite's own conditions applied and reports which gate refused the rest. Candidates are C predicates rather than a data description, because every one measured this session needed operand-role matching, branch arithmetic, encodability through XED or a liveness walk; the file includes `x86lint.c` so a shipped candidate is measured by the code that realizes it, and an unshipped one is a draft check that moves into the linter rather than being rewritten. It mirrors the driver's corpus byte for byte -- same masking, same branch-target prepass, same decode and resync -- so the three shipped candidates reproduce x86lint's own counts exactly (19, 583 and 10 on libxul), which is the tool's regression test. **The refusal breakdown is the point**, and it already said something no ad-hoc census had: of the vector fold's 18,236 libxul sites, 5,743 fail *encodability* rather than liveness, a third of the shape that every throwaway script had pre-filtered away and so never counted. What does not port from armlint's `shapescan.py` is `--selftest`'s mask verification, which exists because armlint hand-writes encoding masks; XED removes that failure mode |
| ~~A target-core axis (`-t`)~~ | **Done, 2026-09-15: [#28](https://github.com/gaul/x86lint/issues/28).** Four behaviours whose worth is per-core became gates rather than prose: the slow-LEA exclusion, POPCNT's phantom destination, the length-changing prefix stall's MOV half and the SUB zeroing idiom. A check declares `target_requires` the way it declares `ext_required`, and `generic` sets every bit so the default scan is what it was. On libxul `-t icelake` takes "ADD foldable into LEA" from **2,678 to 28,064** and silences 6,431 POPCNT findings; the residue this file recorded as 37,037 was measured without every gate applied and the real figure is 25,386. The LCP split is the one that improves existing output rather than adding to it: MOV is 92% of that check's findings on rustc and pays nothing from Sandy Bridge through Skylake |
| ~~An audit or advisory finding class~~ | **Done, 2026-09-15: `-c`.** Three kinds, and the hard half was deciding what the class means rather than adding the flag. A check states a verified rewrite (the default, and what makes a non-zero exit meaningful), advice whose fix the tool cannot check, or a review item that is not a rewrite at all. Membership is the checks that already described themselves that way: the SETcc zero-extension and the length-changing prefix stall are advisory, the IBT-bypassing NOTRACK call is security. The naming collision was real -- `-a` already means scan every byte -- so the flag is `-c`. Enabling a class makes its findings count like any other, matching how `-e` findings already behave |
| ~~Snapshot/integration suite~~ | **Done, 2026-09-15: `snapshots/`, 19 files.** Added as a layer over `driver_test.sh` rather than as a migration, because armlint's shape does not transfer: its `.expected` files replace assertions, and x86lint's 115 `expect`/`reject` lines each state *why* a fixture exists, which a snapshot cannot. So the assertions stay and the snapshots pin everything they do not name -- column widths, ordering, a count on a line nobody wrote a grep for -- across all 19 report surfaces (default, `-a`, `-v`, `--json`, `-f`, `-i`, `-i -v`, `-e`, `-m`, `-c`, `-t`, the PLT skip and the usage text). The work that made them portable was deciding what belongs to the linker rather than the tool: section index, section load address, `--json`'s absolute vaddr, the census's sample addresses, an unpadded target's address, and whether the host's `ld` synthesizes an empty `ISA_1_USED` word or emits no note at all -- the last is why the existing assertion had accepted two spellings. Section-relative offsets, symbol names, byte spellings and every count stay. `make snapshots` regenerates; a missing snapshot is a failure, not a silent create; mismatches print a labelled diff and the run continues, so one invocation shows every changed report. The same commit deleted the suite's own skip: no C compiler now exits 2, because a skip that exits 0 is indistinguishable from a pass to `make` and to CI |
| ~~JIT-dump → ELF converters~~ | **Done, 2026-09-15: `tools/v8dump2elf.py`, `tools/jitdump2elf.py`, `tools/spidermonkey-jitdump.patch`.** Two converters where armlint has three, because the x86 half of the problem is shaped differently: V8's `--print-opt-code` prints encoding bytes and needs no patch, while **neither SpiderMonkey nor JSC prints a byte on x86-64** -- `IONFLAGS=codegen` is AT&T assembly with offsets, which is exactly why the 2026-09 sweeps in this file were awk over text. Both therefore need a hook, and a hook hands over the same four things whatever the engine (address, length, name, bytes), so one binary container serves both: `"X86J" | u64 addr | u32 size | u32 namelen | name | code`, concatenated with no file header so a killed process's dump still parses up to its truncation. The SpiderMonkey half is shipped as a patch to `jit::Linker::newCode`, the one place every blob passes through, and was **verified against SpiderMonkey's own `IONFLAGS=codegen` listing**: same instructions at the same offsets, with the `movabsq $0x0` patch placeholders carrying their linked values, which is what a linter should see. `--raw` reads a bare blob from the shell's own `disnative(f, file)` for a spot check with nothing patched. The driver needed one fix to make the naming worth anything: attribution skipped ET_REL outright, since an ordinary object leaves every section at address 0 and the names would pile up -- a JIT image is the ET_REL case that *does* carry real addresses, and now gets a per-tier by-function table. First contact: TurboFan 79 findings in 1,328 instructions, SpiderMonkey 560 in 16,992, both dominated by the same class (49 and 360 oversized branch displacements) because neither engine runs the relaxation pass an assembler does. `jit_test.sh` covers the parsers on synthetic dumps, so `make check` needs no engine |
| ~~Differential against the decoder's own model~~ | **Done, 2026-09-26: `x86lint_model_check`, a `make check` layer.** `ARMLINT_LIVENESS_SWEEP=1` sweeps all 2^32 A64 encodings asserting that anything Capstone reports as read is never classified dead, and found four real defects on its first run. x86 has no enumerable encoding space, but XED's static instruction table is an enumeration of every iform it knows, and the oracle is better than a second opinion -- it is the decoder the findings are built on. **Five properties over 10,879 iforms and 17 fixtures; zero disagreements**, which is a weaker result than armlint's and needed its own evidence to be worth anything. See the write-up below |
| ~~Doc split~~ | **Done, 2026-09-15.** armlint keeps a 554-line README plus a 3,795-line `analyses.md`; x86lint carried everything in one file that had reached 1,542 lines. The 77 implemented analyses moved to [analyses.md](analyses.md) verbatim, and the README's section became a linked two-column table: 729 lines and 1,057. The move was mechanical and checked as such -- every heading has exactly one link and every link a heading, and a token-level diff confirms the only prose that did not cross is the struck-through NOP row, which is not an implemented analysis and stayed in the table |

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

## JIT corpora (2026-09-15)

The first measurement made by *running the tool* over JIT output rather
than by reading disassembly text, using the converters added the same
day. Two workloads on two engines, so no figure below rests on one
benchmark or one engine:

| corpus | blobs | code | instructions |
| --- | --- | --- | --- |
| V8 Octane 9, TurboFan + Maglev | 2,713 | 6.9 MB | 1,619,714 |
| V8 ARES-6, TurboFan + Maglev | 5,618 | 8.0 MB | 1,876,052 |
| SpiderMonkey Octane 9, all tiers | 6,984 | 12.4 MB | 2,729,950 |
| SpiderMonkey ARES-6, all tiers | 8,365 | 17.8 MB | 4,155,785 |

V8 through `d8 --print-opt-code --print-maglev-code` and
`tools/v8dump2elf.py`; SpiderMonkey through
`tools/spidermonkey-jitdump.patch` and `tools/jitdump2elf.py`, which
catches Ion, Baseline, RegExp and the trampolines. **The corpora are
almost pure code**: 225 undecodable bytes in V8's 6.9 MB and 4,072 in
SpiderMonkey's 12.4 MB, 0.003% and 0.03%, so none of what follows is a
phantom decode of data-in-text -- the risk that dominates `-a` sweeps of
compiled binaries.

Against the same engines' own ahead-of-time code, and libxul for the
project's usual reference:

| corpus | findings | per 1k insns | branch displacement | per 1k | everything else, per 1k |
| --- | --- | --- | --- | --- | --- |
| V8 Octane (JIT) | 75,821 | 46.8 | 54,067 | 33.4 | 13.4 |
| V8 ARES-6 (JIT) | 97,841 | 52.2 | 72,061 | 38.4 | 13.7 |
| SpiderMonkey Octane (JIT) | 193,700 | 71.0 | 161,551 | 59.2 | 11.8 |
| SpiderMonkey ARES-6 (JIT) | 221,834 | 53.4 | 177,181 | 42.6 | 10.7 |
| `d8` (AOT) | 55,561 | 7.9 | 2,962 | 0.42 | 7.5 |
| `libmozjs` (AOT) | 23,225 | 5.1 | 642 | 0.14 | 5.0 |
| `libxul` (AOT) | 259,836 | 8.6 | 3,574 | 0.12 | 8.5 |

**JIT code carries six to nine times the findings per instruction of AOT
code, and one check is nearly all of the difference.** Oversized branch
displacement runs 33-59 per thousand instructions in JIT output against
0.12-0.42 in compiled binaries, a factor of 80 to 490. Take that class
out and the two worlds are within a factor of two of each other: 10.7 to
13.7 against 5.0 to 8.5. Every other class ports across unchanged, which
is the reassuring half of the result -- the check table does not need a
JIT dialect.

**The branch class decomposes completely, and the decomposition is the
finding.** Of all 464,860 branch findings across the four corpora,
**464,860 are forward branches and zero are backward.** Not approximately
zero: none. Both assemblers explain it in the same three lines of source.
V8's `Assembler::jmp(Label*, Distance)` takes `jmp_rel` when the label
`is_bound()`, which picks the 2-byte form whenever the displacement fits;
an unbound (forward) label gets the short form only when the caller
passed `Label::kNear`. SpiderMonkey's `BaseAssembler::jmp_i(JmpDst)` --
the bound-label path -- tests `CAN_SIGN_EXTEND_8_32` and emits
`OP_JMP_rel8`, while `jmp()` and `jCC()`, the unbound ones, emit
`OP_JMP_rel32` and `jccRel32` unconditionally with no near-label concept
at all.

So this is not an engine that forgot the short encoding. Both use it:
V8's Octane output holds 17,672 short branches against 254,291 long
ones, SpiderMonkey's 14,433 against 375,392. It is the one-pass
assembler's forward reservation, and the measurement is of how often the
reservation turned out to be unnecessary -- **21% of V8's long branches
and 43% of SpiderMonkey's**. SpiderMonkey's share is the higher one for
the reason its source gives: V8 at least lets a call site declare a label
near, and 17,672 of them do.

Its price is 3 to 5% of code size: 200,610 wasted bytes in V8's 6.9 MB
Octane output, 603,300 in SpiderMonkey's 12.4 MB, 272,073 and 663,447 on
ARES-6. Actionability differs by engine. In V8 it is per-site and needs
no new machinery -- a `Label::kNear` at the emitting call site, which is
what the other 17,672 already do. In SpiderMonkey it needs either a
near-label form in the base assembler or a relaxation pass, and a
relaxation pass moves every offset already recorded in a safepoint,
snapshot or IC table, which is why neither engine runs one.

**A false-positive class worth naming, because the corpus makes it
measurable.** Of SpiderMonkey Octane's 11,178 "oversized immediate"
findings, **7,230 are 10-byte `movabs` of 0 or -1** -- exactly the
patchable-placeholder class this file recorded in 2026-09 from reading
Ion's assembler, now counted and confirmed in context:

```
nop ; nop
movabs $0xffffffffffffffff, %r11      <- the placeholder
push   %r11
jmp    <bailout tail>
```

`pushArgWithPatch` reserves the full width because the snapshot offset
that replaces it is not known when the code is emitted. The remaining
3,948 are all `and eax, imm32` and are real. Nothing in the encoding
distinguishes the two, so the honest reading of that row is 3,948 with a
named 7,230-site exclusion, and a JIT-aware suppression -- a 10-byte
`movabs` of 0 or -1 whose destination is immediately pushed or called --
is a candidate the AOT corpus could never have motivated.

**The census reads JIT code too.** V8 uses AVX for 66,386 of its 1.62M
instructions (4.1%) and no AVX2 or AVX-512; SpiderMonkey 17,767 (0.65%),
plus the only BMI in either corpus (BMI2 321, BMI1 73). V8's 109 x87
instructions are real rather than phantom: `fld`/`fprem` is how it
implements JavaScript `%` on doubles, which is the one place x87 still
earns its keep on x86-64.

**Per tier, normalized by code size** (findings per KB, Octane):
Maglev 11.1 and TurboFan 11.7; Ion 17.0, Baseline 15.3, RegExp 14.4.
The tiers differ far less than the engines do, and almost all of the
spread is again the branch class.

**The measurement found a bug in its own converter**, which is the
argument for making these figures reproducible rather than one-off: V8
announces Maglev code with a `--- Disassembly: ---` banner where
TurboFan says `--- Optimized code ---`, and the first header gate tested
for the word "code", so 1,883 Maglev objects arrived unnamed and the
tier split read 51,676 "unknown" against 24,145 TurboFan. Fixed, and
pinned in `jit_test.sh`.

## JCC erratum audit (2026-09-26)

**Shipped as `-j`, a verdict mode rather than a check**, and the shape was
the whole question. Skylake-derived cores cannot cache a jump in the
decoded-icache when the jump crosses a 32-byte boundary or ends on one;
10.7-12.9% of the jumps in an unmitigated binary do. Reported per site
that is 12-13 findings per thousand instructions -- the largest class the
table would have, on every binary on the system, and not one of them
individually at fault, because the fix is padding something *earlier* and
the advice is one build flag. So the tool says once, for the whole file,
whether the binary was built with the padding.

**The null hypothesis is arithmetic, which is why the verdict needs no
calibrated threshold.** A jump of length L touches a boundary exactly when
its start is `>= 32 - L` mod 32, which is L of the 32 residues, so the
expectation for a scan is its jump bytes over 32. Every unmitigated binary
measured lands within 5% of its own expectation:

| binary | Jcc+JMP | on a boundary | expected | ratio |
| --- | --- | --- | --- | --- |
| bash | 43,241 | 5,458 (12.6%) | 5,688.50 | 0.96 |
| glibc | 54,572 | 7,037 (12.9%) | 6,975.65 | 1.01 |
| libcrypto | 77,151 | 9,194 (11.9%) | 9,674.06 | 0.95 |
| ld.so | 5,887 | 731 (12.4%) | 744.15 | 0.98 |
| libxul | 3,833,480 | 411,083 (10.7%) | 417,568.90 | 0.98 |
| x86lint.o, stock | 2,366 | 289 (12.2%) | 288.37 | 1.00 |
| x86lint.o, `-Wa,-mbranches-within-32B-boundaries` | 2,366 | **0** | 290.40 | 0.00 |
| /bin/go | 165,353 | 92 (0.1%) | 16,581.65 | 0.01 |

The mitigated object cost 2.6% more text (69,173 → 70,983 bytes). It also
gained four "oversized branch displacement" findings, 19 → 23: padding
moves every downstream byte, so the two analyses genuinely interact, and
the report keeps them apart rather than pretending otherwise.

**The evidence is asymmetric and the four verdicts say so.** One witness is
proof that whatever produced the code holding it did not pad, so `absent`
needs no minimum sample; no witness means nothing until chance would have
produced one, so `present` requires a scan expecting at least eight
(Poisson, so ~3e-4 of seeing none). `partially mitigated` between them is a
real configuration, not a hedge: **Go's own binaries are it**, because
`padJump`/`isJump` in `src/cmd/internal/obj/x86/asm6.go` run for compiler
output and `makePjcCtx` turns them off for `ctxt.IsAsm`, and those 92
witnesses are the hand-written half.

**Go's scope also validated the counter.** Go pads `CALL` and `RET`
(55 of 104,059 and 8 of 28,022) where gas's `-malign-branch=jcc+fused+jmp`
leaves both alone (gas-mitigated: 344 of 1,377 and 9 of 194 -- *worse* than
unpadded, since the padding moved them). Two toolchains, two documented
scopes, and each produced the per-class pattern its own source predicts,
which is stronger evidence that the tally is real than any single number.

**What is deliberately outside the verdict.** Fused compare+Jcc pairs are
padded by both toolchains and counted here, but which pairs really
macro-fuse depends on the core and on operand shape; the approximation in
`jcc_fusible_compare` reports 40 surviving touches on the gas-mitigated
object, so a verdict resting on it would have called a fully padded object
`partially mitigated`. The measurement chose the rule. `CALL` and `RET` are
out for the toolchain-dependence above. Both print beside the verdict,
because reading them together is what identifies which toolchain was at
work.

**Only `-t skylake` makes it a finding.** The erratum is one named group of
models and steppings (V8 enumerates them in `src/base/cpu/cpu-x86.cc`), so
this is the one place where the `-t` axis decides whether something is a
finding at all rather than which rewrite is worth making -- and the one
place the pessimistic `generic` reading is wrong, since applied by default
it would fail every binary on a machine that may never run on an affected
core.

**The JIT case is the one nothing else can measure**, and the reason the
audit was worth building rather than left as a note. V8 implements the
mitigation (`Assembler::AlignForJCCErratum`, `kJCCErratumAlignment = 32`)
and SpiderMonkey implements nothing -- the grep over `js/src/jit/` is
empty. But V8's is gated on `cpu.has_intel_jcc_erratum()`, so a dump's
verdict describes the host that produced it: a V8 corpus captured here (an
AMD Ryzen) reports 50 witnesses against 49.00 expected, correctly
`absent`, because nothing on this machine needed padding. **Still open: a
dump captured on an affected Intel host**, which is the only way to see
V8's padding in the output and the only way to confirm the engine
asymmetry end to end rather than from source.

**Relocatable objects are judged only at 32-byte alignment or better**,
which is not a formality: gas raises `.text` from 1 to 32 when it pads
(verified on a minimal object), precisely so a linker cannot place the
section at 16 mod 32 and undo the padding it just paid for. Sections below
that are counted and reported as skipped. A JIT ELF passes on its real
`sh_addr` instead, which is what `tools/jitdump2elf.py` records.

**One thing to watch.** The gas-mitigated object carries 347 instructions
with a redundant segment prefix where the stock object has none -- that is
how gas shifts a jump without a NOP (`-malign-branch-prefix-size=5`).
Nothing in the table flags them today, and the finding count barely moved
(432 → 435), but a future "useless prefix" check would light up on every
mitigated binary. It needs to know about this.

## Build-property audit (2026-09-26)

**Shipped as `-p`**, the third verdict mode and the first whose answers are
*fractions of the functions* rather than facts about the image. That makes the
symbol table part of the measurement rather than an optimization, which nothing
else here does: a stripped binary has no denominator and gets no verdict.

**Stack-protector coverage is the first property, and the fraction is the
whole point.** `checksec` and `hardening-check` read the symbol table and
report whether `__stack_chk_fail` is present -- a yes or no. Counting the
functions that load the guard separates none from some from every one, which
is what distinguishes the three flag settings, verified against all three:

| build | functions carrying the guard |
| --- | --- |
| no flag | 0 of 4 (0.0%) |
| `-fstack-protector-strong` | 1 of 4 (25.0%) -- the one with an escaping array |
| `-fstack-protector-all` | 4 of 4 (100.0%) |
| glibc | 1,513 of 6,943 (21.8%) |
| /bin/bash | 274 of 1,763 exported (15.5%) |
| libcrypto | 637 of 5,867 exported (10.9%) |
| /bin/go | 0 of 14,862 (0.0%) |
| ld.so | 1 of 474 (0.2%) -- **not** protected; see below |

**The loader is why the verdict rests on two signals.** Reading the guard is
not being protected by it: ld.so touches `%fs:0x28` in exactly one function,
being where the guard is established for everyone else, and names no
`__stack_chk_fail` at all. The first working version called it
`-fstack-protector` on the strength of that one initializer. A protected
function must be able to fail, so with no handler named the verdict is
`no stack protector` however many functions touch the slot -- and the report
says which of the two signals it is looking at.

**Two measurement corrections worth keeping.** The guard load is not a
prologue-only phenomenon: GCC schedules it wherever register pressure allows,
and the first probe searched the first dozen instructions of each function,
which undercounted bash by **35%** (231 against 357). And `.symtab` is absent
from most distro binaries, so where it is stripped the audit measures over
`.dynsym` and labels the denominator: exported functions are a biased sample
of a library's, but a biased fraction answers the question where no sample
answers nothing. Never both tables at once, or every exported function would
be counted twice.

**Informational by design, unlike `-s`.** Coverage is a policy choice rather
than a defect at any level -- partial coverage is precisely what `-strong`
means -- so there is no incomplete-opt-in to report and the mode never sets
the exit status. Which functions `-strong` protects is not decidable from the
bytes (it turns on having a local array or an address-taken local), so the
partial verdict names both flags and does not choose.

**Not covered: another libc's guard slot.** `%fs:0x28` is the glibc x86-64
TLS layout's `tcbhead_t.stack_guard`; musl and the rest are unverified here,
and a libc placing the guard elsewhere would read as unprotected.

**Frame pointers are the second property**, and both halves of the detection
earned their place by being wrong first:

| image | functions keeping a frame pointer |
| --- | --- |
| /bin/bash | 811 of 1,763 exported (46.0%) |
| libcrypto | 2,490 of 5,867 exported (42.4%) |
| glibc | 2,220 of 6,943 (32.0%) |
| ld.so | 123 of 474 (25.9%) |
| **/bin/go** | 12,490 of 14,862 (**84.0%**) |
| `-O2`, no flag | 0 of 4 (0.0%) |
| `-fno-omit-frame-pointer` | 1 of 4 (25.0%) |

**Requiring the pair is most of the accuracy.** Counted together over one
disassembly of bash, 1,031 functions open with `push rbp` and only 753 follow
it with `mov rbp, rsp`; the other 278 use rbp as an ordinary callee-saved
register, so counting the push alone would overstate by 37%. (That pair of
numbers shares a denominator with itself and not with the table above, which
the tool measures over the symbols it can see.)

**Allowing a prologue prefix is the other half, and Go is why.** The first
probe required the pair at the function's first instruction and reported
**0%** frame pointers on every Fedora binary, because CET puts `endbr64`
first; fixed to allow one instruction, it then reported /bin/go at 4.8%, which
is wrong in the opposite direction -- Go's runtime maintains frame pointers
throughout, but opens most functions with a two- or three-instruction
stack-growth check (`cmp rsp, [r14+0x10] ; jbe <morestack>`) before the
identical pair. A window of four instructions takes Go to 84.0% and moves the
saturated C binaries by at most a point, and an `-O2` object stays at 0.0% at
every window. An assignment to rbp before the pair disqualifies it, so the
window cannot promote an unrelated pair into a prologue.

**The internal payoff.** This file records libxul's 34,930 `mov rbp, rsp`
writes killed by a later `pop rbp` as a frame-pointer build artifact rather
than a dead-write population. That was prose; now the tool states the build
property that explains its own finding counts.

**Not covered: other frame idioms.** A prologue that establishes the frame
some other way -- `lea rbp, [rsp+N]` after pushes, which some hand-written
assembly and other ABIs use -- is not recognized. Go was the case that
mattered and it turned out to use the SysV pair, so nothing measured here
needs a second shape.

## Speculation thunk audit (2026-09-26)

**Shipped as `-s`**, the second verdict mode, and the one with proven demand:
Fedora's own kernel ships the mitigation, so unlike the JCC audit this had a
positive control before a line was written. A retpoline replaces an indirect
branch with a thunk call and a return thunk does the same for `RET`, which is
what Retbleed and SRSO attack; both are whole-build decisions and neither is
an encoding a peephole could suggest.

**The signal is positive on both sides**, which is what makes it sharper than
the JCC audit's statistical one. A routed build names the thunk -- in its
relocations while it is still an object, in its symbol table once linked -- and
holds none of the instruction the thunk replaces:

| image | bare returns | routed | bare indirect | verdict |
| --- | --- | --- | --- | --- |
| amt.ko (Fedora module) | **0** | 75 | 0 | routed |
| /bin/bash | 3,032 | 0 | 239 | not routed (names no thunk) |
| 60 Fedora modules | -- | -- | -- | 59 routed, 1 with no returns |

Zero holes across 60 real modules is the calibration that matters: a verdict
firing spuriously on shipped input would be useless for the audit it exists
for. The 75 routed returns were cross-checked against `objdump -dr` and
`readelf -r`, which agree exactly.

**A hole is the finding; an absence is not.** A bare `RET` in an image that
names a return thunk means the build asked for the mitigation and something
escaped it -- hand-written assembly the conversion missed, which is how this
actually goes wrong -- and that exits 1. A binary naming no thunk never opted
in, and unlike the JCC erratum there is **no `-t` value that would make it a
finding**, because what decides is what the binary *is* rather than which CPU
runs it. That asymmetry is the whole reason the audit is worth having: it
reports incomplete opt-ins, which nothing checks on a shipped module from
outside its build.

**The bug the linked case exposed, which the module case could never have.**
A thunk's own body holds the instruction it replaces -- GCC's return
trampoline ends in a `RET`, and its retpoline ends in a `RET` that jumps to
the target it pushed -- so the first working version reported a fully routed
program as `INCOMPLETE` on both axes, and the holes it named were the
mitigation itself. Kernel modules hid this completely, being `thunk-extern`
builds that import the thunks and define none. Fixed by excluding the thunks'
bodies, which then needed a second fix: GCC emits both symbols with
`st_size` 0, so the extent comes from the next symbol in the section, the same
rule `mask_non_function_bytes` applies to an unsized assembly label.

**Limits, both stated in the report rather than papered over.** The routed
*count* is exact only while the object is relocatable, since a linked image
resolved those branches into ordinary direct ones; there the symbol's presence
carries the verdict alone, which the `thunklocal` fixture exercises inside an
ET_REL object by defining the thunk in the scanned section. And a linked image
is judged whole: a retpoline-built program linked against an ordinary libc
reports `INCOMPLETE` because libc's returns really are unrouted -- accurate,
but saying more about the link than the code. Left as a finding rather than
suppressed, since suppressing it would hide real holes; a kernel module has no
passengers, which is why it is the case with clean semantics.

**Not attempted: the indirect half on its own.** "Zero bare indirect branches"
is unremarkable in ordinary code, so that axis rests entirely on the thunk
being named, and a build using `-mindirect-branch=thunk` without
`-mfunction-return` is reported per axis rather than as one verdict. Also not
attempted: matching the kernel's runtime-patched return thunks by
enumeration -- `thunk_family` matches the shared `return_thunk` ending, so
`srso_return_thunk` and its siblings count, and any future spelling will too.

## Model differential (2026-09-26)

**Shipped as `x86lint_model_check`**, called from the unit suite, and the first
thing in this file whose subject is the tool's own reasoning rather than a
binary's. Every check proves a register or a flag dead, and those proofs rest on
claims about what instructions do that were read out of the SDM by hand and
written into a switch. XED holds the same facts in its operand and flag
records, so the two can be compared over every node of XED's static instruction
table.

**It found nothing, and that is the result that needed the most work to make
trustworthy.** armlint's equivalent found four real defects on its first run;
this one reports zero disagreements across 10,879 iforms, 311 of them in the
flag-silent families, plus 17 instruction fixtures. A differential that passes
immediately is indistinguishable from one that checks nothing, so two things
stand behind the zero:

* **A positive control inside the property.** `reg_kill_iclass` excludes
  `CMOVcc`, the shifts and rotates, and `BSF`/`BSR` deliberately; the
  differential asserts XED records each of those 27 iclasses as a conditional
  register write, so the conditional-write property cannot hold by XED marking
  nothing conditional. It would also start failing the day one of them was
  added to the whitelist.
* **Fault injection, one per property.** Adding `CMOVZ` to `reg_kill_iclass`
  produces three disagreements (its two conditional iforms plus the control);
  adding `ADD` to the flag-silent list produces 62, one per ADD iform carrying
  a flag record; claiming `INC` writes CF reports `needs XED to record 0x1f
  written; it records 0x1e`; claiming a shift by CL is unconditional reports the
  `may_write` marker disagreeing; and giving the INC row DEC's bytes reports the
  fixture encoding the wrong instruction. Putting an iclass XED does *not* mark
  conditional into the control list -- `MOVSB` -- reports `the
  reg_kill_iclass property holds vacuously there`, which is the shape that would
  catch XED's operand records going flat under an upgrade. Each message names
  the reasoning rather than an opcode, which is the difference between a failing
  assert and a usable one.

**The one thing it did catch was in itself**, and it is the reason the 17
fixtures pin the iclass they encode the way `CHECK_BYTES_ASM` does: `f3 a6`
decodes as `REPE_CMPSB`, not as `CMPSB` with a prefix attached, so the row
naming the REP claim was written against an iclass XED does not produce there.
The claim was being tested against the right bytes either way, but a
hand-encoding typo would have been invisible without the pin -- a fixture that
tests a claim against some other instruction, and agrees with XED about it.

**Two hand-made SDM arguments came back confirmed by a second source**, which
is the closest thing to a finding here. `reg_kill_iclass` omits the shifts
because the SDM's count-0 pseudocode performs no destination write, and
`BSF`/`BSR` because the destination is undefined when the source is zero. Both
exclusions were argued in prose, and XED independently spells both as
conditional register writes -- 32 of SHL's 168 iforms, 4 of 4 for each bit
scan. XED also records INC's written set as exactly `PF|ZF|SF|OF`, which is the
"INC and DEC leave CF alone" that three checks compute their flag gate from.

**What it cannot cover, both stated rather than left as gaps.** The third
`reg_kill_iclass` exclusion, REP-prefixed string writes, is invisible here:
that conditionality lives in the prefix, not the iform, so XED's operand
records call `MOVSB` an unconditional writer. And the per-check `flag_concerns`
field cannot be checked at all, which this row originally asked for -- it is
the symmetric difference between the original instruction's flag effects and
the *replacement's*, and XED knows only the original's. `suboptimal MOV zero`
declares every arithmetic flag while `MOV` writes none, because the concern is
what the suggested `XOR` would clobber, so any invariant of the form
"`flag_concerns` is a subset of what the instruction writes" is false by
construction. The differential therefore pins the instruction-level claims the
gates are *built from*, and each check's own declaration stays a matter for its
unit fixture.

**The `may_write` rows are the ones most likely to earn their keep later.** The
whole flag walk can treat a written flag set as a kill only because XED folds a
conditionally written flag into the same written and undefined sets as an
unconditional one and distinguishes the two solely by the instruction-level
`may_write` marker. That is an assumption about a dependency's API, not about
the ISA, and it is the kind that breaks quietly on an upgrade: if the marker
stopped discriminating, `flags_live_after` would conclude DEAD on flags that a
shift by a zero CL count leaves untouched. Two fixtures pin it -- `shl eax, cl`
must carry the marker and `add eax, ecx` must not -- so the next XED bump
either passes or says why not.

Not done as part of this: the recall direction. Asking XED which iclasses it
calls unconditional full-width GPR writers that `reg_kill_iclass` omits returns
about 1,500 names, because the static table records operand templates rather
than concrete registers and the width test admits every vector write. Omitting
an iclass costs findings and never soundness, so a list that size is not worth
filtering into something reviewable.

## Suboptimal NOP runs (2026-09-26)

**Measured and reduced 23x, not built.** [#9](https://github.com/gaul/x86lint/issues/9)
asks for the padding rule every assembler already knows: a run of NOPs covering
B bytes wants `ceil(B/9)` instructions, nine bytes being the longest form
needing no prefix beyond the `66` already in it. Counting maximal runs by
address arithmetic -- objdump's raw-byte column wraps at eight bytes and
undercounts, which cost one wrong measurement -- the shape is **2,527 sites**,
with a negative control clean enough to look decisive:

| binary | NOP runs | suboptimal | instructions deleted |
| --- | --- | --- | --- |
| bash | 10,466 | 1 | 1 |
| libc | 14,096 | 2 | 2 |
| libstdc++ | 15,663 | 1 | 1 |
| ld.so | 1,437 | 1 | 1 |
| libcrypto | 28,605 | 185 | 185 |
| libxul | 100,511 | 204 | 1,189 |
| **/bin/go** | 54,798 | **2,133** | **2,411** |

Five sites across four gas-built binaries against 2,133 in one Go binary reads
as a toolchain that forgot the table. It is not, and the shape collapses for two
*independent* reasons, one per population -- which is what makes this row worth
reading rather than just recording.

**Go's are not padding at all.** `fillnop`
(`src/cmd/internal/obj/x86/asm6.go`) walks a table up to the 9-byte form and
takes the longest fit greedily, and all three padding call sites -- `padJump` ->
`noppad`, the loop-align path, and `PCALIGN` -- go through it. The `0x90`s come
from `ginsnop` (`src/cmd/compile/internal/amd64/ggen.go`), which is a **fixed
one-byte NOP on purpose**, spelled `XCHGL AX, AX` with a comment explaining
why it is not gas's `xchg %eax,%eax` (that form zeroes the high 32 bits). Its
four callers all need the NOP to *have a PC*: inline marks, an empty infinite
loop ("so that debuggers are less confused"), a nop after a non-returning call
("we need the return address of a panic call to still be inside the function in
question"), and a frameless leaf whose first instruction came from an inlined
callee, for `FuncForPC` (Go issue 58300). The constraint is stated outright in
`ssagen/ssa.go`: *"Don't use 0-sized instructions as inline marks, because we
need to identify inline mark instructions by pc offset."* Unmatched marks each
emit their own `ginsnop`, so adjacent marks are `90 90` -- 1,618 of the 2,133.

**Settled by a control build rather than by reading the source.** Same program,
same toolchain, inlining the only variable:

| build | instructions | suboptimal runs |
| --- | --- | --- |
| default | 177,349 | **884** |
| `-gcflags=all=-l` | 202,544 | **0** |

Not fewer -- none, in a binary with *more* instructions, so it is not a size
effect. `go tool objdump` then shows the marks carrying distinct positions,
which no byte-level view could:

```
ftoadbox.go:269   0x406d0c   90   NOPL      <- two adjacent 1-byte nops,
ftoadbox.go:241   0x406d0d   90   NOPL         two different source lines
ftoadbox.go:242   0x406d0e   4c01ca  ADDQ R9, DX
```

One site carries four in a row at lines 141, 259, 203 and 204. Merging `90 90`
into `66 90` would put the second mark's PC inside an instruction and destroy
the attribution it exists to provide, so **Go's whole population is the shape
selecting for the intentional case** -- the fourth instance in this file, after
the stack-clash probe, the JIT patch sentinels and the atomics behind the
reload row.

**The second collapse takes almost everything else**, and it is a question the
shape count cannot ask: a NOP run nothing decodes costs nothing however it is
spelled. Classifying each run by whether its predecessor is a terminator:

| binary | suboptimal | on a fall-through path | dead bytes | sound to merge |
| --- | --- | --- | --- | --- |
| /bin/go | 2,171 | 2,030 | 141 | **no**, every `ginsnop` is PC-load-bearing |
| libcrypto | 185 | **0** | 185 | yes, and worth nothing |
| libxul | 204 | 104 | 100 | yes |
| libc | 6 | 4 | 2 | yes |
| bash / libstdc++ / ld.so | 3 | 2 | 1 | yes |

All 185 libcrypto sites sit after a terminator -- perlasm's
`repz ret ; nop ; nopl (%rax)` inter-block fill -- and by the symbol table 199
of libxul's 204 are function-entry alignment, reached only by falling out of the
previous function. (Counts here are without the branch-target gate the check
would apply, which removes another 38 in go and 4 in libc; the predecessor test
is an approximation, since an indirect jump or a call to a `noreturn` function
reads as fall-through.)

**What is actually left is about 110**, executed and sound, and it lands in
exactly the population the shipped "branch to the next instruction" check
reports -- hand-written NASM, not compiler output:

```
325619a: 6 bytes in 6 nops; prev je ...; next movdqa %xmm9,(%r14)       libjpeg-turbo
33544f7: 9 bytes in 2 nops; prev lea ...; next call dav1d_idct_4x4_...  dav1d
```

So the honest sizing is **110 with a named 2,171-site Go exclusion**, which is
below the dead-compare row's 396 and not obviously worth a check. Two things to
keep if it is ever built: the run must be on a fall-through path, since merging
dead bytes buys nothing; and a branch into the run's interior refuses it, which
already costs 38 sites in go and 4 in libc, so the gate is not theoretical.

**The transferable part is that this row was ranked first on its shape.** A
survey of the backlog put it at the top on the strength of 2,527 sites and a
clean negative control, and the negative control was the misleading part: gas
being optimal did not mean the other emitters were wrong, it meant they were
emitting something other than padding. Two measurements an hour apart took the
population to 4% of the shape. Neither was a liveness proof or an encodability
test -- the two conditions every earlier row in this file collapsed on -- but
"is this instruction there for a reason the bytes do not show" and "is this code
ever decoded", which nothing here had needed before.

## Relocation placeholders (2026-09-26)

**A false positive in the default scan on relocatable input, now fixed**
(`x86lint_mask_relocated`). An unlinked object's immediates and
displacements are not values -- they are zero, or a bare addend, waiting for
the linker -- and every check that reads one was reasoning about a number
that will not be there at run time. Found by accident while probing
candidate verdict modes on a Fedora kernel module, which is the input that
makes it loud: `amt.ko`, 8,441 instructions, **275 of 314 findings were
placeholders**.

| class | count | what the finding asked for |
| --- | --- | --- |
| oversized branch displacement | 143 | shorten a relocated `e9 00000000` to rel8 -- and in a `-mfunction-return=thunk-extern` build that is *every return in the module* |
| oversized MOV encoding | 132 | narrow a `mov r64, imm32` whose `R_X86_64_32S` will hold a sign-extended kernel address the shorter form cannot express |

Both are worse than noise: applying either corrupts the field the linker
writes. After the fix the module reports 31, and the three classes that
remain (`oversized ADD/SUB one` 29, two constant conditions) are on
unrelocated instructions.

**The whole instruction is masked, not the field**, with the same `0x06`
the function-range masking uses. An opcode with its immediate cut out
decodes as something else entirely, so a field-level suppression would
replace a wrong finding with an invented one; and the byte-level spelling
buys the part a value-level suppression could not, since the scan's
decode-and-resync treats the masked run as a **barrier** and no
multi-instruction window reasons across a placeholder either. The excluded
volume lands in the report's undecodable-byte count, and a summary line says
how much of that count it is (5,061 of 5,061 on the module).

**Deliberately not applied to `-i` or `-j`.** The census tallies isa-sets and
the JCC audit measures lengths and addresses; neither claim depends on an
immediate's value, and masking would drop real instructions from both
tallies. The census still sees all 8,441 instructions of that module.

**Costs nothing on linked input, by construction.** A linked binary's only
RELA sections are `.rela.dyn` and `.rela.plt`, and neither names a target
section, so no map is even allocated and the summary line never appears --
confirmed by every existing snapshot being byte-identical across the change.

**Still open: the same class where nothing marks it.** SpiderMonkey's
`pushArgWithPatch` sentinels are placeholders in *final* code (see the JIT
corpora section), and no relocation covers them because there is no link
coming. 7,230 of Octane's 11,178 oversized-immediate findings are that, and
this fix cannot reach them -- a JIT-aware suppression would have to
recognize the shape (`movabs` of 0 or -1 whose destination is immediately
pushed or called) rather than read a table.

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
| redundant reload of one address (`reload\|same`, `reload\|copy`) | reuse the first value | **7,237** across the 2026-08 corpus (libc 196/Minsn, bash 205, libxul 228, go 108), about 7,700 with the Rust sweep. **Dissected 2026-09 and filed as [#29](https://github.com/gaul/x86lint/issues/29).** The heap, global and TLS sites are atomics, `volatile` signal flags and wasm2c sandbox memory: a plain load that survives -O2 CSE with no store between is one the source forbade merging, so for those addresses the shape selects for the unsound case. The stack sites are spill reloads -- **2,666** in libxul, 365 in uutils, 65 in libc, 2 in go -- and sound as thread-private memory, about 2,900 of them within the check window. `tools/shapescan` now carries the candidate with the gates a check would apply -- an 8-instruction window, no store, call or branch between, the base unwritten, and the first value still in its register for the copy rewrite -- and reports **538** realized of a 15,358 shape corpus-wide (libxul 418 of 14,669). That is well under defuse's 2,666 for libxul alone, and the gap is the window and the branch rule rather than a disagreement: defuse resets at branch targets where this refuses any control transfer outright. Blocked on the tool's standard that no finding changes the set of memory accesses; see the note below |
| ~~`MOV r, imm` + `TZCNT`/`LZCNT` (the defensive default)~~ | ~~delete the `MOV`~~ | **Done, 2026-09-15: "redundant bit-scan default".** The knob it was blocked on is the `-t` axis, and the check reports its 305 libxul sites under `-t skylake` and later and under `-t zen`, none under the conservative default. Building it surfaced the other half of the same fact: the shipped dependency-break check covers `POPCNT`, `LZCNT` and `TZCNT` in one predicate, but the bit-scan erratum ends at Broadwell where POPCNT's runs to Cascade Lake, so on Skylake that check would have advised inserting an XOR in front of a TZCNT this one calls dead. Its bit-scan arm is now gated on the same bit, and the two are complementary halves rather than rival findings |
| ~~one-operand `MUL` whose low half is dead~~ | ~~`MULX`~~ | **Done: "missing MULX" (`-m bmi2`).** The row said 415 sites; the operand condition takes it to **101**, and the check reports **94**, all in libxul. See the note below -- this is the second estimate in this file to land, and for the same reason as the first |
| `XOR r32, r32` + `XOR r32, r32` | -- | **28,516 sites and nothing to fix.** The most frequent flag-coupled pair in the corpus after the compare/branch families, and it is two independent zeroing idioms; the `fdead` tag says only that the first's flag write is dead, which is true of every zeroing idiom |
| `PUSH r` + `POP r` of one register (an [#24](https://github.com/gaul/x86lint/issues/24) candidate) | delete the pair | **Rejected: the shape is a stack-clash probe.** 0 sites in compiled code across eight binaries (libxul, geckodriver, uutils, go, bash, libc, libcrypto) except **89** in libstdc++, every one GCC's `-fstack-clash-protection` probe in a function whose only frame activity is a call to a `noreturn` function -- `endbr64 ; push rax ; pop rax ; mov edi, 8 ; sub rsp, 8 ; call g`, reproduced with gcc 16 at `-O2 -fstack-clash-protection` and gone under `-fno-stack-clash-protection`. The push touches the page below the return address so a guard page faults before the callee runs; deleting the pair removes the protection. The shape selects for the intentional case, as the reload row's heap half does |
| adjacent `ADD`/`SUB rsp, imm` pairs (an [#24](https://github.com/gaul/x86lint/issues/24) candidate) | one adjustment | **Rejected: 3 real sites.** 38 adjacent pairs across the same eight binaries: **29** have a direct branch onto the second, a join point the incoming-edge gate refuses anyway; **6** are crti/crtn's empty `.fini` (`sub rsp, 8 ; add rsp, 8` with nothing between); and 3 are LLVM's post-call argument-area pop ahead of the epilogue's own adjustment, in Rust `Debug::fmt` (geckodriver 2, libxul 1) |
| armlint's immediate-misfit audit (`-a imm`), the implied-zero / flag-reorder idea from Mozilla [D325572](https://phabricator.services.mozilla.com/D325572) | renumber a constant or a flag bit so it materializes in a cheaper/shorter form | **Rejected: no x86 analog, measured across four corpora.** The audit's premise is AArch64's restrictive immediate encoding; x86's imm32 on every ALU/CMP/TEST/logical op absorbs it. See the note below |

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

**The immediate-misfit and flag-reorder audits: no x86 analog (measured
2026-09-14 over four corpora).** armlint's `-a imm` finds constants that miss
AArch64's immediate encoding and so must be materialized in a register, tallied
by value to surface near-misses a source change fixes wholesale (its V8 win was
a 16 MiB bound one step past `0xfff000`, fixed at 92,109 sites). Mozilla's
[D325572](https://phabricator.services.mozilla.com/D325572) is the sibling idea:
make a NaN-boxed magic value's payload 0 so the ARM64 `movz/movk` chain shortens
and the compare folds. Neither ports to x86, and the reason is the ISA, not the
corpus: x86 takes a full imm32 on every ALU/CMP/TEST/logical op, so an ordinary
constant is never materialized to satisfy an immediate field, and `movabs` is
bit-pattern-flat -- 10 bytes for any true-64-bit value regardless of which bits
are set.

Corpora and method: libxul (objdump), V8 TurboFan (`--print-opt-code`),
SpiderMonkey Ion (`IONFLAGS=codegen` on the `obj-js-x86lint-opt` shell), and
`librustc_driver.so`; ARES-6 was the JIT workload since no shell-runnable
JetStream 3 harness is in-tree.

* **movabs misfit: zero, everywhere.** imm32-fitting 10-byte movabs was libxul
  0/206,123, V8 0/21,977, rustc 0/134,607, SpiderMonkey 0 (excluding patch
  placeholders). Every wide movabs is a genuine 64-bit value -- NaN-box tags,
  heap pointers, division magics (`0xaaaa...ab`, `0xcccc...cd`), hash constants.
  D325572's `0xfff9800000000000` is materialized 15,046x in libxul and 19,091x
  in SpiderMonkey as a flat movabs whatever the payload; the compare is
  `movabs tmp,..;cmp` either way (x86 has no `movn` fold). D325572 saves 0 bytes
  on x86.
* **A SpiderMonkey false positive worth remembering.** Ion's 10-byte
  `movabsq $-1` (13,575x) and `$0` (864x) look like same-value waste but are
  patchable placeholders (`movWithPatch`/`pushArgWithPatch` for IC offsets,
  jump-table bases, wasm `SymbolicAddress`) that require the full width; the
  integrated disassembler prints every imm->reg move as `movabsq`, masking the
  encoding. The genuine paths (`mov(ImmWord)`) already use xor for 0 and the
  compact form otherwise.
* **Flag-reorder into the low-7-bit `test al, imm8` form** (the sound subset,
  already shipped as `check_oversized_test_immediate`): single-bit TEST masks at
  bit>=8 that a source reorder could demote number libxul ~14,021 and rustc
  12,366, but ~0 in the hand-tuned JITs (V8 0, SpiderMonkey 51). They cluster in
  **upstream** code -- Rust std `core::fmt`, LLVM CC/feature tablegen tables,
  `regex_automata` -- and where the flag is project-owned and hot it is stranded
  high **on purpose**: `JSString::LATIN1_CHARS_BIT` is bit 10 because bits 0-2
  are GC-reserved and 3-6 are the four type bits (7-9 already double-booked);
  `core::fmt`'s flags sit in the high byte of a `u32` because the low 21 bits
  hold the fill `char`. Moving the hot flag down means evicting an equally hot
  one -- zero-sum. The only residue is a `test32`->`test8` memory-operand
  lowering worth ~2 bytes, which the checker deliberately skips (narrowing a
  memory access is unsound on MMIO). Nothing here is a sound binary rewrite the
  tool can emit.

The encoding-waste subset that IS sound already ships:
`check_oversized_test_immediate` (low-7-bit TEST masks -> byte form) and
`check_oversized_immediate` (same-value shorter encodings, including a `movabs`
whose value fits imm32).

## Not yet measured

Ideas carried over from armlint's backlog or noted while reading the
corpus, with no population attached. Each needs a sweep before it
earns a row above.

| Item | Notes |
| --- | --- |
| `MOV r, r` + shift/ALU (the APX NDD shape) | 270,543 adjacent sites, the second-largest family in the corpus. Already covered by "missing APX NDD" under `-m apx`; recorded here only so the size of the population is not mistaken for an uncovered one |
| split macro-fusion pairs | Informational, the class armlint files under its `-a` audit idea: a `CMP`/`TEST` separated from its `Jcc` cannot fuse. Needs the per-core fusion tables from the optimization manual, and has no rewrite -- it is a scheduling complaint, not a peephole. The tables are the target axis of [#28](https://github.com/gaul/x86lint/issues/28) |
| ~~constant-condition `Jcc` after a zero test~~ | **Done.** Measured, moved to "Constant conditions" above, and shipped there as both arms: 1,543 findings against the 1,330 the sweep predicted. The CF/OF half this row described (`JB`/`JO` after a zero test) is a subset of the general case |
