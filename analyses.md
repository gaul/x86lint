# x86lint analyses

Full reference for every analysis x86lint implements -- the encoding or
sequence it matches, what the rewrite saves, and the soundness argument
that licenses it. See the [README](README.md) for an at-a-glance table
and for the design and soundness model every entry here assumes.

Candidate checks not yet implemented, with the corpus populations that
argue for or against each, live in [TODO.md](TODO.md).

## ADD foldable into LEA

* `488D04D500000000 4C01E8` (LEA RAX, [RDX*8]; ADD RAX, R13) -- a LEA already
  computes base+index*scale+disp, so an ADD after it is a term the same
  instruction could have carried: LEA RAX, [R13+RDX*8]. Three arms. An
  immediate addend (or INC/DEC) is absorbed by the displacement and the
  destination is unchanged; a register addend takes the LEA's free register
  slot, either keeping the LEA's destination (ADD rD, rT) or moving to the
  ADD's (ADD rT, rD), the latter needing rD dead since its definition goes
  away. The register arms need exactly one free slot, so the LEA may carry a
  base or an index but not both and not neither, and are 64-bit only. SUB by
  a register never folds: an addressing mode cannot negate a term. RIP-relative
  producers are refused, their displacement being measured from the following
  instruction. LEA writes no flags where the ADD writes all of them (INC/DEC
  all but CF), so those must be dead past the pair.
* Reported only when the RESULT stays within two components, **unless the
  target says otherwise**. Base, index and displacement together is the "slow
  LEA": 3 cycles on port 1 alone from Sandy Bridge through Cascade Lake, where
  each two-component form is 1 cycle on two ports. Folding a fast LEA plus an
  ADD (2 cycles, two ports) into a slow one trades a uop and three or four
  bytes for a cycle of latency and a port -- a trade, not an improvement. The
  gate costs most of the population and keeps every finding a win on all three
  of size, uops and latency: the reported shape is `LEA rD, [rX*s]` plus
  `ADD rD, rT`, which becomes a one-cycle two-component LEA where the pair
  took two.
* The gate is `TARGET_SLOW_LEA3`, so `-t icelake` and `-t zen` lift it:
  Agner Fog's tables give Ice Lake and Tiger Lake no separate row for the
  three-component form -- their "with index" form is 1 cycle on p15, the same
  as two components -- and Zen 3 through Zen 5 two cycles as two ops, which
  is what the pair being folded already costs. On libxul the difference is
  **2,678 findings against 28,064**, so 25,386 sound folds are withheld from
  the conservative default and reported for a core that does not pay. TODO.md
  had recorded that residue as 37,037 from a measurement that did not apply
  every gate; the figure here is the check's own

## ADD foldable into memory

* `4883C108 488B01` (ADD RCX, 8; MOV RAX, [RCX]) -- an ADD advancing a
  pointer is an address computation spelled as arithmetic, and the consumer's
  own base+index*scale+disp does it for free in the AGU: MOV RAX, [RCX+8].
  The producer contributes ADD reg, imm as a displacement, SUB reg, imm and
  INC/DEC as a negated or unit one, and ADD reg, reg as a scale-1 index; a
  LEA consumer folds like any other. SUB by a register has no spelling, since
  an addressing mode cannot negate an index, and neither does an addend of
  RSP, which is not a legal SIB index. Encodability is the LEA fold's -- at
  most one index between producer and consumer, displacements summing within
  signed 32 bits -- and so is the register argument: the destination must
  appear in the consumer only as the memory base, and its summed value must
  be dead. Its PRE-ADD value is what the folded address reads, which is the
  point: with the ADD gone the register still holds it. The one gate the LEA
  fold does not need is flags: LEA writes none and this arithmetic writes
  all of them (INC/DEC all but CF), so they must be provably dead past the
  consumer. A 32-bit ADD is excluded, since it truncates the sum and
  zero-extends where the 64-bit addressing mode would not

## AVX-SSE transition

* `C5F458C2 0F28DC` (VADDPS YMM0, YMM1, YMM2; MOVAPS XMM3, XMM4) -- a
  legacy SSE instruction preserves bits 255:128 of its destination's ymm
  register, so executing one while any of ymm0-15 carries dirty upper
  state costs: Sandy Bridge through Broadwell take an ~70-cycle state
  save on the first such instruction (and another restore on returning
  to 256-bit code), and from Skylake every legacy SSE instruction in
  dirty state instead carries a false dependency on its destination's
  stale upper half -- the scalar-merge hazard at 128-bit scale. AMD
  cores take no penalty. The fix is VZEROUPPER after the last 256-bit
  use, or the VEX spelling of the SSE code, which does not merge.
  Compilers emit the VZEROUPPER before every return and call when ymm
  was touched, so compiled code is clean and the population is
  hand-written assembly and JIT output. Flagged only while dirtiness is
  provable on every path to the instruction: a ymm0-15/zmm0-15 write on
  the same straight-line run, with no VZEROUPPER/VZEROALL or
  XRSTOR-family state load, no intervening control transfer (a callee
  may clean the state), and no incoming direct branch edge (whose path
  may arrive clean) -- writes to ymm16-31 have no legacy alias and do
  not count, and a VEX.128 write zeroes only its own register's upper
  bits, so it neither sets nor clears the state. An unseen indirect
  edge could only reach a flagged site with clean uppers, where both
  fixes stay harmless

## bit-cast routed through a frame slot

* `F20F11442408 488B442408` (MOVSD [RSP+8], XMM0; MOV RAX, [RSP+8]) -- a
  value moved between the register files by storing it to a frame slot and
  loading it back, where MOVQ RAX, XMM0 moves the same bits and touches no
  memory. Both directions, both widths: an XMM store by MOVD, MOVQ, MOVSS or
  MOVSD (or their VEX and EVEX forms) read back by a GPR `MOV`, and a GPR
  store read back by one of those into an XMM register. Every one of them
  moves exactly the low 32 or 64 bits, and a load into XMM zeroes the rest
  of the low lane as MOVD/MOVQ from a GPR does, legacy forms leaving the
  upper lanes alone and VEX/EVEX zeroing them, so the replacement is priced
  in the vector half's own encoding family and introduces no SSE/AVX mix.
  A masked EVEX load merges and is refused. The store stays; the load is
  replaced. The claim is the frame-slot table's (see
  [redundant reload](#redundant-reload)), and the bit-cast rides on the
  store's record, which an XMM store now arms
* This is the one frame-slot row whose worth is not bytes: MOVD/MOVQ is four
  to six bytes against a load of three to nine, and the rewrite is refused
  where it would be longer -- a three-byte `mov eax, [rbp-8]` against a
  four-byte MOVD -- which is the line riscvlint draws for its own `fmv`
  forms. What it removes is the store-to-load round trip
* Five-binary sweep: libcrypto 1 and none in libc, ld.so, bash or go -- plus
  libm 1 -- because GCC moves between the files directly. Both sites are
  break-even, five bytes for five: libm's `mov [rbp-0x38], rdi ; movsd
  xmm0, [rbp-0x38]` is MOVQ XMM0, RDI. Mozilla's clang-built libxul (Firefox
  160) has 31, among them a red-zone pair after a `__stack_chk_fail` call,
  `mov [rsp-0x4], ecx ; vmovd xmm2, [rsp-0x4]`

## branch to the next instruction

* `EB00` (JMP .+0) -- a direct branch whose displacement is zero transfers
  control to the instruction after it, which is exactly where falling
  through arrives: taken or not taken, execution continues at the same
  place. JMP and Jcc write no register and no flag, so the instruction is a
  pure no-op whatever the condition evaluates to. It is deletable with no
  liveness argument and no condition to reason about, while it still costs
  fetch bandwidth, a branch-predictor entry, and for the conditional forms a
  possible misprediction.
* **Only the rel8 forms are matched, and the reason is relocations rather
  than size.** In a relocatable object an unresolved `jmp foo` stores a zero
  rel32 and keeps the real target in an `R_X86_64_PC32` entry the
  instruction stream cannot see, so matching rel32 would call every unlinked
  branch a no-op. No toolchain emits an 8-bit branch relocation, so a zero
  rel8 is always a genuine self-relative zero. Nothing is lost by the
  restriction: a linked rel32 branch to the next instruction is already an
  oversized branch displacement, and narrowing it to rel8 lands it here.
* `CALL` is excluded even at zero displacement, since it pushes a return
  address and `call .+0` is the classic get-the-PC idiom of older
  position-independent code. `LOOP`, `LOOPE` and `LOOPNE` are excluded for
  the same class of reason: they decrement RCX, so deleting one changes a
  register. `JRCXZ` writes nothing and is matched.
* Deleting a branch that is itself a branch target is sound, so unlike the
  multi-instruction folds this needs no incoming-edge gate: the entering
  path falls through to the same successor the deleted branch would have
  reached.
* The population is hand-written assembly and JIT output rather than
  compiler codegen, exactly as for armlint's version of this check: **909**
  in libxul, 47 in libcrypto's perlasm, 8 in go, and none at all in glibc,
  libstdc++ or bash. Most of libxul's are libjpeg-turbo's AVX2 colour
  conversion, whose NASM macro chain jumps to a label that lands on the very
  next instruction (`jsimd_ycc_rgb_convert_avx2.column_st31` and its
  siblings). A further 40 libxul sites and 5 in glibc carry the rel32
  spelling and are deliberately not counted; where those are genuine rather
  than unresolved relocations, the oversized-branch-displacement finding
  reaches them first.

## CAS loop foldable into LOCK op

* `8B07 89C1 83C901 F00FB10F 75F5` (MOV EAX, [RDI]; L: MOV ECX, EAX; OR ECX,
  1; LOCK CMPXCHG [RDI], ECX; JNE L) -- a locked compare-exchange retry loop
  whose body recomputes the new value with one bitwise op is an atomic
  fetch-op spelled the long way, and its net effect is what a single
  instruction performs: LOCK OR DWORD PTR [RDI], 1. Four instructions and two
  scratch registers become one, and the contended path stops issuing a locked
  write per failed attempt -- LOCK CMPXCHG writes its destination whether or
  not the comparison succeeds, so the loop costs one locked write per
  iteration where the fold costs one in total. The iteration count is
  contention-dependent, so no correct program observes the difference.
  This is armlint's `-m lse` fetch-op arm with the feature gate removed:
  LOCK OR/AND/XOR to memory is 386 baseline, so unlike `ldset`/`ldclr` the
  rewrite asserts nothing about the target.
* Nothing is proved about the seed load, which is why it is not matched: the
  loop converges from any starting RAX, a mismatch reloading it and retrying.
  What must be proved dead past the loop is everything the fold does not
  produce -- RAX, which CMPXCHG leaves holding the pre-op value and LOCK OR
  discards; the scratch holding the new value; and every arithmetic flag,
  since the loop falls out of its JNE with ZF set where LOCK OR writes SF/ZF/PF
  from the result and clears CF/OF. The op's source may be an immediate or a
  register but neither RAX nor the scratch, and the address may be built from
  neither, since both change inside the loop. Only the window's interior is
  side-entry gated: an edge onto the head is what the loop's own back edge is,
  and any other entry there runs the whole pattern
* **The deadness gate is the whole check, and it removes 97% of the shape.**
  5,192 `LOCK CMPXCHG` + `JNE` pairs in libxul reduce to 614 that are
  structurally fetch-op loops (466 OR, 132 AND, 16 XOR), and those to **19
  findings**; glibc has 3 of the shape and 0 findings. The reason is that
  LLVM already lowers an `atomic_fetch_or` whose result is *discarded*
  straight to `LOCK OR`, so a surviving CAS loop is usually the
  value-returning form -- `jne L ; test eax, eax` and `jne L ; or eax, ecx`
  are the two dominant tails in dav1d -- which no single instruction spells.
  What is left is real: `HttpBaseChannel`'s constructor sets eight bitfield
  flags in a row, each a separate five-instruction CAS loop whose old value
  the next loop's own reload immediately kills. **Zero ADD or SUB loops occur
  anywhere in the corpus**, since `LOCK XADD` is the one value-returning
  locked form and LLVM reaches for it directly

## constant condition after immediate

* `B910000000 4883F928 77xx` (MOV ECX, 0x10; CMP RCX, 0x28; JA) -- the
  register holds a constant and the compare's other operand is a second
  constant, so every flag is decided at assembly time and the Jcc, CMOVcc or
  SETcc reading them has one outcome: 0x10 is not above 0x28, so the JA above
  is never taken. The immediate sibling of "constant condition after
  zeroing", sharing its consumer search and its side-entry gate; the
  difference is only where the constant comes from, read here from the
  encoding rather than from a producer whose two operands name one register.
  Knowing that both operands are fixed is enough to know the outcome is
  decided; both arms do evaluate it, for one purpose: the flags past the
  consumer (see the zeroing arm).
  The compare must read only bits the MOV wrote, which is a real constraint
  rather than a formality: `MOV CL, 5; TEST CL, CL` is admitted and
  `MOV CL, 5; TEST RCX, RCX` is not, the latter reading 56 bits the MOV left
  alone, and the high-byte names (AH, CH, DH, BH) cover bits 15:8 rather than
  7:0. Narrow loads compared at their own width are most of the population,
  not an edge case: 323 of libxul's 455 adjacent sites. Accepts `TEST reg,
  reg` on the loaded register and `CMP reg, imm`; a memory operand on either
  instruction, or a CMP against a second register, leaves an unknown in the
  comparison. The compare is searched for through `APX_NDD_WINDOW` past
  instructions that leave the register alone, and a consumer is required.
  As with the zeroing arm, a never-taken branch says the code it guards is
  unreachable from here. Again a Rust and C++ shape: 520 findings in libxul,
  79 in uutils coreutils, 20 in geckodriver and 9 in http3server, against a
  single site in libcrypto (an inlined constant-size copy in
  `WHIRLPOOL_Final`) and 0 in glibc, ld.so, bash, libstdc++ and go

## constant condition after zeroing

* `31C9 4885C9 74xx` (XOR ECX, ECX; TEST RCX, RCX; JE) -- the register is
  provably zero, so the TEST computes no condition: it sets ZF=1, SF=0, PF=1
  and clears CF and OF, whatever its width. Every Jcc, CMOVcc and SETcc
  condition is a function of exactly those flags, so the consumer's outcome
  is decided at assembly time -- the JE above is always taken, `CMOVE` is a
  `MOV`, `CMOVNE` and `JNE` are dead -- and the TEST goes with it. The
  stronger sibling of "redundant TEST after flags", which refuses these
  sites because it requires the TEST to name the producer's register at its
  exact width; a zeroed register is zero in every width, so any
  sub-register may be tested, and where both checks apply this one is
  reported alone. Note what the proof does not use: the producer's own
  flags. The TEST redefines every flag the consumer reads, from a value
  proven zero, so an intervening instruction may write flags freely and only
  a write of the tested register breaks the chain. Accepts the
  register-register XOR and SUB idioms at any width, and shares the immediate
  arm's bit-range model to say which TESTs each one proves: the idiom zeroes
  its own range of the enclosing register, widened to the full 64 bits for a
  32-bit name, and the TEST must read inside it. `XOR ECX, ECX` proves
  `TEST RCX, RCX` and `TEST CL, CL` alike; `XOR CL, CL` proves only the
  narrow one, since a wider TEST reads 56 bits it never touched; and
  `XOR AL, AL` proves nothing about `TEST AH, AH`, the high-byte names
  covering bits 15:8. **The rewrite deletes the TEST**, so every later reader
  of its flags, not only the consumer, would see older ones: a second CMOVcc
  on the same compare, an ADC, a caller reading flags across a return. Both
  arms therefore require the compare's flags dead past the consumer -- for a
  Jcc, past the successor the decided condition takes, so a never-taken
  branch's target may read flags freely. `tools/rwfuzz` found the deletion
  run past such readers (31 of 1,722 findings of this arm and 345 of 1,948 of
  the immediate one mismatched at 10,000 programs). On Mozilla's 160 libxul
  the gate costs 9 of 94 immediate-arm findings and 2 of 24 zeroing-arm ones,
  every one a decided side that falls into a JMP or runs past the flag walk's
  16-instruction lookahead, where the walk stops conservatively The TEST is searched for through `APX_NDD_WINDOW`, and
  a consumer is required, since without one the site is a dead TEST rather
  than a decided condition. The side-entry
  gate is stricter than the redundant-TEST checks': a direct edge onto the
  TEST, onto anything between it and the consumer, or onto the consumer
  itself suppresses the finding, because that path's register need not be
  zero. Reported at the TEST. A never-taken branch also says the code it
  guards is unreachable from here, which is worth reading as a codegen
  report rather than a byte patch. Almost entirely a Rust and C++ shape:
  562 findings in uutils coreutils and 338 in libxul, 9 in geckodriver and
  5 in http3server, against 0 in glibc, ld.so, bash, libstdc++, libcrypto
  and go

## dead compare

* `39C8 83C102` (CMP EAX, ECX; ADD ECX, 2) -- a compare computes nothing and
  exists only for the flags it sets, so one whose flags are every one
  overwritten before anything reads them is dead outright, and wants deleting
  rather than shortening. The predicate matches any register-only `CMP` or
  `TEST`; the whole claim is the flag-liveness gate, which is the same
  composition "suboptimal MOV zero" uses, read in the other direction -- there
  the flags are what the rewrite would newly clobber, here what it would stop
  producing. A `RET` counts as flag death, since neither the SysV nor the
  Win64 ABI preserves flags across a call, and roughly a quarter of the
  population is that tail.

  A compare that reads memory is excluded, and not for encoding reasons:
  deleting it would remove the load, which may be the entire point. Go spells
  a nil check as `TESTB AL, (AX)`, whose flags nothing reads and whose fault
  *is* the check, and the same rule keeps the tool off MMIO reads and
  stack-probe compares. AF is outside the flag model and deleting the compare
  destroys it too, which costs nothing here: the only way 64-bit code observes
  AF is `LAHF` or `PUSHF`, and both read the five modelled flags as well, so
  the walk reports live and the finding is suppressed before AF can matter.

  Deletion supersedes every encoding finding on the same instruction, so a
  dead `CMP reg, 0` is reported once rather than also as a "suboptimal CMP
  zero" -- one site, one finding, and the stronger claim. The three
  redundant-compare checks defer for the same reason where their flags are
  dead as well: their claim is that the producer already set what the compare
  sets, which is beside the point when nothing reads the result. Measured to
  cost them nothing on real code (libxul stays at 540 and glibc at 7).

  Real sites, one per binary, both with the flags overwritten a few
  instructions later:

  ```
  test r15, rdx ; cmp r12, r11 ; jne     (go, internal/strconv.genericFtoa)
  cmp r12d, 0x7e ; je L ; cmp r12d, 0x1b ; L: lea rax, ... (libxul)
  ```

  The second is the shape: `if (c == 0x7e || c == 0x1b)` where both arms reach
  the same block, so the second comparison's *result* became dead code while
  the compare itself survived. 386 findings, and a language split as sharp as
  any in this table: libxul 352 and go 34, against 0 in glibc, ld.so, bash,
  libstdc++ and libcrypto

## dead store to a frame slot

* `4889442408 4889D1 48895C2408` (MOV [RSP+8], RAX; MOV RCX, RDX; MOV
  [RSP+8], RBX) -- a frame slot stored twice with nothing able to read it in
  between: delete the first store. The store analogue of a dead register
  definition, and limited to frame slots for the reason every row on the
  frame-slot table is (see [redundant reload](#redundant-reload)). Both are
  plain `MOV` stores of exactly the same bytes, of a register at any width or
  of an immediate; a read-modify-write first store reads the slot and is
  never dead
* "Dead" is a claim about every path, so it is ended by more than a held
  value is: a conditional branch (on the taken path the overwrite never
  happens), a read that may overlap the slot -- through the same base an
  overlapping range, through the other frame base anything -- any access
  through another address, and a divide. The last two can fault into a
  handler that reads the frame: Go's nil checks are loads and stores through
  a pointer, and a deferred call reads the panicking frame
* Five-binary sweep: go 94, and none in GCC's libc, ld.so, libcrypto or
  bash. Go's are its open-coded defer bits, 54 `mov byte [rsp+N], 0` at
  entry overwritten by the `mov byte [rsp+N], 1` that arms the defer with
  only frame stores and LEAs between; 32 more are zero-initializations of a
  variable assigned again before any read, 6 other constants, and 2 register
  stores. riscvlint's Go corpus has the same skew (4,172 of its 4,568)

## IBT-bypassing NOTRACK call

*Security class: reported only under `-a security` or `-a all`.*

* `3E FFD0` (NOTRACK CALL RAX) -- the 3E prefix exempts this one indirect
  call from CET indirect-branch tracking: the CPU will not require an
  ENDBR64 landing pad at its target. Compilers emit NOTRACK only for
  register-form JMPs through read-only switch tables, whose basic-block
  targets legitimately lack pads (all 447 NOTRACK branches across bash,
  libc, ld.so, and libcrypto on Fedora 44 are that shape; indirect JMPs
  are therefore not matched). A NOTRACK *call* reaches compiler output
  only through an explicit `__attribute__((nocf_check))` function-pointer
  type, otherwise hand-written assembly: a deliberately untracked forward
  edge in an otherwise enforced binary, exactly where a CFI bypass hides.
  Unlike the optimization checks this finding is a security review flag,
  not a rewrite -- dropping the prefix without padding the target trades
  the bypass for a #CP fault

## LEA foldable into memory

* `488D04B7 488B00` (LEA RAX, [RDI+RSI*4]; MOV RAX, [RAX]) -- the address
  computation folds into the load's own base+index*scale+disp, so the LEA
  disappears: MOV RAX, [RDI+RSI*4]. Fires when the LEA's register is dead
  after the fold (overwritten or unused) and the combined address still fits
  one index and a 32-bit displacement (gated by register liveness). The
  consumer need not access memory: a second LEA folds the same way
  (`LEA RAX, [RBX+RAX]; LEA RAX, [RAX+2]` -> `LEA RAX, [RBX+RAX+2]`), which
  is the shape Go emits, where LLVM output is overwhelmingly the load above.
  Deadness is proved down BOTH successors of a directly following Jcc, since
  a folded address is very often consumed by a compare the next instruction
  branches on (`LEA RDI, [RSI+RDI*4]; CMP [RDI], R14D; JE`) and a
  straight-line walk gives up there.
* A RIP-relative producer folds the same way, into a consumer that is itself
  RIP-relative: `LEA RAX, [RIP+X]; MOV RCX, [RAX]` -> `MOV RCX, [RIP+X']`,
  the address of a static object loaded directly, seven bytes and an
  instruction shorter. The surviving instruction stands where the pair did,
  so its RIP anchor moves by at most the pair's length and the assembler
  recomputes the displacement from the symbol -- the check range-tests with
  headroom for that shift rather than modelling the encoder's choice. Since
  RIP-relative addressing admits neither a base nor an index, the consumer
  must carry neither, which is what keeps the arm small: 95% of the
  RIP-relative pairs in the corpus are the jump-table and global-array shape
  `LEA RAX, [RIP+X]; MOV ECX, [RAX+RDX*4]`, which no single instruction
  spells. Where the producer's LEA carries a relocation this is a codegen
  suggestion rather than a byte patch

## length-changing prefix stall

*Advisory class: reported only under `-a advisory` or `-a all`.*

* `66 81C1 3412` (ADD CX, 0x1234) -- a 66 prefix that changes the
  immediate's length (imm32 -> imm16) defeats the pre-decoder's length
  speculation, costing 2-3 cycles per visit (Intel optimization manual,
  "Length-Changing Prefixes"). Which instructions pay it has moved twice,
  so how much a finding is worth depends on the target (Agner Fog,
  *microarchitecture.pdf*). Arithmetic and logic forms pay on every Intel
  big core from the Pentium 4 to the present. MOV pays on the Pentium 4
  through Nehalem, then not on Sandy Bridge through Skylake -- where
  "mov ax,1234 has no penalty", Haswell and Skylake both inheriting Sandy
  Bridge's behavior -- and then again from Ice Lake onward. The Atom line
  has never paid it at all. MOV is most of what this check fires on -- 92%
  of the findings on librustc_driver -- so against a Sandy-Bridge-through-
  Skylake target the bulk of them cost nothing, while the arithmetic and
  logic subset is valid everywhere. Advisory either way: the clean fix,
  32-bit operands, needs upper-16 liveness this tool does not track. A
  66-prefixed imm16 whose value fits imm8 is already the
  oversized-immediate finding, whose narrowing removes the LCP by itself

## load foldable into ALU

* `488B0E 4801CB` (MOV RCX, [RSI]; ADD RBX, RCX) -- a load whose only use is
  the arithmetic right after it is one instruction, since the two-operand ALU
  forms take their source from memory: ADD RBX, [RSI]. Covers ADD/SUB/ADC/
  SBB/AND/OR/XOR, the two-operand IMUL (whose only direction is the r, r/m
  one the fold needs), and the one-operand MUL/IMUL. The rewrite keeps the
  consumer's opcode, so its result and every flag it writes are unchanged --
  ADC still reads the same CF -- and the memory is read once at the same
  address and width, in the same position relative to the consumer's write,
  so a fault lands where it did. What the fold turns on is which operand may
  become the memory one: the loaded register must appear exactly once and
  READ-ONLY, making it the source. When the consumer writes it instead
  (ADD RCX, RCX-destination under MOV RCX, [M]) the register is not dead and
  the only other fold is ADD [M], RBX, which stores where the original did
  not; that shape is the majority of the load-then-arithmetic pairs in C and
  C++ code. No operand, explicit or implicit, may write the loaded
  register's family, which drops the MUL whose RDX:RAX result would collide
  with it; the register must be named exactly, not aliased at another width;
  and it must be dead after the consumer, proved down both successors of a
  following Jcc as in load foldable into compare. Not folded: a consumer that
  already has a memory operand (including every locked and memory-destination
  form); shifts, whose memory operand is the destination rather than the
  source; DIV/IDIV. One fused-domain uop where the pair was two, and shorter
  by the length of the load, with no macro-fusion at stake

## load foldable into compare

* `8B0E 85C9` (MOV ECX, [RSI]; TEST ECX, ECX) -- a load whose only use is the
  CMP or TEST that follows it folds into that compare, which takes a memory
  operand directly: CMP DWORD [RSI], 0. One instruction and one register
  write disappear. Also `CMP reg, imm` (-> CMP mem, imm), `CMP reg, reg2` and
  `CMP reg2, reg` (-> the memory operand in whichever slot held the loaded
  register). The zero-test arm needs no flag argument: TEST r, r and
  CMP r/m, 0 agree on every flag, both setting SF/ZF/PF from the value and
  clearing CF/OF, since subtracting zero neither borrows nor overflows. The
  other arms keep their own opcode and so their own flag semantics. The
  compare must name the loaded register exactly, since MOV ECX, [M];
  CMP RCX, RBX compares 64 bits of which the load wrote 32, and the register
  must be dead after the compare -- proved down BOTH successors of a directly
  following Jcc, because a compare's whole purpose is the branch that reads
  it, and stopping the liveness walk there would suppress the population
  (measured: 1 finding across glibc with the straight-line walk, 73 with the
  branch split). Suppresses the merging-narrow-move finding on a narrow load
  of the same shape, whose fix this one subsumes. Composes with "suboptimal
  CMP zero": on a loaded register both fire, and taking this one subsumes it.
  Not folded: a compare that already has a memory operand, and CMP whose two
  operands are both the loaded register (CMP RAX, RAX compares a value with
  itself, which no one-operand form spells)

## load foldable into extend

* `8A06 0FB6C0` (MOV AL, [RSI]; MOVZX EAX, AL) -- a narrow load then an
  in-place sign/zero-extension is a single extending load: MOVZX EAX, byte
  [RSI]. Removes the load and its partial-register write; also MOVSX and the
  MOVSXD (32->64) form

## load foldable into vector op

* `0F2817 0F59C2` (MOVAPS XMM2, [RDI]; MULPS XMM0, XMM2) -- a vector load
  whose only use is the next SIMD instruction's source operand is one
  instruction, since the two- and three-operand forms take that operand from
  memory directly: MULPS XMM0, [RDI]. The general-purpose family's argument
  carries over intact -- the memory is read once at the same address and
  width, in the same position relative to the consumer's write, so a fault
  lands where it did; the loaded register must appear in the consumer exactly
  once and READ-ONLY, which is what makes it the operand memory replaces; and
  it must be dead afterward, proved by a vector-register liveness walk whose
  kill rule is structural (an operand written, not read, and at least as wide
  as the value) rather than an iclass list, since a legacy 128-bit write
  leaves bits 255:128 standing where a VEX write zeroes them. One exception
  to the structural rule: XED marks the legacy register-form `MOVSS` and
  `MOVSD` destination written-only, yet they merge into its upper lanes, so
  they are no kill. `tools/rwfuzz` found the fold run past one, and so did
  Mozilla's libxul: `movapd xmm3, [rsp+0x30] ; unpcklpd xmm1, xmm3 ; mulpd
  xmm1, xmm0 ; movsd xmm3, xmm2 ; divpd xmm1, xmm3` divides by the loaded
  upper half the MOVSD kept. The correction took libxul from 379 findings
  to 377
* **Alignment is the one gate with no scalar counterpart, and it resolves
  through the instruction being deleted.** A legacy SSE instruction with a
  memory operand requires 16-byte alignment and #GPs otherwise, which looks
  like a blocker until one notices that MOVAPS/MOVAPD/MOVDQA carry the same
  requirement: a program that executed the load has already established the
  alignment, so folding introduces no fault the original could not take. The
  producer proves the precondition of the instruction that outlives it.
  MOVUPS/MOVDQU/LDDQU prove nothing and may fold only into a VEX consumer,
  whose memory operands require no alignment at all. Whether the consumer has
  a memory form, and in that operand slot, is answered by re-encoding it
  through XED rather than by a table of SIMD iclasses -- a VEX
  non-destructive source that is not the last operand produces no encoding
  and so refuses itself. EVEX is skipped on both sides, as elsewhere, rather
  than reasoning about masking and broadcast, and a vector move consumer is
  excluded since folding a load into a move yields another move
* The deadness gate removes 94% of the shape: 9,298 adjacent libxul sites
  yield **583 findings** (libcrypto 176, and 0 in libc, libstdc++, go and
  bash), because 6,670 read the loaded register again. That is the register
  allocator being right rather than the proof being timid -- a vector
  constant is held in a register precisely because it is used more than once,
  and folding would turn one load into N. What survives is the single-use
  constant: 539 of libxul's are RIP-relative constant-pool loads, the modal
  site being a vectorized polynomial kernel cycling coefficients through one
  scratch, where the next coefficient's load is what proves the previous one
  dead. libcrypto's are OpenSSL's hand-written AES-NI perlasm loading a round
  key per round (`vmovups xmm14, [r15+0x60]; vaesenc xmm12, xmm12, xmm14`),
  the population a fold the compiler already performs leaves behind

## load foldable into vector transfer

* `8B07 660F6EC0` (MOV EAX, [RDI]; MOVD XMM0, EAX) -- the scalar sibling of
  the fold above, with a general-purpose register as the waypoint rather
  than a vector one. MOVD/MOVQ and CVTSI2SD/SS all take their source from
  memory, so the integer register exists only to carry the value across the
  register-file boundary and disappears with the load: MOVD XMM0, dword
  [RDI]. Beyond the instruction and the register this deletes a cross-domain
  transfer, which costs bypass latency on every core; the folded form never
  touches the integer file at all
* Alignment, the gate the vector fold needs, does not arise: these operands
  are eight bytes or fewer and x86 requires no alignment for them. A width
  argument replaces it, and the exact-register match carries it for free --
  `MOV EAX, [M]; MOVQ XMM0, RAX` names EAX and RAX, which are not the same
  register, so the pair that would read four bytes the load never wrote is
  refused without a width test (cf. load foldable into compare, whose CMP
  must likewise name the loaded register exactly). The moffs absolute loads
  are excluded, their full 64-bit address having no modrm spelling to fold
  into. Unlike the vector fold this one takes the both-successors split at a
  following Jcc, because the corpus asks for it: 115 of the 470 adjacent
  sites end at a control transfer, against 2% for the vector one
* Small, and the deadness gate is again why: **10 findings in libxul and 2
  in go** against a 470-site shape. MOVD/MOVQ is the half that collapses,
  and for a reason specific to it -- 275 of its 370 sites read the integer
  register again, the value being wanted in *both* files, which is exactly
  why it was loaded into a GPR rather than straight into the xmm; folding
  would load the same memory twice. What survives is the global read once
  and converted, Firefox's integer preference mirrors being the modal shape
  (`mov eax, [rip+sMirror_apz_fixed_margin_override_top]; cvtsi2ss xmm0,
  eax`, where the next mirror's load is what proves the previous one dead).
  CVTSI2SD merges into its destination's upper bits whatever its source, so
  "missing SSE dependency break" reports the same site; the two findings are
  independent and both correct, one saying fold the load and the other
  saying zero the destination first

## load of a just-stored value

* `4889442408 488B5C2408` (MOV [RSP+8], RAX; MOV RBX, [RSP+8]) -- the bytes
  a store just wrote to a frame slot, read straight back: the store's source
  still holds them, so the load is MOV RBX, RAX and the store stays. At 32
  bits the copy zero-extends exactly as the load does, which also makes a
  32-bit read-back into the source register itself MOV EAX, EAX; at 64 bits
  that load has nothing left to do and is the row below. Nothing is deleted,
  so no liveness question arises. The claim is the frame-slot table's (see
  [redundant reload](#redundant-reload)), and a spill sequence that writes
  several slots before reading any back keeps it, since the stores between
  are to disjoint ranges through the same base
* Five-binary sweep: go 392, libcrypto 95, libc 38, bash 27, ld.so 1. Go's
  are the goroutine pointer spilled and read back across a write-barrier
  test, `mov [rsp+0x48], r14 ; mov rdx, [rsp+0x48]`, and the C sites GCC's
  spill of a call result tested and reloaded as the next argument, `mov
  [rbp-0x108], rax ; test rax, rax ; je ; mov rdi, [rbp-0x108]`

## load of a value the register still holds

* `488B442408 ... 488B442408` (MOV RAX, [RSP+8]; ...; MOV RAX, [RSP+8]) --
  the frame slot loaded into the register that already holds it: delete the
  load. Two shapes, each exact only as stated. The same slot loaded again at
  the same width into an unwritten register recomputes the same value from
  the same bytes, 32-bit zero-extension included. A store read back into its
  own source is exact only at 64 bits: after `mov [rsp+8], eax`, bits 63:32
  of RAX are whatever they were, and `mov eax, [rsp+8]` would zero them, so
  that one is a MOV EAX, EAX under
  [load of a just-stored value](#load-of-a-just-stored-value). The first
  shape is issue #29's "same" half; the claim is the frame-slot table's (see
  [redundant reload](#redundant-reload))
* Five-binary sweep: go 203, libcrypto 31, libc 25, bash 16, ld.so 5. Go's
  are its register-ABI arguments spilled to their home slots at entry and
  read straight back, `mov [rsp+0x8], rax ; mov [rsp+0x10], rbx ; mov rax,
  [rsp+0x8]` in `internal/abi.TypeOf` -- the stores are for tracebacks and
  stay, the load has nothing to do. The C sites are GCC reloading a spilled
  value it never overwrote, past a compare and a conditional branch

## NEG foldable into ADD/SUB

* `F7DA 4101D6` (NEG EDX; ADD R14D, EDX) -- negating a value and adding it
  is subtracting it: SUB R14D, EDX, one instruction and one scratch
  register fewer. The mirror holds too, a NEG feeding a SUB being an ADD.
* The flags are what make this conditional rather than free. SUB's CF is a
  borrow where ADD's, on the negated operand, is an unsigned carry, and the
  two disagree on exactly that bit for every operand but zero, so every
  arithmetic flag must be dead past the pair. The negated value dies with
  the instruction that produced it, so it must be dead as well -- which a
  return does not establish, a register being able to escape there.
* 16 findings of 61 adjacent sites in libxul, none elsewhere; the gap is
  almost entirely the negated value still being live

## missing ANDN (only with `-m bmi1`)

* `F7D0 21C8` (NOT EAX; AND EAX, ECX) -- one ANDN EAX, EAX, ECX (BMI1)
  computes ~x & y directly. An exact fold: both forms write only the
  destination, SF/ZF come from the same result, and CF/OF are cleared by
  both; flagged only while PF -- which AND defines and ANDN leaves
  undefined -- is dead. Immediate masks are not flagged (ANDN has no
  immediate form), nor is an AND into a different register (the NOT's
  result would stay live)

## missing APX NDD (only with `-m apx`)

* `89F8 29F0` (MOV EAX, EDI; SUB EAX, ESI) -- one EVEX new-data-destination
  SUB EAX, EDI, ESI (APX) computes the difference straight into the copy's
  register: the mov exists only because the legacy op destroys its first
  source. An exact fold with no liveness gate at all: each promoted form
  sets every flag exactly as its legacy twin (the one delta in the family
  is SBB's AF, defined -> undefined, which 64-bit user code cannot read
  and this tool does not track -- the LEA fold accepts the same drop), and
  only the destination is written, with the identical value. Matches SUB,
  AND, OR, XOR, ADC, SBB, and two-operand IMUL with a register, immediate,
  or memory-load source; NEG and NOT; and immediate shifts and rotates
  with a nonzero masked count (the SDM leaves a count-0 shift writing
  nothing, so the copy's value would survive in the original where the
  NDD form's write behavior is unverified); CMOVcc folds as a true
  select -- the copy is the untaken value, the moved one the taken, the
  32-bit forms zero-extend on a false condition in both shapes, and
  behind a load head the inverse condition code puts the loaded default
  in the selectable slot. The copy may equally be a
  plain modrm load -- `8B06 29F8` (MOV EAX, [RSI]; SUB EAX, EDI) is SUB
  EAX, [RSI], EDI, the promoted forms taking one memory source -- which
  is where the population lives: a loaded value on the left of a
  non-commutative op has no legacy single-instruction form. Behind a
  load head ADD, SUB, INC, and DEC belong here too (the LEA fold's head
  is register-to-register), the op itself must not touch memory (no NDD
  form carries two memory operands), the moffs absolute loads are never
  matched (no EVEX re-encoding), and the pair must be adjacent -- across
  a gap the fold would reorder the access and its fault against the
  gap's effects. A register-headed consumer need not be adjacent: the
  fold looks through up to `APX_NDD_WINDOW - 2` intervening
  instructions (six at the default of 8, the measured knee of the yield
  curve; a build-time constant sized for experimentation) that prove
  themselves independent -- straight-line
  code that never touches the copy's register at any width and never
  writes the mov's source -- so a scheduling gap like a flag-zeroing
  XOR, a load, or a store does not hide the pair. Division of labor:
  register and immediate ADD, immediate SUB, and INC/DEC belong to the
  MOV+ADD-foldable-to-LEA finding, which needs no extension, while the
  flags they write die -- lea writes none. While those flags live that
  fold is suppressed and this one takes the exact complement of its
  gate, so exactly one of the two claims any pair (behind a load head
  there is no split: lea cannot see those at all). CL-count
  shifts stay with missing SHLX; and under both extensions the BLSI
  triple's mov/neg prefix defers to the 3 -> 1 BLSI collapse. One
  instruction and one uop fewer and a shorter dependency chain, though
  the 4-byte EVEX prefix can cost two bytes of size on a 32-bit pair

## missing APX SETZU (only with `-m apx`)

* `0F94C0 0FB6C0` (SETZ AL; MOVZX EAX, AL) -- one zero-upper SETZ (APX,
  EVEX ND=1: XED's record models the byte register, the spec zeroes bits
  63:8) writes the 0/1 result zero-extended to 64 bits itself, reading
  the same condition flags, so the widening pair collapses exactly.
  This is the suboptimal-SETcc-zero-extension idiom made foldable: the
  baseline finding is advisory because its fix lives upstream of the
  flag-setter, where a peephole proves nothing, but the zero-upper form
  replaces the pair in place. One matcher serves both, and the
  dispatcher reports exactly one of the two -- this finding with the
  extension, the advisory without it

## missing BLSI (only with `-m bmi1`)

* `89F9 F7D9 21F9` (MOV ECX, EDI; NEG ECX; AND ECX, EDI) -- one BLSI ECX,
  EDI (BMI1) isolates the lowest set bit, collapsing the whole triple: the
  copy exists only because x and -x must coexist, and BLSI reads its
  source directly. Flagged only while CF -- which AND clears but BLSI sets
  to (source != 0) -- and PF -- defined vs undefined -- are dead. Not
  flagged when the copy aliases its source (the AND then computes -x, not
  x & -x) or when the AND lands in the source register (the original
  keeps -x live in the copy)

## missing BLSMSK (only with `-m bmi1`)

* `8D50FF 31C2` (LEA EDX, [RAX-1]; XOR EDX, EAX) -- one BLSMSK EDX, EAX
  (BMI1) builds the mask through the lowest set bit: the BLSR idiom with
  the AND swapped for an XOR, gated the same way (CF and PF dead). ZF
  needs no gate -- BLSMSK hardwires it to 0 where XOR computes it, but
  x ^ (x-1) is never zero. Not flagged when the XOR's destination is the
  decremented register itself (the original keeps source-1 live there)

## missing BLSR (only with `-m bmi1`)

* `8D50FF 21C2` (LEA EDX, [RAX-1]; AND EDX, EAX) -- one BLSR EDX, EAX
  (BMI1) clears the lowest set bit. Flagged only while CF -- which AND
  clears but BLSR sets to (source == 0) -- and PF -- defined vs undefined
  -- are dead; SF/ZF come from the same result either way. Not flagged when
  the AND's destination is the decremented register itself (the original
  keeps source-1 live there)

## missing BZHI (only with `-m bmi2`)

* `B9FFFFFFFF C4E269F7C9 F7D1 21F1` (MOV ECX, -1; SHLX ECX, ECX, EDX; NOT
  ECX; AND ECX, ESI) -- one BZHI ECX, ESI, EDX (BMI2) keeps the low n bits,
  four instructions for one. Advisory (`-a advisory`): SHL and SHLX reduce
  the count mod the operand width, while BZHI reads bits 7:0 of the index
  and keeps the whole source at the width or above, so the forms agree only
  for a count below the width -- a range fact no window can show. A C
  compiler knows it and emits BZHI; a JIT for wasm or JavaScript, whose
  shifts are defined mod the width, does not, which is where the idiom
  survives (zlib's bit reader in a JetStream 3 wasm build, 9 sites).
  Withheld while PF -- defined by AND, undefined by BZHI -- may be read.
  The legacy `SHL reg, CL` form matches too. Not flagged when the SHLX
  shifts a different all-ones register (dropping its MOV needs that
  register dead) or the count is the mask register itself. When reported
  it replaces the ANDN finding at the window's NOT, which it subsumes

## missing MOVBE (only with `-m movbe`)

* `8B06 0FC8` (MOV EAX, [RSI]; BSWAP EAX) -- one MOVBE EAX, [RSI] performs
  the byte-swapping load: one instruction instead of two, never larger.
  None of the three instructions touches a flag and only the destination
  register is written, so the fold is exact with no liveness gate at all
  (uops.info: fused-uop-neutral on Intel big cores, half the ops on Zen).
  The store direction is never flagged -- MOVBE [RSI], EAX would leave the
  register un-swapped where the original leaves it swapped -- and neither
  is the moffs absolute form, whose 64-bit address the modrm-only MOVBE
  cannot encode

## missing MULX (only with `-m bmi2`)

* `48F7E2 4889D0` (MUL RDX; MOV RAX, RDX) -- one-operand MUL is pinned to
  fixed registers, multiplying RAX by its operand into RDX:RAX, so a widening
  multiply that wants only the high half spends a second instruction moving
  it out. MULX has no such pinning: one multiplicand implicitly from RDX, the
  other from any r/m, both halves of the product named, and no flags written.
  The pair is MULX RAX, RDX, RAX -- high half to RAX where the MOV was putting
  it, the low half (which the MOV proved dead by overwriting it unread) dumped
  into RDX. Six bytes and two instructions become five and one, with the flag
  write gone. Fires only for `MUL RDX`/`MUL EDX`: MULX's implicit multiplicand
  is RDX where MUL's is RAX, so `MUL RCX` would need a MOV into RDX in front
  and end up back at two instructions -- the condition that takes the corpus
  population from 415 sites to 101. Also requires RDX dead after the pair
  (MULX has no discard encoding for the low half, and RDX is the only home
  available without register allocation) and every arithmetic flag dead (MUL
  defines CF and OF and leaves SF/ZF/PF undefined; MULX writes none). IMUL
  never qualifies -- MULX is unsigned-only, which excludes the 517
  one-operand IMUL sites in the same shape. The MUL is often preceded by a
  `MOV RAX, src` that exists only because MUL demands its multiplicand in RAX;
  MULX takes that operand from any r/m, so applying such a finding frequently
  removes that instruction too, three to one

## missing POPCNT dependency break

* `F30FB8C1` (POPCNT EAX, ECX) -- on Sandy Bridge through Cascade Lake the
  destination is a phantom input (uops.info measures 3 cycles of latency
  from it), serializing independent counts behind the register's last
  writer. Insert XOR dst, dst just before: the count overwrites the zero
  and rewrites every arithmetic flag, so the insertion is value- and
  flag-invisible. Not flagged when the source is the destination (a real
  dependency the xor would destroy), when memory is addressed through the
  destination, or when the preceding instruction already redefined the
  register -- the mitigation gcc and clang emit. LZCNT and TZCNT (affected
  through Broadwell) are flagged the same way; their legacy aliases
  BSF/BSR are never flagged -- real silicon preserves their destination on
  a zero source, which the xor would change

## missing SSE dependency break

* `F30F5AC1` (CVTSS2SD XMM0, XMM1) -- the legacy scalar SSE instructions
  write only their destination's low element and leave the rest of the
  register standing ("DEST[127:64] (unmodified)" in the SDM), so the
  destination is an input to that merge on every core. Code that keeps
  scalars in vector registers never wants those bits, so the dependency is
  pure latency: the instruction serializes behind whatever wrote the
  register last, however unrelated. Insert XORPS dst, dst just before --
  the low element is overwritten, the upper bits were dead, and vector XOR
  writes no flags, so the insertion is invisible. gcc and clang both emit
  it; llvm carries a pass for it (X86's BreakFalseDeps). Flagged for
  CVTSI2SD/SS, CVTSS2SD, CVTSD2SS, SQRTSD/SS, ROUNDSD/SS, RCPSS and
  RSQRTSS. Not flagged when the source is the destination (a real
  dependency the xor would destroy), for the VEX and EVEX forms (whose
  third operand names the merge source outright -- the fix there is to
  choose that operand, a different rewrite reported separately as a stale
  VEX merge operand), when the preceding
  instruction already rewrote the whole register, whether by a
  same-register vector XOR or by any full producer, or when a same-register
  vector XOR reaches it on every path with no write to the register since,
  at any distance and across forward branches (a backward branch, a call,
  an ENDBR64, or an instruction after a jmp or ret that no seen branch
  targets clears that knowledge). ADDSD and the other
  scalar arithmetic merge identically and are never flagged: their
  destination is a genuine source operand, the same real-versus-phantom
  input distinction that keeps BSF/BSR out of the POPCNT check. A memory
  source needs no exception, unlike POPCNT's -- the address is built from
  general-purpose registers a vector zero idiom cannot disturb

## stale VEX merge operand

* `C5EA5AD1` (VCVTSS2SD XMM2, XMM2, XMM1) -- the VEX and EVEX three-operand
  forms of the same scalar family name the merge source outright, so
  passing the data source (or a register known dead) as that operand makes
  the destination a pure output at no cost: the fix is operand
  substitution, not insertion, and the fixed encoding is the same length.
  Flagged when the merge operand is neither the data source nor freshly
  rewritten (the same suppression window as the SSE check). This includes
  the destination-as-merge shape above and assemblers that fill vvvv with
  the "unused" 1111b pattern on an instruction that reads vvvv, which
  names xmm0 and silently serializes behind its last producer --
  SpiderMonkey's JIT emitted exactly that for every Math.floor
  (VROUNDSD XMM15, XMM0, XMM1, 1). For the integer conversions there is
  no XMM source to reuse, so as with the legacy forms only a fresh merge
  register is clean. Masked EVEX forms are skipped

## merging scalar move

* `F20F10CA` (MOVSD XMM1, XMM2) -- between registers MOVSS and MOVSD copy
  one element and merge the rest, the legacy forms from the destination's
  old value and VMOVSS/VMOVSD from their explicit vvvv operand, so a move
  that meant "copy the scalar" pays the same false dependency as the
  family above. Unlike the conversions the instruction itself is
  avoidable: MOVAPS copies the whole register a byte shorter (VMOVAPS at
  the same length), reads nothing but its source, and is eliminated at
  rename on current cores, which a merging move -- a real two-input uop
  -- never is. Flagged when the merge input is neither the data source
  nor freshly rewritten (the family's suppression window). The register
  form is also SSE2's idiom for a genuine two-source blend, the one
  consumer of these merge semantics that means them and the one place
  MOVAPS would corrupt the result, so this check alone adds a forward
  gate: a downstream read of the destination wider than the moved element
  -- git's gcc-vectorized loops movss-merge a recomputed lane and
  immediately movq-store both lanes -- proves the merged lanes live and
  suppresses, while a scalar-width consumer or an escape (glibc's fmax
  moves the chosen argument to the return register and returns) leaves
  the finding standing. A blend whose vector consumer sits past a branch
  or beyond the lookahead is still misflagged -- the accepted, narrowed
  residue of an advisory. The memory forms zero the upper lanes and are
  never flagged; masked EVEX forms are skipped

## merging narrow move

* `8A06` (MOV AL, [RSI]) -- the general-purpose sibling: an 8- or 16-bit
  register-destination MOV (a load or a register copy) writes only the
  low bits of its parent and merges the rest, and on every current core
  that merge is a real input -- Sandy Bridge's separate low-byte renaming
  was dropped in Haswell, and AMD never renamed partials, so the narrow
  write itself serializes behind the register's last producer, however
  unrelated. MOVZX (or MOVSX where the sign is wanted) performs the same
  load or copy writing the register whole: one uop either way, the byte
  forms one byte longer, the word forms the same length (the 66 prefix
  trades for the 0F escape), the dependency gone. Unlike the vector
  family the soundness condition is exactly computable, so this is a
  gated equivalence rewrite, not an advisory: flagged only when the bits
  at and above the written width are provably dead (register liveness at
  the matching boundary), which silences the deliberate byte-packing
  merge -- it reads the parent wide downstream -- and every escape,
  since a narrow value crossing a RET or branch may be the low end of a
  register whose upper bits carry real data. Store forms write no
  register; immediate sources are a different trade (three extra bytes,
  and the 16-bit-immediate shape is already the LCP finding); a
  high-byte destination has no extending spelling (reading AH as a
  source stays the efficient extraction and is never flagged); the
  same-register copy is redundant MOV reg, reg; a load whose next
  instruction extends it in place is load foldable into extend, and one
  whose next instruction compares it and lets it die is load foldable into
  compare; and
  8/16-bit arithmetic merges identically but has no same-cost full-width
  spelling with its flags and width semantics, so nothing sound can be
  suggested there

## missing SHLX/SHRX/SARX (only with `-m bmi2`)

* `D3E0` (SHL EAX, CL) -- SHLX EAX, EAX, ECX (BMI2) shifts without touching
  any flag, dropping the flag-merge uops CL-count shifts cost on Intel
  cores, and takes its count from any register. Flagged only while every
  arithmetic flag is dead (the CL form writes them all for a nonzero count;
  the BMI2 forms write none) and, for 32-bit forms, while the destination's
  upper half is dead -- the SDM leaves a count-0 shift writing nothing,
  where SHLX always zero-extends

## MOV constant foldable

* `B905000000 01C8` (MOV ECX, 5; ADD EAX, ECX) -- the constant folds into the
  next instruction's immediate: ADD EAX, 5. Applies to ADD/SUB/ADC/SBB/AND/OR/
  XOR/CMP/TEST/MOV that use the register as a source, when it is dead after the
  fold and the constant fits the immediate (gated by register liveness)

## MOV+ADD foldable to LEA

* `89F2 01FA` (MOV EDX, ESI; ADD EDX, EDI) -- the two are the non-destructive
  three-operand LEA EDX, [RSI+RDI], saving the MOV, when the arithmetic flags
  ADD would set are dead (gated by flag liveness)
* `89F2 83C205` (MOV EDX, ESI; ADD EDX, 5) -- an immediate addend folds the
  same way, as LEA EDX, [RSI+5]; SUB negates the displacement and INC/DEC
  are the implied +/-1 forms, which -- like LEA -- leave CF untouched, so
  only the flags they do write gate them. The pair need not be adjacent:
  the fold shares the missing-APX-NDD check's window and independence
  proof (`APX_NDD_WINDOW`), looking through instructions that neither
  touch the destination nor write the source, which keeps the division
  of labor with that check -- these pairs fold to LEA while the flags
  die, to an NDD op while they live -- exact at every distance. The
  finding is reported at the MOV, the instruction that disappears, but
  the LEA takes the ADD's place, and for a gapped pair that placement is
  what makes it correct: only the source's read moves later, which the
  window's independence proof covers, while the addend is still read
  where the ADD read it. Writing the LEA at the MOV instead would hoist
  the addend's read above anything between them -- in `MOV RCX, R12;
  MOV RBX, [RSP+0x70]; ADD RCX, RBX` (a Go site) it would read RBX
  before the load

## OR foldable into memory (only with `-m v8`)

* `8B4E6B 4C09F1 448B414F` (MOV ECX, [RSI+0x6B]; OR RCX, R14; MOV R8D,
  [RCX+0x4F]) -- V8's pointer decompression: a 32-bit compressed field is
  loaded (zero-extending) and merged with the cage base in R14, then used as
  a base. The OR is an ADD in disguise, because the cage base is 4 GB aligned
  and the loaded value fits in 32 bits, so the two share no set bits; the
  consumer's addressing mode carries the sum for free: MOV R8D,
  [R14+RCX*1+0x4F]. This is the ADD-foldable-into-memory check with a
  different producer, and it inherits every gate of that check (adjacency,
  a single index, dead flags, a dead destination, no incoming edge onto the
  consumer). What it adds is the disjointness proof: the merged register
  must be R14, the immediately preceding instruction must write the
  destination as a 32-bit register (which zero-extends), and no direct edge
  may land on the OR to bypass that write. The alignment of R14 is the one
  thing the bytes cannot prove, which is why the check is off without `-m
  v8`. V8 switched this sequence from ADD to OR in 2026-08 (commit
  2cdd6c55d1a); against JetStream 3 the ADD form had been the second most
  frequent finding of all. Measured on V8 15.5's JIT output for JetStream
  3's Kotlin compose benchmark, 6,851 of the 15,457 cage ORs in Liftoff code
  fold; of the rest, all but 61 fail the adjacency gate (the pointer is
  consumed later than the next instruction, or compared or stored rather
  than dereferenced), not the zero-extension proof.

## oversized ADD/SUB 128

* `05 80000000` instead of `83E8 80` (ADD EAX, 128 -> SUB EAX, -128)
* `2D 80000000` instead of `83C0 80` (SUB EAX, 128 -> ADD EAX, -128)

## oversized ADD/SUB one

* `83C0 01` instead of `FFC0` (ADD EAX, 1 -> INC EAX, when CF is unused)
* `836B10 01` instead of `FF4B10` (SUB DWORD [RBX+0x10], 1 -> DEC DWORD [RBX+0x10])
* The long-standing advice runs the other way -- "always use ADD and SUB
  instead of INC and DEC" (Agner Fog, *microarchitecture.pdf*) -- because
  INC and DEC write every arithmetic flag but CF, so a later read of CF
  together with them has to join two sources: a multi-cycle partial-flags
  stall through Core 2, and from Sandy Bridge an extra µop, still present on
  Haswell, whose example is exactly `inc eax ; jbe L1`. That cost lands only
  when something downstream reads CF, which is the very condition the CF
  gate above rules out: every finding emitted here has CF provably dead
  before its next write, so no reader spans the two halves and no merge is
  inserted. The gate that makes the rewrite correct is what makes it free

## oversized branch displacement

* `E9 00000000` instead of `EB 03` (JMP rel32 that fits in rel8)

## oversized displacement

* `8B 83 10000000` instead of `8B 43 10` (MOV EAX, [RBX+0x10]; disp32 that fits in disp8)

## oversized EVEX encoding

* `62F1FD286FCA` instead of `C5FD6FCA` (VMOVDQA64 YMM1, YMM2 -> VMOVDQA;
  without an opmask, broadcast, rounding, 512-bit length, or xmm16-31,
  the 4-byte EVEX prefix wastes 1-2 bytes over VEX). The demotion is proved
  by re-encoding through XED and comparing lengths, so a form VEX cannot
  express suppresses itself. A shorter encoding is not enough on its own,
  though: for a few families the VEX spelling is a *later* extension with
  its own CPUID bit rather than the older encoding of one feature --
  AVX512\_IFMA against AVX\_IFMA (VPMADD52LUQ/HUQ), AVX512\_VNNI against
  AVX\_VNNI (VPDP\*), AVX512\_BF16 against AVX\_NE\_CONVERT -- where the
  rewrite would fault on the very parts the EVEX form targets. The
  re-encoded instruction is decoded back and rejected on those ISA sets,
  which lets XED name the feature instead of the check inferring it

## oversized immediates

* `81C0 01000000` instead of `83C0 01` (ADD EAX, 1)
* `68 01000000` instead of `6A 01` (PUSH 1)
* `66 81C1 1200` instead of `66 83C1 12` (ADD CX, 0x12; imm16 narrows to the
  sign-extended imm8 the same way, except for AX, whose accumulator form
  already ties it)

## oversized LEA width

* `48 8D0411` instead of `8D0411` (LEA RAX, [RCX+RDX] -> LEA EAX, [RCX+RDX]) --
  both forms store the same low 32 address bits; they differ only in bits
  63:32, which the 64-bit form fills with the address's upper half and the
  32-bit form zeroes. When those bits are dead (gated by register liveness,
  with no backward zero-extension escape -- the rewrite still writes the
  register, so a predecessor's zeroing proves nothing about the new
  address's upper half) the REX.W byte is pure waste. Flagged only when W is
  the sole REX payload; an extended register in any slot keeps the prefix.
  Compilers emit this constantly for arithmetic that is immediately
  truncated: `lea rdx, [rax+5]; and edx, 0x3f`

## oversized MOV encoding

* `C7C0 01000000` instead of `B8 01000000` (MOV EAX, 1)
* `48 C7C0 01000000` instead of `B8 01000000` (MOV RAX, 1; the 32-bit form zero-extends)

## oversized TEST immediate

* `A9 01000000` instead of `A8 01` (TEST EAX, 1 -> TEST AL, 1; TEST has no
  sign-extended imm8 form, and a mask within the low seven bits sets
  identical flags at byte width)

## oversized VEX encoding

* `C4E17D6FCA` instead of `C5FD6FCA` (VMOVDQA YMM1, YMM2; the three-byte VEX
  prefix wastes a byte when the two-byte form's map/W/register constraints
  are met)

## oversized XCHG encoding

* `87C8` instead of `91` (XCHG EAX, ECX; the 90+r accumulator form is one byte)

## redundant ADD/SUB zero

* `83C0 00` (ADD EAX, 0) -- use TEST or remove (flag-exact; the 32-bit
  form's zero-extension is gated by register liveness)

## redundant AND immediate

* `83E0 FF` instead of `85C0` (AND EAX, -1 -> TEST EAX, EAX; an all-ones mask
  sets identical flags; the 32-bit form's zero-extension -- GCC's fused
  zero-extend-and-test -- is gated by register liveness)

## redundant bit-scan default

* `41B840000000 F34C0FBCC6` (MOV R8D, 0x40; TZCNT R8, RSI) -- a compiler
  writing the operand size into a register before a bit scan is supplying
  the zero-source answer by hand. That idiom exists because `BSF` and `BSR`
  leave their destination *undefined* when the source is zero, and real
  silicon preserves it, which is exactly what the sequence relies on.
  `TZCNT` and `LZCNT` have no such hole: they are defined to return the
  operand size and they write the destination unconditionally, so for those
  two spellings the MOV is dead outright. The constant carries its own
  proof, being equal to the width the instruction already returns.
* "Dead" needs two conditions the constant does not carry, both found by
  `tools/rwfuzz` (246 of 1,511 findings mismatched at 10,000 programs). The
  scan must not read the MOV's register: `MOV RCX, 64; TZCNT RCX, RCX`
  counts the 64, and an address formed from RCX loads through it. And the
  scan's write must cover the MOV's: a 16-bit `TZCNT CX, SI` writes bits
  15:0 only, so after `MOV ECX, 16` the zeroes in bits 63:16 are the MOV's,
  and deleting it would leave whatever RCX held before. `MOV CX, 16` in
  front of the same scan is still dead
* `BSF` and `BSR` are never matched, for the reason that makes this sound at
  all: their preserved destination is the mechanism, so the same MOV in
  front of one is load-bearing. The two are easy to tell apart by the
  constant, which is the answer in one case and a sentinel in the other --
  `mov ecx, 0x7f ; bsr rcx, rdx ; xor ecx, 0x3f` computes `63 - index`, and
  127 exclusive-ored with 63 gives 64 for the zero case.
* **The same MOV is also the false-dependency break**, which is why this
  needs a target rather than a liveness proof. `TZCNT` and `LZCNT` treat
  their destination as a phantom input through Broadwell, the same erratum
  class as `POPCNT`'s, and a `mov r32, imm32` is a full write with no input,
  so it cuts the chain. The shipped dependency-break check says as much and
  declines to flag a site "when the preceding instruction already redefined
  the register -- the mitigation gcc and clang emit". Two checks fighting
  over one instruction is worse than either finding, so this one reports only
  where the erratum is gone (`-t skylake` and later, and `-t zen`) and the
  dependency-break check drops its bit-scan arm on exactly those targets.
  The two gates are complementary halves of one fact.
* Measured: **305 sites in libxul** and none in the rest of the corpus, all
  of them under a target that has the fix. Every site dumped has the constant
  exactly equal to the operand size -- 108 of 108 sampled, 81 at 64 and 27 at
  32, with no exceptions -- which is what makes the width test a proof rather
  than a heuristic. The 1,067 `BSR` sites in the same shape carry a sentinel
  and are correctly not matched

## redundant CMOVcc reg, reg

* `480F44C0` (CMOVE RAX, RAX) -- a conditional move naming one register
  twice moves a value onto itself: it reads the flags and changes nothing.
  The 16- and 64-bit forms are pure no-ops.
* The 32-bit form is not, quite. CMOVcc writes its destination whether or
  not the condition holds, and a 32-bit write zero-extends, so deleting it
  is sound only while bits 63:32 are dead (register liveness, with the
  backward escape licensed because the rewrite deletes the write rather
  than replacing it -- cf. redundant MOV reg, reg).
* The memory form never matches and could not: it carries no second
  register, and it loads unconditionally, so it is not a no-op at all.
* 3 sites in libxul and none elsewhere in the corpus

## redundant MOV constant

* `B801000000 ... B801000000` (MOV EAX, 1; ...; MOV EAX, 1) -- the second
  move writes a value the register already holds, so it is dead. MOV writes
  no flags, so deleting it is unconditional, and no target question arises:
  this is the strong half of the constant tracking described under
  [rematerialized constant](#rematerialized-constant), where the register
  still holding the value is the destination itself
* 238 sites: libxul 188, libstdc++ 31, go 18, and none in libcrypto, glibc
  or bash

## rematerialized constant

* `41BA02000000 BF02000000` (MOV R10D, 2; MOV EDI, 2) -- a constant
  materialized into a register that another register provably still holds is
  a copy: MOV EDI, R10D, three bytes against five, and against ten where the
  immediate needed a MOVABS. There is no imm8 form of MOV, so the copy is
  shorter at every width
* **This check carries state across the scan**, as the frame-slot rows do,
  because the rewrite's precondition is about a value rather than a pattern. The map
  is deliberately small and loses toward not-a-finding: only the 32- and
  64-bit `MOV r, imm` forms are recorded, as the full 64-bit contents the
  write leaves behind; every register an instruction writes is cleared; and
  the whole map is cleared at a call, at any control transfer, at a branch
  target and at a decode error, since a register's contents cannot be carried
  across an edge the scan cannot see. What survives is a value provably
  present on every path reaching the site, which is also why the copy needs
  no liveness argument -- nothing has written the source since it was set.
* **The three MOV-immediate forms leave three different values behind**, and
  conflating them is a false positive rather than a missed finding. A 32-bit
  write zero-extends, so `MOV EDX, 0xffffffff` leaves `0x00000000ffffffff`,
  where the 64-bit imm32 form sign-extends and `MOV RDX, -1` leaves all ones.
  Reading the raw immediate for both makes them compare equal, which reported
  glibc's `__isoc23_strtoul` clamp as a redundant move of a value the
  register does not hold. A fixture pins it
* Target-gated on move elimination, so `-t skylake` and `-t zen` only. The
  rewrite replaces an independent immediate with a dependent copy:
  `mov r10d, 2 ; mov edi, 2` is two one-cycle instructions free to issue
  together, and the copy serializes them. Agner Fog's tables give `MOV r,r`
  latency 0 by renaming on Zen 1 through Zen 5 and 0-1 on Ivy Bridge through
  Coffee Lake, against a full cycle with no elimination on Sandy Bridge, Ice
  Lake and Tiger Lake. Zero defers to "suboptimal MOV zero", whose XOR is two
  bytes rather than three and breaks the dependency the copy would create
* **Unusually for this tool the conditions cost almost nothing**: 33,218
  findings of a 33,456 shape, 99%, where the CAS loop went 614 to 19 and the
  vector fold 18,236 to 583. TODO.md predicted that and gave the reason --
  the population was defined by the rewrite's own precondition rather than by
  a pattern the conditions would later cut down. libxul supplies 32,168,
  then go 403, libcrypto 195, libstdc++ 152, glibc 165 and bash 135
* What it does not settle is whether a compiler wants the advice.
  Rematerialization is a deliberate register-allocator technique, and LLVM
  marks `MOV32ri` trivially rematerializable precisely so the allocator can
  duplicate a constant rather than keep it live. A finding here is often the
  compiler's choice rather than its oversight, which is not true of anything
  else in this file

## redundant MOV reg, reg

* `4889C0` (MOV RAX, RAX)
* `89C0` (MOV EAX, EAX) -- the 8/16/64-bit forms are pure no-ops; the 32-bit
  form clears the upper 32 bits, so it is flagged when those bits are dead
  downstream or already zero from the preceding 32-bit write (both gated by
  register liveness)

## redundant OR/XOR zero

* `83C8 00` (OR EAX, 0) -- no-op that sets flags; use TEST or remove (the
  32-bit form's zero-extension is gated by register liveness)

## redundant zero-extension

* `C1EA18 0FB6D2` (SHR EDX, 24; MOVZX EDX, DL) -- the shift leaves at most
  the low eight bits standing and, being a 32-bit write, zeroes bits 63:32
  as well, so the extension after it clears nothing. Also `SETZ AL; AND AL,
  1`, where SETcc has already written 0 or 1.
* The producer's guarantee is a *range*, bits `[from, upto)` of the
  destination, and both ends matter. armlint tracks only the lower bound,
  because an AArch64 W-form write zeroes the upper half and the guarantee
  always reaches the top of the register; x86's 8- and 16-bit writes merge,
  so the upper bound has to be carried too. Dropping it is not hypothetical:
  `SETZ AL` guarantees bits 7:1 are zero and says nothing whatever about
  63:8, so it cannot excuse a following `MOVZX EAX, AL` -- that pair is the
  shipped "suboptimal SETcc zero-extension" and not this finding.
* Redundant when the guarantee starts at or below the bit the consumer
  clears from and reaches at least as high as the consumer writes. Producers
  recognized: an immediate `SHR`, an immediate `AND`, and any `SETcc`.
  Consumers: an in-place `MOVZX`, and an `AND` with a run of low bits, which
  writes the flags and so needs them dead where `MOVZX` does not.
* **MOVZX and MOVSX producers are deliberately absent**, being the shipped
  "redundant re-extension" check's own. That exclusion is most of the shape:
  counting them put this at 285 on libxul against that check's 254, which is
  re-reporting covered ground rather than sizing a candidate.
* 48 findings of 55 sites in libxul and 6 in go, the residue being consumers
  a branch targets

## redundant re-extension

* `0FB606 0FB6C0` (MOVZX EAX, byte [RSI]; MOVZX EAX, AL) -- the second
  extension re-establishes bits the first already made zero (or, for
  MOVSX/MOVSXD, already made the sign): a pure no-op when the kinds match,
  the producer extends from the same or a narrower source, and its
  established range covers every bit the consumer writes (sign-extensions
  must agree on destination width, since the 32-bit form zeroes bits 63:32
  where the 64-bit form sign-fills them). Rejected when a direct branch
  targets the re-extension -- a path that skips the producer

## redundant reload

* `488B442408 4889D1 488B5C2408` (MOV RAX, [RSP+8]; MOV RCX, RDX; MOV RBX,
  [RSP+8]) -- the frame slot is loaded again while the first load's value is
  still in a register, so the reload is MOV RBX, RAX: a load-port uop and the
  cache latency gone, and one to five bytes, since every load form of a
  frame slot is longer than the register copy at the same width. The 32-bit
  form is exact too, both the load and MOV r32, r32 zero-extending. Frame
  slots only, and RBP only as the frame pointer; see "Memory accesses: frame
  slots only" in the README for why, and for the table this check shares with
  the other frame-slot rows
* The claim survives anything that leaves the slot, the holding register and
  the base alone, including the fall-through of a conditional branch: the
  reload is reached by falling through, so the first load ran. A disjoint
  store through the same base provably misses the slot; any store through
  another address may not. The widths must agree. A load that replaces its
  own base (`mov rbp, [rbp-8]`) arms nothing
* Five-binary sweep: libc 57, libcrypto 34, bash 16, go 5, ld.so 3. Every
  C site is GCC's spill reload through the frame pointer -- `mov edi,
  [rbp-0x224] ; test edi, edi ; je ; ... ; mov eax, [rbp-0x224]` in bash's
  `check_signals` -- and go's are RSP-based, the population issue #29
  predicted from `tools/defuse` (libc 65, bash 27, libcrypto 33, counting the
  same-register reloads, which are their own row)

## redundant shift/rotate by zero

* `C1E0 00` (SHL EAX, 0) -- value and flags unchanged; hardware still
  zero-extends the 32-bit form even at count 0, so it is gated by register
  liveness. Register destinations only: removing `SHL dword [RDI], 0` would
  delete a memory access, which is observable in itself (it can fault, has
  MMIO side effects regardless of the value, and its non-atomic write-back
  can overwrite a racing store) -- and in practice the memory form is what
  data bytes (`C0 00 00`) decode to, not what compilers emit

## redundant TEST after flags

* `21D8 85C0` (AND EAX, EBX; TEST EAX, EAX) -- the AND already set SF/ZF/PF,
  so the TEST is dead. AND/OR/XOR match TEST's flags exactly (CF/OF cleared)
  and fire unconditionally; ADD/SUB/INC/DEC and friends diverge only on CF/OF
  and are flagged only when those are dead downstream (gated by flag liveness).
  The TEST need not be adjacent: it is searched for through `APX_NDD_WINDOW`,
  past instructions writing neither the flags nor the tested register. Reads
  of either are looked through -- both see the same value with the TEST gone
  -- which an alignment NOP or a spill store between the pair depends on;
  Go's assembler pads before an aligned branch target, hiding these behind a
  NOP. The register must match the producer's exactly, since `AND EAX, EBX`
  clears bits 63:32 and `TEST RAX, RAX` would read a sign bit the narrow
  form never sees

## redundant TEST after SETcc

* `0F94C0 84C0 74xx` (SETZ AL; TEST AL, AL; JE) -- SETcc preserves the
  compare's flags, so the TEST only recomputes a condition they still hold;
  branch on them directly (JE -> negated Jcc, JNE -> same). Drop the TEST
  always, and the SETcc too when AL is dead. Only JE/JNE and an exact-width
  TEST AL, AL match, gated on every arithmetic flag being dead on both
  successors (a direct branch's target is a known offset, so both are scanned)

## redundant TEST after shift

* `48D1E0 4885C0 75xx` (SHL RAX, 1; TEST RAX, RAX; JNE) -- a SHL/SHR/SAR of
  a register by a statically nonzero count (a nonzero masked immediate, or
  the by-one D0/D1 forms) already set SF/ZF/PF from its result, so the TEST
  recomputes flags the shift produced; branch on them directly. This closes,
  for the counts that are provably nonzero, the hole that keeps shifts out
  of "redundant TEST after flags" (a CL or masked-to-zero count writes no
  flags). CF/OF still diverge -- the shift's CF is the last bit shifted out
  where TEST clears it -- so both must be dead past the TEST; because the
  dominant consumer is a branch, a directly following JZ/JNZ/JS/JNS/JP/JNP
  (the CF/OF-blind conditions) is scanned on both successors instead of
  straight-line only (cf. redundant TEST after SETcc), and the walks treat
  a CALL as flag death -- neither ABI preserves flags across calls, and the
  motivating branch targets the cold-path call directly. Rotates never
  qualify: they write only CF/OF. The motivating shape is rustc/LLVM's
  panic-counter check `(x & ~(1 << 63)) == 0`, compiled to SHL RAX, 1;
  TEST RAX, RAX; JNE -- LLVM's TEST-immediate shrink creates the SHL behind
  its shl-to-add pattern's back and its compare peephole refuses shift
  counts 1-3 (kept convertible to LEA), so the dead TEST ships in every
  Rust binary. Composes with "suboptimal SHL one": both rewrites together
  leave ADD RAX, RAX; JNE

## redundant TEST immediate

* `A9 FFFFFFFF` instead of `85C0` (TEST EAX, -1 -> TEST EAX, EAX; an all-ones
  mask sets identical flags)

## shift pair foldable into extend

* `C1E018 C1F818` (SHL EAX, 24; SAR EAX, 24) -- shifting the low byte to the
  top and arithmetic-shifting it back sign-extends it in place; MOVSX EAX, AL
  computes that in one instruction at half the bytes (MOVSXD RAX, EAX for the
  64-bit shift by 32). SHR instead of SAR is the zero-extending twin -> MOVZX
  (MOV EAX, EAX for 32 -> 64). Fires when the low remainder is 8/16/32 bits
  and the second shift's flags are dead (gated by flag liveness)

## store of a value the slot already holds

* `488B442408 4885C0 7405 4889442408` (MOV RAX, [RSP+8]; TEST RAX, RAX; JE;
  MOV [RSP+8], RAX) -- a store of the bytes the frame slot already holds:
  delete it. The dead store read from the other end. That row deletes the
  first of two stores and needs the overwrite to be certain; this deletes
  the second and needs nothing of the kind, since putting back what is there
  is a no-op on every path that reaches it -- so it survives a conditional
  branch and a load through a pointer, neither of which changes the slot or
  the register. Where the earlier store is still unread, the pair is the
  dead store's, one rewrite per site
* What is compared is the bytes, not how they were read: the register a
  load filled at the store's width, the register an earlier store wrote
  from, or the same immediate an earlier `MOV` store wrote -- x86's form of
  riscvlint's store of `x0`. A slot keeps a store's claim and a load's side
  by side, as riscvlint's window does, so `mov [rsp+8], eax ; mov ecx,
  [rsp+8] ; mov [rsp+8], eax` is still found
* Five-binary sweep: go 870, libcrypto 147, bash 39, libc 36, ld.so 5.
  Go's are register-ABI arguments spilled to their home slots on one path
  and spilled again on the next, `mov [rsp+0xc0], rcx ; test rbx, rbx ; je ;
  ... ; mov [rsp+0xc0], rcx` in `runtime.mapassign_faststr`. GCC's are slots
  loaded, tested and written back unchanged -- `mov rcx, [rbp-0x28]` after
  a call and `mov [rbp-0x28], rcx` three instructions on in
  `ASYNC_start_job` -- often through `r8`-`r11`

## suboptimal AND immediate

* `25 FF000000` (AND EAX, 0xFF) -- use MOVZBL

## suboptimal AND zero

* `83E0 00` (AND EAX, 0) -- use XOR EAX, EAX (same flags, fewer bytes)

## suboptimal CMP zero

* `83F8 00` instead of `85C0` (CMP EAX, 0 -> TEST EAX, EAX)

## suboptimal CMP one

* `83F8 01 72xx` (CMP EAX, 1; JB) -- unsigned "< 1" is "== 0": TEST EAX,
  EAX; JZ answers it a byte shorter (JAE -> JNZ). Only the branch decision
  survives the rewrite, not the flags, so every arithmetic flag must be
  dead on both successors (gated by flag liveness, cf. redundant TEST
  after SETcc)

## suboptimal IMUL constant

* `6BC0 03` (IMUL EAX, EAX, 3) -- use LEA
* `6BC0 10` (IMUL EAX, EAX, 16) -- use SHL (any power of two, same register)
* `6BC1 00` (IMUL EAX, ECX, 0) -- the product is always zero: use XOR
* `6BC1 01` (IMUL EAX, ECX, 1) -- the product is the source: use MOV, or
  remove the same-register form outright (its dropped zero-extension is
  gated by register liveness)
* `6BC0 FF` (IMUL EAX, EAX, -1) -- in-place negation: use NEG

## suboptimal lane-0 extract

* `660F3A16C000` (PEXTRD EAX, XMM0, 0) -- extracting lane 0 of a vector
  register is a plain cross-file move, which the MOV forms spell in fewer
  bytes and on an older feature level:

  ```
  pextrd eax, xmm0, 0      66 0F 3A 16 C0 00   ->  movd eax, xmm0      4 bytes
  pextrq rax, xmm0, 0      +REX.W, 7 bytes     ->  movq rax, xmm0      5 bytes
  vextractps [m], xmm0, 0  C4 E3 79 17 ... 00  ->  vmovss [m], xmm0    4 bytes
  ```

* The index is the whole condition: lane 0 is exactly what MOVD, MOVQ and
  MOVSS address, and the instructions are otherwise identical in what they
  read and write. PEXTR is SSE4.1 where MOVD is SSE2, so the rewrite also
  lowers the feature level the code requires, which no target turns into a
  loss.
* 10 sites in libxul, every one the `vextractps` spelling, and none
  elsewhere in the corpus

## suboptimal LEA

* `488D03` (LEA RAX, [RBX]) -- use MOV RAX, RBX (more ports, no AGU)
* `488D0408` (LEA RAX, [RAX+RCX]) -- an in-place two-register LEA is ADD RAX,
  RCX, a byte shorter (no SIB) and on more ports, when the arithmetic flags
  are dead (gated by flag liveness). Not when the address is narrower than
  the destination: `67488D0408` (LEA RAX, [EAX+ECX]) sums in 32 bits and
  zero-extends, which no ADD computes. `tools/rwfuzz` ran that rewrite and
  found the difference (124 of 3,409 findings at 10,000 programs)

## suboptimal MOV zero

* `B8 00000000` (MOV EAX, 0) -- use XOR EAX, EAX (fewer bytes, breaks the
  dependency chain); flagged only when the arithmetic flags XOR would clobber
  are dead, so the deliberate flag-preserving MOV before a CMOV
  ([#7](https://github.com/gaul/x86lint/issues/7)) is not flagged

## suboptimal OR/AND reg, reg

* `09C0` (OR EAX, EAX) -- use TEST EAX, EAX (same flags, no register write;
  the 32-bit form's zero-extension is gated by register liveness)

## suboptimal SETcc inversion

* `0F94C0 3401` (SETZ AL; XOR AL, 1) -- SETcc writes 0 or 1, so inverting it
  with XOR reproduces what the complementary condition code sets directly:
  SETNZ AL, and the XOR disappears. Every condition has a complement, so the
  rewrite always exists. SETcc writes no flags where XOR writes all the
  arithmetic ones, so the finding is gated on those being dead past the pair
  (flag liveness). The register must match exactly and the XOR be 8-bit:
  XOR EAX, 1 flips the same bit but writes the whole register, zero-extending
  into bits 63:8 where SETNZ AL leaves them alone. Adjacent-only -- the pair
  is one emitted idiom, and a gap could neither read the destination (it
  would see the value before an inversion the rewrite moves earlier) nor
  write it

## suboptimal SETcc zero-extension

*Advisory class: reported only under `-a advisory` or `-a all`. Under `-m apx`
the same pair is "missing APX SETZU" instead, which is a verified rewrite and
stays in the default scan.*

* `0F94C0 0FB6C0` (SETZ AL; MOVZX EAX, AL) -- Intel's preferred form zeroes
  the register ahead of the flag-setting compare (XOR EAX, EAX; CMP ...;
  SETZ AL), dropping the MOVZX and the partial-register merge it exists to
  hide. Advisory: the XOR belongs upstream of the flag-setter, whose
  surroundings a peephole cannot prove safe, so the rewrite is suggested,
  not verified. Same-register, low-byte, 32/64-bit forms only; rejected
  when a direct branch targets the MOVZX -- that path's byte was set by
  something else. Under `-m apx` the same pair reports as missing APX
  SETZU instead: the zero-upper form is the exact in-place fold the
  baseline lacks

## suboptimal SHL one

* `D1E0` (SHL EAX, 1) -- ADD EAX, EAX computes the same value with the same
  flags in the same two bytes but on roughly twice the execution ports; the
  C1 imm8 form of a 1-count shift is a byte longer besides. CF takes the
  shifted-out bit either way, and OF agrees because a 1-bit shift defines it
  as MSB(result) XOR CF, which is exactly the signed overflow of adding a
  value to itself. The one divergence is AF, which SHL leaves undefined and
  ADD defines; that runs in the safe direction -- no correct program reads
  an undefined flag -- so the finding stays unconditional

## suboptimal SSE MOV opcode

* `660F6FCA` instead of `0F28CA` (MOVDQA XMM1, XMM2 -> MOVAPS; the legacy
  66/F3-prefixed copies movapd/movdqa/movupd/movdqu waste a byte over
  movaps/movups). All four are bit copies, so the rewrite never changes a
  value. The byte is free on the load and store forms -- no bypass delay
  attaches to moving the "wrong" type to or from memory (Agner Fog,
  *microarchitecture.pdf*) -- and those are the bulk of the findings here,
  88-92% on the larger binaries in the measurement corpus. The
  register-to-register forms carry a caveat on cores that separate the
  integer and FP domains: from Nehalem, MOVAPS/MOVAPD issue on port 5 alone
  where MOVDQA reaches the integer units, so the shorter encoding can cost
  bypass latency in a dependency chain, and throughput besides -- one move
  per clock against three. Move elimination on later cores erases the
  distinction, so this is recorded as a caveat rather than a gate

## suboptimal SSE zero idiom

* `660FEFC0` instead of `0F57C0` (PXOR XMM0, XMM0 -> XORPS XMM0, XMM0; XOR
  is typeless, and the self forms write identical bits -- 128 zeros, upper
  YMM and flags untouched, no exceptions -- while every recent core zeroes
  them at rename, so the integer/float domain choice cannot matter. XORPD's
  self form wastes the same 66 prefix. Legacy SSE only: under VEX the
  prefix rides in the pp field and vpxor/vxorps are the same length. Only
  the self form is flagged -- a data XOR really executes, where the domain
  can matter on older cores)

## suboptimal SUB reg, reg

* `29C0` (SUB EAX, EAX) -- XOR EAX, EAX zeroes the register in the same two
  bytes, so this is not about size but about which self-operations a core
  recognizes as independent of the register's prior value. Intel's big cores
  and AMD list XOR and SUB together and the rewrite buys nothing there; the
  low-power line does not, and on Silvermont "SUB, SBB and CMP instructions
  are not recognized in this way" (Agner Fog, *microarchitecture.pdf*), so
  the SUB carries a false dependency the XOR breaks. Measured on a desktop
  part this check looks like noise, which is why the reason is written down.
  One flag diverges, and unusually it runs the wrong way: SUB defines AF
  where XOR leaves it undefined. Nothing here can gate on that -- FLAG_ARITH
  omits AF -- and no 64-bit code observes it without LAHF or PUSHF

## suboptimal VEX operand order

* `C4C175FEC0` instead of `C5BDFEC1` (VPADDD YMM0, YMM1, YMM8 -> VPADDD
  YMM0, YMM8, YMM1). The two-byte VEX prefix carries VEX.R and all four
  vvvv bits but not VEX.B, so a register 8-15 in ModRM.rm forces the
  three-byte form even where map 0F and W0 would otherwise fit the short
  one. A commutative operation can move its high source into vvvv,
  provided the other source is 0-7 and can take rm.
* `C4C1796FC0` instead of `C5797FC0` (VMOVDQA XMM0, XMM8, load form ->
  store form). A register copy has two spellings, with the source in rm or
  in reg, so a high source goes in reg when the destination is 0-7. The
  pairs are MOVAPS/MOVAPD 28/29, MOVUPS/MOVUPD 10/11, MOVDQA/MOVDQU 6F/7F
  and MOVQ xmm, xmm F3 7E/66 D6.
* Sound by construction. The set of commutative operations is exact:
  integer add, saturating add, multiply, multiply-add, average, SAD,
  equality compares, min/max, and the bitwise logic of both domains. None
  of these writes flags or raises an exception. FP add and multiply are
  excluded although GCC and LLVM both treat them as commutative: when both
  sources are NaN, the result is the first source's payload. Scalar forms
  are excluded because they take their upper lanes from the first source.
  VMOVSS/VMOVSD are excluded because their register forms merge a third
  operand. A memory operand is never flagged, since there VEX.B extends the
  base. The rewrite is assembled and decoded, and the finding stands only
  if XED reads back the same iclass with the operands where they should be,
  one byte shorter. The check fires only with VEX.B set and
  [oversized VEX encoding](#oversized-vex-encoding) only with it clear, so
  the two never report the same instruction.
* Measured on 2026-11-01:

  | binary | sites | mix |
  | --- | --- | --- |
  | libcrypto | 1,224 | perlasm, mostly `vpxor`, `vpaddd`, `vpaddq` |
  | libxul | 606 | 523 sources to swap, 83 `vmovdqa` |
  | glibc | 380 | 376 in the AVX2 `strcasecmp`/`strncasecmp` family, 368 of them `vpaddb` |
  | Go toolchain | 296 | hand-written assembly |
  | SpiderMonkey WasmBaseline | 186 | |
  | SpiderMonkey WasmIon | 29 | |

  libLLVM, libclang-cpp, bash and ld.so have none, nor do SpiderMonkey's JS
  tiers. Clang's output has none because LLVM already commutes for the
  short encoding. GCC 16 does not. GNU as `-O2` swaps some sources and no
  copies, and Go's assembler encodes what it is given.
* Most three-byte copies in the corpus cannot be fixed this way. In libxul
  and WasmIon they are `vmovd` to or from a GPR, which has no second
  spelling, or copies with both registers high.

## suboptimal XOR immediate

* `83F0 FF` instead of `F7D0` (XOR EAX, -1 -> NOT EAX, when flags are unused)

## unneeded explicit immediate

* `C1D0 01` instead of `D1D0` (RCL EAX, 1)

## unneeded explicit register

* `81C0 00010000` instead of `05 00010000` (ADD EAX, 0x100)

## unneeded LOCK prefix on XCHG


## unneeded MOVSX

* `0FBFC0` instead of `98` (MOVSX EAX, AX -> CWDE)
* `66 0FBEC0` instead of `66 98` (MOVSX AX, AL -> CBW)

## unneeded MOVSXD

* `48 63 C0` instead of `48 98` (MOVSXD RAX, EAX -> CDQE)

## unneeded REP prefix on RET

* `F3C3` instead of `C3` (REP RET, the AMD K8/K10 branch-predictor
  workaround gcc emitted until GCC 8; every core ignores the prefix and the
  predictor quirk is gone since Bulldozer and Zen, so dropping the byte is
  unconditional)

## unneeded REX prefix

* XOR RAX, RAX `4831C0` instead of XOR EAX, EAX `31C0`
* `40C9` instead of `C9` (LEAVE)
* `48 0FB6C3` instead of `0FB6C3` (MOVZX RAX, BL -> MOVZX EAX, BL; the r32 form zero-extends to 64)

## unneeded SIB byte

* `C64465 04 05` instead of `C645 04 05` (MOV byte [RBP+4], 5)

## unneeded zero displacement

* `017E 00` instead of `013E` (ADD [RSI], EDI)
