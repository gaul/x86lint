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
* Reported only when the RESULT stays within two components. Base, index and
  displacement together is the "slow LEA": 3 cycles on port 1 alone from Sandy
  Bridge onward, where each two-component form is 1 cycle on two ports. Folding
  a fast LEA plus an ADD (2 cycles, two ports) into a slow one trades a uop and
  three or four bytes for a cycle of latency and a port -- a trade, not an
  improvement. The gate costs most of the population (2,678 findings of 39,715
  sound folds in libxul) and keeps every finding a win on all three of size,
  uops and latency: the reported shape is `LEA rD, [rX*s]` plus `ADD rD, rT`,
  which becomes a one-cycle two-component LEA where the pair took two

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
  Neither arm evaluates the condition -- knowing that both operands are fixed
  is enough to know the outcome is.
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
  covering bits 15:8. The TEST is searched for through `APX_NDD_WINDOW`, and
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

## IBT-bypassing NOTRACK call

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
  leaves bits 255:128 standing where a VEX write zeroes them
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
  VEX merge operand), or when the preceding
  instruction already rewrote the whole register, whether by a
  same-register vector XOR or by any full producer. ADDSD and the other
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

## redundant MOV reg, reg

* `4889C0` (MOV RAX, RAX)
* `89C0` (MOV EAX, EAX) -- the 8/16/64-bit forms are pure no-ops; the 32-bit
  form clears the upper 32 bits, so it is flagged when those bits are dead
  downstream or already zero from the preceding 32-bit write (both gated by
  register liveness)

## redundant OR/XOR zero

* `83C8 00` (OR EAX, 0) -- no-op that sets flags; use TEST or remove (the
  32-bit form's zero-extension is gated by register liveness)

## redundant re-extension

* `0FB606 0FB6C0` (MOVZX EAX, byte [RSI]; MOVZX EAX, AL) -- the second
  extension re-establishes bits the first already made zero (or, for
  MOVSX/MOVSXD, already made the sign): a pure no-op when the kinds match,
  the producer extends from the same or a narrower source, and its
  established range covers every bit the consumer writes (sign-extensions
  must agree on destination width, since the 32-bit form zeroes bits 63:32
  where the 64-bit form sign-fills them). Rejected when a direct branch
  targets the re-extension -- a path that skips the producer

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

## suboptimal LEA

* `488D03` (LEA RAX, [RBX]) -- use MOV RAX, RBX (more ports, no AGU)
* `488D0408` (LEA RAX, [RAX+RCX]) -- an in-place two-register LEA is ADD RAX,
  RCX, a byte shorter (no SIB) and on more ports, when the arithmetic flags
  are dead (gated by flag liveness)

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
