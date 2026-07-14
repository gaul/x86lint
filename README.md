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
  nothing regardless of downstream reads. The escape holds only if every
  path to the instruction runs through that predecessor, so a direct branch
  targeting the instruction itself -- arriving with unknown upper bits --
  cancels it. The escape is licensed per check, because it is sound only for
  rewrites that *delete* the write: narrowing `lea rax, [...]` to
  `lea eax, [...]` (oversized LEA width) still writes the register, swapping
  the address's upper half for zeros, so a predecessor's zeroing of the
  destination -- overwritten either way -- proves nothing, and that check
  runs the forward gate alone.

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
* length-changing prefix stall
  - `66 81C1 3412` (ADD CX, 0x1234) -- a 66 prefix that changes the
    immediate's length (imm32 -> imm16) defeats the pre-decoder's length
    speculation on Intel big cores through the Skylake era, costing ~3 cycles
    per visit (Intel optimization manual, "Length-Changing Prefixes").
    Advisory: the clean fix -- 32-bit operands -- needs upper-16 liveness
    this tool does not track. A 66-prefixed imm16 whose value fits imm8 is
    already the oversized-immediate finding, whose narrowing removes the LCP
    by itself
* load foldable into extend
  - `8A06 0FB6C0` (MOV AL, [RSI]; MOVZX EAX, AL) -- a narrow load then an
    in-place sign/zero-extension is a single extending load: MOVZX EAX, byte
    [RSI]. Removes the load and its partial-register write; also MOVSX and the
    MOVSXD (32->64) form
* missing ANDN (only with `-m bmi1`)
  - `F7D0 21C8` (NOT EAX; AND EAX, ECX) -- one ANDN EAX, EAX, ECX (BMI1)
    computes ~x & y directly. An exact fold: both forms write only the
    destination, SF/ZF come from the same result, and CF/OF are cleared by
    both; flagged only while PF -- which AND defines and ANDN leaves
    undefined -- is dead. Immediate masks are not flagged (ANDN has no
    immediate form), nor is an AND into a different register (the NOT's
    result would stay live)
* missing APX NDD (only with `-m apx`)
  - `89F8 29F0` (MOV EAX, EDI; SUB EAX, ESI) -- one EVEX new-data-destination
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
    NDD form's write behavior is unverified). The consumer need not be
    adjacent: the fold looks through up to `APX_NDD_WINDOW - 2` intervening
    instructions (one at the default of 3; a build-time constant sized for
    experimentation) that prove themselves independent -- straight-line
    code that never touches the copy's register at any width and never
    writes the mov's source -- so a scheduling gap like a flag-zeroing
    XOR, a load, or a store does not hide the pair. Division of labor:
    register and immediate ADD and immediate SUB stay with the
    MOV+ADD-foldable-to-LEA finding, which needs no extension; CL-count
    shifts stay with missing SHLX; and under both extensions the BLSI
    triple's mov/neg prefix defers to the 3 -> 1 BLSI collapse. One
    instruction and one uop fewer and a shorter dependency chain, though
    the 4-byte EVEX prefix can cost two bytes of size on a 32-bit pair
* missing BLSI (only with `-m bmi1`)
  - `89F9 F7D9 21F9` (MOV ECX, EDI; NEG ECX; AND ECX, EDI) -- one BLSI ECX,
    EDI (BMI1) isolates the lowest set bit, collapsing the whole triple: the
    copy exists only because x and -x must coexist, and BLSI reads its
    source directly. Flagged only while CF -- which AND clears but BLSI sets
    to (source != 0) -- and PF -- defined vs undefined -- are dead. Not
    flagged when the copy aliases its source (the AND then computes -x, not
    x & -x) or when the AND lands in the source register (the original
    keeps -x live in the copy)
* missing BLSMSK (only with `-m bmi1`)
  - `8D50FF 31C2` (LEA EDX, [RAX-1]; XOR EDX, EAX) -- one BLSMSK EDX, EAX
    (BMI1) builds the mask through the lowest set bit: the BLSR idiom with
    the AND swapped for an XOR, gated the same way (CF and PF dead). ZF
    needs no gate -- BLSMSK hardwires it to 0 where XOR computes it, but
    x ^ (x-1) is never zero. Not flagged when the XOR's destination is the
    decremented register itself (the original keeps source-1 live there)
* missing BLSR (only with `-m bmi1`)
  - `8D50FF 21C2` (LEA EDX, [RAX-1]; AND EDX, EAX) -- one BLSR EDX, EAX
    (BMI1) clears the lowest set bit. Flagged only while CF -- which AND
    clears but BLSR sets to (source == 0) -- and PF -- defined vs undefined
    -- are dead; SF/ZF come from the same result either way. Not flagged when
    the AND's destination is the decremented register itself (the original
    keeps source-1 live there)
* missing LOCK prefix on CMPXCHG and XADD
* missing MOVBE (only with `-m movbe`)
  - `8B06 0FC8` (MOV EAX, [RSI]; BSWAP EAX) -- one MOVBE EAX, [RSI] performs
    the byte-swapping load: one instruction instead of two, never larger.
    None of the three instructions touches a flag and only the destination
    register is written, so the fold is exact with no liveness gate at all
    (uops.info: fused-uop-neutral on Intel big cores, half the ops on Zen).
    The store direction is never flagged -- MOVBE [RSI], EAX would leave the
    register un-swapped where the original leaves it swapped -- and neither
    is the moffs absolute form, whose 64-bit address the modrm-only MOVBE
    cannot encode
* missing POPCNT dependency break
  - `F30FB8C1` (POPCNT EAX, ECX) -- on Sandy Bridge through Cascade Lake the
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
* missing SHLX/SHRX/SARX (only with `-m bmi2`)
  - `D3E0` (SHL EAX, CL) -- SHLX EAX, EAX, ECX (BMI2) shifts without touching
    any flag, dropping the flag-merge uops CL-count shifts cost on Intel
    cores, and takes its count from any register. Flagged only while every
    arithmetic flag is dead (the CL form writes them all for a nonzero count;
    the BMI2 forms write none) and, for 32-bit forms, while the destination's
    upper half is dead -- the SDM leaves a count-0 shift writing nothing,
    where SHLX always zero-extends
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
  - `66 81C1 1200` instead of `66 83C1 12` (ADD CX, 0x12; imm16 narrows to the
    sign-extended imm8 the same way, except for AX, whose accumulator form
    already ties it)
* oversized LEA width
  - `48 8D0411` instead of `8D0411` (LEA RAX, [RCX+RDX] -> LEA EAX, [RCX+RDX]) --
    both forms store the same low 32 address bits; they differ only in bits
    63:32, which the 64-bit form fills with the address's upper half and the
    32-bit form zeroes. When those bits are dead (gated by register liveness,
    with no backward zero-extension escape -- the rewrite still writes the
    register, so a predecessor's zeroing proves nothing about the new
    address's upper half) the REX.W byte is pure waste. Flagged only when W is
    the sole REX payload; an extended register in any slot keeps the prefix.
    Compilers emit this constantly for arithmetic that is immediately
    truncated: `lea rdx, [rax+5]; and edx, 0x3f`
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
* redundant re-extension
  - `0FB606 0FB6C0` (MOVZX EAX, byte [RSI]; MOVZX EAX, AL) -- the second
    extension re-establishes bits the first already made zero (or, for
    MOVSX/MOVSXD, already made the sign): a pure no-op when the kinds match,
    the producer extends from the same or a narrower source, and its
    established range covers every bit the consumer writes (sign-extensions
    must agree on destination width, since the 32-bit form zeroes bits 63:32
    where the 64-bit form sign-fills them). Rejected when a direct branch
    targets the re-extension -- a path that skips the producer
* redundant shift/rotate by zero
  - `C1E0 00` (SHL EAX, 0) -- value and flags unchanged; hardware still
    zero-extends the 32-bit form even at count 0, so it is gated by register
    liveness. Register destinations only: removing `SHL dword [RDI], 0` would
    delete a memory access, which is observable in itself (it can fault, has
    MMIO side effects regardless of the value, and its non-atomic write-back
    can overwrite a racing store) -- and in practice the memory form is what
    data bytes (`C0 00 00`) decode to, not what compilers emit
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
* shift pair foldable into extend
  - `C1E018 C1F818` (SHL EAX, 24; SAR EAX, 24) -- shifting the low byte to the
    top and arithmetic-shifting it back sign-extends it in place; MOVSX EAX, AL
    computes that in one instruction at half the bytes (MOVSXD RAX, EAX for the
    64-bit shift by 32). SHR instead of SAR is the zero-extending twin -> MOVZX
    (MOV EAX, EAX for 32 -> 64). Fires when the low remainder is 8/16/32 bits
    and the second shift's flags are dead (gated by flag liveness)
* suboptimal AND immediate
  - `25 FF000000` (AND EAX, 0xFF) -- use MOVZBL
* suboptimal AND zero
  - `83E0 00` (AND EAX, 0) -- use XOR EAX, EAX (same flags, fewer bytes)
* suboptimal CMP zero
  - `83F8 00` instead of `85C0` (CMP EAX, 0 -> TEST EAX, EAX)
* suboptimal CMP one
  - `83F8 01 72xx` (CMP EAX, 1; JB) -- unsigned "< 1" is "== 0": TEST EAX,
    EAX; JZ answers it a byte shorter (JAE -> JNZ). Only the branch decision
    survives the rewrite, not the flags, so every arithmetic flag must be
    dead on both successors (gated by flag liveness, cf. redundant TEST
    after SETcc)
* suboptimal IMUL constant
  - `6BC0 03` (IMUL EAX, EAX, 3) -- use LEA
  - `6BC0 10` (IMUL EAX, EAX, 16) -- use SHL (any power of two, same register)
  - `6BC1 00` (IMUL EAX, ECX, 0) -- the product is always zero: use XOR
  - `6BC1 01` (IMUL EAX, ECX, 1) -- the product is the source: use MOV, or
    remove the same-register form outright (its dropped zero-extension is
    gated by register liveness)
  - `6BC0 FF` (IMUL EAX, EAX, -1) -- in-place negation: use NEG
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
* suboptimal SETcc zero-extension
  - `0F94C0 0FB6C0` (SETZ AL; MOVZX EAX, AL) -- Intel's preferred form zeroes
    the register ahead of the flag-setting compare (XOR EAX, EAX; CMP ...;
    SETZ AL), dropping the MOVZX and the partial-register merge it exists to
    hide. Advisory: the XOR belongs upstream of the flag-setter, whose
    surroundings a peephole cannot prove safe, so the rewrite is suggested,
    not verified. Same-register, low-byte, 32/64-bit forms only; rejected
    when a direct branch targets the MOVZX -- that path's byte was set by
    something else
* suboptimal SHL one
  - `D1E0` (SHL EAX, 1) -- ADD EAX, EAX computes the same value with identical
    flags (CF gets the shifted-out bit either way, and OF matches too) in the
    same two bytes but on roughly twice the execution ports; the C1 imm8 form
    of a 1-count shift is a byte longer besides. Value- and flag-exact at
    every width, so unconditional
* suboptimal SSE MOV opcode
  - `660F6FCA` instead of `0F28CA` (MOVDQA XMM1, XMM2 -> MOVAPS; the legacy
    66/F3-prefixed copies movapd/movdqa/movupd/movdqu waste a byte over
    movaps/movups)
* suboptimal SSE zero idiom
  - `660FEFC0` instead of `0F57C0` (PXOR XMM0, XMM0 -> XORPS XMM0, XMM0; XOR
    is typeless, and the self forms write identical bits -- 128 zeros, upper
    YMM and flags untouched, no exceptions -- while every recent core zeroes
    them at rename, so the integer/float domain choice cannot matter. XORPD's
    self form wastes the same 66 prefix. Legacy SSE only: under VEX the
    prefix rides in the pp field and vpxor/vxorps are the same length. Only
    the self form is flagged -- a data XOR really executes, where the domain
    can matter on older cores)
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
* unneeded REP prefix on RET
  - `F3C3` instead of `C3` (REP RET, the AMD K8/K10 branch-predictor
    workaround gcc emitted until GCC 8; every core ignores the prefix and the
    predictor quirk is gone since Bulldozer and Zen, so dropping the byte is
    unconditional)
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

Run the unit suite and the ELF-driver smoke test with
`XED_PATH=/path/to/xed make check`.

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
    return check_instructions(inst, len, /*verbose=*/false, /*summary=*/NULL,
                              /*extensions=*/0);
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
oversized immediate at offset: 0x14: push 0x0
  68 00 00 00 00
...
```

Pass `-m bmi1`, `-m bmi2`, `-m movbe`, and/or `-m apx` to declare that the
binary's target supports those instruction-set extensions, enabling the
checks that suggest replacing a baseline sequence with an instruction from
that set (missing ANDN, missing BLSI, missing BLSMSK, missing BLSR, missing
SHLX/SHRX/SARX, missing MOVBE, missing APX NDD). These
are opt-in because the finding is only actionable when the target guarantees
the extension: a distro binary built for x86-64-v2 could not have used ANDN
however clear the opportunity, and inferring availability from the
surrounding bytes is unsound for binaries like glibc that keep baseline code
and CPU-dispatched BMI-rich variants in the same section. The flags are
independent, matching their CPUID feature bits: `-m bmi2` does not imply
`-m bmi1`.

The exit status follows the grep convention -- 0 for a clean scan, 1 when any
opportunity is found, 2 on a tool failure (unreadable or malformed input) --
so x86lint can gate a compiler test suite and CI can tell a dirty scan from a
broken run.

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
