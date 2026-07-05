# x86lint

x86lint examines x86-64 machine code to find suboptimal encodings and sequences.
For example, `add eax, 1` can encode with either an 8- or 32-bit immediate:

```
83C0 01
81C0 01000000
```

Using the former can result in smaller and faster code.  x86lint can help
compiler writers generate better code and documents the complexity of x86.

## Implemented analyses

* missing LOCK prefix on CMPXCHG and XADD
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
  - `83C0 00` (ADD EAX, 0) -- use TEST or remove
* redundant MOV reg, reg
  - `4889C0` (MOV RAX, RAX)
* redundant shift/rotate by zero
  - `C1E0 00` (SHL EAX, 0) -- no-op, flags also unchanged
* suboptimal AND immediate
  - `83E0 FF` (AND EAX, 0xFF) -- use MOVZBL
* suboptimal CMP zero
  - `83F8 00` instead of `85C0` (CMP EAX, 0 -> TEST EAX, EAX)
* suboptimal IMUL constant
  - `6BC0 03` (IMUL EAX, EAX, 3) -- use LEA or SHL
* suboptimal LEA
  - `488D03` (LEA RAX, [RBX]) -- use MOV RAX, RBX (more ports, no AGU)
* ~~suboptimal NOP sequence~~, see [#9](https://github.com/gaul/x86lint/issues/9)
  - multiple `90` instead of a single `66 90`, etc.
* suboptimal OR/AND reg, reg
  - `09C0` (OR EAX, EAX) -- use TEST EAX, EAX (same flags, no register write)
* suboptimal SSE MOV opcode
  - `660F6FCA` instead of `0F28CA` (MOVDQA XMM1, XMM2 -> MOVAPS; the legacy
    66/F3-prefixed copies movapd/movdqa/movupd/movdqu waste a byte over
    movaps/movups)
* suboptimal SUB reg, reg
  - `29C0` (SUB EAX, EAX) -- use XOR for dependency-breaking
* suboptimal XOR immediate
  - `83F0 FF` instead of `F7D0` (XOR EAX, -1 -> NOT EAX, when flags are unused)
* ~~suboptimal zero register~~, see [#7](https://github.com/gaul/x86lint/issues/7)
  - MOV EAX, 0 instead of XOR EAX, EAX
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

The process exits non-zero when any opportunity is found, so x86lint can gate
a compiler test suite.

## References

* [Agner Fog optimization guide](https://www.agner.org/optimize/optimizing_assembly.pdf)
* [Intel instruction set reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf)
* [Intel optimization manual](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-optimization-manual.pdf)
* [Intel x86 encoder decoder](https://github.com/intelxed/xed) - library to parse instructions
* [armlint](https://github.com/gaul/armlint) - AArch64 equivalent of armlint

## License

Copyright (C) 2018 Andrew Gaul

Licensed under the Apache License, Version 2.0
