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
* oversized ADD 128
  - `05 80000000` instead of `83E8 80` (ADD EAX, 128 -> SUB EAX, -128)
* oversized branch displacement
  - `E9 00000000` instead of `EB 03` (JMP rel32 that fits in rel8)
* oversized displacement
  - `8B 83 10000000` instead of `8B 43 10` (MOV EAX, [RBX+0x10]; disp32 that fits in disp8)
* oversized immediates
  - `81C0 01000000` instead of `83C0 01` (ADD EAX, 1)
  - `68 01000000` instead of `6A 01` (PUSH 1)
* oversized MOV encoding
  - `C7C0 01000000` instead of `B8 01000000` (MOV EAX, 1)
  - `48 C7C0 01000000` instead of `B8 01000000` (MOV RAX, 1; the 32-bit form zero-extends)
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
* suboptimal SUB reg, reg
  - `29C0` (SUB EAX, EAX) -- use XOR for dependency-breaking
* ~~suboptimal zero register~~, see [#7](https://github.com/gaul/x86lint/issues/7)
  - MOV EAX, 0 instead of XOR EAX, EAX
* unneeded explicit immediate
  - `C1D0 01` instead of `D1D0` (RCL EAX, 1)
* unneeded explicit register
  - `81C0 00010000` instead of `05 00010000` (ADD EAX, 0x100)
* unneeded LOCK prefix on XCHG
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

x86lint is intended to be part of compiler test suites which should `#include
"x86lint.h"` and link `libx86lint.a`.  It can also read arbitrary ELF executables via:

```
./x86lint /bin/ls
```

## References

* [Agner Fog optimization guide](https://www.agner.org/optimize/optimizing_assembly.pdf)
* [Intel instruction set reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf)
* [Intel optimization manual](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-optimization-manual.pdf)
* [Intel x86 encoder decoder](https://github.com/intelxed/xed) - library to parse instructions
* [armlint](https://github.com/gaul/armlint) - AArch64 equivalent of armlint

## License

Copyright (C) 2018 Andrew Gaul

Licensed under the Apache License, Version 2.0
