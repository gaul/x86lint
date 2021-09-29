# x86lint

x86lint examines x86 machine code to find suboptimal encodings and sequences.
For example, `add eax, 1` can encode with either an 8- or 32-bit immediate:

```
83C0 01
81C0 01000000
```

Using the former can result in smaller and faster code.  x86lint can help
compiler writers generate better code and documents the complexity of x86.

## Implemented analyses

* implicit EAX
  - `81C0 00010000` instead of `05 00010000` (ADD EAX, 0x100)
* missing LOCK prefix on CMPXCHG and XADD
* oversized immediates
  - `81C0 01000000` instead of `83C0 01` (ADD EAX, 1)
* strength-reduce AND with immediate to MOVZBL
* suboptimal CMP 0 `83FF 00` instead of TEST `85C0`
* suboptimal no-ops
  - multiple `90` instead of a single `60 90`, etc.
* ~~suboptimal zero register~~, see [#7](https://github.com/gaul/x86lint/issues/7)
  - MOV EAX, 0 instead of XOR EAX, EAX
* unnecessary REX prefix
  - XOR RAX, RAX `4831C0` instead of XOR EAX, EAX `31C0`
  - `40C9` instead of `C9` (LEAVE)
* unnecessary immediate
  - `C1D0 01` instead of `D1D0` (RCL EAX, 1)
* unneeded LOCK prefix on XCHG

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

## License

Copyright (C) 2018 Andrew Gaul

Licensed under the Apache License, Version 2.0
