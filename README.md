# asmlint

asmlint examines x86 instructions to find suboptimal encodings and sequences.
For example, `add eax, 1` can encode with either an 8- or 32-bit immediate:

```
83C0 01
81C0 01000000
```

Using the former can result in smaller and faster code.  asmlint can help
compiler writers generate better code and documents the complexity of x86.

## Analyses

* implicit EAX
  - `81C0 00010000` instead of `05 00010000` (ADD EAX, 1)
* oversized immediates
  - `81C0 01000000` instead of `83C0 01` (ADD EAX, 1)
* suboptimal zero register
  - MOV EAX, 0 instead of XOR EAX, EAX
* unnecessary REX prefix
  - `40C9` instead of `C9` (LEAVE)

## Possible analyses

single-instruction
* CMP vs. TEST
* nonsense instructions
  - MOV RAX, RAX
* strength reduce MUL with immediate to LEA
* unneeded LOCK prefix
  - XCHG

peephole
* 16-byte alignment for jump targets
* [64-byte alignment for macro-fusion](https://code.fb.com/data-infrastructure/accelerate-large-scale-applications-with-bolt/)
* duplicate constant loads
* [near-duplicate constant loads](https://paul.bone.id.au/2018/09/14/large-immediate-values/)
* suboptimal no-ops
  - multiple 0x90 instead of 0x60 0x90, etc.
* unneeded register spills

## Compilation

First install the Intel x86 encoder decoder:

```
git clone https://github.com/intelxed/xed.git xed
git clone https://github.com/intelxed/mbuild.git mbuild
cd xed
./mfile.py install --install-dir=kits/xed-install
```

Next build asmlint:

```
git clone https://github.com/gaul/asmlint.git asmlint
cd asmlint
XED_PATH=/path/to/xed make all
```

## References

* [Agner Fog optimization guide](https://www.agner.org/optimize/optimizing_assembly.pdf)
* [Intel instruction set reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf)
* [Intel optimization manual](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-optimization-manual.pdf)
* [Intel x86 encoder decoder](https://github.com/intelxed/xed) - library to parse instructions

## License

Copyright (C) 2018 Andrew Gaul

Licensed under the Apache License, Version 2.0
