#!/usr/bin/env python3
"""Convert a raw JIT code dump into an ELF object for x86lint.

Neither SpiderMonkey nor JavaScriptCore prints encoding bytes on x86-64.
SpiderMonkey's IONFLAGS=codegen spew is AT&T assembly with offsets and no
bytes, and JSC's disassembly is text from an external disassembler, so on
this architecture -- unlike AArch64, where a listing carries the whole
32-bit word -- there is nothing to reassemble a code object from.  Both
engines therefore need a few lines in their linker, and since what those
lines have to hand over is the same thing (an address, a length, a name and
the bytes), one binary container serves both and this one converter reads it:

    "X86J" | u64 address | u32 code size | u32 name size | name | code

Records are simply concatenated.  There is no file header and no index, on
purpose: a JIT process is usually stopped rather than exited, and a dump
truncated mid-record still parses up to the truncation, which is reported
rather than treated as corruption.

  * SpiderMonkey: apply tools/spidermonkey-jitdump.patch to a Gecko tree,
    build the JS shell or the browser, and run with X86LINT_JITDUMP=<path>.
    Each process that links code writes <path>.<pid>: every blob through
    jit::Linker::newCode -- Ion, Baseline, RegExp and the trampolines, named
    for its CodeKind -- and every wasm code block through
    wasm::CodeBlock::initialize, named WasmBaseline, WasmIon, WasmStubs or
    WasmLazyStubs.  A shell run leaves one file; a Firefox run leaves one
    per process that ran JS, which is what keeps the parent's chrome code
    apart from the page's.
  * JavaScriptCore: the same record from LinkBuffer's
    finalizeCodeWithoutDisassemblyImpl, naming the blob for its
    LinkBuffer::Profile (Baseline, DFG, FTL, InlineCache, YarrJIT, ...).
    Not shipped here as a patch; the format is the whole interface.

Names are taken from the record; a repeated name gets a .2, .3 suffix, since
a JIT recompiles the same function at several tiers and reuses addresses as
code is discarded.

A blob's inline jump tables -- 8-byte code pointers the engine writes into
the code stream for switch dispatch, and in SpiderMonkey the Baseline
Interpreter's whole opcode table -- are left out of the symbol ranges x86lint
scans, since decoded as instructions they yield phantom findings that depend
on nothing but the heap address (see jitelf.code_pointer_words).
--keep-code-pointers scans them anyway, which is how to measure that effect.

--raw reads a file that is nothing but machine code, which is what
SpiderMonkey's disnative(f, "file") writes for one function's jitcode with no
patch applied at all. Use it for a spot check; the hook is what reaches every
tier and every trampoline.

Usage: jitdump2elf.py DUMP [-o OUT.elf] [--map FILE] [--min-bytes N]
       jitdump2elf.py --raw BLOB [--addr 0x...] [--name NAME]
"""

import struct
import sys

import jitelf

MAGIC = b'X86J'
HEADER = struct.Struct('<QII')          # address, code size, name size


def parse_dump(path):
    """Return (chunks, truncated_bytes) from a raw JIT dump file."""
    with open(path, 'rb') as f:
        blob = f.read()

    chunks = []
    names = jitelf.NameTable()
    off = 0
    end = len(blob)
    truncated = 0
    while off < end:
        if blob[off:off + 4] != MAGIC:
            # Not a record boundary: the writer was interrupted, or the file
            # holds something else entirely. Either way the rest is unusable.
            truncated = end - off
            break
        if off + 4 + HEADER.size > end:
            truncated = end - off
            break
        addr, size, namelen = HEADER.unpack_from(blob, off + 4)
        body = off + 4 + HEADER.size
        rec_end = body + namelen + size
        if rec_end > end:
            truncated = end - off
            break
        name = blob[body:body + namelen].decode('utf-8', 'replace')
        code = blob[body + namelen:rec_end]
        if size:
            chunks.append(jitelf.Chunk(
                names.unique(name or 'jit_%x' % addr), addr, code))
        off = rec_end
    return chunks, truncated


def main():
    ap = jitelf.parser(__doc__, 'raw JIT dump written by an engine hook')
    jitelf.add_output_args(ap, 'jitcode.elf')
    ap.add_argument('--raw', action='store_true',
                    help='the input is one bare code blob, not records')
    ap.add_argument('--addr', default='0x1000',
                    help='load address for --raw (default 0x1000)')
    ap.add_argument('--name', default='jitcode',
                    help='symbol name for --raw (default jitcode)')
    ap.add_argument('--keep-code-pointers', action='store_true',
                    help='scan inline jump tables as if they were code')
    args = ap.parse_args()

    if args.raw:
        with open(args.dump, 'rb') as f:
            code = f.read()
        chunks = [jitelf.Chunk(args.name, int(args.addr, 0), code)]
    else:
        chunks, truncated = parse_dump(args.dump)
        if truncated:
            print('%d trailing bytes were not a complete record and were '
                  'dropped' % truncated, file=sys.stderr)
    if not args.keep_code_pointers:
        for c in chunks:
            jitelf.mask_code_pointers(c)
    return jitelf.emit(chunks, args)


if __name__ == '__main__':
    sys.exit(main())
