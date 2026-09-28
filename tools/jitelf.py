"""Shared ELF64 emitter for x86lint's JIT-dump converters.

A JIT has no object file: its code lives in an anonymous mapping that
disappears with the process.  The converters in this directory take what an
engine can be made to print or write -- a disassembly listing with encoding
bytes, or a raw blob per linked code object -- and reassemble it into an
ET_REL image x86lint can scan, so the whole check table applies to JIT output
instead of only to what a compiler leaves on disk.

The layout is the same for every converter:

  * one SHF_EXECINSTR section per code blob, sh_addr set to the original JIT
    address, so a finding's address cross-references back into the dump.
    Separate sections also stop x86lint's window peepholes and its bounded
    liveness walks from running off the end of one code object into the next,
    which are unrelated instruction streams that merely happen to be adjacent
    in the dump;
  * an STT_FUNC symbol per section, carrying the tier and the JS function
    name where the engine reveals them, so -v findings and the -i census
    attribute to the generating tier.  x86lint's default scan is restricted
    to function symbols, and in an ET_REL object it locates them by section
    index and offset, which is why every symbol here is section-relative with
    st_value 0 and st_shndx pointing at its own section;
  * ET_REL rather than ET_EXEC, because there is no program to load: the
    addresses are documentation, and a relocatable object is the honest
    spelling of "sections with addresses and nothing else".

Byte order is little-endian and the machine is EM_X86_64; a converter that
wants a different machine passes it to write_elf.
"""

import argparse
import re
import struct
import sys

SHT_NULL, SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB = 0, 1, 2, 3
SHF_ALLOC, SHF_EXECINSTR = 0x2, 0x4
ET_REL = 1
EM_X86_64 = 62

# e_shnum is 16 bits, and the section-count overflow spelling (SHN_XINDEX,
# with the real count in section 0's sh_size) is not worth writing here when
# splitting the output costs a loop.  Four sections of our own plus headroom.
MAX_SECTIONS = 60000

# Symbol names reach x86lint's -v output and its by-function table; keep them
# to what a report can print without quoting.
SANITIZE_RE = re.compile(r'[^A-Za-z0-9_.@:<>/-]')


class Chunk:
    """One contiguous run of machine code at a known address.

    `ranges` lists the (start, end) offsets that hold instructions; None means
    all of it.  A chunk with ranges is still written as one section, so its
    bytes and addresses stay exactly what the engine had, but it gets one
    STT_FUNC symbol per range and x86lint's default scan -- restricted to
    function symbols -- never decodes the bytes between them.
    """

    __slots__ = ('name', 'addr', 'data', 'ranges')

    def __init__(self, name, addr, data=b'', ranges=None):
        self.name = name
        self.addr = addr
        self.data = bytearray(data)
        self.ranges = ranges

    def code_ranges(self):
        return self.ranges if self.ranges is not None else [(0, len(self.data))]


def code_pointer_words(chunk):
    """Offsets of the 8-byte words in a chunk that hold an address inside it.

    A JIT's switch dispatch is a table of absolute code pointers written into
    the code stream itself: SpiderMonkey's writeCodePointer does it for Ion,
    Baseline and both wasm tiers, and the Baseline Interpreter's opcode table
    is the same thing 239 entries long.  A decoder reads those eight bytes as
    instructions, and which instructions depends on the heap address -- the
    top bytes of a 0x7f00... pointer decode as `add byte ptr [r15], r15b`
    with a zero displacement, a different browser or shell mapping decodes as
    something else -- so the same table yields different phantom findings in
    different runs, and none of it shows in the undecodable-byte count.

    A word pointing into its own blob is such an entry.  The one legitimate
    instruction that carries one is `MOV r64, imm64` (REX.W B8+r), which is
    how the table's base address gets into a register, so a word whose two
    preceding bytes spell that opcode is kept.  Tables are pointer-aligned by
    the engine (haltingAlign(sizeof(void*))) and blobs are at least as
    aligned, so only aligned words are considered.

    The other pointer a SpiderMonkey blob carries in its code stream points
    the other way, out of the blob: every far jump to other code goes through
    a 16-byte entry of the blob's extended jump table, `jmp qword ptr
    [rip+2] ; ud2 ; <8-byte absolute target>` (Assembler-x64's
    SizeOfExtendedJump), and the target bytes decode as instructions too.
    Those are found by the entry's own signature, FF 25 02 00 00 00 0F 0B,
    whatever their alignment.
    """
    data = chunk.data
    lo = chunk.addr
    hi = lo + len(data)
    words = []
    for off in range(0, len(data) - 7, 8):
        value = int.from_bytes(data[off:off + 8], 'little')
        if not lo <= value < hi:
            continue
        if off >= 2 and data[off - 2] in (0x48, 0x49) and 0xb8 <= data[off - 1] <= 0xbf:
            continue
        words.append(off)
    start = 0
    while True:
        at = data.find(EXTENDED_JUMP, start)
        if at < 0 or at + 16 > len(data):
            break
        words.append(at + 8)
        start = at + 16
    words.sort()
    return words


# jmp qword ptr [rip+2] ; ud2 -- the head of an extended jump table entry,
# whose tail is the absolute address the jump reads.
EXTENDED_JUMP = bytes.fromhex('ff25020000000f0b')


def mask_code_pointers(chunk):
    """Restrict a chunk's code ranges to the bytes between its pointer
    tables.  Returns how many table words were masked."""
    words = code_pointer_words(chunk)
    if not words:
        return 0
    ranges = []
    start = 0
    for off in words:
        if off > start:
            ranges.append((start, off))
        start = max(start, off + 8)
    if start < len(chunk.data):
        ranges.append((start, len(chunk.data)))
    chunk.ranges = ranges
    return len(words)


def explode(chunks):
    """One chunk per code range, at its own address: for a tool that reads
    whole sections and knows nothing of symbols, such as objdump or the -i
    census, which scans every byte of an executable section."""
    out = []
    for c in chunks:
        ranges = c.code_ranges()
        if len(ranges) == 1 and ranges[0] == (0, len(c.data)):
            out.append(c)
            continue
        for start, end in ranges:
            out.append(Chunk(c.name, c.addr + start, c.data[start:end]))
    return out


class NameTable:
    """Deterministic, collision-free symbol names.

    A JIT reuses addresses as code is discarded and recompiles the same
    function at several tiers, so both the address and the name repeat within
    one dump.  Repeats get .2, .3 suffixes in first-seen order rather than
    being merged: they are different code.
    """

    def __init__(self):
        self.seen = {}

    def unique(self, base):
        base = SANITIZE_RE.sub('_', base)[:80] or 'anonymous'
        n = self.seen.get(base, 0) + 1
        self.seen[base] = n
        return base if n == 1 else '%s.%d' % (base, n)


def align(n, to=16):
    return (n + to - 1) & ~(to - 1)


def write_elf(chunks, path, machine=EM_X86_64):
    ehsize = 64
    shentsize = 64

    # Section contents, back to back after the ELF header, each aligned so a
    # section's bytes start where its sh_addralign says they do.
    payload = bytearray()
    offsets = []
    for c in chunks:
        payload += b'\0' * (align(ehsize + len(payload)) - ehsize - len(payload))
        offsets.append(ehsize + len(payload))
        payload += c.data

    shstrtab = bytearray(b'\0')

    def shname(s):
        off = len(shstrtab)
        shstrtab.extend(s.encode() + b'\0')
        return off

    text_name = shname('.text')
    symtab_name = shname('.symtab')
    strtab_name = shname('.strtab')
    shstrtab_name = shname('.shstrtab')

    strtab = bytearray(b'\0')
    symtab = bytearray(b'\0' * 24)          # index 0: the null symbol
    nsyms = 1
    for i, c in enumerate(chunks):
        st_name = len(strtab)
        strtab.extend(c.name.encode() + b'\0')
        st_info = (0 << 4) | 2              # STB_LOCAL, STT_FUNC
        # One symbol per code range, section-relative; a chunk with pointer
        # tables gets several under the same name, and the table bytes fall
        # under none of them.
        for start, end in c.code_ranges():
            symtab += struct.pack('<IBBHQQ', st_name, st_info, 0,
                                  1 + i, start, end - start)
            nsyms += 1

    nsections = 1 + len(chunks) + 3         # null, chunks, symtab/strtab/shstrtab
    symtab_idx = 1 + len(chunks)
    strtab_idx = symtab_idx + 1
    shstrtab_idx = strtab_idx + 1

    symtab_off = ehsize + len(payload)
    strtab_off = symtab_off + len(symtab)
    shstrtab_off = strtab_off + len(strtab)
    shoff = align(shstrtab_off + len(shstrtab), 8)

    def shdr(name, type_, flags, addr, off, size, link, info, addralign,
             entsize):
        return struct.pack('<IIQQQQIIQQ', name, type_, flags, addr, off,
                           size, link, info, addralign, entsize)

    shdrs = [shdr(0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0)]
    for c, off in zip(chunks, offsets):
        shdrs.append(shdr(text_name, SHT_PROGBITS,
                          SHF_ALLOC | SHF_EXECINSTR, c.addr, off,
                          len(c.data), 0, 0, 16, 0))
    # sh_info is one past the last local symbol, and every symbol here is
    # local; sh_link names the string table the symbol names live in.
    shdrs.append(shdr(symtab_name, SHT_SYMTAB, 0, 0, symtab_off,
                      len(symtab), strtab_idx, nsyms, 8, 24))
    shdrs.append(shdr(strtab_name, SHT_STRTAB, 0, 0, strtab_off,
                      len(strtab), 0, 0, 1, 0))
    shdrs.append(shdr(shstrtab_name, SHT_STRTAB, 0, 0, shstrtab_off,
                      len(shstrtab), 0, 0, 1, 0))

    ehdr = struct.pack('<4sBBBBB7xHHIQQQIHHHHHH',
                       b'\x7fELF', 2, 1, 1, 0, 0,   # 64-bit, LSB, SysV
                       ET_REL, machine,
                       1, 0, 0, shoff, 0,
                       ehsize, 0, 0, shentsize, nsections, shstrtab_idx)

    with open(path, 'wb') as f:
        f.write(ehdr)
        f.write(payload)
        f.write(symtab)
        f.write(strtab)
        f.write(shstrtab)
        f.write(b'\0' * (shoff - shstrtab_off - len(shstrtab)))
        for s in shdrs:
            f.write(s)


def add_output_args(ap, default_output):
    ap.add_argument('-o', '--output', default=default_output,
                    help='ELF image to write (default: %s)' % default_output)
    ap.add_argument('--max-sections', type=int, default=MAX_SECTIONS,
                    help='code blobs per ELF before the output is split')
    ap.add_argument('--map',
                    help='also write "name 0xaddr size" lines to this file')
    ap.add_argument('--min-bytes', type=int, default=0,
                    help='drop blobs smaller than this many bytes')


def emit(chunks, args):
    """Write the chunks out as one or more ELF images. Returns an exit code."""
    if args.min_bytes:
        chunks = [c for c in chunks if len(c.data) >= args.min_bytes]
    if not chunks:
        print('no code found in dump', file=sys.stderr)
        return 1

    if args.map:
        with open(args.map, 'w') as f:
            for c in chunks:
                f.write('%s 0x%x %d\n' % (c.name, c.addr, len(c.data)))

    total = sum(len(c.data) for c in chunks)
    if len(chunks) <= args.max_sections:
        write_elf(chunks, args.output)
        outs = [args.output]
    else:
        outs = []
        for i in range(0, len(chunks), args.max_sections):
            part = '%s.%d' % (args.output, len(outs) + 1)
            write_elf(chunks[i:i + args.max_sections], part)
            outs.append(part)
    masked = sum(len(c.data) - sum(e - s for s, e in c.ranges)
                 for c in chunks if c.ranges is not None) // 8
    in_blobs = sum(1 for c in chunks if c.ranges is not None)
    print('%d code blobs, %d code bytes%s -> %s' %
          (len(chunks), total,
           ', %d code-pointer words masked in %d blobs' % (masked, in_blobs)
           if masked else '', ' '.join(outs)), file=sys.stderr)
    return 0


def parser(doc, dump_help):
    """An argument parser with the arguments every converter takes."""
    ap = argparse.ArgumentParser(
        description=doc.split('\n')[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='\n'.join(doc.split('\n')[1:]))
    ap.add_argument('dump', help=dump_help)
    return ap
