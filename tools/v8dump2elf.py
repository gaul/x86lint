#!/usr/bin/env python3
"""Convert a V8 --print-opt-code style dump into an ELF object for x86lint.

V8's code printer (d8/node --print-opt-code, --print-maglev-code,
--print-code, --print-regexp-code, in a build with v8_enable_disassembler)
emits, per code object, a header block followed by a listing that carries the
encoding bytes:

  --- Optimized code ---
  kind = TURBOFAN_JS
  name = add
  compiler = turbofan

  Instructions (size = 280)
  0x5605e0000d40     0  55                   push rbp
  0x5605e0000d41     1  488bec               REX.W movq rbp,rsp

The address, the object-relative offset and the raw bytes are the three
columns this reads; the disassembly text is V8's and is ignored, since XED
decodes the bytes itself.  Unlike the AArch64 listing there are no constant
pools to step over: x64 code objects keep their constants inline or in the
data area past the instruction stream, and the listing ends before it.

A new section starts wherever the addresses stop being contiguous, so an
object with a gap in its listing becomes two sections rather than one section
whose bytes lie about their addresses.

Findings are worth reading with -m v8: V8 addresses a compressed pointer as
`or rcx, r13 ; mov eax, [rcx+N]`, and that flag is what tells x86lint the
cage base is 4 GB aligned, which is the invariant the fold rests on.

Usage: v8dump2elf.py DUMP [-o OUT.elf] [--map FILE] [--min-bytes N]
"""

import re
import sys

import jitelf

# Columns: absolute address, object-relative offset, encoding bytes, text.
# The byte column is variable length here and never contains a separator, so
# an odd-length capture means the line was not what it looked like.
INSN_RE = re.compile(r'^0x([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)(?:\s+(.*))?$')
HEADER_FIELD_RE = re.compile(r'^(name|kind|compiler)\s*=\s*(.*)$')
INSTRUCTIONS_RE = re.compile(r'^Instructions\s*\(size')
BANNER_RE = re.compile(r'^--- (.*) ---\s*$')

KIND_PREFIX = {
    'TURBOFAN_JS': 'TF',
    'TURBOFAN': 'TF',
    'MAGLEV': 'ML',
    'BASELINE': 'BL',
    'REGEXP': 'RE',
    'WASM_FUNCTION': 'WA',
    'BUILTIN': 'BI',
    'BYTECODE_HANDLER': 'BH',
    'FOR_TESTING': 'XX',
}


def parse_dump(fp):
    """Return (chunks, odd_lines) from a V8 code dump stream."""
    chunks = []
    names = jitelf.NameTable()
    name = ''
    kind = ''
    in_code = False
    in_header = False
    cur = None
    odd = 0

    def display_name():
        prefix = KIND_PREFIX.get(kind, kind[:8] if kind else 'UN')
        return names.unique('%s_%s' % (prefix, name or 'anonymous'))

    for line in fp:
        line = line.rstrip('\n')
        if in_code:
            m = INSN_RE.match(line)
            if m:
                text = m.group(3)
                if len(text) % 2:
                    # Not an instruction line after all: some other column
                    # shape that happens to be three hex-looking fields.
                    odd += 1
                    continue
                addr = int(m.group(1), 16)
                data = bytes.fromhex(text)
                if cur is None or addr != cur.addr + len(cur.data):
                    if cur is not None and cur.data:
                        chunks.append(cur)
                    cur = jitelf.Chunk(display_name(), addr)
                cur.data += data
                continue
            if not line.strip() or line.lstrip().startswith(';;'):
                continue
            # Any other line shape (Safepoints, RelocInfo, Deoptimization
            # tables, "--- End code ---", the script's own output) ends the
            # listing; fall through so a banner still resets the header.
            if cur is not None and cur.data:
                chunks.append(cur)
            cur = None
            in_code = False
        m = BANNER_RE.match(line)
        if m:
            # A code banner opens a header block and forgets the previous
            # object's identity, so an unnamed object does not inherit its
            # predecessor's name. Every other banner -- "Raw source" above
            # all -- closes it, which keeps a line of JS source that happens
            # to read `name = x` out of the symbol table.
            in_header = 'code' in m.group(1).lower()
            name = ''
            kind = ''
            continue
        if in_header:
            m = HEADER_FIELD_RE.match(line)
            if m:
                if m.group(1) == 'name':
                    name = m.group(2).strip()
                elif m.group(1) == 'kind':
                    kind = m.group(2).strip()
                continue
        if INSTRUCTIONS_RE.match(line):
            in_code = True
            in_header = False
            cur = None
    if cur is not None and cur.data:
        chunks.append(cur)
    return chunks, odd


def main():
    ap = jitelf.parser(__doc__, 'V8 code dump (- for stdin)')
    jitelf.add_output_args(ap, 'v8code.elf')
    args = ap.parse_args()

    if args.dump == '-':
        chunks, odd = parse_dump(sys.stdin)
    else:
        with open(args.dump, 'r', errors='replace') as fp:
            chunks, odd = parse_dump(fp)
    if odd:
        print('%d listing lines had an odd-length byte column and were '
              'skipped' % odd, file=sys.stderr)
    return jitelf.emit(chunks, args)


if __name__ == '__main__':
    sys.exit(main())
