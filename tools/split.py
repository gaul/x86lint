#!/usr/bin/env python3
"""Split a mixed C++/Rust binary's findings by source language.

    split.py [--cold-below ADDR] ELF FINDINGS...

Each FINDINGS file is the text output of `x86lint -v` (any classes) or of
`tools/shapescan -e NAME` on the same ELF. Every finding is attributed to
the function whose symbol contains its address, and the function to a
language by its mangling: `_R` and the legacy `_ZN...17h<16 hex>E` are
Rust, any other `_Z` is C++.

A function with no mangling -- C, assembly, a Rust `#[no_mangle]` export --
takes the language of its mangled neighbours in address order, when the two
agree. This rests on the linker keeping each language's objects together,
which the first table lets you check: in Fedora's libxul the mangled
functions change language only six times across 352,855 of them. A function
between two languages is reported as "boundary" and left out of both sides.

Symbols come from the file's `.symtab`, or, when that is stripped, from the
MiniDebugInfo in `.gnu_debugdata` (an xz-compressed ELF that Fedora and
others ship holding function symbols only). Instructions are counted by
objdump inside function symbols, so the per-million rates use each side's
own denominator; code outside every symbol is counted and reported apart.

Two compiler fingerprints are counted per side as a check on the split:
the stack-protector canary check (GCC writes `sub %fs:0x28`, clang reloads
with `mov` and compares; Rust uses no stack protector) and INC/DEC against
ADD/SUB 1 (LLVM prefers INC, GCC's speed tuning does not). GCC also prefers
INC wherever it optimizes for size, which in a PGO build is all
profile-cold code. `--cold-below ADDR` reports what fraction of each C++
count lies below ADDR, for a binary whose cold partition sits at the start
of `.text`; the end of the highest `.cold` function is printed as a
starting point for finding that boundary.

The 2026-11-01 split of Fedora's libxul made with this is written up in
TODO.md, "libxul split by language".
"""

import argparse
import bisect
import collections
import lzma
import os
import re
import subprocess
import sys
import tempfile

FUNC_TYPES = set('tTwWi')
RUST_LEGACY = re.compile(r'^_ZN.*17h[0-9a-f]{16}E(\.[A-Za-z0-9_.]+)?$')

SIDES = ['C', 'uC', 'R', 'uR', 'u?', None]
LABEL = {
    'C': 'C++',
    'uC': 'unmangled, C++ side',
    'R': 'Rust',
    'uR': 'unmangled, Rust side',
    'u?': 'unmangled, boundary',
    None: 'outside any symbol',
}


def language(name):
    if name.startswith('_R') or RUST_LEGACY.match(name):
        return 'R'
    if name.startswith('_Z'):
        return 'C'
    return 'u'


def nm_functions(path):
    out = subprocess.run(['nm', '-S', '--defined-only', path],
                         capture_output=True, text=True).stdout
    funcs = []
    for line in out.splitlines():
        parts = line.split(None, 3)
        if len(parts) == 4 and parts[2] in FUNC_TYPES:
            funcs.append((int(parts[0], 16), int(parts[1], 16), parts[3]))
    return funcs


def function_symbols(elf):
    """The ELF's function symbols, from .symtab or else .gnu_debugdata."""
    funcs = nm_functions(elf)
    if funcs:
        return funcs, '.symtab'
    with tempfile.TemporaryDirectory() as tmp:
        xz = os.path.join(tmp, 'gnu_debugdata.xz')
        dump = subprocess.run(
            ['objcopy', '--dump-section', '.gnu_debugdata=' + xz, elf,
             os.path.join(tmp, 'discard')],
            capture_output=True, text=True)
        if dump.returncode != 0 or not os.path.exists(xz):
            sys.exit('%s: no .symtab and no .gnu_debugdata to name its '
                     'functions' % elf)
        mini = os.path.join(tmp, 'minidebuginfo.elf')
        with open(xz, 'rb') as f, open(mini, 'wb') as g:
            g.write(lzma.decompress(f.read()))
        funcs = nm_functions(mini)
    if not funcs:
        sys.exit('%s: .gnu_debugdata names no functions' % elf)
    return funcs, '.gnu_debugdata'


class Symbols:
    """Function symbols sorted by address, each tagged with a side."""

    def __init__(self, funcs):
        # Aliases share an address (an extern "C" name beside its mangled
        # one, folded identical bodies). Keep one symbol per address,
        # preferring a mangled name, whose language is known, then the
        # larger size.
        best = {}
        for a, s, name in funcs:
            key = (language(name) != 'u', s)
            if a not in best or key > best[a][0]:
                best[a] = (key, (a, s, name))
        funcs = sorted(v for _k, v in best.values())
        langs = [language(name) for _a, _s, name in funcs]
        mangled = [i for i, l in enumerate(langs) if l != 'u']
        self.sides = []
        for i, l in enumerate(langs):
            if l != 'u':
                self.sides.append(l)
                continue
            j = bisect.bisect_left(mangled, i)
            prev = langs[mangled[j - 1]] if j > 0 else None
            nxt = langs[mangled[j]] if j < len(mangled) else None
            self.sides.append('u' + prev if prev is not None and prev == nxt
                              else 'u?')
        self.funcs = funcs
        self.starts = [a for a, _s, _n in funcs]
        self.changes = sum(1 for a, b in zip(mangled, mangled[1:])
                           if langs[a] != langs[b])
        self.counts = collections.Counter(langs)
        cold = [a + s for a, s, n in funcs if n.endswith('.cold')]
        self.cold_end = max(cold) if cold else None

    def side(self, vaddr):
        i = bisect.bisect_right(self.starts, vaddr) - 1
        if i >= 0:
            a, s, _n = self.funcs[i]
            if a <= vaddr < a + max(s, 1):
                return self.sides[i]
        return None


INSN = re.compile(r'^\s*([0-9a-f]+):\t(.*)$')
ADD_ONE = re.compile(r'^(add|sub) +[^,]+,0x1$')


def count_instructions(elf, symbols):
    insns = collections.Counter()
    prints = collections.defaultdict(collections.Counter)
    proc = subprocess.Popen(
        ['objdump', '-d', '--no-show-raw-insn', '-M', 'intel', elf],
        stdout=subprocess.PIPE, text=True, errors='replace')
    for line in proc.stdout:
        m = INSN.match(line)
        if not m:
            continue
        text = m.group(2)
        if not text.strip() or text.startswith('(bad)'):
            continue
        side = symbols.side(int(m.group(1), 16))
        insns[side] += 1
        if 'fs:0x28' in text:
            if text.startswith('sub '):
                prints[side]['canary sub'] += 1
            elif text.startswith('mov '):
                prints[side]['canary mov'] += 1
        if text.startswith(('inc ', 'dec ')):
            prints[side]['inc/dec'] += 1
        elif ADD_ONE.match(text):
            prints[side]['add/sub 1'] += 1
    if proc.wait() != 0:
        sys.exit('objdump failed on %s' % elf)
    return insns, prints


SECTION = re.compile(r'^== section .*: vaddr 0x([0-9a-f]+),')
X86LINT = re.compile(r'^(.+) at offset: 0x([0-9a-f]+)')
SHAPESCAN = re.compile(r'^  \[(.+)\] .*\+0x([0-9a-f]+): ')


def read_findings(paths):
    """(check, vaddr) for every finding in x86lint -v or shapescan text."""
    for path in paths:
        base = None
        for line in open(path, errors='replace'):
            m = SECTION.match(line)
            if m:
                base = int(m.group(1), 16)
                continue
            m = SHAPESCAN.match(line)
            if m:
                yield m.group(1), int(m.group(2), 16)
                continue
            m = X86LINT.match(line)
            if m:
                if base is None:
                    sys.exit('%s: a finding precedes any "== section" line; '
                             'run x86lint with -v' % path)
                yield m.group(1), base + int(m.group(2), 16)


def main():
    ap = argparse.ArgumentParser(
        description='Split findings by source language (C++ or Rust).')
    ap.add_argument('--cold-below', type=lambda s: int(s, 16), metavar='ADDR',
                    help='report the share of each C++ count below ADDR (hex)')
    ap.add_argument('elf')
    ap.add_argument('findings', nargs='+')
    args = ap.parse_args()

    funcs, source = function_symbols(args.elf)
    symbols = Symbols(funcs)
    print('%d function symbols from %s at %d addresses: %d C++, %d Rust, '
          '%d unmangled; the language changes %d times in address order' % (
              len(funcs), source, len(symbols.funcs), symbols.counts['C'],
              symbols.counts['R'], symbols.counts['u'], symbols.changes))
    if symbols.cold_end is not None:
        print('highest .cold function ends at 0x%x' % symbols.cold_end)
    print()

    insns, prints = count_instructions(args.elf, symbols)
    print('%-22s %13s %16s %20s' % ('side', 'instructions', 'canary sub/mov',
                                    'inc-dec/add-sub-1'))
    for side in SIDES:
        p = prints[side]
        print('%-22s %13d %8d/%-7d %10d/%-9d' % (
            LABEL[side], insns[side], p['canary sub'], p['canary mov'],
            p['inc/dec'], p['add/sub 1']))
    cxx = insns['C'] + insns['uC']
    rust = insns['R'] + insns['uR']
    print()

    found = collections.defaultdict(collections.Counter)
    cold = collections.Counter()
    for check, vaddr in read_findings(args.findings):
        side = symbols.side(vaddr)
        found[check][side] += 1
        if (args.cold_below is not None and side in ('C', 'uC') and
                vaddr < args.cold_below):
            cold[check] += 1

    def rate(n, d):
        return '%9.0f' % (n * 1e6 / d) if d else '%9s' % '-'

    header = '%-44s %9s %9s %9s %9s %7s' % (
        'check', 'C++', 'Rust', 'C++ /M', 'Rust /M', 'other')
    if args.cold_below is not None:
        header += ' %10s' % 'cold share'
    print(header)
    for check, n in sorted(found.items(), key=lambda kv: -sum(kv[1].values())):
        c = n['C'] + n['uC']
        r = n['R'] + n['uR']
        line = '%-44s %9d %9d %s %s %7d' % (
            check[:44], c, r, rate(c, cxx), rate(r, rust),
            n['u?'] + n[None])
        if args.cold_below is not None:
            line += ' %9s' % ('%d%%' % round(100 * cold[check] / c) if c
                              else '')
        print(line)


if __name__ == '__main__':
    main()
