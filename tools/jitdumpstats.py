#!/usr/bin/env python3
"""Corpus analysis of x86lint JIT dumps: per process, per tier, per check.

    jitdumpstats.py --out DIR [--ps PS.LOG] [--title TEXT] DUMP...

Each DUMP is one process's file from tools/spidermonkey-jitdump.patch
(firefox.jitdump.<pid>, shell.jitdump.<pid>). For each, the records are split
by the tier the engine named them for -- Ion, Baseline, RegExp, Other,
WasmBaseline, WasmIon, WasmStubs, WasmLazyStubs -- into one ELF per tier
under DIR, and x86lint -v runs on every tier image; its text is streamed
rather than its JSON collected, because a browser's benchmark process links
hundreds of megabytes of code and the JSON for its findings would not fit.
Whole-process figures are the sums of the tier figures: every blob is its own
section and x86lint never looks across sections, so nothing is lost by
scanning them apart. Each blob's inline jump tables are left out of the
symbol ranges (jitelf.mask_code_pointers; --keep-code-pointers scans them),
and a second image per tier with the tables cut out entirely feeds -i for
the ISA census and objdump for the rel8-against-rel32 branch count, which is
the denominator the branch-displacement class needs.

PS.LOG is tools/jetstream3/run-browser.sh's "pid args" listing, which names each dump's
process type (parent, tab, ...). Without it every dump is "shell".

Writes DIR/report.md and prints it; each tier's x86lint summary stays under
DIR as <dump>.<tier>.summary.txt.
"""

import argparse
import collections
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = HERE
sys.path.insert(0, TOOLS)

import jitdump2elf  # noqa: E402
import jitelf  # noqa: E402

X86LINT = os.environ.get('X86LINT',
                         os.path.normpath(os.path.join(HERE, '..',
                                                       'x86lint')))
BRANCH = 'oversized branch displacement'
IMMEDIATE = 'oversized immediate'
TIER_ORDER = ['Ion', 'Baseline', 'RegExp', 'Other',
              'WasmIon', 'WasmBaseline', 'WasmStubs', 'WasmLazyStubs']
PREFIXES = {0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x66, 0x67, 0xf0, 0xf2, 0xf3}

# x86lint -v: "<check> at offset: 0x.. (<symbol>+0x..): <text>", then the
# encoding bytes on a line of their own, then the trailer.
FINDING_RE = re.compile(r'^(.+?) at offset: 0x[0-9a-f]+(?: \([^)]*\))?: .*$')
BYTES_RE = re.compile(r'^  ([0-9a-f]{2}(?: [0-9a-f]{2})*)$')
TRAILER_RE = re.compile(r'^(\d+) optimization opportunities in (\d+) instructions$')
SKIPPED_RE = re.compile(r'^(\d+) undecodable bytes skipped')


def tier_of(name):
    return re.sub(r'\.\d+$', '', name)


def skip_prefixes(raw):
    i = 0
    while i < len(raw) and (raw[i] in PREFIXES or 0x40 <= raw[i] <= 0x4f):
        i += 1
    return i


def branch_displacement(raw):
    """The rel32 of a near JMP/Jcc, or None if the bytes are something else."""
    i = skip_prefixes(raw)
    if i < len(raw) and raw[i] == 0xe9 and len(raw) == i + 5:
        return int.from_bytes(raw[i + 1:i + 5], 'little', signed=True)
    if (i + 1 < len(raw) and raw[i] == 0x0f and 0x80 <= raw[i + 1] <= 0x8f
            and len(raw) == i + 6):
        return int.from_bytes(raw[i + 2:i + 6], 'little', signed=True)
    return None


def is_placeholder_movabs(raw):
    """A 10-byte MOV r64, imm64 of 0 or -1: SpiderMonkey's patch sentinel."""
    if (len(raw) != 10 or not 0x48 <= raw[0] <= 0x4f
            or not 0xb8 <= raw[1] <= 0xbf):
        return False
    return int.from_bytes(raw[2:], 'little', signed=True) in (0, -1)


class Tally:
    FIELDS = ('blobs', 'code', 'instructions', 'skipped', 'findings',
              'branch_forward', 'branch_backward', 'branch_other',
              'branch_bytes', 'placeholders', 'masked_words', 'masked_blobs',
              'rel8', 'rel32')

    def __init__(self):
        for k in self.FIELDS:
            setattr(self, k, 0)
        self.checks = collections.Counter()
        self.censuses = []

    def add(self, other):
        for k in self.FIELDS:
            setattr(self, k, getattr(self, k) + getattr(other, k))
        self.checks.update(other.checks)
        self.censuses += other.censuses

    def per_k(self, n):
        return 1000.0 * n / self.instructions if self.instructions else 0.0

    @property
    def branch(self):
        return self.checks.get(BRANCH, 0)

    def take_finding(self, check, raw):
        self.findings += 1
        self.checks[check] += 1
        if check == BRANCH:
            disp = branch_displacement(raw)
            if disp is None:
                self.branch_other += 1
            elif disp >= 0:
                self.branch_forward += 1
            else:
                self.branch_backward += 1
            # rel32 forms are 5 (JMP) or 6 (Jcc) bytes; rel8 is 2.
            self.branch_bytes += len(raw) - 2
        elif check == IMMEDIATE and is_placeholder_movabs(raw):
            self.placeholders += 1

    def take_stream(self, lines, summary_out):
        """Consume x86lint -v output; keep the trailer for the record."""
        pending = None
        reported = None
        trailer = []
        for line in lines:
            line = line.rstrip('\n')
            if pending is not None:
                m = BYTES_RE.match(line)
                if m:
                    self.take_finding(pending, bytes.fromhex(m.group(1).replace(' ', '')))
                    pending = None
                    continue
                # A finding line without its bytes line: count it anyway.
                self.take_finding(pending, b'')
                pending = None
            m = FINDING_RE.match(line)
            if m:
                pending = m.group(1)
                continue
            if line.startswith('== section '):
                continue
            m = TRAILER_RE.match(line)
            if m:
                reported = int(m.group(1))
                self.instructions += int(m.group(2))
            m = SKIPPED_RE.match(line)
            if m:
                self.skipped += int(m.group(1))
            if line and not line.startswith('  ') or trailer:
                trailer.append(line)
        if pending is not None:
            self.take_finding(pending, b'')
        summary_out.write('\n'.join(trailer) + '\n')
        return reported


def stream_x86lint(elf, *flags):
    p = subprocess.Popen([X86LINT, *flags, elf], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True, errors='replace')
    yield from p.stdout
    err = p.stderr.read()
    if p.wait() not in (0, 1):
        sys.exit('x86lint %s failed (%d): %s' % (elf, p.returncode,
                                                 err.strip()[:500]))


def count_branch_encodings(elf):
    """(rel8, rel32) JMP/Jcc counts in an image, from objdump's byte column.

    x86lint reports only the rel32 branches that could have been rel8, so the
    denominator for "how often the forward reservation was unnecessary" --
    every rel32 branch -- has to come from a plain decode of the same bytes.
    Returns None without objdump."""
    try:
        p = subprocess.Popen(['objdump', '-d', '-w', elf],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             text=True, errors='replace')
    except FileNotFoundError:
        return None
    rel8 = rel32 = 0
    for line in p.stdout:
        parts = line.split('\t')
        if len(parts) < 3 or not parts[0].strip().endswith(':'):
            continue
        if not parts[2].lstrip().startswith('j'):
            continue
        try:
            raw = bytes.fromhex(parts[1].replace(' ', ''))
        except ValueError:
            continue
        i = skip_prefixes(raw)
        if i >= len(raw):
            continue
        if raw[i] == 0xeb or 0x70 <= raw[i] <= 0x7f:
            rel8 += 1
        elif raw[i] == 0xe9:
            rel32 += 1
        elif raw[i] == 0x0f and i + 1 < len(raw) and 0x80 <= raw[i + 1] <= 0x8f:
            rel32 += 1
    p.wait()
    return rel8, rel32


# Every blob is its own section and nothing is judged across sections, so
# splitting a tier into several images changes no result; the census and
# branch counts are summed back over the parts. The split dates from when
# x86lint's cost per image was quadratic in its section count (fixed in
# main.c on 2026-09-27); it stays because it costs nothing and keeps each
# image's -v stream and memory bounded.
SECTIONS_PER_IMAGE = 4000


def parts_of(chunks, outdir, base, tag):
    """Write chunks as one ELF, or several when there are too many sections."""
    n = SECTIONS_PER_IMAGE
    paths = []
    for part, i in enumerate(range(0, len(chunks), n)):
        suffix = '' if len(chunks) <= n else '.%d' % (part + 1)
        elf = os.path.join(outdir, '%s.%s%s.elf' % (base, tag, suffix))
        jitelf.write_elf(chunks[i:i + n], elf)
        paths.append(elf)
    return paths


def analyze_process(dump, outdir, label, keep_code_pointers=False):
    chunks, truncated = jitdump2elf.parse_dump(dump)
    base = os.path.basename(dump)
    by_tier = collections.OrderedDict()
    for c in chunks:
        by_tier.setdefault(tier_of(c.name), []).append(c)

    tiers = collections.OrderedDict()
    total = Tally()
    for tier in sorted(by_tier, key=lambda t: (TIER_ORDER.index(t)
                                               if t in TIER_ORDER else 99, t)):
        tchunks = by_tier[tier]
        tally = Tally()
        tally.blobs = len(tchunks)
        tally.code = sum(len(c.data) for c in tchunks)
        if not keep_code_pointers:
            for c in tchunks:
                words = jitelf.mask_code_pointers(c)
                if words:
                    tally.masked_words += words
                    tally.masked_blobs += 1
        with open(os.path.join(outdir, '%s.%s.summary.txt' % (base, tier)),
                  'w') as summary:
            parts = parts_of(tchunks, outdir, base, tier)
            for i, elf in enumerate(parts):
                print('  %s x86lint -v %s (%d/%d)' % (
                    time.strftime('%H:%M:%S'), os.path.basename(elf), i + 1,
                    len(parts)), file=sys.stderr)
                before = tally.findings
                reported = tally.take_stream(stream_x86lint(elf, '-v'), summary)
                if reported is not None and reported != tally.findings - before:
                    # Counting from the finding lines must agree with the
                    # tool's own total, or the parser is dropping lines.
                    print('  WARNING: parsed %d findings, x86lint reported %d'
                          % (tally.findings - before, reported),
                          file=sys.stderr)
        # The census scans whole sections and objdump knows no symbols, so
        # the image they read has the pointer tables cut out, not uncovered.
        parts = parts_of(jitelf.explode(tchunks), outdir, base, tier + '.code')
        for i, elf in enumerate(parts):
            print('  %s x86lint -i and objdump on %s (%d/%d)' % (
                time.strftime('%H:%M:%S'), os.path.basename(elf), i + 1,
                len(parts)), file=sys.stderr)
            tally.censuses.append(''.join(stream_x86lint(elf, '-i')))
            enc = count_branch_encodings(elf)
            if enc is not None:
                tally.rel8 += enc[0]
                tally.rel32 += enc[1]
        tiers[tier] = tally
        total.add(tally)

    census = merge_census(total.censuses)
    with open(os.path.join(outdir, base + '.census.txt'), 'w') as f:
        f.write(census)

    return {'dump': dump, 'label': label, 'truncated': truncated,
            'tiers': tiers, 'total': total, 'census': census}


PSABI_LEVELS = ['baseline x86-64 (v1)', 'x86-64-v2', 'x86-64-v3', 'x86-64-v4']
FEATURE_RE = re.compile(r'([A-Za-z0-9._+/-]+) \((\d+)(?:, (\d+) unevidenced)?\)')
X87_RE = re.compile(r'^(\d+) \(control/env (\d+), 80-bit operands (\d+), '
                    r'other (\d+)\)')


def merge_census(texts):
    """Sum the -i censuses of the parts of one image into one census text."""
    insns = skipped = 0
    baseline = [0, 0]
    feats = collections.OrderedDict()
    x87 = [0, 0, 0, 0]
    highest = 0
    others = collections.OrderedDict()
    for text in texts:
        for line in text.splitlines():
            m = re.match(r'^ISA census: (\d+) instructions, (\d+) undecodable',
                         line)
            if m:
                insns += int(m.group(1))
                skipped += int(m.group(2))
                continue
            m = re.match(r'^  ([^:]+): (.*)$', line)
            if not m:
                continue
            label, value = m.groups()
            if label == PSABI_LEVELS[0]:
                m = re.match(r'^(\d+)(?: \((\d+) unevidenced\))?', value)
                baseline[0] += int(m.group(1))
                baseline[1] += int(m.group(2) or 0)
            elif label in PSABI_LEVELS[1:] or label == 'outside the psABI levels':
                c = feats.setdefault(label, collections.Counter())
                for name, n, _ in FEATURE_RE.findall(value):
                    c[name] += int(n)
            elif label == 'x87 legacy FP':
                m = X87_RE.match(value)
                if m:
                    for i in range(4):
                        x87[i] += int(m.group(i + 1))
            elif label == 'highest psABI level':
                if value in PSABI_LEVELS:
                    highest = max(highest, PSABI_LEVELS.index(value))
            else:
                others.setdefault(label, value)
    out = ['ISA census: %d instructions, %d undecodable bytes skipped'
           % (insns, skipped)]
    out.append('  %s: %d%s' % (PSABI_LEVELS[0], baseline[0],
                               ' (%d unevidenced)' % baseline[1]
                               if baseline[1] else ''))
    for label in PSABI_LEVELS[1:] + ['outside the psABI levels']:
        c = feats.get(label, {})
        out.append('  %s: %s' % (label, ', '.join(
            '%s (%d)' % (k, v) for k, v in sorted(c.items(),
                                                  key=lambda kv: -kv[1]))
            or 'none'))
    out.append('  x87 legacy FP: %s' % (
        '%d (control/env %d, 80-bit operands %d, other %d)' % tuple(x87)
        if x87[0] else 'none'))
    out.append('  highest psABI level: %s' % PSABI_LEVELS[highest])
    for label, value in others.items():
        out.append('  %s: %s' % (label, value))
    return '\n'.join(out) + '\n'


def load_ps(path):
    """pid -> process type from run-browser.sh's ps.log."""
    types = {}
    if not path:
        return types
    with open(path) as f:
        for line in f:
            parts = line.split()
            if not parts or not parts[0].isdigit():
                continue
            pid = int(parts[0])
            args = parts[1:]
            if '-contentproc' in args:
                kind = args[-1]
                if kind.startswith('webIsolated='):
                    kind = 'web ' + kind.split('=', 1)[1]
            elif '-forkserver' in args:
                kind = 'forkserver'
            else:
                kind = 'parent'
            types[pid] = kind
    return types


def label_for(dump, ps_types):
    m = re.search(r'\.(\d+)$', dump)
    if not m:
        return 'shell'
    pid = int(m.group(1))
    if not ps_types:
        return 'shell %d' % pid
    return '%s %d' % (ps_types.get(pid, 'unknown'), pid)


def fmt(n):
    return format(n, ',d')


def human(n):
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024 or unit == 'GB':
            return ('%d %s' if unit == 'B' else '%.1f %s') % (n, unit)
        n /= 1024.0


def report(results, title):
    out = []
    w = out.append
    w('# %s' % title)
    w('')
    w('| process | blobs | code | instructions | undecodable | findings | per 1k | branch displacement per 1k | everything else per 1k |')
    w('| --- | --- | --- | --- | --- | --- | --- | --- | --- |')
    grand = Tally()
    for r in results:
        t = r['total']
        grand.add(t)
        w('| %s | %s | %s | %s | %s | %s | %.1f | %.1f | %.1f |' % (
            r['label'], fmt(t.blobs), human(t.code), fmt(t.instructions),
            fmt(t.skipped), fmt(t.findings), t.per_k(t.findings),
            t.per_k(t.branch), t.per_k(t.findings - t.branch)))
    if len(results) > 1:
        t = grand
        w('| **all processes** | %s | %s | %s | %s | %s | %.1f | %.1f | %.1f |' % (
            fmt(t.blobs), human(t.code), fmt(t.instructions), fmt(t.skipped),
            fmt(t.findings), t.per_k(t.findings), t.per_k(t.branch),
            t.per_k(t.findings - t.branch)))
    w('')

    for r in results:
        t = r['total']
        w('## %s' % r['label'])
        w('')
        if r['truncated']:
            w('%d trailing bytes were not a complete record.' % r['truncated'])
            w('')
        w('| tier | blobs | code | instructions | findings | per 1k | branch per 1k | else per 1k | findings per KB |')
        w('| --- | --- | --- | --- | --- | --- | --- | --- | --- |')
        for tier, tt in r['tiers'].items():
            w('| %s | %s | %s | %s | %s | %.1f | %.1f | %.1f | %.1f |' % (
                tier, fmt(tt.blobs), human(tt.code), fmt(tt.instructions),
                fmt(tt.findings), tt.per_k(tt.findings), tt.per_k(tt.branch),
                tt.per_k(tt.findings - tt.branch),
                1024.0 * tt.findings / tt.code if tt.code else 0))
        w('')
        if t.masked_words:
            w('Inline code-pointer words left unscanned: %s in %s blobs (%s '
              'of table bytes); per tier: %s.'
              % (fmt(t.masked_words), fmt(t.masked_blobs),
                 human(8 * t.masked_words),
                 ', '.join('%s %s in %s' % (tier, fmt(tt.masked_words),
                                           fmt(tt.masked_blobs))
                           for tier, tt in r['tiers'].items()
                           if tt.masked_words)))
            w('')
        w('Branch displacement findings: %s forward, %s backward, %s other; '
          '%s bytes of rel32 that rel8 would have covered (%.2f%% of the code).'
          % (fmt(t.branch_forward), fmt(t.branch_backward),
             fmt(t.branch_other), fmt(t.branch_bytes),
             100.0 * t.branch_bytes / t.code if t.code else 0))
        if t.rel32:
            w('Branch encodings in the image: %s rel8, %s rel32; the %s '
              'findings are %.1f%% of the rel32 branches.'
              % (fmt(t.rel8), fmt(t.rel32), fmt(t.branch),
                 100.0 * t.branch / t.rel32))
        imm = t.checks.get(IMMEDIATE, 0)
        w('Oversized immediate: %s, of which %s are 10-byte `movabs` of 0 or '
          '-1 (the patch-placeholder class), leaving %s.'
          % (fmt(imm), fmt(t.placeholders), fmt(imm - t.placeholders)))
        w('')
        w('| tier | branch findings | forward | backward | rel8 in image | rel32 in image | findings / rel32 | `movabs` placeholders |')
        w('| --- | --- | --- | --- | --- | --- | --- | --- |')
        for tier, tt in r['tiers'].items():
            w('| %s | %s | %s | %s | %s | %s | %.1f%% | %s |' % (
                tier, fmt(tt.branch), fmt(tt.branch_forward),
                fmt(tt.branch_backward), fmt(tt.rel8), fmt(tt.rel32),
                100.0 * tt.branch / tt.rel32 if tt.rel32 else 0,
                fmt(tt.placeholders)))
        w('')
        w('| check | findings | per 1k | share |')
        w('| --- | --- | --- | --- |')
        top = t.checks.most_common(25)
        for check, n in top:
            w('| %s | %s | %.2f | %.1f%% |' % (check, fmt(n), t.per_k(n),
                                              100.0 * n / t.findings))
        rest = t.findings - sum(n for _, n in top)
        if rest:
            w('| %d more checks | %s | %.2f | %.1f%% |' % (
                len(t.checks) - len(top), fmt(rest), t.per_k(rest),
                100.0 * rest / t.findings))
        w('')
        w('| check | ' + ' | '.join(r['tiers']) + ' |')
        w('| --- |' + ' --- |' * len(r['tiers']))
        for check, _ in t.checks.most_common(15):
            w('| %s | ' % check + ' | '.join(
                fmt(tt.checks.get(check, 0)) for tt in r['tiers'].values()) + ' |')
        w('')
        w('```')
        w(r['census'].strip())
        w('```')
        w('')
    return '\n'.join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('dumps', nargs='+')
    ap.add_argument('--out', required=True)
    ap.add_argument('--ps')
    ap.add_argument('--title', default='JIT corpus')
    ap.add_argument('--keep-code-pointers', action='store_true',
                    help='scan inline jump tables as if they were code')
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    ps_types = load_ps(args.ps)
    results = []
    for dump in args.dumps:
        label = label_for(dump, ps_types)
        print('analyzing %s (%s)' % (dump, label), file=sys.stderr)
        results.append(analyze_process(dump, args.out, label,
                                       args.keep_code_pointers))
    results.sort(key=lambda r: -r['total'].code)
    text = report(results, args.title)
    with open(os.path.join(args.out, 'report.md'), 'w') as f:
        f.write(text + '\n')
    print(text)
    return 0


if __name__ == '__main__':
    sys.exit(main())
