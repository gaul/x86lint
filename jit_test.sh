#!/bin/sh
# Tests for the JIT-dump converters (tools/v8dump2elf.py, tools/jitdump2elf.py).
# Both turn an engine's account of its own code into an ELF object x86lint can
# scan, so what has to hold is that the bytes arrive intact, at the addresses
# the engine gave them, split at the boundaries between unrelated code objects,
# and named for the tier that produced them. The fixtures are synthetic: an
# engine is not needed to check a parser, and pinning the formats here is what
# says which spelling the converters promise to read.
set -u

X86LINT=${X86LINT:-./x86lint}
TOOLS=$(dirname "$0")/tools

# The suite never skips itself on toolchain grounds; see driver_test.sh.
if ! command -v python3 >/dev/null 2>&1; then
    echo "jit_test.sh: no python3 to run the converters" >&2
    exit 2
fi

dir=$(mktemp -d) || exit 2
trap 'rm -rf "$dir"' EXIT
status=0

fail() {
    echo "FAIL: $*" >&2
    status=1
}

# convert <converter> <args...>: run a converter, capturing its stderr report
# in $dir/conv and failing on a non-zero exit.
convert() {
    tool=$1
    shift
    if ! python3 "$TOOLS/$tool" "$@" >"$dir/conv" 2>&1; then
        fail "$tool $* failed: $(cat "$dir/conv")"
        return 1
    fi
    return 0
}

expect() {  # expect <file> <pattern> [description]
    grep -qE "$2" "$1" || fail "missing '${3:-$2}' in $1"
}

reject() {  # reject <file> <pattern> [description]
    grep -qE "$2" "$1" && fail "unexpected '${3:-$2}' in $1"
}

# === V8: a --print-opt-code listing ===
#
# Four code objects. The first is named and contiguous. The second has a gap
# in its addresses, which must split it into two sections rather than one
# section whose bytes lie about where they are. The third has no name line at
# all, and the "name =" inside its raw source must not become its symbol. The
# fourth is announced by V8's other banner: TurboFan objects say "Optimized
# code" and Maglev ones say "Disassembly:", and a header gate that tested for
# the word "code" cost every Maglev object its tier and name.
cat >"$dir/v8.txt" <<'EOF'
--- Raw source ---
function f(a) { let name = a; return name; }

--- Optimized code ---
optimization_id = 1
kind = TURBOFAN_JS
name = add
compiler = turbofan

Instructions (size = 9)
0x1000     0  b83c000000           movl rax,0x3c
0x1005     5  87c8                 xchg rax,rcx
0x1007     7  31ff                 xorl rdi,rdi

Safepoints (stack slots = 2, byte size = 4)
0x1005     5  slots (sp->fp): 10

RelocInfo (size = 0)

--- End code ---
--- Optimized code ---
kind = MAGLEV
name = split
compiler = maglev

Instructions (size = 6)
0x2000     0  87c8                 xchg rax,rcx
0x2002     2  90                   nop
0x3000  1000  87c8                 xchg rax,rcx
0x3002  1002  c3                   ret

--- End code ---
--- Raw source ---
name = definitely not a header field

--- Optimized code ---
kind = BASELINE
compiler = baseline

Instructions (size = 3)
0x4000     0  87c8                 xchg rax,rcx
0x4002     2  c3                   ret

--- End code ---
--- Disassembly: ---
kind = MAGLEV
name = maglev
compiler = maglev

Instructions (size = 3)
0x5000     0  87c8                 xchg rax,rcx
0x5002     2  c3                   ret

--- End code ---
EOF

if convert v8dump2elf.py "$dir/v8.txt" -o "$dir/v8.elf" --map "$dir/v8.map"; then
    expect "$dir/conv" '^5 code blobs, 21 code bytes' "V8 chunk and byte count"
    # The tier prefix, the JS name, and the split at the address gap. The
    # second half of the split object keeps the name with a .2 suffix: it is
    # more of the same code object, not a different one.
    expect "$dir/v8.map" '^TF_add 0x1000 9$'
    expect "$dir/v8.map" '^ML_split 0x2000 3$'
    expect "$dir/v8.map" '^ML_split.2 0x3000 3$'
    expect "$dir/v8.map" '^BL_anonymous 0x4000 3$' "unnamed object's symbol"
    expect "$dir/v8.map" '^ML_maglev 0x5000 3$' "object under the Disassembly banner"
    reject "$dir/v8.map" 'definitely' "raw source leaking into a symbol"

    # The bytes arrive: four xchg sites, one per object plus the split half,
    # and nothing from the Safepoints or RelocInfo blocks that follow the
    # listing (they would decode as instructions if they were copied in).
    "$X86LINT" "$dir/v8.elf" >"$dir/out" 2>&1
    rc=$?
    [ "$rc" -eq 1 ] || fail "x86lint on the V8 image exited $rc, expected 1"
    expect "$dir/out" '^ +5 +oversized XCHG encoding$' "one finding per object"
    expect "$dir/out" '^5 optimization opportunities in 11 instructions$'
    expect "$dir/out" '^scan restricted to 5 function symbols'

    # -v attributes each finding to its section at the JIT address the dump
    # gave, which is what makes a finding cross-referenceable back into it.
    "$X86LINT" -v "$dir/v8.elf" >"$dir/out" 2>&1
    expect "$dir/out" '^== section 1 .text: vaddr 0x1000, 9 bytes ==$'
    expect "$dir/out" '^oversized XCHG encoding at offset: 0x5 \(TF_add\+0x5\)'
    expect "$dir/out" '^== section 3 .text: vaddr 0x3000, 3 bytes ==$' \
        "the split object's second section"
fi

# A listing line whose byte column has an odd digit count is not an
# instruction line, whatever it looks like; it is reported and skipped rather
# than silently truncated into the stream.
cat >"$dir/odd.txt" <<'EOF'
--- Optimized code ---
kind = TURBOFAN_JS
name = odd

Instructions (size = 4)
0x1000     0  87c8                 xchg rax,rcx
0x1002     2  abc                  not an instruction
0x1002     2  c3                   ret
EOF
if convert v8dump2elf.py "$dir/odd.txt" -o "$dir/odd.elf"; then
    expect "$dir/conv" 'odd-length byte column'
    expect "$dir/conv" '^1 code blobs, 3 code bytes'
fi

# An empty dump is a tool failure, not an empty ELF nobody notices.
: >"$dir/empty.txt"
if python3 "$TOOLS/v8dump2elf.py" "$dir/empty.txt" -o "$dir/empty.elf" \
        >"$dir/conv" 2>&1; then
    fail "an empty dump produced an ELF"
else
    expect "$dir/conv" 'no code found'
fi

# === The raw record container (SpiderMonkey and JSC hooks) ===
#
# "X86J" | u64 address | u32 code size | u32 name size | name | code
python3 - "$dir/rec.jitdump" <<'PYEOF'
import struct, sys
def rec(addr, name, code):
    return (b'X86J' + struct.pack('<QII', addr, len(code), len(name))
            + name + code)
blobs = [
    (0x7f0000001000, b'Ion', bytes.fromhex('b83c00000087c831ff')),
    (0x7f0000002000, b'Baseline', bytes.fromhex('87c8c3')),
    (0x7f0000003000, b'Ion', bytes.fromhex('87c8c3')),
]
with open(sys.argv[1], 'wb') as f:
    for addr, name, code in blobs:
        f.write(rec(addr, name, code))
    # A fourth record cut off mid-code, as a killed process leaves behind.
    f.write(rec(0x7f0000004000, b'RegExp', bytes.fromhex('87c8c3'))[:-2])
PYEOF

if convert jitdump2elf.py "$dir/rec.jitdump" -o "$dir/rec.elf" \
        --map "$dir/rec.map"; then
    expect "$dir/conv" 'were not a complete record' "truncation report"
    expect "$dir/conv" '^3 code blobs, 15 code bytes' \
        "the three whole records"
    expect "$dir/rec.map" '^Ion 0x7f0000001000 9$'
    expect "$dir/rec.map" '^Baseline 0x7f0000002000 3$'
    expect "$dir/rec.map" '^Ion.2 0x7f0000003000 3$' "repeated tier name"
    "$X86LINT" "$dir/rec.elf" >"$dir/out" 2>&1
    expect "$dir/out" '^ +3 +oversized XCHG encoding$'
    expect "$dir/out" '^3 optimization opportunities in 7 instructions$'
fi

# --min-bytes drops the blobs too small to hold a window, which is how a dump
# full of one-instruction stubs is kept out of a corpus figure.
if convert jitdump2elf.py "$dir/rec.jitdump" -o "$dir/min.elf" \
        --min-bytes 4 --map "$dir/min.map"; then
    expect "$dir/conv" '^1 code blobs, 9 code bytes'
    reject "$dir/min.map" 'Baseline' "a blob under --min-bytes"
fi

# A file that is not records at all is refused at the first byte rather than
# being read as a headerless blob.
printf 'not a jit dump at all' >"$dir/junk.bin"
if python3 "$TOOLS/jitdump2elf.py" "$dir/junk.bin" -o "$dir/junk.elf" \
        >"$dir/conv" 2>&1; then
    fail "a non-record file produced an ELF"
else
    expect "$dir/conv" 'no code found'
fi

# --raw takes a file that is nothing but machine code, which is what
# SpiderMonkey's disnative(f, "file") writes with no patch applied.
printf '\267\074\000\000\000\207\310\303' >"$dir/blob.bin"
if convert jitdump2elf.py --raw "$dir/blob.bin" -o "$dir/blob.elf" \
        --addr 0x5000 --name ion_hot --map "$dir/blob.map"; then
    expect "$dir/blob.map" '^ion_hot 0x5000 8$'
    "$X86LINT" -v "$dir/blob.elf" >"$dir/out" 2>&1
    expect "$dir/out" '^== section 1 .text: vaddr 0x5000, 8 bytes ==$'
    expect "$dir/out" 'oversized XCHG encoding at offset: 0x5 \(ion_hot\+0x5\)'
fi

# === The ELF the converters write ===
#
# x86lint locates symbols in an ET_REL object by section index and offset, so
# a converter that wrote absolute st_value would mask every byte of every
# section and report a clean scan over nothing at all. Check the shape
# directly rather than inferring it from a finding count.
if command -v readelf >/dev/null 2>&1; then
    readelf -hSs "$dir/v8.elf" >"$dir/elf.txt" 2>&1
    expect "$dir/elf.txt" 'Type: +REL \(Relocatable file\)'
    expect "$dir/elf.txt" 'Machine: +Advanced Micro Devices X86-64'
    expect "$dir/elf.txt" '\.text +PROGBITS +0000000000001000'
    expect "$dir/elf.txt" '0000000000000000 +9 FUNC +LOCAL +DEFAULT +1 TF_add' \
        "section-relative STT_FUNC symbol"
else
    echo "jit_test.sh: no readelf, skipping the ELF shape check" >&2
fi

if [ "$status" -eq 0 ]; then
    echo "jit_test.sh: all JIT converter checks passed"
fi
exit "$status"
