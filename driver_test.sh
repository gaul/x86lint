#!/bin/sh
# Smoke test for the ELF driver (main.c): section walk, symbol-table scan
# restriction and its -a override, -v per-finding lines with section-relative
# offsets, the --json document, the summary tail, and the grep-convention
# exit codes (0 clean scan, 1 opportunities found, 2 tool failure).
# Fixtures are tiny static ELFs assembled with the system toolchain at run
# time; instructions are spelled as .byte so the assembler cannot pick
# different encodings.
set -u

X86LINT=${X86LINT:-./x86lint}

if ! command -v cc >/dev/null 2>&1; then
    echo "driver_test.sh: no C compiler for fixtures, skipping" >&2
    exit 0
fi

dir=$(mktemp -d) || exit 2
trap 'rm -rf "$dir"' EXIT
status=0

fail() {
    echo "FAIL: $*" >&2
    status=1
}

# run <expected_rc> <args...>: invoke the driver, capture combined output in
# $dir/out, and assert the exit code.
run() {
    expected=$1
    shift
    "$X86LINT" "$@" >"$dir/out" 2>&1
    rc=$?
    if [ "$rc" -ne "$expected" ]; then
        fail "x86lint $* exited $rc, expected $expected"
    fi
}

expect() {  # expect <pattern> [description]
    grep -qE "$1" "$dir/out" || fail "missing '${2:-$1}' in output of last run"
}

reject() {  # reject <pattern> [description]
    grep -qE "$1" "$dir/out" && fail "unexpected '${2:-$1}' in output of last run"
}

# _start is a sized function symbol holding exactly one finding (the modrm
# xchg, whose rewrite to 91 is unconditional -- no liveness dependence). Two
# more xchg bytes sit OUTSIDE its range: the default symbol-restricted scan
# must mask them (they count as skipped, not instructions) and -a must not.
cat >"$dir/finding.s" <<'EOF'
    .text
    .globl _start
    .type _start, @function
_start:
    .byte 0xb8, 0x3c, 0x00, 0x00, 0x00  # 0x0: mov eax, 60 (clean)
    .byte 0x87, 0xc8                    # 0x5: xchg eax, ecx (oversized XCHG)
    .byte 0x31, 0xff                    # 0x7: xor edi, edi (clean)
    .byte 0x0f, 0x05                    # 0x9: syscall (clean)
    .size _start, . - _start
    .byte 0x87, 0xc8                    # 0xb: outside _start, masked by default
    .section .note.GNU-stack, "", @progbits
EOF

cat >"$dir/clean.s" <<'EOF'
    .text
    .globl _start
    .type _start, @function
_start:
    .byte 0xb8, 0x3c, 0x00, 0x00, 0x00  # mov eax, 60
    .byte 0x31, 0xff                    # xor edi, edi
    .byte 0x0f, 0x05                    # syscall
    .size _start, . - _start
    .section .note.GNU-stack, "", @progbits
EOF

# Three extension-gated patterns in one fixture: a NOT/AND pair that folds
# to ANDN (a finding only under -m bmi1; the trailing sub kills the flags
# the fold's PF gate watches), a load/BSWAP pair that folds to MOVBE (only
# under -m movbe), and a MOV/SUB pair that folds to an NDD sub (only under
# -m apx). Each -m run must see exactly its own finding.
cat >"$dir/bmi.s" <<'EOF'
    .text
    .globl _start
    .type _start, @function
_start:
    .byte 0xf7, 0xd0                    # not eax
    .byte 0x21, 0xc8                    # and eax, ecx
    .byte 0x8b, 0x06                    # mov eax, [rsi]
    .byte 0x0f, 0xc8                    # bswap eax
    .byte 0x89, 0xf8                    # mov eax, edi
    .byte 0x29, 0xf0                    # sub eax, esi
    .byte 0xc3                          # ret
    .size _start, . - _start
    .section .note.GNU-stack, "", @progbits
EOF

# A 3E-prefixed indirect call is exempt from CET indirect-branch tracking
# and is flagged; the same prefix on an indirect JMP is the compilers'
# switch-table idiom and must stay clean.
cat >"$dir/notrack.s" <<'EOF'
    .text
    .globl _start
    .type _start, @function
_start:
    .byte 0x3e, 0xff, 0xd0              # notrack call rax (IBT bypass)
    .byte 0x3e, 0xff, 0xe0              # notrack jmp rax (switch idiom)
    .byte 0xc3                          # ret
    .size _start, . - _start
    .section .note.GNU-stack, "", @progbits
EOF

# Attribution fixture: two sized functions holding two and one findings,
# plus an unsized label (no .size) holding a fourth -- the masked scan
# still reaches it (unsized coverage extends to the section end) but
# attribution, sized-only, books it against no function.
cat >"$dir/perfunc.s" <<'EOF'
    .text
    .globl _start
    .type _start, @function
_start:
    .byte 0x87, 0xc8                    # 0x0: xchg eax, ecx (finding)
    .byte 0x87, 0xc8                    # 0x2: xchg eax, ecx (finding)
    .byte 0xc3                          # ret
    .size _start, . - _start
    .globl f2
    .type f2, @function
f2:
    .byte 0x87, 0xc8                    # 0x5: xchg eax, ecx (finding)
    .byte 0xc3                          # ret
    .size f2, . - f2
    .globl f3
    .type f3, @function
f3:
    .byte 0x87, 0xc8                    # 0x8: xchg eax, ecx (finding)
    .byte 0xc3                          # ret
    .section .note.GNU-stack, "", @progbits
EOF

# Census fixture for -i: one v2 instruction, one v3, one x87 control
# instruction, the rest baseline.
cat >"$dir/census.s" <<'EOF'
    .text
    .globl _start
    .type _start, @function
_start:
    .byte 0xf3, 0x0f, 0xb8, 0xc0        # popcnt eax, eax (v2)
    .byte 0xc5, 0xfd, 0xfc, 0xc0        # vpaddb ymm0, ymm0, ymm0 (v3 AVX2)
    .byte 0xd9, 0x28                    # fldcw [rax] (x87 control/env)
    .byte 0xc3                          # ret (baseline)
    .size _start, . - _start
    .section .note.GNU-stack, "", @progbits
EOF

# A census fixture carrying the toolchain ISA accounting (-mneeded style):
# ISA_1_NEEDED says baseline+v2, ISA_1_USED all four levels. Properties in
# one note must be sorted by ascending pr_type: NEEDED (0xc0008002) before
# USED (0xc0010002).
cat >"$dir/isanote.s" <<'EOF'
    .section .note.gnu.property,"a",@note
    .p2align 3
    .long 1f - 0f                       # n_namesz
    .long 3f - 2f                       # n_descsz
    .long 5                             # NT_GNU_PROPERTY_TYPE_0
0:  .asciz "GNU"
1:  .p2align 3
2:  .long 0xc0008002                    # GNU_PROPERTY_X86_ISA_1_NEEDED
    .long 4
    .long 0x3                           # baseline | v2
    .long 0
    .long 0xc0010002                    # GNU_PROPERTY_X86_ISA_1_USED
    .long 4
    .long 0xf                           # baseline | v2 | v3 | v4
    .long 0
3:
    .text
    .globl _start
    .type _start, @function
_start:
    .byte 0xf3, 0x0f, 0xb8, 0xc0        # popcnt eax, eax (v2)
    .byte 0xc3                          # ret (baseline)
    .size _start, . - _start
    .section .note.GNU-stack, "", @progbits
EOF

# A hand-written Go 1.20+ pclntab over two functions, linked stripped: the
# table is the only code evidence left, exactly the stripped-Go-binary case
# the source exists for. textStart is stored as 0 the way modern linkers
# write it ("unused"), so the parse must recover the base from the section
# start, anchored by the entry point. A trailing xchg sits outside the
# table's coverage to prove the labeling discriminates.
cat >"$dir/gopcln.s" <<'EOF'
    .text
    .globl _start
_start:
    .byte 0xf3, 0x0f, 0xb8, 0xc0        # popcnt eax, eax (v2)
    .byte 0xc3                          # ret
f2:
    .byte 0x31, 0xff                    # xor edi, edi
    .byte 0x0f, 0x05                    # syscall
    .byte 0xc3                          # ret
tend:
    .byte 0x87, 0xc8                    # xchg outside the functab
    .section .gopclntab,"a"
    .p2align 3
pcln:
    .long 0xfffffff1                    # Go 1.20+ magic
    .byte 0, 0                          # pad
    .byte 1                             # pc quantum
    .byte 8                             # pointer size
    .quad 2                             # nfunc
    .quad 0                             # nfiles
    .quad 0                             # textStart: 0 since Go dropped it
    .quad 0, 0, 0, 0                    # funcname/cutab/filetab/pctab
    .quad ftab - pcln                   # functab offset
ftab:
    .long _start - _start, 0            # func 0: entry offset, funcoff
    .long f2 - _start, 0                # func 1
    .long tend - _start                 # sentinel: end of the last function
    .section .note.GNU-stack, "", @progbits
EOF

# The same functions under the Go 1.16-1.17 header: the functab offset
# sits in header word 6 and the entries are absolute vaddrs (link-time
# relocations), the layout every pre-1.18 toolchain era shares.
cat >"$dir/gopcln116.s" <<'EOF'
    .text
    .globl _start
_start:
    .byte 0xf3, 0x0f, 0xb8, 0xc0        # popcnt eax, eax (v2)
    .byte 0xc3                          # ret
f2:
    .byte 0x31, 0xff                    # xor edi, edi
    .byte 0x0f, 0x05                    # syscall
    .byte 0xc3                          # ret
tend:
    .byte 0x87, 0xc8                    # xchg outside the functab
    .section .gopclntab,"a"
    .p2align 3
pcln:
    .long 0xfffffffa                    # Go 1.16-1.17 magic
    .byte 0, 0                          # pad
    .byte 1                             # pc quantum
    .byte 8                             # pointer size
    .quad 2                             # nfunc
    .quad 0                             # nfiles
    .quad 0, 0, 0, 0                    # funcname/cutab/filetab/pctab
    .quad ftab - pcln                   # functab offset
ftab:
    .quad _start, 0                     # func 0: absolute entry, funcoff
    .quad f2, 0                         # func 1
    .quad tend                          # sentinel: end of the last function
    .section .note.GNU-stack, "", @progbits
EOF

# The same table buried at +8 in an anonymous data section: external
# linking can leave the pclntab without a section of its own, found only
# by the byte scan.
cat >"$dir/gopclnscan.s" <<'EOF'
    .text
    .globl _start
_start:
    .byte 0xf3, 0x0f, 0xb8, 0xc0        # popcnt eax, eax (v2)
    .byte 0xc3                          # ret
f2:
    .byte 0x31, 0xff                    # xor edi, edi
    .byte 0x0f, 0x05                    # syscall
    .byte 0xc3                          # ret
tend:
    .byte 0x87, 0xc8                    # xchg outside the functab
    .section .data.rel.ro,"aw"
    .p2align 3
    .quad 0                             # not the table start: the scan digs
pcln:
    .long 0xfffffff1                    # Go 1.20+ magic
    .byte 0, 0                          # pad
    .byte 1                             # pc quantum
    .byte 8                             # pointer size
    .quad 2                             # nfunc
    .quad 0                             # nfiles
    .quad 0                             # textStart: 0 since Go dropped it
    .quad 0, 0, 0, 0                    # funcname/cutab/filetab/pctab
    .quad ftab - pcln                   # functab offset
ftab:
    .long _start - _start, 0            # func 0: entry offset, funcoff
    .long f2 - _start, 0                # func 1
    .long tend - _start                 # sentinel: end of the last function
    .section .note.GNU-stack, "", @progbits
EOF

# CET fixtures for -e. The .note.gnu.property section is the same note gcc
# emits under -fcf-protection (the linker merges it through to the output):
# cetgood declares IBT+SHSTK and pads its entry point, cetbad declares IBT
# only and does not pad, cetlost pads without declaring (the linker ANDs
# the note across inputs, so this is what a link poisoned by one non-CET
# object leaves), cetret declares only SHSTK (-fcf-protection=return), and
# cetso is a shared object whose exported fn_bad lacks its pad.
cat >"$dir/cetgood.s" <<'EOF'
    .section .note.gnu.property,"a",@note
    .p2align 3
    .long 1f - 0f                       # n_namesz
    .long 3f - 2f                       # n_descsz
    .long 5                             # NT_GNU_PROPERTY_TYPE_0
0:  .asciz "GNU"
1:  .p2align 3
2:  .long 0xc0000002                    # GNU_PROPERTY_X86_FEATURE_1_AND
    .long 4
    .long 3                             # FEATURE_1_IBT | FEATURE_1_SHSTK
    .long 0
3:
    .text
    .globl _start
    .type _start, @function
_start:
    .byte 0xf3, 0x0f, 0x1e, 0xfa        # endbr64
    .byte 0xb8, 0x3c, 0x00, 0x00, 0x00  # mov eax, 60 (clean)
    .byte 0x31, 0xff                    # xor edi, edi (clean)
    .byte 0x0f, 0x05                    # syscall (clean)
    .size _start, . - _start
    .section .note.GNU-stack, "", @progbits
EOF

cat >"$dir/cetbad.s" <<'EOF'
    .section .note.gnu.property,"a",@note
    .p2align 3
    .long 1f - 0f                       # n_namesz
    .long 3f - 2f                       # n_descsz
    .long 5                             # NT_GNU_PROPERTY_TYPE_0
0:  .asciz "GNU"
1:  .p2align 3
2:  .long 0xc0000002                    # GNU_PROPERTY_X86_FEATURE_1_AND
    .long 4
    .long 1                             # GNU_PROPERTY_X86_FEATURE_1_IBT
    .long 0
3:
    .text
    .globl _start
    .type _start, @function
_start:
    .byte 0xb8, 0x3c, 0x00, 0x00, 0x00  # mov eax, 60 (clean)
    .byte 0x31, 0xff                    # xor edi, edi (clean)
    .byte 0x0f, 0x05                    # syscall (clean)
    .size _start, . - _start
    .section .note.GNU-stack, "", @progbits
EOF

cat >"$dir/cetlost.s" <<'EOF'
    .text
    .globl _start
    .type _start, @function
_start:
    .byte 0xf3, 0x0f, 0x1e, 0xfa        # endbr64
    .byte 0xb8, 0x3c, 0x00, 0x00, 0x00  # mov eax, 60 (clean)
    .byte 0x31, 0xff                    # xor edi, edi (clean)
    .byte 0x0f, 0x05                    # syscall (clean)
    .size _start, . - _start
    .section .note.GNU-stack, "", @progbits
EOF

# cetret: only the shadow-stack bit (-fcf-protection=return). No IBT claim
# to hold the code to, but the asymmetric declaration is reported.
cat >"$dir/cetret.s" <<'EOF'
    .section .note.gnu.property,"a",@note
    .p2align 3
    .long 1f - 0f                       # n_namesz
    .long 3f - 2f                       # n_descsz
    .long 5                             # NT_GNU_PROPERTY_TYPE_0
0:  .asciz "GNU"
1:  .p2align 3
2:  .long 0xc0000002                    # GNU_PROPERTY_X86_FEATURE_1_AND
    .long 4
    .long 2                             # GNU_PROPERTY_X86_FEATURE_1_SHSTK
    .long 0
3:
    .text
    .globl _start
    .type _start, @function
_start:
    .byte 0xb8, 0x3c, 0x00, 0x00, 0x00  # mov eax, 60
    .byte 0x31, 0xff                    # xor edi, edi
    .byte 0x0f, 0x05                    # syscall
    .size _start, . - _start
    .section .note.GNU-stack, "", @progbits
EOF

cat >"$dir/cetso.s" <<'EOF'
    .section .note.gnu.property,"a",@note
    .p2align 3
    .long 1f - 0f                       # n_namesz
    .long 3f - 2f                       # n_descsz
    .long 5                             # NT_GNU_PROPERTY_TYPE_0
0:  .asciz "GNU"
1:  .p2align 3
2:  .long 0xc0000002                    # GNU_PROPERTY_X86_FEATURE_1_AND
    .long 4
    .long 1                             # GNU_PROPERTY_X86_FEATURE_1_IBT
    .long 0
3:
    .text
    .globl fn_good
    .type fn_good, @function
fn_good:
    .byte 0xf3, 0x0f, 0x1e, 0xfa        # endbr64
    .byte 0xc3                          # ret
    .size fn_good, . - fn_good
    .globl fn_bad
    .type fn_bad, @function
fn_bad:
    .byte 0xc3                          # ret
    .size fn_bad, . - fn_bad
    .section .init_array,"aw",@init_array
    .p2align 3
    .quad fn_good
    .section .note.GNU-stack, "", @progbits
EOF

for f in finding clean bmi notrack census isanote perfunc; do
    if ! cc -nostdlib -static -Wl,--build-id=none \
            -o "$dir/$f" "$dir/$f.s"; then
        echo "driver_test.sh: fixture build failed" >&2
        exit 2
    fi
done
# The Go fixtures link stripped: the pclntab must carry the evidence alone.
for f in gopcln gopcln116 gopclnscan; do
    if ! cc -nostdlib -static -Wl,--build-id=none,-s \
            -o "$dir/$f" "$dir/$f.s"; then
        echo "driver_test.sh: fixture build failed" >&2
        exit 2
    fi
done
# The CET executables link as PIE: only a program with an interpreter has an
# indirectly entered entry point (a kernel-entered static binary starts with
# the tracker idle), so a static fixture would evidence no targets at all --
# and plain `cc -nostdlib` with no shared dependencies emits no PT_INTERP
# either. cleandyn is the clean fixture linked the same way, for the
# not-an-IBT verdict.
for f in cetgood cetbad cetlost cetret; do
    if ! cc -nostdlib -pie -Wl,--build-id=none -o "$dir/$f" "$dir/$f.s"; then
        echo "driver_test.sh: fixture build failed" >&2
        exit 2
    fi
done
if ! cc -nostdlib -pie -Wl,--build-id=none \
        -o "$dir/cleandyn" "$dir/clean.s" ||
   ! cc -shared -nostdlib -Wl,--build-id=none \
        -o "$dir/cetso.so" "$dir/cetso.s" ||
   ! cc -c -o "$dir/clean.o" "$dir/clean.s"; then
    echo "driver_test.sh: fixture build failed" >&2
    exit 2
fi

# Findings fixture, default scan: the trailing out-of-function xchg is
# masked, so one finding over the four in-function instructions.
run 1 "$dir/finding"
expect '^Optimization opportunities by type:$'
expect '^ +1 +oversized XCHG encoding$' "count of 1 for oversized XCHG"
expect '^scan restricted to 1 function symbols'
expect '^1 optimization opportunities in 4 instructions$'

# -a scans every byte of the section: the masked xchg surfaces.
run 1 -a "$dir/finding"
expect '^ +2 +oversized XCHG encoding$' "count of 2 for oversized XCHG"
expect '^2 optimization opportunities in 5 instructions$'
reject 'scan restricted' "restricted-scan line under -a"

# -v adds a per-finding line with the section-relative offset.
run 1 -v "$dir/finding"
expect '^oversized XCHG encoding at offset: 0x5' "-v finding line at 0x5"

# Clean fixture: no per-type table, zero count, exit 0.
run 0 "$dir/clean"
expect '^0 optimization opportunities in 3 instructions$'
reject '^Optimization opportunities by type:$' "by-type table on a clean scan"

# Attribution: findings tally per containing function beside the by-type
# table, top offenders first, with the unsized f3's finding in the honest
# outside-every-range row.
run 1 "$dir/perfunc"
expect '^Optimization opportunities by function:$'
expect '^ +2 +_start$'
expect '^ +1 +f2$'
expect '^ +1 +outside every function range$'
expect '^4 optimization opportunities in 7 instructions$'
# -v names the holder inline with its function-relative offset; the
# unsized f3's line stays bare.
run 1 -v "$dir/perfunc"
expect '^oversized XCHG encoding at offset: 0x2 \(_start\+0x2\): '
expect '^oversized XCHG encoding at offset: 0x5 \(f2\+0x0\): '
expect '^oversized XCHG encoding at offset: 0x8: ' "bare -v line for unsized f3"

# -f restricts the scan to one named function, in lint and census mode
# both; an unsized or unknown name is a tool failure, as is combining -f
# with -a.
run 1 -f f2 "$dir/perfunc"
expect "^scan restricted to function 'f2': 1 site, 3 bytes$"
expect '^1 optimization opportunities in 2 instructions$'
reject '_start' "findings from outside the -f target"
run 0 -i -f f2 "$dir/perfunc"
expect '^ISA census: 2 instructions, 0 undecodable bytes skipped$'
expect 'covering 3 of 3 executable bytes$'
expect "^scan restricted to function 'f2': 1 site, 3 bytes$"
run 2 -f f3 "$dir/perfunc"
expect "no sized function symbol named 'f3'"
run 2 -f nosuch "$dir/perfunc"
run 2 -a -f f2 "$dir/perfunc"
expect 'mutually exclusive'

# --json: the same findings the -v scan reports, as one streamable document
# keyed by absolute address. The human report's furniture -- the by-type
# table and the restriction line -- must not leak into it.
run 1 --json "$dir/finding"
expect '^\{"file": ' "JSON document opening"
expect '"check": "oversized XCHG encoding"'
expect '"function": "_start"'
expect '"restriction": \{"symbols": 1\}'
expect '"instructions": 4'
expect '"opportunities": 1'
reject '^Optimization opportunities by type:$' "by-type table under --json"
reject '^scan restricted to' "restriction prose under --json"
reject 'optimization opportunities in' "summary tail under --json"

# A clean scan is an empty findings array, not an absent one, and still 0.
run 0 --json "$dir/clean"
expect '"findings": \[$'
expect '"opportunities": 0'

# -a drops the restriction entirely; -f reports which function it kept.
run 1 --json -a "$dir/finding"
expect '"opportunities": 2'
reject '"restriction"' "restriction key under -a"
run 1 --json -f f2 "$dir/perfunc"
expect '"restriction": \{"function": "f2", "sites": 1, "bytes": 3\}'
expect '"opportunities": 1'

# --json owns stdout, so the reports that would interleave with it are
# refused rather than silently dropped.
run 2 --json -v "$dir/finding"
expect 'cannot be combined'
run 2 --json -i "$dir/finding"
expect 'cannot be combined'
run 2 --json -e "$dir/finding"
expect 'cannot be combined'

# A file the driver rejects leaves no half-written document behind.
"$X86LINT" --json "$dir/finding.s" >"$dir/out" 2>/dev/null
if [ -s "$dir/out" ]; then
    fail "--json wrote a partial document for a non-ELF input"
fi

# Structural check where a JSON parser is at hand: the document parses, its
# array length agrees with the total it reports, and the findings carry the
# absolute addresses of the fixture's four xchg sites.
if command -v python3 >/dev/null 2>&1; then
    "$X86LINT" --json -a "$dir/perfunc" >"$dir/out.json" 2>/dev/null
    python3 - "$dir/out.json" <<'PYEOF' || fail "--json validation failed"
import json, sys
d = json.load(open(sys.argv[1]))
assert d["opportunities"] == 4, d["opportunities"]
assert len(d["findings"]) == d["opportunities"], "array length disagrees"
addrs = [f["vaddr"] for f in d["findings"]]
assert [a - addrs[0] for a in addrs] == [0, 2, 5, 8], addrs
for f in d["findings"]:
    assert f["check"] == "oversized XCHG encoding", f
    assert f["length"] == 2 and f["bytes"] == "87c8", f
    assert f["section"] == ".text", f
PYEOF
else
    echo "driver_test.sh: no python3, skipping --json structural check" >&2
fi

# Extension-gated checks: the fixture is clean at baseline; each -m enables
# exactly its own finding (the bits are independent).
run 0 "$dir/bmi"
reject 'missing' "extension-gated finding without -m"
run 1 -m bmi1 "$dir/bmi"
expect '^ +1 +missing ANDN$' "count of 1 for missing ANDN under -m bmi1"
reject 'missing MOVBE' "MOVBE finding under -m bmi1"
run 1 -m movbe "$dir/bmi"
expect '^ +1 +missing MOVBE$' "count of 1 for missing MOVBE under -m movbe"
reject 'missing ANDN' "ANDN finding under -m movbe"
run 1 -m apx "$dir/bmi"
expect '^ +1 +missing APX NDD$' "count of 1 for missing APX NDD under -m apx"
reject 'missing MOVBE' "MOVBE finding under -m apx"

# The NOTRACK call is flagged; the switch-table jmp idiom beside it is not
# (the instruction count pins that the jmp decoded and produced nothing).
run 1 "$dir/notrack"
expect '^ +1 +IBT-bypassing NOTRACK call$' "count of 1 for NOTRACK call"
expect '^1 optimization opportunities in 3 instructions$'

# -i replaces the lint scan with the ISA census: levels attributed, the
# verdict line present, and none of the lint report's furniture.
run 0 -i "$dir/census"
expect '^ISA census: 4 instructions, 0 undecodable bytes skipped$'
expect '^  x86-64-v2: POPCNT \(1\)$'
expect '^  x86-64-v3: AVX2 \(1\)$'
expect '^  x86-64-v4: none$'
expect '^  x87 legacy FP: 1 \(control/env 1, 80-bit operands 0, other 0\)$'
expect '^  highest psABI level: x86-64-v3$'
# The fixture's sized _start is the code evidence; every byte is inside
# it, so no family carries an unevidenced annotation.
expect '^  code evidence: 1 function symbols \+ 0 .eh_frame FDEs \+ 0 Go pclntab functions covering 11 of 11 executable bytes$'
reject 'unevidenced' "unevidenced annotation with full coverage"
# Depending on the host binutils, the fixture link either carries no ISA
# property at all or a synthesized empty ISA_1_USED word; both spellings
# are correct census output for "the toolchain recorded nothing usable".
expect '^  GNU property ISA note: (none|used = 0)$'
expect '^  IFUNC resolvers defined: 0$'
reject 'optimization opportunities' "lint tail in census mode"

# A binary whose toolchain recorded its ISA levels reports both words.
run 0 -i "$dir/isanote"
expect '^  GNU property ISA note: needed = x86-64-baseline\+x86-64-v2, used = x86-64-baseline\+x86-64-v2\+x86-64-v3\+x86-64-v4$'

# Stripped Go-shaped fixtures: the pclntab is the only evidence left. The
# named section parses with its base recovered from the section start
# (textStart stores 0, as modern linkers write it); the sectionless
# variant is found by the data-section byte scan at a nonzero offset.
# The trailing xchg decodes but lies past the sentinel: one unevidenced.
for f in gopcln gopcln116 gopclnscan; do
    run 0 -i "$dir/$f"
    expect '^ISA census: 6 instructions, 0 undecodable bytes skipped$'
    expect '^  x86-64-v2: POPCNT \(1\)$'
    expect '^  baseline x86-64 \(v1\): 5 \(1 unevidenced\)$'
    expect '^  code evidence: 0 function symbols \+ 0 .eh_frame FDEs \+ 2 Go pclntab functions covering 10 of 12 executable bytes$'
done

# The census ignores the symbol-table scan restriction (the out-of-function
# xchg byte pair decodes and counts) and a baseline-only binary says so.
run 0 -i "$dir/finding"
expect '^ISA census: 5 instructions, 0 undecodable bytes skipped$'
expect '^  x87 legacy FP: none$'
expect '^  highest psABI level: baseline x86-64 \(v1\)$'
# The out-of-function xchg decodes and counts, but lies outside the
# sized _start -- the census scans it and labels it.
expect '^  baseline x86-64 \(v1\): 5 \(1 unevidenced\)$'
expect '^  code evidence: 1 function symbols \+ 0 .eh_frame FDEs \+ 0 Go pclntab functions covering 11 of 13 executable bytes$'
reject 'scan restricted' "restricted-scan line in census mode"

# -i -v adds per-extension sample addresses.
run 0 -i -v "$dir/census"
expect '^    AVX2 at 0x[0-9a-f]+$' "-v census sample line"

# -e is opt-in: without it no ENDBR64 pass runs, even on a CET-broken binary.
run 0 "$dir/cetbad"
reject 'ENDBR64' "ENDBR64 output without -e"
reject 'SHSTK' "SHSTK output without -e"

# Note present, entry point padded: clean, exit 0. cetgood declares both
# CET bits, the -fcf-protection=full shape.
run 0 -e "$dir/cetgood"
expect '^ENDBR64: IBT property note present; all 1 indirect branch targets land on ENDBR64$'
expect '^SHSTK: shadow stack declared alongside IBT$'

# Note present, entry point bare: a would-be #CP fault, printed without -v.
# cetbad declares IBT alone, so the SHSTK asymmetry is reported.
run 1 -e "$dir/cetbad"
expect '^indirect branch target missing ENDBR64: 0x[0-9a-f]+ \(entry point\)$'
expect '1 of 1 indirect branch targets missing ENDBR64'
expect '^SHSTK: no shadow stack in the property note despite IBT \(branch-only -fcf-protection\?\)$'

# Pads without the note: the poisoned-link verdict, one finding, exit 1.
# The SHSTK line states the bit's absence without claiming a loss (the
# pads evidence branch protection only).
run 1 -e "$dir/cetlost"
expect 'IBT annotation lost at link\?'
reject 'missing ENDBR64' "per-target miss on a fully padded binary"
expect '^SHSTK: no shadow stack in the property note$'

# No IBT declaration, no pads: not an IBT binary, no findings, and no
# SHSTK line either -- a binary with no CET story gets no CET output.
run 0 -e "$dir/cleandyn"
expect '^ENDBR64: no IBT in the property note and no ENDBR64 landing pads; not an IBT binary$'
reject 'SHSTK' "SHSTK line on a note-less non-CET binary"

# Return-only CET: shadow stack declared without IBT. Nothing to hold the
# instruction stream to (exit 0), but the asymmetry is reported.
run 0 -e "$dir/cetret"
expect '^ENDBR64: no IBT in the property note and no ENDBR64 landing pads; not an IBT binary$'
expect '^SHSTK: shadow stack declared without IBT \(SHSTK-only asm in the link, or return-only -fcf-protection\?\)$'

# Shared object: fn_bad is reachable through any caller's PLT and unpadded;
# the miss is named via the dynamic symbol table.
run 1 -e "$dir/cetso.so"
expect 'missing ENDBR64: 0x[0-9a-f]+ <fn_bad> \(exported function\)'
expect '1 of 2 indirect branch targets missing ENDBR64'

# Relocatable objects have no link-time target evidence: tool failure.
run 2 -e "$dir/clean.o"
expect 'requires a linked executable or shared object'

# A real binary must never be a tool failure (0 or 1 both fine).
"$X86LINT" "$X86LINT" >/dev/null 2>&1
rc=$?
if [ "$rc" -gt 1 ]; then
    fail "self-lint of $X86LINT exited $rc"
fi

# Tool-failure paths: usage, unknown flag, dangling or unknown -m value,
# unreadable file, non-ELF input.
run 2
expect 'usage:'
run 2 -x "$dir/finding"
expect 'usage:'
run 2 -m
expect 'usage:'
run 2 -m sse9 "$dir/finding"
expect 'usage:'
run 2 "$dir/does-not-exist"
run 2 "$dir/finding.s"
expect 'not an ELF file'

if [ "$status" -eq 0 ]; then
    echo "driver_test.sh: all driver checks passed"
fi
exit "$status"
