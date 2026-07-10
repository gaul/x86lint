#!/bin/sh
# Smoke test for the ELF driver (main.c): section walk, symbol-table scan
# restriction and its -a override, -v per-finding lines with section-relative
# offsets, the summary tail, and the grep-convention exit codes (0 clean scan,
# 1 opportunities found, 2 tool failure). Fixtures are tiny static ELFs
# assembled with the system toolchain at run time; instructions are spelled
# as .byte so the assembler cannot pick different encodings.
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

# A NOT/AND pair that folds to ANDN: a finding only under -m bmi1 (the ret
# kills the flags the fold's PF gate watches).
cat >"$dir/bmi.s" <<'EOF'
    .text
    .globl _start
    .type _start, @function
_start:
    .byte 0xf7, 0xd0                    # not eax
    .byte 0x21, 0xc8                    # and eax, ecx
    .byte 0xc3                          # ret
    .size _start, . - _start
    .section .note.GNU-stack, "", @progbits
EOF

for f in finding clean bmi; do
    if ! cc -nostdlib -static -Wl,--build-id=none \
            -o "$dir/$f" "$dir/$f.s"; then
        echo "driver_test.sh: fixture build failed" >&2
        exit 2
    fi
done

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

# Extension-gated checks: the NOT/AND pair is clean at baseline and a missing
# ANDN under -m bmi1.
run 0 "$dir/bmi"
reject 'missing ANDN' "BMI finding without -m"
run 1 -m bmi1 "$dir/bmi"
expect '^ +1 +missing ANDN$' "count of 1 for missing ANDN under -m bmi1"

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
