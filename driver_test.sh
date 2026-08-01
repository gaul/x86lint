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

# CET fixtures for -e. The .note.gnu.property section is the same note gcc
# emits under -fcf-protection (the linker merges it through to the output):
# cetgood declares IBT and pads its entry point, cetbad declares IBT but
# does not pad, cetlost pads without declaring (the linker ANDs the note
# across inputs, so this is what a link poisoned by one non-CET object
# leaves), and cetso is a shared object whose exported fn_bad lacks its pad.
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
    .long 1                             # GNU_PROPERTY_X86_FEATURE_1_IBT
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

for f in finding clean bmi notrack; do
    if ! cc -nostdlib -static -Wl,--build-id=none \
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
for f in cetgood cetbad cetlost; do
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

# -e is opt-in: without it no ENDBR64 pass runs, even on a CET-broken binary.
run 0 "$dir/cetbad"
reject 'ENDBR64' "ENDBR64 output without -e"

# Note present, entry point padded: clean, exit 0.
run 0 -e "$dir/cetgood"
expect '^ENDBR64: IBT property note present; all 1 indirect branch targets land on ENDBR64$'

# Note present, entry point bare: a would-be #CP fault, printed without -v.
run 1 -e "$dir/cetbad"
expect '^indirect branch target missing ENDBR64: 0x[0-9a-f]+ \(entry point\)$'
expect '1 of 1 indirect branch targets missing ENDBR64'

# Pads without the note: the poisoned-link verdict, one finding, exit 1.
run 1 -e "$dir/cetlost"
expect 'IBT annotation lost at link\?'
reject 'missing ENDBR64' "per-target miss on a fully padded binary"

# No IBT declaration, no pads: not an IBT binary, no findings.
run 0 -e "$dir/cleandyn"
expect '^ENDBR64: no IBT in the property note and no ENDBR64 landing pads; not an IBT binary$'

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
