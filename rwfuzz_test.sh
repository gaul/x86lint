#!/usr/bin/env bash
#
# Run x86lint's advice: tools/rwfuzz applies each finding's rewrite to random
# programs and runs original and rewrite side by side (see its header). `all`
# plants every family and must run findings of at least RWFUZZ_MIN_KINDS
# names; every other mode, and `all` under the two other tuning targets that
# enable rows of their own, then run a tenth of the programs. A run whose
# control arm applied refused rewrites must also see some of them change a
# result: a harness that had stopped seeing differences would pass everything
# else. Exit status: 0 passed, 1 a check failed, 2 the test could not run
# (no rwfuzz binary, not an x86-64 host).
#
#   RWFUZZ_PROGRAMS   programs for `all` (default 10000)
#   RWFUZZ_SEED       seed (default 0: the same programs every run)
#   RWFUZZ_MIN_KINDS  the floor on the kinds `all` runs (default 60)
#   RWFUZZ_CC         the compiler driver rwfuzz assembles with (default cc)

set -eu

cd "$(dirname "$0")"
RWFUZZ=./tools/rwfuzz

case "$(uname -m)" in
    x86_64|amd64) ;;
    *)
        echo "rwfuzz_test: the programs run natively, and this host is $(uname -m)" >&2
        exit 2
        ;;
esac
if [ ! -x "$RWFUZZ" ]; then
    echo "rwfuzz_test: $RWFUZZ not found; run 'make tools/rwfuzz' first" >&2
    exit 2
fi

PROGRAMS=${RWFUZZ_PROGRAMS:-10000}
SEED=${RWFUZZ_SEED:-0}
MIN_KINDS=${RWFUZZ_MIN_KINDS:-60}
SHORT=$((PROGRAMS / 10 > 0 ? PROGRAMS / 10 : 1))
MODES=$("$RWFUZZ" 2>&1 | sed -n 's/^modes: //p' || true)
if [ -z "$MODES" ]; then
    echo "rwfuzz_test: $RWFUZZ lists no modes" >&2
    exit 2
fi

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

FAIL=0
run_mode() {
    local cmd=("$RWFUZZ" -s "$SEED" "$@")
    echo "== ${cmd[*]}"
    set +e
    "${cmd[@]}" >"$T/out" 2>&1
    local rc=$?
    set -e
    cat "$T/out"
    if [ "$rc" -ne 0 ]; then
        echo "  FAIL    ${*}: rwfuzz exited $rc"
        FAIL=1
        return
    fi
    local tried changed
    tried=$(sed -n 's/^  control: \([0-9][0-9]*\) refused.*/\1/p' "$T/out")
    changed=$(sed -n 's/^  control: .*, \([0-9][0-9]*\) changed the result$/\1/p' "$T/out")
    if [ -n "$tried" ] && [ "$tried" -gt 0 ] && [ "$changed" -eq 0 ]; then
        echo "  FAIL    ${*}: no refused rewrite changed a result"
        FAIL=1
    fi
}

run_mode -n "$PROGRAMS" -k "$MIN_KINDS" all
for mode in $MODES; do
    if [ "$mode" != all ]; then
        run_mode -n "$SHORT" "$mode"
    fi
done
for target in skylake silvermont; do
    run_mode -n "$SHORT" -t "$target" all
done

if [ "$FAIL" -ne 0 ]; then
    echo "rwfuzz: FAILED (replay: RWFUZZ_SEED=$SEED RWFUZZ_PROGRAMS=$PROGRAMS $0)"
    exit 1
fi
echo "rwfuzz: passed"
