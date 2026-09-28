#!/bin/bash
# Run JetStream 3's shell driver in a SpiderMonkey shell built with
# tools/spidermonkey-jitdump.patch.
#
#   run-shell.sh OUTDIR JS JETSTREAM
#
# JS is the shell (dist/bin/js of a build that carries the patch); JETSTREAM a
# checkout of https://github.com/WebKit/JetStream. The shell writes
# OUTDIR/shell.jitdump.<pid>; the driver's JSON results go to OUTDIR/shell.log.
# SpiderMonkey takes the driver's flags directly after the script name (the
# "--" separator is a d8 and jsc thing). The two Worker workloads only run in
# a browser, so the shell covers 75 of JetStream 3's 77.
set -u

out=${1:?output directory}
js=${2:?js shell}
jetstream=${3:?JetStream checkout}

mkdir -p "$out"
out=$(cd "$out" && pwd)
rm -f "$out"/shell.jitdump.*
cd "$jetstream" || exit 2
start=$(date +%s)
X86LINT_JITDUMP="$out/shell.jitdump" "$js" cli.js --dump-json-results \
    > "$out/shell.log" 2>&1
status=$?
echo "js exited $status after $(( $(date +%s) - start )) s"
ls -la "$out"/shell.jitdump.* 2>/dev/null
exit "$status"
