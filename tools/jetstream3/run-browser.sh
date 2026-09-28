#!/bin/bash
# Run JetStream 3 in a headless Firefox built with tools/spidermonkey-jitdump.patch
# and collect one JIT dump per process.
#
#   run-browser.sh OUTDIR FIREFOX JETSTREAM
#
# FIREFOX is the browser binary (dist/bin/firefox of a build that carries the
# patch); JETSTREAM a checkout of https://github.com/WebKit/JetStream. The
# checkout is served on loopback by server.py, opened with
# ?startAutomatically=true&report=true, and the POST /report the driver makes
# when the last workload finishes is the completion signal. Every process
# that linked JIT code leaves OUTDIR/firefox.jitdump.<pid>; OUTDIR/ps.log maps
# each pid to its process type so the benchmark's tab can be told from the
# parent, and OUTDIR/report.json holds the scores. Then:
#
#   python3 tools/jitdumpstats.py --out OUTDIR/analysis --ps OUTDIR/ps.log \
#       OUTDIR/firefox.jitdump.*
#
# Runs inside a network-namespaced sandbox as long as loopback is up. Takes
# about two minutes on a 2025 desktop; TIMEOUT (seconds) bounds the wait.
set -u

here=$(cd "$(dirname "$0")" && pwd)
out=${1:?output directory}
firefox=${2:?firefox binary}
jetstream=${3:?JetStream checkout}
timeout_s=${TIMEOUT:-2400}

mkdir -p "$out/profile" "$out/home"
rm -f "$out"/firefox.jitdump.* "$out/report.json" "$out/server.log" \
    "$out/server.port" "$out/ps.log"

cat > "$out/profile/user.js" <<'EOF'
// The content-process sandbox would refuse the dump file's open(2).
user_pref("security.sandbox.content.level", 0);
// Loopback only, and never a system proxy.
user_pref("network.proxy.type", 0);
// A fresh profile's first-run pages and update chatter, off.
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("startup.homepage_welcome_url", "");
user_pref("startup.homepage_welcome_url.additional", "");
user_pref("browser.aboutwelcome.enabled", false);
user_pref("browser.newtabpage.enabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("toolkit.telemetry.enabled", false);
user_pref("app.update.disabledForTesting", true);
user_pref("app.normandy.enabled", false);
user_pref("extensions.blocklist.enabled", false);
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);
user_pref("browser.search.update", false);
user_pref("network.captive-portal-service.enabled", false);
user_pref("network.connectivity-service.enabled", false);
user_pref("services.settings.server", "http://127.0.0.1:1/");
EOF

python3 "$here/server.py" --dir "$jetstream" --port 0 \
    --report "$out/report.json" --log "$out/server.log" > "$out/server.port" &
server=$!
for _ in $(seq 20); do
    [ -s "$out/server.port" ] && break
    sleep 0.5
done
port=$(cat "$out/server.port")
if [ -z "$port" ]; then
    echo "run-browser.sh: the server did not start" >&2
    kill "$server" 2>/dev/null
    exit 2
fi
url="http://127.0.0.1:$port/index.html?startAutomatically=true&report=true"
echo "serving JetStream 3 at $url"

# A private HOME keeps the run off the user's own profiles and caches, and
# works where the real one is not readable.
HOME="$out/home" \
X86LINT_JITDUMP="$out/firefox.jitdump" MOZ_DISABLE_CONTENT_SANDBOX=1 \
MOZ_HEADLESS=1 \
    "$firefox" --headless --no-remote --profile "$out/profile" "$url" \
    > "$out/firefox.log" 2>&1 &
ff=$!

start=$(date +%s)
status=0
while kill -0 "$ff" 2>/dev/null; do
    # Record pid -> process type while the processes still exist.
    ps -e -o pid=,args= | grep -F -- "$firefox" | grep -v -F 'grep -F' \
        >> "$out/ps.log"
    if [ -s "$out/report.json" ]; then
        echo "report received after $(( $(date +%s) - start )) s"
        break
    fi
    if [ $(( $(date +%s) - start )) -ge "$timeout_s" ]; then
        echo "run-browser.sh: no report after $timeout_s s" >&2
        status=1
        break
    fi
    sleep 2
done
if ! kill -0 "$ff" 2>/dev/null; then
    echo "run-browser.sh: firefox exited on its own" >&2
    status=1
fi
kill "$ff" 2>/dev/null
wait "$ff" 2>/dev/null
kill "$server" 2>/dev/null
sort -u -o "$out/ps.log" "$out/ps.log"
ls -la "$out"/firefox.jitdump.* 2>/dev/null
exit "$status"
