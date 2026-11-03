#!/usr/bin/env bash
# The center installed as a service on a real Linux (docs/user/center.md, "Run
# it as a service"): `install` makes the user nerve-center, its state folder,
# the settings file with a harness token, the program and the unit, and starts
# it; a harness reaches MCP over HTTP with that token and with no other; the
# unit holds the center as the page says; `install` again keeps the token; an
# `update --from` another build replaces the program and keeps the state; a
# plain `uninstall` keeps the state and the settings for a later `install`,
# which brings the same token back; `uninstall --purge` leaves nothing. Run as
# root on a machine that may be changed and broken (a CI runner, a test VM).
#
#   NERVE_CENTER_REAL=<the nerve-center to install>
#   .github/scripts/center-service-end-to-end.sh
set -euo pipefail

CENTER=${NERVE_CENTER_REAL:?the nerve-center to install}
BIN=/usr/local/bin/nerve-center
UNIT=/etc/systemd/system/nerve-center.service
ENV_FILE=/etc/nerve-center/center.env
STATE=/var/lib/nerve-center
MCP=http://127.0.0.1:7481/mcp
OUT=$(mktemp -d)
FROM=$(mktemp -d)
chmod 755 "$FROM"
install -m 755 "$CENTER" "$FROM/nerve-center"
CENTER=$FROM/nerve-center
cd /

step() { printf '\n==== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
summary() { [ -n "${GITHUB_STEP_SUMMARY:-}" ] && printf '%s\n' "$*" >> "$GITHUB_STEP_SUMMARY" || true; }

cleanup() {
  code=$?
  if [ "$code" != 0 ]; then
    echo "---- diagnostics"
    systemctl status nerve-center --no-pager -l 2>&1 | tail -20 || true
    journalctl -u nerve-center --no-pager -n 60 2>&1 || true
    ls -la /etc/nerve-center "$STATE" 2>&1 || true
  fi
  if [ -e "$BIN" ]; then "$BIN" uninstall --purge >/dev/null 2>&1 || true; fi
  rm -rf "$OUT" "$FROM"
  exit "$code"
}
trap cleanup EXIT

# One JSON-RPC message to the HTTP endpoint: the answer's body in $OUT/body,
# its headers in $OUT/headers, and the status code printed.
mcp() {
  local token=$1 session=$2 body=$3
  local args=(-sS --max-time 20 -o "$OUT/body" -D "$OUT/headers" -w '%{http_code}'
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream')
  [ -z "$token" ] || args+=(-H "Authorization: Bearer $token")
  [ -z "$session" ] || args+=(-H "Mcp-Session-Id: $session")
  printf '%s' "$body" | curl "${args[@]}" --data @- "$MCP"
}
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"ci","version":"0"}}}'

until_up() {
  for _ in $(seq 1 60); do
    code=$(mcp "$1" "" "$INIT" 2>/dev/null) || code=
    [ "$code" = 200 ] && return 0
    sleep 1
  done
  fail "the center does not answer on $MCP"
}

token() { sed -n 's/^NERVE_HARNESS_TOKEN=//p' "$ENV_FILE"; }

[ ! -e "$UNIT" ] || fail "the center is installed here already"

step "1. install"
"$CENTER" install | tee "$OUT/install"
id nerve-center
[ "$(id -u nerve-center)" -lt 1000 ] || fail "nerve-center is no system user"
[ "$(getent passwd nerve-center | cut -d: -f7)" != /bin/bash ] || fail "nerve-center may log in"
systemctl is-active --quiet nerve-center || fail "the service does not run"
systemctl is-enabled --quiet nerve-center || fail "the service is not enabled"
[ "$(stat -c '%U %a' "$STATE")" = "nerve-center 700" ] || fail "the state folder is $(stat -c '%U %a' "$STATE")"
[ "$(stat -c '%U %a' "$ENV_FILE")" = "root 600" ] || fail "the settings file is $(stat -c '%U %a' "$ENV_FILE")"
cmp -s "$CENTER" "$BIN" || fail "the program in place is not the one installed"
TOKEN=$(token)
[ -n "$TOKEN" ] || fail "the settings file has no harness token"

step "2. MCP over HTTP with the harness token, and with no other"
until_up "$TOKEN"
code=$(mcp "$TOKEN" "" "$INIT")
[ "$code" = 200 ] || fail "initialize answered $code"
SESSION=$(sed -n 's/^[Mm]cp-[Ss]ession-[Ii]d: *//p' "$OUT/headers" | tr -d '\r')
[ -n "$SESSION" ] || fail "initialize gave no session"
grep -q '"serverInfo"' "$OUT/body" || fail "initialize: $(cat "$OUT/body")"
mcp "$TOKEN" "$SESSION" '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null
code=$(mcp "$TOKEN" "$SESSION" '{"jsonrpc":"2.0","id":2,"method":"tools/list"}')
[ "$code" = 200 ] || fail "tools/list answered $code"
python3 - "$OUT/body" <<'PY' || fail "tools/list does not give list and execute: $(cat "$OUT/body")"
import json, sys
tools = sorted(t["name"] for t in json.load(open(sys.argv[1]))["result"]["tools"])
assert tools == ["execute", "list"], tools
PY
code=$(mcp "$TOKEN" "$SESSION" '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list","arguments":{}}}')
[ "$code" = 200 ] || fail "list answered $code"
grep -q '"result"' "$OUT/body" || fail "list: $(cat "$OUT/body")"
code=$(mcp "not-the-token" "" "$INIT") || true
[ "$code" = 401 ] || fail "a wrong token got $code, not 401"
code=$(mcp "" "" "$INIT") || true
[ "$code" = 401 ] || fail "no token got $code, not 401"
# The node port for every address, the web UI and MCP on loopback only, as
# the defaults say, and nothing else.
ss -Hltnp | grep '"nerve-center"' | awk '{print $4}' | sort | tee "$OUT/listen"
grep -qxE '(0\.0\.0\.0|\*|\[::\]):7443' "$OUT/listen" || fail "no node port 7443"
grep -qx '127.0.0.1:7480' "$OUT/listen" || fail "no web UI on 127.0.0.1:7480"
grep -qx '127.0.0.1:7481' "$OUT/listen" || fail "no MCP endpoint on 127.0.0.1:7481"
[ "$(grep -vcxE '(0\.0\.0\.0|\*|\[::\]):7443|127\.0\.0\.1:748[01]' "$OUT/listen")" = 0 ] \
  || fail "the center listens where the defaults do not say"

step "3. The unit holds the center"
systemctl show nerve-center -p User -p NoNewPrivileges -p ProtectHome -p PrivateDevices \
  -p ProtectSystem -p CapabilityBoundingSet -p RestrictNamespaces | tee "$OUT/unit"
grep -qx 'User=nerve-center' "$OUT/unit" || fail "the service does not run as nerve-center"
grep -qx 'NoNewPrivileges=yes' "$OUT/unit" || fail "the service may gain privileges"
grep -qx 'ProtectHome=yes' "$OUT/unit" || fail "the service sees the home folders"
grep -qx 'PrivateDevices=yes' "$OUT/unit" || fail "the service sees the devices"
grep -qx 'ProtectSystem=strict' "$OUT/unit" || fail "the service may write the system"
grep -qx 'CapabilityBoundingSet=' "$OUT/unit" || fail "the service keeps capabilities"
grep -qx 'RestrictNamespaces=yes' "$OUT/unit" || fail "the service may make namespaces"
pid=$(systemctl show nerve-center -p MainPID --value)
[ "$(stat -c %U "/proc/$pid")" = nerve-center ] || fail "the center's process is not nerve-center's"

step "4. install again keeps the token"
"$CENTER" install | tee "$OUT/install2"
[ "$(token)" = "$TOKEN" ] || fail "a second install changed the harness token"
until_up "$TOKEN"

step "5. update --from another build"
"$BIN" update --from "$CENTER" | tee "$OUT/update-same"
grep -q 'nothing to update' "$OUT/update-same" || fail "an update to the same program did something"
cp "$CENTER" "$OUT/nerve-center-next"
printf '\n' >> "$OUT/nerve-center-next"
chmod 755 "$OUT/nerve-center-next"
"$BIN" update --from "$OUT/nerve-center-next" | tee "$OUT/update"
cmp -s "$OUT/nerve-center-next" "$BIN" || fail "update did not put the new program in place"
systemctl is-active --quiet nerve-center || fail "the service does not run after the update"
[ "$(token)" = "$TOKEN" ] || fail "the update changed the settings"
until_up "$TOKEN"

step "6. uninstall keeps the state, install brings it back"
"$BIN" uninstall | tee "$OUT/uninstall"
[ ! -e "$BIN" ] || fail "the program is still there"
[ ! -e "$UNIT" ] || fail "the unit is still there"
if id nerve-center >/dev/null 2>&1; then fail "the user nerve-center is still there"; fi
[ "$(stat -c %U "$STATE")" = root ] || fail "the kept state folder is not root's"
[ "$(stat -c %U "$ENV_FILE")" = root ] || fail "the kept settings are not root's"
"$CENTER" install | tee "$OUT/install3"
[ "$(token)" = "$TOKEN" ] || fail "install after uninstall has another token"
[ "$(stat -c %U "$STATE")" = nerve-center ] || fail "install did not take the kept state folder up again"
until_up "$TOKEN"

step "7. uninstall --purge"
"$BIN" uninstall --purge | tee "$OUT/purge"
for p in "$BIN" "$UNIT" "$STATE" /etc/nerve-center; do
  [ ! -e "$p" ] || fail "$p is still there"
done
if id nerve-center >/dev/null 2>&1; then fail "the user nerve-center is still there"; fi
if ss -Hltnp | grep -q '"nerve-center"'; then fail "something of the center still listens"; fi

step "Done"
summary "- the center as a service end to end: passed"
