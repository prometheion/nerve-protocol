#!/usr/bin/env bash
# The installed node on a real Linux, on this machine's kernel (issue #135):
# its keys in the system keyring, and folder mode as `nerve-run`. Run as root
# on a machine that may be changed and broken (a CI runner, a test VM). The
# keyring used to be refused below Linux 7.1, so the script refuses a kernel
# of 7.1 or later (the job would prove nothing new there) unless
# KEYRING_E2E_ANY_KERNEL=1. CI runs it on the Ubuntu 22.04 and 24.04 runners,
# whose kernels are 6.8 and 7.0 at the time of writing (GitHub's Azure kernels;
# neither is the 5.15 of a 22.04 install), both with Landlock: the case
# without Landlock, and the 5.15 kernel, are not tested there.
#
#   NERVE_NODE_REAL=<the nerve-node to install>
#   REAL_ACCOUNT_TEST=<the real_account test program>
#   .github/scripts/keyring-end-to-end.sh
#
# 1. crates/nerve-node/tests/real_account.rs, its first test: install, the
#    account nerve-run, folder grants as ACLs, uninstall. Then its provider
#    test: the owner's program attaches on the provider socket and its paths
#    count by the folders the owner gave alone (not nerve-run's own), a
#    folder nerve-run may not look into refuses its call, another account's
#    program is refused; uninstall. Then its test of the capabilities of
#    node.toml: they run as nerve-run, their arguments as data, held by
#    Landlock to the folders and the account's own; uninstall.
# 2. The keyring path as an owner takes it: install the node (with the
#    owner's sudo), run `setup` in a terminal and answer yes to the keyring,
#    which installs GNOME Keyring, a session for `nerve` and a login keyring
#    (crates/nerve-node/src/keyring_setup.rs); check that the keys moved out of
#    their files; restart the session of nerve, as a reboot does, and check
#    the node starts again with its keys; the second test of real_account.rs
#    pairs a center, restarts the node and runs a folder mode command as
#    nerve-run, which cannot reach the node's bus or keyring folder;
#    `uninstall --purge` takes it all away.
# The system-wide /etc/environment of the machine is given another user's
# runtime folder, bus and XDG folders first, as a runner image has: the
# session of nerve must keep its own.
#
# What this machine lacks compared to a desktop, and the node does not make
# up: nothing the node needs. A desktop's keyring is started by the user's
# graphical login and unlocked with its password; the node asks for neither.
# Its own step (apt, `loginctl enable-linger nerve`, the plain login keyring)
# gives `nerve` a systemd user session with a D-Bus that starts GNOME
# Keyring, exactly as on a server without a desktop. So nothing is set up
# here by hand but the owner.
set -euo pipefail

NODE=${NERVE_NODE_REAL:?the nerve-node to install}
TESTS=${REAL_ACCOUNT_TEST:?the real_account test program}
OWNER=${NERVE_REAL_OWNER:-nrvown}
PASS=ci-owner-pass
BIN=/usr/local/bin/nerve-node
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
OUT=$(mktemp -d)
# The program where the owner can run it: a checkout is often below a home
# that only its user may enter.
INSTALL_FROM=$(mktemp -d)
chmod 755 "$INSTALL_FROM"
install -m 755 "$NODE" "$INSTALL_FROM/nerve-node"
NODE=$INSTALL_FROM/nerve-node
# A folder every account can enter, and none the owner's.
cd /

step() { printf '\n==== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
as_owner() { runuser -u "$OWNER" -- "$BIN" "$@"; }
# Root through the owner's sudo, as a person installs and uninstalls.
owners_sudo() { printf '%s\n' "$PASS" | runuser -u "$OWNER" -- sudo -S -p '' "$@"; }
summary() { [ -n "${GITHUB_STEP_SUMMARY:-}" ] && printf '%s\n' "$*" >> "$GITHUB_STEP_SUMMARY" || true; }

diagnostics() {
  echo "---- diagnostics"
  systemctl status nerve-node --no-pager -l 2>&1 | tail -20 || true
  journalctl -u nerve-node --no-pager -n 60 2>&1 || true
  loginctl list-users 2>&1 || true
  nuid=$(id -u nerve 2>/dev/null || true)
  [ -z "$nuid" ] || systemctl status "user@$nuid.service" "user-runtime-dir@$nuid.service" --no-pager -l 2>&1 | tail -30 || true
  [ -z "$nuid" ] || journalctl -u "user@$nuid" --no-pager -n 40 2>&1 || true
  # What the session of nerve was given: its manager's environment, the
  # system-wide one every login reads, and this script's own session.
  [ -z "$nuid" ] || runuser -u nerve -- env -i "XDG_RUNTIME_DIR=/run/user/$nuid" systemctl --user show-environment 2>&1 | grep -E 'XDG|DBUS' || true
  grep -E 'XDG|DBUS' /etc/environment 2>&1 || true
  # The generator that keeps the session right at every start of its manager:
  # there, readable for nerve, and what it prints for nerve.
  ls -ld /etc/systemd /etc/systemd/user-environment-generators /etc/systemd/user-environment-generators/* 2>&1 || true
  runuser -u nerve -- /etc/systemd/user-environment-generators/99-nerve-session 2>&1 || true
  env | grep -E '^(XDG|DBUS)' || true
  ls -la /etc/nerve /etc/nerve/keys /var/lib/nerve /var/lib/nerve/state 2>&1 || true
  [ -z "$nuid" ] || ls -la "/run/user/$nuid" 2>&1 || true
}
cleanup() {
  code=$?
  [ "$code" = 0 ] || diagnostics
  # What a failed run leaves: the node, the accounts, the owner.
  if [ -e "$BIN" ]; then "$BIN" uninstall --purge >/dev/null 2>&1 || true; fi
  userdel -r "$OWNER" >/dev/null 2>&1 || true
  [ ! -e "$OUT/environment" ] || cp "$OUT/environment" /etc/environment
  rm -rf "$OUT" "$INSTALL_FROM"
  exit "$code"
}
trap cleanup EXIT

step "This kernel"
KERNEL=$(uname -r)
LSM=$(cat /sys/kernel/security/lsm 2>/dev/null || echo "(no /sys/kernel/security/lsm)")
case ",$LSM," in *,landlock,*) LANDLOCK=yes ;; *) LANDLOCK=no ;; esac
echo "kernel:   $KERNEL"
echo "LSMs:     $LSM"
echo "Landlock: $LANDLOCK"
grep -E '^(PRETTY_NAME)=' /etc/os-release || true
summary "- kernel \`$KERNEL\`, Landlock: $LANDLOCK (\`$LSM\`)"
# Below 7.1 the keyring used to be refused; from 7.1 on this run no longer
# shows that it works there. The runner image has moved on: say so, loudly.
KMAJOR=${KERNEL%%.*}
KMINOR=${KERNEL#*.}; KMINOR=${KMINOR%%[!0-9]*}
if [ "$KMAJOR" -gt 7 ] || { [ "$KMAJOR" -eq 7 ] && [ "$KMINOR" -ge 1 ]; }; then
  msg="the kernel is $KERNEL, 7.1 or later: this job no longer tests a kernel below 7.1 (issue #135); it needs an older machine"
  echo "::error::$msg"
  summary "- **$msg**"
  [ "${KEYRING_E2E_ANY_KERNEL:-}" = 1 ] || fail "$msg (KEYRING_E2E_ANY_KERNEL=1 runs it anyway)"
fi

step "The owner"
# Not a system account: it has a home and a password, and is in sudo, as the
# person who installs the node is.
id "$OWNER" >/dev/null 2>&1 && userdel -r "$OWNER" >/dev/null 2>&1 || true
useradd --create-home --shell /bin/bash "$OWNER"
chmod 750 "/home/$OWNER"
usermod -aG sudo "$OWNER"
printf '%s:%s\n' "$OWNER" "$PASS" | chpasswd

step "1. real_account.rs: install, nerve-run, folder grants, uninstall"
NERVE_NODE_REAL=$NODE NERVE_REAL_OWNER=$OWNER \
  "$TESTS" --ignored --exact --nocapture folder_mode_runs_as_nerve_run_on_this_machine
# The test changes the owner's password.
printf '%s:%s\n' "$OWNER" "$PASS" | chpasswd
[ ! -e "$BIN" ] || fail "the test left the node installed"

step "1b. real_account.rs: the owner's program as a provider, held to the folders"
# Another account, whose program the provider socket refuses.
OTHER=nrvother
id "$OTHER" >/dev/null 2>&1 && userdel -r "$OTHER" >/dev/null 2>&1 || true
useradd --create-home --shell /bin/bash "$OTHER"
NERVE_NODE_REAL=$NODE NERVE_REAL_OWNER=$OWNER NERVE_REAL_OTHER=$OTHER \
  "$TESTS" --ignored --exact --nocapture the_owners_program_attaches_and_is_held_to_the_folders
userdel -r "$OTHER" >/dev/null 2>&1 || true
[ ! -e "$BIN" ] || fail "the test left the node installed"

step "1c. real_account.rs: capabilities of node.toml, run as nerve-run under Landlock"
NERVE_NODE_REAL=$NODE NERVE_REAL_OWNER=$OWNER \
  "$TESTS" --ignored --exact --nocapture a_config_capability_runs_as_nerve_run_in_a_folder_pairing
[ ! -e "$BIN" ] || fail "the test left the node installed"

step "2. Install the node as the owner"
owners_sudo "$NODE" install
as_owner status | tee "$OUT/status-files"
grep -q 'daemon: running' "$OUT/status-files"
as_owner config get machine.secret_storage | tee "$OUT/storage"
grep -q 'file' "$OUT/storage"
# The keys start in their files; setup moves them.
[ -f /var/lib/nerve/state/config.key ] || fail "no config.key before setup"
NERVE_UID=$(id -u nerve)
[ ! -e "/run/user/$NERVE_UID/bus" ] || fail "nerve has a session bus already"

step "2b. A system-wide environment that names another user's session"
# What a runner image's /etc/environment does (it names the runner's own
# XDG_RUNTIME_DIR and XDG_CONFIG_HOME); here the owner's, with its data and
# cache folders too: GNOME Keyring keeps its keyrings in XDG_DATA_HOME.
cp /etc/environment "$OUT/environment"
OWNER_UID=$(id -u "$OWNER")
cat >> /etc/environment <<ENV
XDG_RUNTIME_DIR=/run/user/$OWNER_UID
DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$OWNER_UID/bus
XDG_CONFIG_HOME=/home/$OWNER/.config
XDG_DATA_HOME=/home/$OWNER/.local/share
XDG_CACHE_HOME=/home/$OWNER/.cache
XDG_STATE_HOME=/home/$OWNER/.local/state
ENV
# secret-tool, to ask nerve's keyring as any program of nerve would.
if ! command -v secret-tool >/dev/null; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libsecret-tools >/dev/null
fi

step "3. setup at a terminal, yes to the keyring"
# The questions: the node's name (Enter), where the keys go (keyring), the
# offer to install a keyring (y), a pairing link (Enter).
python3 "$HERE/pty-answers.py" \
  'Name of this node=' \
  'Where the node keeps its keys=keyring' \
  'Install it now=y' \
  'Pairing link=' \
  -- runuser -u "$OWNER" -- "$BIN" setup | tee "$OUT/setup"
grep -q 'the system keyring answers for nerve' "$OUT/setup" || fail "setup did not install a keyring that answers"
grep -q "the node's keys are in the system keyring now" "$OUT/setup" || fail "setup did not move the keys"

step "4. The keys are in the keyring"
as_owner --json config get machine.secret_storage | tee "$OUT/storage"
grep -q '"keyring"' "$OUT/storage"
grep -q '"usable": *true' "$OUT/storage" || fail "the node says the keyring is not usable"
[ ! -e /var/lib/nerve/state/config.key ] || fail "config.key is still a file"
[ -z "$(find /etc/nerve/keys -name '*.key' 2>/dev/null)" ] || fail "a node key is still a file"
[ -S "/run/user/$NERVE_UID/bus" ] || fail "nerve has no session bus"
# GNOME Keyring holds them, as nerve's own secret service.
ls -la /var/lib/nerve/.local/share/keyrings/
[ -f /var/lib/nerve/.local/share/keyrings/login.keyring ] || fail "no login keyring in nerve's home"
# nerve's session got its own folders although /etc/environment names the
# owner's, and any program of nerve finds the keyring there.
nerve_env() { runuser -u nerve -- env -i HOME=/var/lib/nerve "XDG_RUNTIME_DIR=/run/user/$NERVE_UID" "$@"; }
nerve_env systemctl --user show-environment | tee "$OUT/session-env"
grep -qx "XDG_RUNTIME_DIR=/run/user/$NERVE_UID" "$OUT/session-env" || fail "the session of nerve has another runtime folder"
grep -qx "XDG_DATA_HOME=/var/lib/nerve/.local/share" "$OUT/session-env" || fail "the session of nerve has another data folder"
printf 'a secret' | nerve_env secret-tool store --label=nerve-ci nerve-ci probe || fail "secret-tool cannot store in the keyring of nerve"
[ "$(nerve_env secret-tool lookup nerve-ci probe)" = "a secret" ] || fail "secret-tool does not find what it stored"
nerve_env secret-tool clear nerve-ci probe

step "5. The node starts again with the keys from the keyring"
systemctl restart nerve-node
for _ in $(seq 1 60); do
  as_owner status 2>/dev/null | grep -q 'daemon: running' && break
  sleep 1
done
as_owner status | tee "$OUT/status-keyring"
grep -q 'daemon: running' "$OUT/status-keyring" || fail "the node does not come up with its keys in the keyring"
if grep -q 'folder mode runs no command' "$OUT/status-keyring"; then fail "folder mode is refused with the keys in the keyring"; fi
# What status says in JSON: the node found its keyring and no folder mode
# command is held back (the refusal this job exists to keep away).
as_owner --json status | tee "$OUT/status-json"
python3 - "$OUT/status-json" <<'PY' || fail "status does not say the node runs with its keys in the keyring"
import json, sys
text = open(sys.argv[1]).read()
status = json.loads(text[text.index("{"):])
status = status.get("data", status)
assert status["keyring_failed"] is False, status
assert "folder_commands_off" not in status or status["folder_commands_off"] is None, status
PY

step "5b. The session of nerve starts again, as at a reboot"
# Its service manager reads /etc/environment again. The generator setup wrote
# gives the session its own folders again, and the keyring and the node find
# them as before. The generator is the one thing this step may not get right
# yet in every image: a failure is noted, the next step tests the node's own
# repair, and the script fails at its end.
GENERATOR_FAILED=
# A reboot stops the session's manager and, much later, starts a new one.
# `systemctl restart user@N` starts the new one in the same second, and on
# systemd 249 (Ubuntu 22.04) that fails with status 219/CGROUP while the old
# cgroup is still being removed (nothing of nerve-node's, and before any
# generator runs). So: stop, wait until the cgroup is gone, start, and try
# the start again a few times.
restart_session() {
  local cg="/sys/fs/cgroup/user.slice/user-$NERVE_UID.slice/user@$NERVE_UID.service"
  systemctl stop "user@$NERVE_UID.service"
  for _ in $(seq 1 60); do [ -e "$cg" ] || break; sleep 0.5; done
  local started=
  for _ in 1 2 3 4 5; do
    if systemctl start "user@$NERVE_UID.service"; then started=1; break; fi
    systemctl status "user@$NERVE_UID.service" --no-pager -l 2>&1 | tail -15 || true
    sleep 3
  done
  [ -n "$started" ] || fail "the session of nerve does not start again"
  for _ in $(seq 1 60); do [ -S "/run/user/$NERVE_UID/bus" ] && break; sleep 1; done
  [ -S "/run/user/$NERVE_UID/bus" ] || fail "nerve has no session bus after its session started again"
  nerve_env systemctl --user show-environment | tee "$1"
}
restart_session "$OUT/session-env2"
if ! grep -qx "XDG_RUNTIME_DIR=/run/user/$NERVE_UID" "$OUT/session-env2" ||
   ! grep -qx "XDG_DATA_HOME=/var/lib/nerve/.local/share" "$OUT/session-env2"; then
  GENERATOR_FAILED=1
  echo "::error::the generator did not give the restarted session of nerve its own folders"
  ls -ld /etc/systemd /etc/systemd/user-environment-generators /etc/systemd/user-environment-generators/* 2>&1 || true
  runuser -u nerve -- /etc/systemd/user-environment-generators/99-nerve-session 2>&1 || true
fi
node_runs_with_keys() {
  systemctl restart nerve-node
  for _ in $(seq 1 90); do
    as_owner status 2>/dev/null | grep -q 'daemon: running' && break
    sleep 1
  done
  as_owner --json status | tee "$OUT/status-json2"
  python3 - "$OUT/status-json2" <<'PY' || fail "the node does not run with its keys in the keyring ($1)"
import json, sys
text = open(sys.argv[1]).read()
status = json.loads(text[text.index("{"):])
status = status.get("data", status)
assert status["keyring_failed"] is False, status
PY
  nerve_env systemctl --user show-environment | tee "$OUT/session-env-node"
  grep -qx "XDG_RUNTIME_DIR=/run/user/$NERVE_UID" "$OUT/session-env-node" || fail "the session of nerve has another runtime folder ($1)"
  grep -qx "XDG_DATA_HOME=/var/lib/nerve/.local/share" "$OUT/session-env-node" || fail "the session of nerve has another data folder ($1)"
  printf 'a secret' | nerve_env secret-tool store --label=nerve-ci nerve-ci probe || fail "secret-tool cannot store ($1)"
  nerve_env secret-tool clear nerve-ci probe
}
node_runs_with_keys "after the session started again"

step "5c. Without the generator the node sets the session right when it starts"
GENERATOR=/etc/systemd/user-environment-generators/99-nerve-session
cp -p "$GENERATOR" "$OUT/generator"
rm -f "$GENERATOR"
restart_session "$OUT/session-env3"
# The test is a test only if the session is wrong now.
grep -qx "XDG_DATA_HOME=/home/$OWNER/.local/share" "$OUT/session-env3" || fail "the session of nerve is not wrong without the generator, so this step tests nothing"
node_runs_with_keys "the node's own repair"
# Back in its place, so that step 7 shows that uninstall takes it away.
install -m 755 "$OUT/generator" "$GENERATOR"
[ -z "$GENERATOR_FAILED" ] || fail "the generator did not keep the session of nerve right (see above)"

step "6. real_account.rs: a center, a restart, a folder mode command as nerve-run"
NERVE_REAL_KEYRING=1 NERVE_REAL_OWNER=$OWNER \
  "$TESTS" --ignored --exact --nocapture the_installed_node_with_its_keys_in_the_keyring_runs_folder_commands_as_nerve_run

step "7. uninstall --purge"
[ -e "$GENERATOR" ] || fail "the generator is not there before uninstall, so its removal would show nothing"
owners_sudo "$BIN" uninstall --purge | tee "$OUT/uninstall"
if id nerve >/dev/null 2>&1; then fail "the account nerve is still there"; fi
if id nerve-run >/dev/null 2>&1; then fail "the account nerve-run is still there"; fi
[ ! -e "$BIN" ] || fail "the program is still installed"
[ ! -e /etc/systemd/system/nerve-node.service ] || fail "the unit is still there"
[ ! -e /var/lib/nerve ] || fail "the node's home is still there"
[ ! -e "/run/user/$NERVE_UID" ] || fail "nerve's session is still there"
[ ! -e "$GENERATOR" ] || fail "uninstall left the session generator"

step "Done"
summary "- the keyring path end to end: passed"
