#!/usr/bin/env bash
# A machine of another distribution for the install test, where GitHub has no
# runner of it: a container of <image> with systemd as its init, as on a
# server of that distribution, with what such a server has and the tests
# use (sudo, polkit, a session bus for user sessions, ACL tools, python3,
# curl, ss). It shares the runner's kernel. Privileged, with a cgroup
# namespace of its own: systemd manages its cgroups, the node gets its
# service's cgroup delegated, and Landlock is not filtered away. The
# workspace and the runner's temp folder are mounted at the same paths, so
# as-root.sh runs the same command lines there as on a runner. Debian and
# Ubuntu images only (apt).
#
#   systemd-container.sh <image> <name>
set -euo pipefail

IMAGE=${1:?the image}
NAME=${2:?the name of the container}

docker run --detach --name "$NAME" --hostname "$NAME" \
  --privileged --cgroupns=private \
  --tmpfs /run --tmpfs /run/lock \
  --volume "$GITHUB_WORKSPACE:$GITHUB_WORKSPACE:ro" \
  --volume "$RUNNER_TEMP:$RUNNER_TEMP" \
  "$IMAGE" bash -c '
    set -e
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends \
      systemd systemd-sysv dbus dbus-user-session libpam-systemd polkitd pkexec \
      sudo acl python3 curl ca-certificates iproute2 file
    # A server has it, and the keyring test changes it.
    touch /etc/environment
    exec /sbin/init'

# The packages first, then systemd's start: up to five minutes.
for _ in $(seq 1 300); do
  if [ "$(docker inspect -f '{{.State.Running}}' "$NAME")" != true ]; then
    docker logs "$NAME" 2>&1 | tail -n 50
    echo "the container $NAME stopped" >&2
    exit 1
  fi
  state=$(docker exec "$NAME" systemctl is-system-running 2>/dev/null || true)
  case $state in
    running | degraded) break ;;
  esac
  sleep 1
done
echo "systemd in $NAME: ${state:-not up}"
case $state in
  running | degraded) ;;
  *)
    docker logs "$NAME" 2>&1 | tail -n 50
    exit 1
    ;;
esac
# What did not start, for the log; a container lacks some of a machine's units.
docker exec "$NAME" systemctl --failed --no-pager || true
docker exec "$NAME" systemctl is-active systemd-logind dbus
echo "NERVE_CI_CONTAINER=$NAME" >> "$GITHUB_ENV"
