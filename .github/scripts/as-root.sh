#!/usr/bin/env bash
# Runs a command as root on the machine of a CI job: the runner itself
# (through sudo), or the container that NERVE_CI_CONTAINER names
# (systemd-container.sh made it, with the workspace and the runner's temp
# folder at the same paths). Leading NAME=value words are its environment.
#
#   as-root.sh [NAME=value ...] <command> [args ...]
set -euo pipefail
if [ -n "${NERVE_CI_CONTAINER:-}" ]; then
  exec docker exec "$NERVE_CI_CONTAINER" env "$@"
fi
exec sudo env "$@"
