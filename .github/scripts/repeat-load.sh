#!/usr/bin/env bash
# Loads the machine while repeat.yml runs tests, so they meet what the full
# `cargo test --workspace` of a CI job gives them: every core busy, and
# processes starting and ending all the time (the flaky tests of #107, #112
# and #180 failed on a start that took seconds). For each of the <workers>
# one loop burns a core and one starts a process again and again. Runs until
# it gets TERM or INT, then ends its loops.
set -u

workers=${1:-}
case $workers in '' | *[!0-9]*)
  echo "usage: repeat-load.sh <workers>" >&2
  exit 2
  ;;
esac

loops=()
# The loops are subshells of this script, so ending the script alone would
# leave them running for as long as the job lives.
trap 'kill "${loops[@]}" 2>/dev/null; exit 0' TERM INT

for _ in $(seq 1 "$workers"); do
  (while :; do :; done) &
  loops+=($!)
  # `env` is a program on every system; a builtin would start nothing.
  (while :; do env true; done) &
  loops+=($!)
done
wait
