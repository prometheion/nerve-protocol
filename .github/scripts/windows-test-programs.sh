#!/usr/bin/env bash
# The test programs of .github/workflows/installed-windows.yml, built in debug
# from the checked-out commit and copied into <folder> under the names that
# workflow runs them by. CI's `windows` job and the release's `windows` job
# both run it, so a test the installed job runs is built for either.
#
#   windows-test-programs.sh <folder>
set -euo pipefail

OUT=${1:?the folder for the test programs}
mkdir -p "$OUT"

# The executable cargo built for the test target that the arguments name.
exe() {
  cargo test --locked "$@" --no-run --message-format=json \
    | python -c 'import json,sys; [e] = [m["executable"] for m in map(json.loads, sys.stdin) if m.get("executable") and m["profile"]["test"]]; print(e)'
}

cp "$(exe -p nerve-node-desktop --test real)" "$OUT/real.exe"
cp "$(exe -p nerve-node --test win_sudo)" "$OUT/win_sudo.exe"
cp "$(exe -p nerve-node --test win_limits)" "$OUT/win_limits.exe"
cp "$(exe -p nerve-node --test win_account)" "$OUT/win_account.exe"
cp "$(exe -p nerve-node --test win_provider)" "$OUT/win_provider.exe"
cp "$(exe -p nerve-node --test win_vault)" "$OUT/win_vault.exe"
cp "$(exe -p nerve-center --test win_service)" "$OUT/win_service.exe"
cp "$(exe -p nerve-node --lib)" "$OUT/nerve_node_lib.exe"
cp "$(exe -p nerve-sandbox --lib)" "$OUT/nerve_sandbox_lib.exe"
cp "$(exe -p nerve-service --lib)" "$OUT/nerve_service_lib.exe"
ls -l "$OUT"
