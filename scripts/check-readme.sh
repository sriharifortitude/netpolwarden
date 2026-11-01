#!/usr/bin/env bash
# Fails if the README's demo block differs from what the built binary prints.
set -euo pipefail
cd "$(dirname "$0")/.."
expected=$(awk '/<!-- demo:start -->/{f=1;next} /<!-- demo:end -->/{f=0} f' README.md | sed '1d;$d')
actual=$(./scripts/demo.sh)
if [ "$expected" != "$actual" ]; then
  diff <(echo "$expected") <(echo "$actual") || true
  echo "README demo is out of date" >&2
  exit 1
fi
echo "README demo matches"
