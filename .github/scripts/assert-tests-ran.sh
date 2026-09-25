#!/usr/bin/env bash
# Usage: assert-tests-ran.sh <label> <results-path-fragment> <RequiredTestClass>...
# A Gradle test task that runs nothing still exits green, so each platform job asserts it did not.
# Kept to bash 3.2: macOS runners have no globstar or mapfile.
set -euo pipefail

label=$1
fragment=$2
shift 2

list=$(mktemp)
find . -type f -path "*${fragment}*" -name 'TEST-*.xml' 2>/dev/null > "$list" || true
if [ ! -s "$list" ]; then
  echo "::error::$label produced no result files under *${fragment}*"
  exit 1
fi

total=0
while IFS= read -r f; do
  [ -n "$f" ] || continue
  while IFS= read -r suite; do
    tests=$(echo "$suite" | grep -o ' tests="[0-9]*"' | grep -o '[0-9]*' || echo 0)
    skipped=$(echo "$suite" | grep -o ' skipped="[0-9]*"' | grep -o '[0-9]*' || echo 0)
    total=$(( total + ${tests:-0} - ${skipped:-0} ))
  done < <(grep -o '<testsuite [^>]*>' "$f" || true)
done < "$list"

echo "$label: $total tests executed across $(wc -l < "$list" | tr -d ' ') result files"
if [ "$total" -eq 0 ]; then
  echo "::error::$label produced result files but ran 0 tests"
  exit 1
fi

missing=0
for cls in "$@"; do
  found=0
  while IFS= read -r f; do
    if grep -q -E "classname=\"([^\"]*\.)?${cls}\"" "$f"; then found=1; break; fi
  done < "$list"
  if [ "$found" -eq 1 ]; then
    echo "  ran: $cls"
  else
    echo "::error::$cls did not run in $label - it is a load-bearing check on this platform"
    missing=1
  fi
done
exit "$missing"
