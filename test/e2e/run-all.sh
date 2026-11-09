#!/usr/bin/env bash
# Runs the e2e suite once per pgs image tag listed in pgs-versions.txt.
# Needs the TF_ACC* environment (see `just e2e-all`). Logs go to .logs/<tag>.log.
# Exits non-zero if any version fails.
set -u
cd "$(dirname "$0")"
mkdir -p .logs
failed=()
for v in $(grep -v '^#' pgs-versions.txt); do
  if PGS_IMAGE="ghcr.io/picosh/pgs:$v" go test -tags e2e -count=1 -timeout 30m . > ".logs/$v.log" 2>&1; then
    echo "PASS pgs $v"
  else
    echo "FAIL pgs $v (see test/e2e/.logs/$v.log)"
    failed+=("$v")
  fi
done
if [ ${#failed[@]} -gt 0 ]; then
  echo "failed versions: ${failed[*]}"
  exit 1
fi
echo "all versions passed"
