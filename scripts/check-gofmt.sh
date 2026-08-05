#!/usr/bin/env bash
# Fails if any Go file is not gofmt-clean. `gofmt -l` exits 0 even when it finds
# unformatted files, which makes it useless in CI on its own.
set -euo pipefail

cd "$(dirname "$0")/.."

unformatted=$(gofmt -l . | grep -v '^$' || true)
if [ -n "$unformatted" ]; then
  echo "these files are not gofmt-clean:" >&2
  echo "$unformatted" >&2
  echo >&2
  echo "run: pnpm format" >&2
  exit 1
fi
echo "gofmt: clean"
