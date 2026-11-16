#!/bin/sh
set -eu
cd "$(dirname "$0")"
if command -v python3 >/dev/null 2>&1; then PY=python3; else PY=python; fi
printf '%s\n' 'Ghost Portal Cartographer independent local audit'
"$PY" --version
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum -c SOURCE_HASHES.sha256
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 -c SOURCE_HASHES.sha256
else
  printf '%s\n' 'SHA-256 CLI is unavailable; verify SOURCE_HASHES.sha256 independently.'
  exit 1
fi

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM
"$PY" -m unittest -v test_gpc.py
"$PY" run_demo.py
"$PY" mutation_check.py "$TMP_DIR/mutation.json"
"$PY" benchmark.py "$TMP_DIR/benchmark.csv"
