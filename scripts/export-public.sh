#!/usr/bin/env bash
# Export the public copy of this repository: the same history, minus
# - tests/fixtures/evtx  (real logs from a training image we can't redistribute;
#                         the suites that need them skip when they're absent)
# - crates/evtx-wasm/target  (Rust build intermediates; the deployable WASM
#                         output lives in lib/evtx-wasm and public/)
# with every commit authored under the GitHub noreply address.
#
# Requires git-filter-repo (brew install git-filter-repo).
# Usage: scripts/export-public.sh [destination]   (default: ../evtx-parser-public)
set -euo pipefail

src=$(git rev-parse --show-toplevel)
dest=${1:-"$src/../evtx-parser-public"}
if [ -e "$dest" ]; then
  echo "error: $dest already exists" >&2
  exit 1
fi

git clone --no-local --quiet "$src" "$dest"
cd "$dest"
git filter-repo --force --invert-paths \
  --path tests/fixtures/evtx \
  --path crates/evtx-wasm/target \
  --name-callback 'return b"Florian Amette"' \
  --email-callback 'return b"50982737+florianamette@users.noreply.github.com"'
git gc --prune=now --quiet

echo "Public copy ready in $dest ($(git rev-list --count HEAD) commits)."
echo "Review it, then add a remote and push."
