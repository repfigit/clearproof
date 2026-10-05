#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Developer Certificate of Origin check: every non-merge commit in BASE..HEAD must carry a
# Signed-off-by trailer whose email matches the commit author. Bot authors ([bot]) are exempt.
# Usage: scripts/check_dco.sh <base-sha> <head-sha>
set -euo pipefail

base="${1:?usage: check_dco.sh <base-sha> <head-sha>}"
head="${2:?usage: check_dco.sh <base-sha> <head-sha>}"
failed=0
checked=0

for sha in $(git rev-list --no-merges "${base}..${head}"); do
  author_name="$(git show -s --format='%an' "$sha")"
  author_email="$(git show -s --format='%ae' "$sha" | tr '[:upper:]' '[:lower:]')"
  subject="$(git show -s --format='%s' "$sha")"
  if [[ "$author_name" == *"[bot]" ]]; then
    echo "skip  ${sha:0:12} ${author_name} (bot): ${subject}"
    continue
  fi
  checked=$((checked + 1))
  signoffs="$(git show -s --format='%(trailers:key=Signed-off-by,valueonly)' "$sha" | tr '[:upper:]' '[:lower:]')"
  if grep -qF "<${author_email}>" <<<"$signoffs"; then
    echo "ok    ${sha:0:12} ${subject}"
  else
    echo "::error::Commit ${sha:0:12} (\"${subject}\") has no Signed-off-by matching its author <${author_email}>."
    failed=1
  fi
done

if [[ "$failed" -ne 0 ]]; then
  cat <<'MSG'

Every commit must be signed off under the Developer Certificate of Origin (see CONTRIBUTING.md).
Fix with:  git rebase --signoff origin/main && git push --force-with-lease
MSG
  exit 1
fi
echo "DCO: ${checked} commit(s) signed off."
