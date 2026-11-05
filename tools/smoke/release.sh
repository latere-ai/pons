#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Latere AI
# SPDX-License-Identifier: Apache-2.0
#
# Asserts a running ponsd from the outside after a rollout. The release
# pipeline runs it and attaches its markdown evidence to the release; an
# operator can run it by hand after an upgrade. It is unauthenticated,
# read-only and safe to run any number of times. It does not wait: it fails
# at once and the caller runs it again.
#
# BASE_URL is the origin plus the base path ponsd serves under, for example
# https://pons.example.com/v1/connections. It has no default: a smoke with a
# default target gets run against the wrong one.
#
# ponsd serves /livez and /readyz at its own root only, and the Ingress
# claims just the base path (and, on a connect host, the root as an exact
# match), so there is no public health route and none is invented here. The
# build's version is public below the base path.
#
# Checks, in order:
#   1. GET {BASE_URL}/openapi.yaml answers 200 with the Pons contract, which
#      is public and proves the request reached ponsd through its rule.
#   2. GET {BASE_URL}/connections answers 401 with no token, which proves
#      the authenticated surface is mounted and refusing.
#   3. GET {BASE_URL}/version serves a version, and when TAG is set it
#      equals TAG.
#
# Required tools: curl, grep.
#
# Environment:
#   BASE_URL   the origin and base path to smoke; required
#   TAG        the release being proved; when set the served version must equal it
#   COMMIT     the release commit, for the evidence
#   DEPLOY_URL the run that deployed it, for the evidence
#   OUTPUT_MD  where to write the markdown evidence; nowhere when unset

set -euo pipefail

BASE_URL="${BASE_URL:-}"
BASE_URL="${BASE_URL%/}"
TAG="${TAG:-}"
COMMIT="${COMMIT:-unknown}"
DEPLOY_URL="${DEPLOY_URL:-}"
OUTPUT_MD="${OUTPUT_MD:-}"

pass() { printf 'ok: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

[ -n "$BASE_URL" ] || fail "BASE_URL is required; this smoke has no default target"
for cmd in curl grep; do
  command -v "$cmd" >/dev/null || fail "$cmd is required"
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

check_status() {
  local label="$1" path="$2" want="$3" out="$4" code
  code=$(curl -sS --max-time 20 -o "$out" -w '%{http_code}' "${BASE_URL}${path}") \
    || fail "$label: curl failed"
  [ "$code" = "$want" ] || fail "$label: expected $want, got $code (body: $(head -c 200 "$out" 2>/dev/null || true))"
  pass "$label ($code)"
}

check_status "GET /openapi.yaml" "/openapi.yaml" "200" "$tmp/openapi"
grep -q '^  title: Pons' "$tmp/openapi" || fail "GET /openapi.yaml: the body is not the Pons contract"

check_status "GET /connections" "/connections" "401" "$tmp/connections"

check_status "GET /version" "/version" "200" "$tmp/version"
# `|| true`: grep exits 1 on no match, and the message below should be said.
served=$(grep -o '"version":"[^"]*"' "$tmp/version" | head -1 | cut -d'"' -f4 || true)
[ -n "$served" ] || fail "GET /version: no version in $(head -c 200 "$tmp/version")"
if [ -n "$TAG" ]; then
  [ "$served" = "$TAG" ] || fail "version mismatch: served $served, expected $TAG"
  pass "served version matches the tag ($served)"
else
  pass "served version recorded ($served)"
fi

if [ -n "$OUTPUT_MD" ]; then
  {
    echo "<!-- release-evidence -->"
    echo
    echo "## Release evidence"
    echo
    echo "- Tag: \`${TAG:-unknown}\`"
    echo "- Commit: \`${COMMIT}\`"
    [ -n "$DEPLOY_URL" ] && echo "- Deploy: ${DEPLOY_URL}"
    echo "- Origin: ${BASE_URL}"
    echo "- Served version: \`${served}\`${TAG:+, equal to the tag}"
    echo "- Smoke: \`/openapi.yaml\` answered 200 with the Pons contract"
    echo "- Surface: \`/connections\` answered 401 with no token, so the origin routes the base path to ponsd"
  } > "$OUTPUT_MD"
fi

printf '\nrelease smoke passed\n'
