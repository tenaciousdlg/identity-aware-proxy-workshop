#!/usr/bin/env bash
# Smoke test for identity-aware-proxy-workshop.
# Verifies JWT authentication and RBAC enforcement against a running cluster.
#
# Usage:
#   bash scripts/smoke-test.sh                  # assumes port-forwards already running
#   PORT_FORWARD=true bash scripts/smoke-test.sh # script sets up port-forwards automatically
set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
PF_PIDS=()

cleanup() {
  for pid in "${PF_PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT

info() { echo -e "${YELLOW}▶ $*${NC}"; }
pass() { echo -e "${GREEN}✓ PASS${NC} — $*"; ((PASS++)) || true; }
fail() { echo -e "${RED}✗ FAIL${NC} — $*"; ((FAIL++)) || true; }

assert_http() {
  local desc=$1 expected=$2
  shift 2
  local actual
  actual=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$@")
  if [[ "$actual" == "$expected" ]]; then
    pass "$desc (HTTP $actual)"
  else
    fail "$desc (expected HTTP $expected, got $actual)"
  fi
}

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8180}"
ENVOY_URL="${ENVOY_URL:-http://localhost:8080}"

# ── Port-forwards ────────────────────────────────────────────────────────────
if [[ "${PORT_FORWARD:-false}" == "true" ]]; then
  info "Starting port-forwards..."
  kubectl port-forward svc/keycloak 8180:8180 &
  PF_PIDS+=($!)
  kubectl port-forward svc/envoy 8080:8080 &
  PF_PIDS+=($!)
  sleep 3
fi

# ── Wait for Keycloak ────────────────────────────────────────────────────────
info "Waiting for Keycloak at $KEYCLOAK_URL..."
for i in $(seq 1 30); do
  if curl -sf "$KEYCLOAK_URL/realms/demo" -o /dev/null 2>&1; then break; fi
  echo "  not ready (attempt $i/30) — retrying in 3s"
  sleep 3
done
curl -sf "$KEYCLOAK_URL/realms/demo" -o /dev/null && pass "Keycloak ready" || { fail "Keycloak not reachable"; exit 1; }

# ── Fetch tokens ─────────────────────────────────────────────────────────────
info "Fetching tokens from Keycloak..."
ALICE_TOKEN=$(curl -sf "$KEYCLOAK_URL/realms/demo/protocol/openid-connect/token" \
  -d "client_id=demo-client&grant_type=password&username=alice&password=password" \
  | jq -r .access_token)
BOB_TOKEN=$(curl -sf "$KEYCLOAK_URL/realms/demo/protocol/openid-connect/token" \
  -d "client_id=demo-client&grant_type=password&username=bob&password=password" \
  | jq -r .access_token)

[[ -n "$ALICE_TOKEN" && "$ALICE_TOKEN" != "null" ]] && pass "alice token obtained" || { fail "alice token fetch failed"; exit 1; }
[[ -n "$BOB_TOKEN"   && "$BOB_TOKEN"   != "null" ]] && pass "bob token obtained"   || { fail "bob token fetch failed"; exit 1; }

# ── Wait for Envoy ───────────────────────────────────────────────────────────
info "Waiting for Envoy at $ENVOY_URL..."
for i in $(seq 1 20); do
  if curl -sf "$ENVOY_URL/health" -o /dev/null 2>&1; then break; fi
  sleep 2
done

# ── JWT authentication ───────────────────────────────────────────────────────
info "Testing JWT authentication..."
assert_http "no token → /public → 401"  "401" "$ENVOY_URL/public"
assert_http "no token → /alice  → 401"  "401" "$ENVOY_URL/alice"
assert_http "no token → /bob    → 401"  "401" "$ENVOY_URL/bob"

# ── RBAC: /public (any authenticated user) ───────────────────────────────────
info "Testing /public (any authenticated user)..."
assert_http "alice → /public → 200" "200" -H "Authorization: Bearer $ALICE_TOKEN" "$ENVOY_URL/public"
assert_http "bob   → /public → 200" "200" -H "Authorization: Bearer $BOB_TOKEN"   "$ENVOY_URL/public"

# ── RBAC: /alice (alice only) ────────────────────────────────────────────────
info "Testing /alice (alice only)..."
assert_http "alice → /alice → 200" "200" -H "Authorization: Bearer $ALICE_TOKEN" "$ENVOY_URL/alice"
assert_http "bob   → /alice → 403" "403" -H "Authorization: Bearer $BOB_TOKEN"   "$ENVOY_URL/alice"

# ── RBAC: /bob (bob only) ────────────────────────────────────────────────────
info "Testing /bob (bob only)..."
assert_http "bob   → /bob → 200"   "200" -H "Authorization: Bearer $BOB_TOKEN"   "$ENVOY_URL/bob"
assert_http "alice → /bob → 403"   "403" -H "Authorization: Bearer $ALICE_TOKEN" "$ENVOY_URL/bob"

# ── JWT payload forwarded to app ─────────────────────────────────────────────
info "Testing x-jwt-payload forwarded to app..."
RESPONSE=$(curl -s -H "Authorization: Bearer $ALICE_TOKEN" "$ENVOY_URL/public")
if echo "$RESPONSE" | jq -e '.jwt_claims.username' -r 2>/dev/null | grep -qi "alice"; then
  pass "alice identity visible in app response (jwt_claims.username)"
else
  fail "alice identity not found in app response (got: $RESPONSE)"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "────────────────────────────────"
echo -e "  ${GREEN}Passed: $PASS${NC}   ${RED}Failed: $FAIL${NC}"
echo "────────────────────────────────"
if [[ $FAIL -eq 0 ]]; then
  echo -e "${GREEN}All tests passed.${NC}"
else
  echo -e "${RED}$FAIL test(s) failed.${NC}"
  exit 1
fi
