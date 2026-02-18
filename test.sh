#!/usr/bin/env bash
set -euo pipefail

HOST="${HOST:-http://localhost:8080}"
TOKEN="${TOKEN:-secret123}"
TAG="${TAG:-v0.0.13}"
FILE="${FILE:-docker-compose.yml}"

AUTH="Authorization: Bearer $TOKEN"
CT="Content-Type: application/json"

green() { printf '\033[32m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*"; }
header() { echo; green "=== $* ==="; }

# --- Tests ---

header "GET /version"
curl -s "$HOST/version" | jq .

header "POST /compose/up (streaming)"
curl -sN "$HOST/compose/up" \
  -H "$AUTH" -H "$CT" \
  -d "{\"tag\": \"$TAG\", \"file\": \"$FILE\"}"
echo

header "POST /compose/logs"
curl -s "$HOST/compose/logs" \
  -H "$AUTH" -H "$CT" \
  -d "{\"file\": \"$FILE\", \"tail\": 10}" | jq .

header "GET /docker/ps"
curl -s "$HOST/docker/ps" \
  -H "$AUTH" | jq .

header "POST /docker/restart (first container from docker ps)"
CONTAINER=$(curl -s "$HOST/docker/ps" -H "$AUTH" | jq -r '.output' | head -1 | jq -r '.Names')
if [ -n "$CONTAINER" ] && [ "$CONTAINER" != "null" ]; then
  echo "Restarting container: $CONTAINER"
  curl -s "$HOST/docker/restart" \
    -H "$AUTH" -H "$CT" \
    -d "{\"container\": \"$CONTAINER\"}" | jq .
else
  red "No containers found, skipping restart test"
fi

header "POST /compose/down (streaming)"
curl -sN "$HOST/compose/down" \
  -H "$AUTH" -H "$CT" \
  -d "{\"tag\": \"$TAG\", \"file\": \"$FILE\"}"
echo

header "POST /compose/up with env vars (streaming)"
curl -sN "$HOST/compose/up" \
  -H "$AUTH" -H "$CT" \
  -d "{\"tag\": \"$TAG\", \"file\": \"$FILE\", \"env\": {\"MY_VAR\": \"hello\"}}"
echo

header "POST /compose/down (cleanup)"
curl -sN "$HOST/compose/down" \
  -H "$AUTH" -H "$CT" \
  -d "{\"tag\": \"$TAG\", \"file\": \"$FILE\"}"
echo

header "POST /docker/clean (volumes)"
curl -s "$HOST/docker/clean" \
  -H "$AUTH" -H "$CT" \
  -d '{"volumes": true, "images": false}' | jq .

green "All tests completed."
