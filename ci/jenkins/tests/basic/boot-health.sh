#!/usr/bin/env sh
# Brings the controller up, waits for it to be healthy, checks the JCasC
# load produced no errors, and confirms the JCasC-configured security realm
# is actually live (not just that Jenkins booted).
set -eu

cd "$(dirname "$0")/../.."

if [ -f .env ]; then
    # shellcheck disable=SC1091
    . ./.env
fi

JENKINS_URL="${JENKINS_URL:-http://localhost:8080}"
JENKINS_ADMIN_ID="${JENKINS_ADMIN_ID:-admin}"

if [ -z "${JENKINS_ADMIN_PASSWORD:-}" ]; then
    echo "JENKINS_ADMIN_PASSWORD not set (source .env first)" >&2
    exit 84
fi

docker compose -f docker-compose.yml up -d --build --wait jenkins

echo "Checking controller logs for CasC errors..."
if docker compose -f docker-compose.yml logs jenkins | grep -iE 'casc|configuration as code' | grep -iE 'error|severe'; then
    echo "CasC load reported errors — see above." >&2
    exit 84
fi

echo "Checking security realm is live..."
curl -sf -u "${JENKINS_ADMIN_ID}:${JENKINS_ADMIN_PASSWORD}" "${JENKINS_URL}/whoAmI/api/json" >/dev/null

echo "Controller is healthy and JCasC-configured security is live."
