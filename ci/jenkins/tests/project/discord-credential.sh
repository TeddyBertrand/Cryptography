#!/usr/bin/env sh
# Assumes the controller is already up and healthy. Structural check only —
# a real Discord delivery needs a live webhook and a red build (see README).
set -eu

cd "$(dirname "$0")/../.."

if [ -f .env ]; then
    # shellcheck disable=SC1091
    . ./.env
fi

JENKINS_URL="${JENKINS_EXTERNAL_URL:-http://localhost:8080}"
JENKINS_ADMIN_ID="${JENKINS_ADMIN_ID:-admin}"

if [ -z "${JENKINS_ADMIN_PASSWORD:-}" ]; then
    echo "JENKINS_ADMIN_PASSWORD not set (source .env first)" >&2
    exit 84
fi

cred=$(curl -sf -u "${JENKINS_ADMIN_ID}:${JENKINS_ADMIN_PASSWORD}" \
    "${JENKINS_URL}/credentials/store/system/domain/cryptography/credential/discord-webhook-url/api/json")

ok=$(echo "$cred" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print('1' if data.get('id') == 'discord-webhook-url' else '0')
")

if [ "$ok" != "1" ]; then
    echo "discord-webhook-url credential missing" >&2
    exit 1
fi
echo "discord-webhook-url credential exists."
