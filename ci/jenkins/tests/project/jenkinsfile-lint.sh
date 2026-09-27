#!/usr/bin/env sh
# Assumes the controller is already up and healthy. Validates the
# cryptography Jenkinsfile against Jenkins' built-in Declarative Pipeline
# linter — a real syntax/semantic check without needing the agent up.
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

result=$(curl -sf -u "${JENKINS_ADMIN_ID}:${JENKINS_ADMIN_PASSWORD}" \
    -F "jenkinsfile=<jenkinsfiles/cryptography.Jenkinsfile" \
    "${JENKINS_URL}/pipeline-model-converter/validate")

echo "$result"
case "$result" in
    *"Jenkinsfile successfully validated"*) exit 0 ;;
    *) echo "Jenkinsfile validation failed" >&2; exit 84 ;;
esac
