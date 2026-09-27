#!/usr/bin/env sh
# Jenkins computes each JNLP agent's secret internally — JCasC cannot pin an
# arbitrary chosen value. Run this once the controller is up and healthy to
# fetch the rust-agent's secret and drop it into .env, so the rest of
# bring-up stays fully scripted.
set -eu

cd "$(dirname "$0")/.."

if [ -f .env ]; then
    # shellcheck disable=SC1091
    . ./.env
fi

JENKINS_URL="${JENKINS_EXTERNAL_URL:-http://localhost:8080}"
JENKINS_ADMIN_ID="${JENKINS_ADMIN_ID:-admin}"
JENKINS_AGENT_NAME="${JENKINS_AGENT_NAME:-rust-agent}"

if [ -z "${JENKINS_ADMIN_PASSWORD:-}" ]; then
    echo "JENKINS_ADMIN_PASSWORD not set (source .env first)" >&2
    exit 84
fi

secret=$(curl -sf -u "${JENKINS_ADMIN_ID}:${JENKINS_ADMIN_PASSWORD}" \
    "${JENKINS_URL}/computer/${JENKINS_AGENT_NAME}/jenkins-agent.jnlp" \
    | grep -oE '<application-desc[^>]*>.*</application-desc>' \
    | grep -oE '<argument>[^<]*</argument>' \
    | sed -n '1p' \
    | sed -E 's#</?argument>##g')

if [ -z "$secret" ]; then
    echo "Could not extract agent secret — is the controller up and the node provisioned?" >&2
    exit 84
fi

if grep -q '^JENKINS_AGENT_SECRET=' .env 2>/dev/null; then
    sed -i.bak -E "s#^JENKINS_AGENT_SECRET=.*#JENKINS_AGENT_SECRET=${secret}#" .env && rm -f .env.bak
else
    echo "JENKINS_AGENT_SECRET=${secret}" >> .env
fi

echo "Wrote JENKINS_AGENT_SECRET to ci/jenkins/.env"
