#!/usr/bin/env sh
# Assumes the controller is already up and healthy. Asserts both seed jobs
# (casc/projects/cryptography/seed-job.yaml) actually created their pipelines.
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

status=0
for job_name in cryptography-dev cryptography-main; do
    job=$(curl -sf -u "${JENKINS_ADMIN_ID}:${JENKINS_ADMIN_PASSWORD}" \
        "${JENKINS_URL}/job/${job_name}/api/json")

    ok=$(echo "$job" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print('1' if data.get('buildable') else '0')
")

    if [ "$ok" != "1" ]; then
        echo "${job_name} job missing or not buildable" >&2
        status=1
    else
        echo "${job_name} seed job exists and is buildable."
    fi
done

exit "$status"
