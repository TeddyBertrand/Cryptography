#!/usr/bin/env sh
# Assumes the controller is already up and healthy. Asserts every seed job
# (casc/projects/cryptography/seed-job.yaml) actually created its pipeline,
# and that the nightly one carries its cron trigger.
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
for job_name in cryptography-dev cryptography-main cryptography-nightly; do
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

config=$(curl -sf -u "${JENKINS_ADMIN_ID}:${JENKINS_ADMIN_PASSWORD}" \
    "${JENKINS_URL}/job/cryptography-nightly/config.xml")

case "$config" in
    *TimerTrigger*"H 3 * * *"*)
        echo "cryptography-nightly has its nightly cron trigger." ;;
    *)
        echo "cryptography-nightly is missing the 'H 3 * * *' cron trigger" >&2
        status=1 ;;
esac

exit "$status"
