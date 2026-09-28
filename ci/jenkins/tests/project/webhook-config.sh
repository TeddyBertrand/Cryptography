#!/usr/bin/env sh
# Assumes the controller is already up and healthy. Structural checks only —
# a real webhook delivery and status check need a live smee.io channel and a
# real GitHub push, which can't be scripted hermetically (see README).
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
    config=$(curl -sf -u "${JENKINS_ADMIN_ID}:${JENKINS_ADMIN_PASSWORD}" \
        "${JENKINS_URL}/job/${job_name}/config.xml")

    case "$config" in
        *GitHubPushTrigger*)
            echo "${job_name} has a githubPush trigger configured." ;;
        *)
            echo "${job_name} is missing the githubPush trigger" >&2
            status=1 ;;
    esac
done

cred=$(curl -sf -u "${JENKINS_ADMIN_ID}:${JENKINS_ADMIN_PASSWORD}" \
    "${JENKINS_URL}/credentials/store/system/domain/cryptography/credential/github-status-token/api/json")

ok=$(echo "$cred" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print('1' if data.get('id') == 'github-status-token' else '0')
")

if [ "$ok" != "1" ]; then
    echo "github-status-token credential missing" >&2
    status=1
else
    echo "github-status-token credential exists."
fi

exit "$status"
