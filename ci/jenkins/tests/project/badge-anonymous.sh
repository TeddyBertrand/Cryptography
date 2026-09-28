#!/usr/bin/env sh
# Assumes the controller is already up and healthy. Asserts the build status
# badge of each pushed-to job is served without credentials, as the README
# fetches it anonymously.
set -eu

cd "$(dirname "$0")/../.."

if [ -f .env ]; then
    # shellcheck disable=SC1091
    . ./.env
fi

JENKINS_URL="${JENKINS_EXTERNAL_URL:-http://localhost:8080}"

status=0
for job_name in cryptography-dev cryptography-main; do
    badge=$(curl -sf "${JENKINS_URL}/buildStatus/icon?job=${job_name}") || badge=""

    case "$badge" in
        *"<svg"*)
            echo "${job_name} badge is served anonymously." ;;
        *)
            echo "${job_name} badge not served anonymously" >&2
            status=1 ;;
    esac
done

exit "$status"
