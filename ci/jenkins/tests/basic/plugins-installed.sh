#!/usr/bin/env sh
# Assumes the controller is already up and healthy (run boot-health.sh first).
# Asserts every plugin in plugins.txt is installed, enabled and active.
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

installed=$(curl -sf -u "${JENKINS_ADMIN_ID}:${JENKINS_ADMIN_PASSWORD}" \
    "${JENKINS_URL}/pluginManager/api/json?depth=1")

status=0
while IFS= read -r line; do
    [ -z "$line" ] && continue
    case "$line" in \#*) continue ;; esac
    plugin_id=$(echo "$line" | cut -d: -f1)
    ok=$(echo "$installed" | python3 -c "
import sys, json
data = json.load(sys.stdin)
pid = sys.argv[1]
for p in data.get('plugins', []):
    if p.get('shortName') == pid:
        print('1' if p.get('enabled') and p.get('active') else '0')
        sys.exit()
print('0')
" "$plugin_id")
    if [ "$ok" != "1" ]; then
        echo "Plugin not enabled/active: $plugin_id" >&2
        status=1
    fi
done < plugins.txt

if [ "$status" -eq 0 ]; then
    echo "All plugins in plugins.txt are enabled and active."
fi
exit "$status"
