#!/usr/bin/env sh
# Orchestrates both test tiers against a fresh, hermetic controller/agent
# stack, tearing everything down afterwards regardless of outcome.
set -eu

cd "$(dirname "$0")/.."

cleanup() {
    docker compose -f docker-compose.yml down -v
}
trap cleanup EXIT

sh tests/basic/validate-casc.sh
sh tests/basic/boot-health.sh
sh tests/basic/plugins-installed.sh

sh tests/project/seed-job-exists.sh
sh tests/project/jenkinsfile-lint.sh
sh tests/project/webhook-config.sh

echo "All JCasC tests passed."
