#!/usr/bin/env sh
# Static well-formedness check for every JCasC yaml file. This only catches
# "is this valid YAML" — real JCasC schema validation requires a running
# controller (see boot-health.sh).
set -eu

cd "$(dirname "$0")/../.."

status=0
for f in $(find casc -name '*.yaml' -o -name '*.yml'); do
    if ! python3 -c "import sys, yaml; yaml.safe_load(open(sys.argv[1]))" "$f"; then
        echo "INVALID YAML: $f" >&2
        status=1
    fi
done

if [ "$status" -eq 0 ]; then
    echo "All CasC yaml files are well-formed."
fi
exit "$status"
