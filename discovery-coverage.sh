#!/usr/bin/env sh
set -eu
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ACTION="${1:-show}"
for name in large-bundle-spa many-states-spa runtime-discovery-spa large-api-response bft-regression-spa scope-noise complex-react-auth; do
  "$SCRIPT_DIR/testbed-coverage.sh" "$ACTION" "$name"
done
