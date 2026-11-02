#!/usr/bin/env bash
# Local test run recorded by adahandle-deployments/common/test-evidence.sh (replaces the old Actions build).
# Dependencies (DeMi SDK, kora-secrets-crypto) are the published npm packages.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
npm ci
npm run lint
npm run build
npm test
