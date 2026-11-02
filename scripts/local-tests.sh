#!/usr/bin/env bash
# Local test run recorded by adahandle-deployments/common/test-evidence.sh (replaces the old Actions build).
# The old CI built this repo next to two pinned siblings; recreate that layout in a temp workspace.
set -euo pipefail
repo="$(git rev-parse --show-toplevel)"
ws="$(mktemp -d "${TMPDIR:-/var/tmp}/kora-secrets-protocol-ws.XXXXXX")"
trap 'rm -rf "$ws"' EXIT
git clone -q "$repo" "$ws/kora-secrets-protocol"
pin() { git clone -q "https://github.com/koralabs/$1.git" "$ws/$1" && git -C "$ws/$1" checkout -q "$2"; }
pin decentralized-minting bfe3542bf262363faa7c8a11740a254f46e1e347
pin kora-secrets-crypto f1d9dc9f88c7fd9d63aa5a5afabaea6fbbde1080
cd "$ws"
node kora-secrets-protocol/ci/prepare-library-builds.mjs
npm ci --prefix decentralized-minting
npm run build --prefix decentralized-minting
npm ci --prefix kora-secrets-crypto
npm run build --prefix kora-secrets-crypto
npm ci --prefix kora-secrets-protocol
npm run lint --prefix kora-secrets-protocol
npm run build --prefix kora-secrets-protocol
