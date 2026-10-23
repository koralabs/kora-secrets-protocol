# @koralabs/kora-secrets-protocol

## Contributor test policy

Tests and coverage are local-only; GitHub Actions must not execute them directly or through package lifecycle scripts, composites, templates, or shared build/publish helpers. Preserve local test scripts. Build, lint, publication, deployment, and production guards remain permitted. Retire obsolete required test checks from branch protections.

The off-chain protocol layer for **Social Secret Recovery** (SSR) on ADA Handles.

- **`.`** — CIP-68 datum codecs (policy / request / approval / guardian-profile), tx-plan
  builders, chain-query providers (Blockfrost + a fake for tests), IPFS blob storage,
  reconciliation. Browser-safe (no `@cardano-sdk`/scalus pulled in).
- **`./chain`** — the live tx realizers: build/sign/submit InitiateRecovery, CancelRecovery,
  CreatePolicy, ApproveRecovery, CompleteRecovery, the guardian-(003) mint through the DeMi
  `demimntmpt` contract, the reference-script deployer, the CIP-1852 signer, and the
  minting-data MPT trie. Node-side (`@cardano-sdk` + scalus).
- **`./cardano-sdk`** — the vendored pure-`@cardano-sdk` + scalus helpers (Blockfrost build
  context, UTxO fetch, `finalizeTxPlan`, script-data-hash, vkey splice, param application).

Depends on `@koralabs/kora-secrets-crypto` for all secret handling. Only approved Cardano
libraries (`@cardano-sdk`, scalus) — no Lucid/Helios/Mesh/CSL.

```ts
import { buildCreatePolicyTx, encodeRecoveryPolicyDatum } from '@koralabs/kora-secrets-protocol';
import { buildInitiateRecoveryRealTx, signerFromMnemonic } from '@koralabs/kora-secrets-protocol/chain';
```

Built with `tsc` to `lib/`; published via OIDC trusted publishing.

Registry reconstruction requires SDK 4's explicit `{ name, labels }` entries. It fetches
the full handle list and the sparse `/mpt-root/registry-labels` snapshot, validates the
snapshot network/count and canonical four-byte label sets, and verifies the rebuilt
root against both the API snapshot and `handle_root@handle_settings` on-chain datum.
Missing sparse keys denote empty label sets only after those root checks pass. A failed
fetch, malformed snapshot, or mismatched root aborts proof construction; names-only
reconstruction and hardcoded label lists are not valid substitutes.

This recovery build is private. The DeMi SDK 4.0.0 and crypto 1.1.0 are exact
peer dependencies: install them once alongside the protocol in the consumer. This
preserves `SsrError` class identity and lets label-mint callers use the same SDK and
Trie instance as registry reconstruction. Bundling a private crypto copy broke the
real caller's `isSsrError` check; bundling the SDK also hid its label-mint API.

Until those versions exist in the registry, vendor all three verified tarballs in
the consumer and declare direct `file:vendor/<version-and-hash>.tgz` dependencies.
The protocol checkout uses `npm ci` with its integrity-locked local development
artifacts. Their source revisions and checksums are in `vendor/PROVENANCE.json`.
Build the protocol tarball with `npm run pack:portable -- /path/to/output`; it compiles
into a fresh staging directory and bundles no dependencies. Validate an installed
consumer with `npm run validate:consumer -- /path/to/consumer`, plus its own npm ci,
typecheck and tests. The check verifies shared crypto/SDK resolution, cross-package
session-mismatch errors, the label-mint API and a real labeled trie inclusion proof.
Publication remains disabled until both exact peer versions exist in the registry.

API, Blockfrost and IPFS calls share a process-wide rate-limit gate. It honors header/body
waits across callers, returns long waits, and never automatically retries a 429.
