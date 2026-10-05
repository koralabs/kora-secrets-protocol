# @koralabs/kora-secrets-protocol

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

This recovery build is private and uses integrity-locked SDK 4.0.0 and crypto 1.1.0
artifacts in `vendor/`. Use `npm ci` to install from the checkout lock, which resolves
those exact versions to the local tarballs without unpublished registry dependencies.
Their source revisions and checksums are in `vendor/PROVENANCE.json`.

Build a portable consumer package with `npm run pack:portable -- /path/to/output`.
The command compiles into a fresh staging directory, verifies the two source tarballs,
and bundles their installed runtime closure except the shared public type owners:
`@cardano-sdk/core` and `@aiken-lang/merkle-patricia-forestry`. Those remain normal
registry dependencies so the protocol, SDK and consumer use the same public classes.
A full bundle caused a reproduced Cardano private-field type conflict; omitting the
entire dependency closure instead caused missing crypto modules at runtime. The
portable command addresses both failures and retains the locked internal versions.

The bundle is about 15 MB compressed. Other bundled libraries and internal Cardano
SDK versions may remain duplicated; do not assume identity across those boundaries.
Consumer lock integrity covers the outer protocol tarball and normally resolved
registry packages, while the embedded source SDK/crypto hashes remain in provenance.
Publication stays disabled until both exact dependency versions exist in the registry.

API, Blockfrost and IPFS calls share a process-wide rate-limit gate. It honors header/body
waits across callers, returns long waits, and never automatically retries a 429.
