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
