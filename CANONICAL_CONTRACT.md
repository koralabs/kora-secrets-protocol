# kora-secrets-protocol canonical contract

## Purpose and authority

I am the off-chain protocol layer for Social Secret Recovery on ADA Handles: datum codecs, transaction plans and builders, chain readers, content-addressed bundle storage, and the Node-side realizers that build recovery transactions. The operator is the authority over this contract. A change to the files in [`.enclave`](./.enclave) merges into `master` only with operator approval. Nothing here authorizes signing, spending, publishing, or any change to on-chain validators or settings; those keep their own operator gates.

## Invariants

1. My datum bytes equal what the on-chain validators read. Encoding each datum type must equal the Aiken fixture `src/__fixtures__/datum-cbor-v1.json`, and decode(encode(x)) must return x. Enforced in `src/datums.test.ts`, including a negative control.
2. I build transactions unsigned. The builders return unsigned CBOR and a hash; signing is the owner's wallet (CIP-30) or an explicitly supplied `SsrSigner`. Nothing in the builders submits. Partly enforced in `src/lifecycle.test.ts`; no test forbids a builder from calling submit.
3. Network never mixes. A bundle or datum for one network is rejected against another (`NETWORK_MISMATCH`). Enforced in `src/reconciliation.test.ts`.
4. An off-chain bundle is trusted only after it matches the on-chain anchor: integrity hash, anchored hash, threshold and guardian set each fail with a distinct error. Enforced in `src/reconciliation.test.ts`.
5. Stored blobs are verified against their content address on every read; a corrupted blob is an error, never data. Enforced in `src/storage.test.ts`.
6. A recovery session id is derived from the consumed seed UTxO exactly as the validator derives it, so it is unique. Enforced in `src/tx-builders.test.ts` and `src/lifecycle.test.ts`.
7. The handle registry root is rebuilt from the full handle list and the label snapshot, and must equal both the API snapshot root and the on-chain `handle_root@handle_settings` datum before any proof is used. A failed fetch, malformed snapshot or root mismatch aborts. Enforced in `src/chain/mpt-registry.test.ts`. Names-only reconstruction is never valid.
8. Every outbound HTTP call honors provider rate-limit waits and remembers them for the process. Enforced in `src/rate-limited-fetch.test.ts` and `src/rate-limited-callers.test.ts`.
9. Mnemonics and private keys are never logged or stored. `src/chain/wallet-signer.ts` derives them in memory only. Not yet enforced by a test.
10. Only approved Cardano libraries (`@cardano-sdk`, scalus) are used; no Lucid, Helios, Mesh or CSL. Not enforced by a test.

## Boundaries and known limits

I do not run on-chain code, so passing tests here never proves a validator accepts a transaction; preview runs do. The `.github/workflows/deploy.yml` workflow is listed because it publishes me to npm, and consumers pin my version. The Node signer exists for funded test wallets and scripts, not for production owner keys.

## Refactors needed to enforce this

- Add a test that no builder module imports or calls a submit function (invariant 2).
- Add a dependency allow-list check for invariant 10.
- Add a log-capture test around `signerFromMnemonic` for invariant 9.
