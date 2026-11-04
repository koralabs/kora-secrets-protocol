# kora-secrets-protocol canonical contract

The off-chain protocol layer for Social Secret Recovery on ADA Handles: datum codecs, transaction plans and builders, chain readers, content-addressed bundle storage, and the Node-side realizers that build recovery transactions.

1. Datum bytes equal what the on-chain validators read: each datum type encodes to the Aiken fixture and decode(encode(x)) returns x.
2. Transactions are built unsigned; builders return unsigned CBOR and a hash and never submit. Signing is the owner's wallet or an explicitly supplied `SsrSigner`.
3. Networks never mix: a bundle or datum for one network is rejected against another (`NETWORK_MISMATCH`).
4. An off-chain bundle is trusted only after it matches the on-chain anchor: integrity hash, anchored hash, threshold and guardian set each fail with a distinct error.
5. Stored blobs are verified against their content address on every read; a corrupted blob is an error, never data.
6. A recovery session id is derived from the consumed seed UTxO exactly as the validator derives it.
7. The handle registry root is rebuilt from the full handle list and label snapshot and must equal both the API snapshot root and the on-chain `handle_root@handle_settings` datum before any proof is used; a failed fetch, malformed snapshot or mismatch aborts.
8. Mnemonics and private keys are only derived in memory and never logged or stored.
