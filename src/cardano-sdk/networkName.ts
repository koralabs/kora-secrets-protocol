// @ts-nocheck — VENDORED from koralabs/decentralized-minting/src/helpers/cardano-sdk
// Pure @cardano-sdk + scalus (the only approved Cardano libs; no Lucid/Helios/Mesh/CSL/WASM).
// Type-checked & unit-tested upstream; SSR validates the integration live on preview. Do not
// hand-edit the byte-splice / script-data-hash logic — re-vendor from source if it changes.
/**
 * Replaces `@helios-lang/tx-utils`'s `NetworkName`. The tx-building stack no
 * longer depends on Helios, so we keep the set of networks we actually
 * support as a local literal union.
 */
export type NetworkName = "mainnet" | "preprod" | "preview";

export const getNetworkId = (network: NetworkName): 0 | 1 =>
  network === "mainnet" ? 1 : 0;
