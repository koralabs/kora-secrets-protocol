// @ts-nocheck — VENDORED from koralabs/decentralized-minting/src/helpers/cardano-sdk
// Pure @cardano-sdk + scalus (the only approved Cardano libs; no Lucid/Helios/Mesh/CSL/WASM).
// Type-checked & unit-tested upstream; SSR validates the integration live on preview. Do not
// hand-edit the byte-splice / script-data-hash logic — re-vendor from source if it changes.
import { createRequire } from "node:module";

// Enable Conway-era set tagging before any tx CBOR is built.
const require = createRequire(import.meta.url);
const { setInConwayEra } = require("@cardano-sdk/core") as {
  setInConwayEra: (value: boolean) => boolean;
};

setInConwayEra(true);
