import type { Cardano as CardanoTypes } from '@cardano-sdk/core';
import { roundRobinRandomImprove, type SelectionSkeleton } from '@cardano-sdk/input-selection';
import {
  computeMinimumCoinQuantity,
  createTransactionInternals,
  defaultSelectionConstraints,
  GreedyTxEvaluator
} from '@cardano-sdk/tx-construction';

import { type BlockfrostBuildContext } from '../cardano-sdk/blockfrostContext.ts';
import { asPaymentAddress, buildPlaceholderSignatures, Serialization, transactionToCbor } from '../cardano-sdk/index.ts';

// Server-side SSR tx builder, mirroring koralabs/decentralized-minting/src/deploymentTx.ts:
// coin-selection via roundRobinRandomImprove + createTransactionInternals, with the
// production-proven fee margin for reference-script outputs (cardano-sdk's computeMinimumCost
// doesn't size scriptReference bytes into the fee, so a raw ref-script deploy comes out short of
// the node minimum). Pure @cardano-sdk — no Lucid/WASM-serialization. Validated live on preview.

export interface BuiltUnsignedTx {
  /** The core tx (body + empty witness) — its body hash is what the signer signs. */
  tx: CardanoTypes.Tx;
  /** CBOR of the unsigned tx (tag-258 stripped) — input to the vkey-splice merge. */
  unsignedTxCbor: string;
  /** Fee the coin selector sized the body around (lovelace). */
  fee: bigint;
}

const buildUnsignedTxForFee = (
  selection: SelectionSkeleton,
  requestedOutputs: CardanoTypes.TxOut[],
  validityInterval: CardanoTypes.ValidityInterval
): CardanoTypes.Tx => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const bodyWithHash = createTransactionInternals({ inputSelection: selection, validityInterval, outputs: requestedOutputs } as any);
  return {
    id: bodyWithHash.hash,
    body: bodyWithHash.body,
    witness: { signatures: buildPlaceholderSignatures(1) }
  };
};

/**
 * Build an unsigned reference-script deployment tx: one output at `ownerAddress` carrying the
 * compiled validator as a `scriptReference` (min-UTxO funded), with change back to the owner.
 * No Plutus execution (a plain payment that parks the script on-chain), so no script_data_hash.
 */
export const buildRefScriptDeployTx = async (params: {
  scriptCborHex: string;
  plutusVersion: 'v2' | 'v3';
  ownerAddress: string;
  utxos: CardanoTypes.Utxo[];
  buildContext: BlockfrostBuildContext;
}): Promise<BuiltUnsignedTx> => {
  const { scriptCborHex, plutusVersion, ownerAddress, utxos, buildContext } = params;
  const address = asPaymentAddress(ownerAddress);

  const scriptReference: CardanoTypes.Script =
    plutusVersion === 'v3'
      ? Serialization.PlutusV3Script.fromCbor(scriptCborHex as never).toCore()
      : Serialization.PlutusV2Script.fromCbor(scriptCborHex as never).toCore();

  const minimumCoinQuantity = computeMinimumCoinQuantity(buildContext.protocolParameters.coinsPerUtxoByte);
  const output: CardanoTypes.TxOut = { address, value: { coins: 0n }, scriptReference };
  output.value = { ...output.value, coins: minimumCoinQuantity(output) };
  const requestedOutputs = [output];

  // Fee margin for the ref-script output (mirrors deploymentTx.ts): cardano-sdk's
  // computeMinimumCost omits scriptReference bytes, leaving the deploy ~minFeeA×bytes short.
  const refScriptBytes = Serialization.Script.fromCore(scriptReference).toCbor().length / 2;
  const minFeeCoefficient = BigInt(buildContext.protocolParameters.minFeeCoefficient ?? 44);
  const feeSafetyMargin = 2000n + (BigInt(Math.ceil(refScriptBytes)) * minFeeCoefficient * 13n) / 10n;

  const inputSelector = roundRobinRandomImprove({
    changeAddressResolver: {
      resolve: async (selection) => selection.change.map((change) => ({ ...change, address }))
    }
  });
  const txEvaluator = new GreedyTxEvaluator(async () => buildContext.protocolParameters);
  const baseConstraints = defaultSelectionConstraints({
    protocolParameters: buildContext.protocolParameters,
    buildTx: (selection) => Promise.resolve(buildUnsignedTxForFee(selection, requestedOutputs, buildContext.validityInterval)),
    redeemersByType: {},
    txEvaluator
  });
  const constraints = {
    ...baseConstraints,
    computeMinimumCost: async (selection: SelectionSkeleton) => {
      const result = await baseConstraints.computeMinimumCost(selection);
      return { ...result, fee: result.fee + feeSafetyMargin };
    }
  };

  const selection = await inputSelector.select({
    preSelectedUtxo: new Set<CardanoTypes.Utxo>(),
    utxo: new Set(utxos),
    outputs: new Set(requestedOutputs),
    constraints
  });

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const finalBody = createTransactionInternals({ inputSelection: selection.selection, validityInterval: buildContext.validityInterval, outputs: requestedOutputs } as any);
  const fee = selection.selection.fee;
  const tx: CardanoTypes.Tx = {
    id: finalBody.hash,
    body: { ...finalBody.body, fee },
    witness: { signatures: new Map() }
  };
  return { tx, unsignedTxCbor: transactionToCbor(tx), fee };
};
