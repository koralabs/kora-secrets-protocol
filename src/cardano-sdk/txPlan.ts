// @ts-nocheck — VENDORED from koralabs/decentralized-minting/src/txs/txPlan.ts
// finalizeTxPlan: the Plutus tx assembler (coin selection + GreedyTxEvaluator ex-units +
// computeScriptDataHash + collateral-return minimization + mint/refInputs/redeemers).
// Pure @cardano-sdk + the vendored cardano-sdk helpers. Validated live on preview.
import { Buffer } from "node:buffer";

import type { Cardano as CardanoTypes } from "@cardano-sdk/core";
import type { Ed25519KeyHashHex } from "@cardano-sdk/crypto";
import {
  roundRobinRandomImprove,
  type SelectionSkeleton,
} from "@cardano-sdk/input-selection";
import {
  computeMinimumCoinQuantity,
  createTransactionInternals,
  defaultSelectionConstraints,
  GreedyTxEvaluator,
} from "@cardano-sdk/tx-construction";

import type { BlockfrostBuildContext } from "./blockfrostContext.ts";
import {
  asPaymentAddress,
  buildPlaceholderSignatures,
  computeScriptDataHash,
  type HexBlob,
  Serialization,
  transactionHashFromCore,
  transactionToCbor,
} from "./index.ts";

/**
 * Shared Plutus-tx spec used by the DeMi tx builders. A `TxPlan` captures
 * all the declarative intent of a tx — inputs, outputs, redeemers, mints,
 * withdrawals, reference inputs — and `finalizeTxPlan` runs coin selection,
 * Conway-correct script_data_hash computation, and CBOR serialization.
 *
 * Callers never touch `@helios-lang/*`. They never touch cardano-sdk's
 * broken Alonzo-array-format script_data_hash either — this helper uses
 * the ported MAP-format `computeScriptDataHash` under the hood.
 */
export interface TxPlan {
  /** Preselected UTxOs (contract spends + token-carrying wallet UTxOs). */
  preSelectedUtxos: CardanoTypes.Utxo[];
  /** Additional wallet UTxOs to cover fees. */
  spareUtxos: CardanoTypes.Utxo[];
  /** Required outputs. Coin values are pre-filled; the selector may add change. */
  outputs: CardanoTypes.TxOut[];
  /** Reference inputs (script refs + reference datums). */
  referenceInputs?: Set<CardanoTypes.TxIn>;
  /** Tokens minted/burned keyed by asset id. */
  mint?: Map<CardanoTypes.AssetId, bigint>;
  /** Withdrawals keyed by reward account (bech32). */
  withdrawals?: Map<CardanoTypes.RewardAccount, bigint>;
  /** Certificates (stake registration, etc). */
  certificates?: CardanoTypes.Certificate[];
  /** All redeemers (spend/mint/cert/withdraw). */
  redeemers?: CardanoTypes.Redeemer[];
  /** Required ed25519 key-hash signers in addition to wallet signers. */
  requiredSigners?: Ed25519KeyHashHex[];
  /** Plutus language versions actually used in this tx. */
  usedPlutusVersions?: CardanoTypes.PlutusLanguageVersion[];
  /** Collateral UTxO(s) for Plutus-spending txs. */
  collateralUtxo?: CardanoTypes.Utxo;
  /** Change address (bech32). Defaults to the first wallet UTxO's address. */
  changeAddress: string;
  /** Blockfrost build context (protocol params + validity interval). */
  buildContext: BlockfrostBuildContext;
  /** Optional pre-computed datums attached in the witness set (non-inline). */
  datums?: CardanoTypes.PlutusData[];
  /** Extra fee (lovelace) folded into the selector's min-cost — e.g. the Conway reference-
   *  script fee that cardano-sdk's computeMinimumCost omits. Taken from change. */
  feeSafetyMarginLovelace?: bigint;
  /** The single Plutus-spent input (txId#index). finalize remaps the spend redeemer's pointer
   *  to this input's position in the post-selection sorted input list. */
  spendRedeemerTargetInput?: { txId: string; index: number };
  /** Inline native scripts to attach to the witness (e.g. the legacy handle policy for a native
   *  label-asset mint). */
  nativeScripts?: CardanoTypes.NativeScript[];
}

export interface FinalizedTx {
  /** Unsigned tx CBOR hex. */
  cborHex: string;
  /** txHash (matches body hash). */
  txHash: string;
  /** UTxO refs consumed as inputs. */
  consumedInputs: Set<string>;
  /** Estimated signed tx size in bytes. */
  estimatedSignedTxSize: number;
}

const DUMMY_SCRIPT_DATA_HASH = "0".repeat(64);
const toUtxoRef = (utxo: CardanoTypes.Utxo): string =>
  `${utxo[0].txId}#${utxo[0].index}`;

const toCollateralTxIn = (u: CardanoTypes.Utxo): CardanoTypes.TxIn => ({
  txId: u[0].txId,
  index: u[0].index,
});

/**
 * Plug a provisional tx body shape into `createTransactionInternals` using
 * the given selection, then attach the Plutus fields needed for the Conway
 * witness set. Returns a full `CardanoTypes.Tx` with placeholder vkey
 * witnesses for accurate fee estimation.
 */
const buildTxForSelection = (
  selection: SelectionSkeleton,
  plan: TxPlan,
  scriptDataHash: string,
): CardanoTypes.Tx => {
   
  const bodyWithHash = createTransactionInternals({
    inputSelection: selection,
    validityInterval: plan.buildContext.validityInterval,
    outputs: plan.outputs,
    certificates: plan.certificates,
    withdrawals: plan.withdrawals,
    mint: plan.mint,
    referenceInputs: plan.referenceInputs,
    requiredExtraSignatures: plan.requiredSigners,
    collaterals: plan.collateralUtxo
      ? new Set<CardanoTypes.TxIn>([toCollateralTxIn(plan.collateralUtxo)])
      : undefined,
    scriptIntegrityHash: scriptDataHash as HexBlob,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any);

  const witness: CardanoTypes.Witness = {
    signatures: buildPlaceholderSignatures(
      (plan.requiredSigners?.length ?? 0) + 2,
    ),
    ...(plan.redeemers && plan.redeemers.length > 0
      ? { redeemers: plan.redeemers }
      : {}),
    ...(plan.datums && plan.datums.length > 0 ? { datums: plan.datums } : {}),
    // Inline native scripts (e.g. the legacy handle policy RequireSignature) needed to mint under
    // a native policy. Not part of script_data_hash. Preserved through the vkey-splice on submit.
    ...(plan.nativeScripts && plan.nativeScripts.length > 0 ? { scripts: plan.nativeScripts } : {}),
  };

  return {
    id: transactionHashFromCore({
      body: bodyWithHash.body,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any) as unknown as CardanoTypes.TransactionId,
    body: bodyWithHash.body,
    witness,
  };
};

export const finalizeTxPlan = async (plan: TxPlan): Promise<FinalizedTx> => {
  const changeAddressBech32 = asPaymentAddress(plan.changeAddress);
  const inputSelector = roundRobinRandomImprove({
    changeAddressResolver: {
      resolve: async (selection) =>
        selection.change.map((change) => ({
          ...change,
          address: changeAddressBech32,
        })),
    },
  });
  const txEvaluator = new GreedyTxEvaluator(
    async () => plan.buildContext.protocolParameters,
  );

  // Fill in minimum coin quantity for any output with 0 coins.
  const minimumCoinQuantity = computeMinimumCoinQuantity(
    plan.buildContext.protocolParameters.coinsPerUtxoByte,
  );
  const filledOutputs = plan.outputs.map((out) => {
    if (out.value.coins === 0n) {
      return { ...out, value: { ...out.value, coins: minimumCoinQuantity(out) } };
    }
    return out;
  });
  const planWithFilled: TxPlan = { ...plan, outputs: filledOutputs };

  // The selection's evaluator looks up redeemers by purpose to size ex-units. DeMi passed {} (its
  // mints are native), so any Plutus redeemer threw "No redeemers found for <purpose>". Group by
  // purpose — and note cardano-sdk's shape quirk: SPEND redeemers must be a Map keyed by the spent
  // input "txId#index" (reorgRedeemers iterates its entries + sets the pointer index); every other
  // purpose is a plain array.
  const redeemersByType = {};
  for (const r of planWithFilled.redeemers ?? []) {
    if (r.purpose === "spend") {
      const t = planWithFilled.spendRedeemerTargetInput;
      if (!t) throw new Error("spend redeemer requires plan.spendRedeemerTargetInput");
      (redeemersByType.spend ??= new Map()).set(`${t.txId}#${t.index}`, r);
    } else {
      (redeemersByType[r.purpose] ??= []).push(r);
    }
  }

  const buildForSelection = (selection: SelectionSkeleton) =>
    Promise.resolve(
      buildTxForSelection(selection, planWithFilled, DUMMY_SCRIPT_DATA_HASH),
    );

  const selection = await inputSelector.select({
    preSelectedUtxo: new Set(planWithFilled.preSelectedUtxos),
    utxo: new Set(planWithFilled.spareUtxos),
    outputs: new Set(planWithFilled.outputs),
    constraints: (() => {
      const base = defaultSelectionConstraints({
        protocolParameters: planWithFilled.buildContext.protocolParameters,
        buildTx: buildForSelection,
        redeemersByType,
        txEvaluator,
      });
      // cardano-sdk's computeMinimumCost omits the Conway reference-script fee
      // (minFeeRefScriptCostPerByte × ref-script bytes). With a Plutus tx that references a
      // deployed script, that leaves the fee short → FeeTooSmallUTxO. Add the caller's margin
      // INSIDE the selector so inputs/change are sized for it (bumping after select would break
      // value conservation).
      const margin = planWithFilled.feeSafetyMarginLovelace ?? 0n;
      if (margin <= 0n) return base;
      return {
        ...base,
        computeMinimumCost: async (selection) => {
          const r = await base.computeMinimumCost(selection);
          return { ...r, fee: r.fee + margin };
        },
      };
    })(),
    ...(planWithFilled.mint ? { implicitValue: { mint: planWithFilled.mint } } : {}),
  });

  // Remap the spend redeemer's pointer to its input's position in the SORTED input list. The
  // node identifies a spend redeemer by (tag=spend, index=position in canonical input order),
  // not by which UTxO we meant. Coin selection adds fee inputs, so the script input's final
  // position isn't known until after selection. (DeMi only ever spent a single dominant UTxO, so
  // index 0 happened to hold; SSR's request UTxO can sort anywhere.) Done before the script data
  // hash, which is computed over the redeemers.
  let effectiveRedeemers = planWithFilled.redeemers;
  if (planWithFilled.spendRedeemerTargetInput && planWithFilled.redeemers?.some((r) => r.purpose === "spend")) {
    const probe = buildTxForSelection(selection.selection, planWithFilled, DUMMY_SCRIPT_DATA_HASH);
    const t = planWithFilled.spendRedeemerTargetInput;
    const pos = probe.body.inputs.findIndex((i) => i.txId === t.txId && i.index === t.index);
    if (pos < 0) throw new Error(`spend redeemer target ${t.txId}#${t.index} not among selected inputs`);
    effectiveRedeemers = planWithFilled.redeemers.map((r) => (r.purpose === "spend" ? { ...r, index: pos } : r));
  }
  const planForBuild: TxPlan = { ...planWithFilled, redeemers: effectiveRedeemers };

  // Now compute the real Conway-correct script data hash using the actual
  // redeemers + cost models.
  const scriptDataHash = computeScriptDataHash(
    planForBuild.buildContext.protocolParameters.costModels,
    planForBuild.usedPlutusVersions ?? [],
    effectiveRedeemers,
    planForBuild.datums,
  );

  const finalTx = buildTxForSelection(
    selection.selection,
    planForBuild,
    scriptDataHash ?? DUMMY_SCRIPT_DATA_HASH,
  );

  // Strip placeholder signatures — we return unsigned.
  let finalBody = { ...finalTx.body, fee: selection.selection.fee };

  // Minimize collateral to the protocol-required amount (fee *
  // collateralPercentage / 100), returning the excess to the collateral owner.
  // Without an explicit collateral return the ENTIRE collateral UTxO is the
  // total collateral — which UNDER-collateralizes when the only available
  // ADA-only UTxO is smaller than the requirement (a heavy DeMi sub-mint needs
  // ~10.5 ADA) and dangerously OVER-collateralizes a large one (e.g. an 869 ADA
  // change UTxO put fully at risk). With the return, any UTxO >= required works
  // safely and forfeits only the required amount on script failure.
  if (planWithFilled.collateralUtxo) {
    const collateralCoins = planWithFilled.collateralUtxo[1].value.coins;
    const collateralPct = BigInt(
      planWithFilled.buildContext.protocolParameters.collateralPercentage ?? 150,
    );
    // The ~50-byte collateralReturn output is not in the coin-selection fee
    // estimate (buildTxForSelection omits it), so nudge the declared fee up a
    // touch to stay above min-fee for the slightly larger body.
    const feeWithReturn = finalBody.fee + 5_000n;
    const requiredCollateral = (feeWithReturn * collateralPct + 99n) / 100n;
    const returnCoins = collateralCoins - requiredCollateral;
    if (returnCoins > 0n) {
      const returnOut: CardanoTypes.TxOut = {
        address: planWithFilled.collateralUtxo[1].address,
        value: { coins: returnCoins },
      };
      // Only attach a return if the excess clears the min-UTxO floor; otherwise
      // leave the whole UTxO as collateral (already covers the requirement).
      if (returnCoins >= minimumCoinQuantity(returnOut)) {
        // Bumping the main fee by `feeDelta` must come OUT of the main balance, or
        // inputs < outputs+fee and the node rejects with ValueNotConservedUTxO. Pull
        // it from a change output (the selector sized change against the un-bumped
        // fee). DeMi never hit this — its collateral-return txs carried no change.
        const feeDelta = feeWithReturn - finalBody.fee;
        const changeIdx = finalBody.outputs.findIndex(
          (o) => o.address === changeAddressBech32 && o.value.coins > feeDelta && (!o.value.assets || o.value.assets.size === 0),
        );
        if (changeIdx >= 0) {
          const adjusted = finalBody.outputs.map((o, i) =>
            i === changeIdx ? { ...o, value: { ...o.value, coins: o.value.coins - feeDelta } } : o,
          );
          finalBody = {
            ...finalBody,
            outputs: adjusted,
            fee: feeWithReturn,
            totalCollateral: requiredCollateral,
            collateralReturn: returnOut,
          };
        } else {
          finalBody = { ...finalBody, totalCollateral: requiredCollateral, collateralReturn: returnOut };
        }
      }
    }
  }

  const unsignedTx: CardanoTypes.Tx = {
    ...finalTx,
    id: transactionHashFromCore({
      body: finalBody,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any) as unknown as CardanoTypes.TransactionId,
    body: finalBody,
    witness: {
      ...finalTx.witness,
      signatures: new Map(),
    },
  };

   
  const estimationTx = {
    ...unsignedTx,
    witness: {
      ...unsignedTx.witness,
      signatures: buildPlaceholderSignatures(
        (plan.requiredSigners?.length ?? 0) + 1,
      ),
    },
  };
  const estimatedSignedTxSize =
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (Serialization as any).Transaction.fromCore(estimationTx)
      .toCbor()
      .length / 2;

  const cborHex = transactionToCbor(unsignedTx);
  const txHash =
    typeof unsignedTx.id === "string"
      ? (unsignedTx.id as string)
      : Buffer.from(unsignedTx.id as unknown as Uint8Array).toString("hex");

  const consumedInputs = new Set<string>();
  for (const utxo of selection.selection.inputs) {
    consumedInputs.add(toUtxoRef(utxo));
  }

  return { cborHex, txHash, consumedInputs, estimatedSignedTxSize };
};
