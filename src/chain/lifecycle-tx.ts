import type { Cardano as CardanoTypes } from '@cardano-sdk/core';
import { computeMinimumCoinQuantity } from '@cardano-sdk/tx-construction';
import type { HexBlob } from '@cardano-sdk/util';
import { hexToBytes } from '@koralabs/kora-secrets-crypto';

import { type BlockfrostBuildContext } from '../cardano-sdk/blockfrostContext.ts';
import { Cardano, Serialization } from '../cardano-sdk/index.ts';
import { finalizeTxPlan, type TxPlan as DemiTxPlan } from '../cardano-sdk/txPlan.ts';
import { datumToCborHex, decodeRecoveryRequestDatum, encodeGuardianApprovalDatum, encodeRecoveryPolicyDatum, encodeRecoveryRequestDatum, type GuardianApprovalDatum, type RecoveryPolicyDatum } from '../datums.ts';
import { PD } from '../plutus-data.ts';
import { buildInitiateRecoveryTx, type InitiateRecoveryArgs } from '../tx-builders.ts';

// SSR Plutus lifecycle realizer: turn an SSR semantic tx-plan into a balanced, ex-unit-evaluated,
// script_data_hash'd unsigned tx via DeMi's finalizeTxPlan. Pure @cardano-sdk + scalus. Validated
// live on preview. The on-chain validators are referenced (deployed ref scripts), never inlined.

// SsrRedeemer constructor order (contracts/lib/ssr/types.ak) → mint/spend redeemer index.
const SSR_REDEEMER_INDEX = {
  RegisterGuardianKeyProfile: 0,
  CreatePolicy: 1,
  RotatePolicy: 2,
  InitiateRecovery: 3,
  CancelRecovery: 4,
  ApproveRecovery: 5,
  CompleteRecovery: 6
} as const;

export const encodeSsrRedeemerCbor = (action: keyof typeof SSR_REDEEMER_INDEX): string =>
  datumToCborHex(PD.constr(SSR_REDEEMER_INDEX[action], []));

/** Enterprise (no-stake) script address for a validator hash — matches `address.from_script`. */
export const scriptEnterpriseAddress = (scriptHash: string, networkId: number): string =>
  Cardano.EnterpriseAddress.fromCredentials(networkId, {
    type: Cardano.CredentialType.ScriptHash,
    hash: scriptHash as never
  })
    .toAddress()
    .toBech32();

export interface InitiateRecoveryRealArgs {
  /** Datum/session inputs (the semantic plan is built from these). */
  recovery: Omit<InitiateRecoveryArgs, 'seed_utxo'>;
  networkId: number;
  /** Compiled+deployed ssr_request script: its hash (= mint policy id) + reference UTxO + size. */
  ssrRequestScriptHash: string;
  refScriptUtxo: { txId: string; outputIndex: number };
  /** Byte size of the referenced script — for the Conway reference-script fee margin. */
  refScriptBytes: number;
  /** The seed UTxO — consumed as an input; session_id is derived from its ref. */
  seedUtxo: CardanoTypes.Utxo;
  /** Wallet UTxOs available to cover fees (excluding the seed + collateral). */
  spareUtxos: CardanoTypes.Utxo[];
  collateralUtxo: CardanoTypes.Utxo;
  changeAddress: string;
  buildContext: BlockfrostBuildContext;
}

export interface RealizedTx {
  unsignedTxCbor: string;
  txHash: string;
  sessionId: string;
  stateTokenAssetId: string;
}

/**
 * Build an unsigned InitiateRecovery tx: mint one state token under the ssr_request policy and
 * place it (with the Pending RecoveryRequestDatum) at the ssr_request script address, consuming
 * the seed UTxO that binds session_id. References the deployed ssr_request script.
 */
export const buildInitiateRecoveryRealTx = async (args: InitiateRecoveryRealArgs): Promise<RealizedTx> => {
  const seedRef = { tx_id: args.seedUtxo[0].txId, index: args.seedUtxo[0].index };
  const { plan: semanticPlan, datum } = buildInitiateRecoveryTx({ ...args.recovery, seed_utxo: seedRef });
  const sessionId = datum.session_id;
  const datumCborHex = semanticPlan.output?.datum_cbor_hex;
  if (!datumCborHex) throw new Error('initiate-recovery plan missing datum');

  // State token: any name under the ssr_request policy satisfies `carries_state_token`; use the
  // session_id (32 bytes) so the token is traceable to its request.
  const policyId = Cardano.PolicyId(args.ssrRequestScriptHash as HexBlob);
  const assetId = Cardano.AssetId.fromParts(policyId, Cardano.AssetName(sessionId as HexBlob));
  const mint = new Map<CardanoTypes.AssetId, bigint>([[assetId, 1n]]);

  const scriptAddress = scriptEnterpriseAddress(args.ssrRequestScriptHash, args.networkId);
  const datumCore = Serialization.PlutusData.fromCbor(datumCborHex as HexBlob).toCore();

  const output: CardanoTypes.TxOut = {
    address: scriptAddress as CardanoTypes.PaymentAddress,
    value: { coins: 0n, assets: new Map([[assetId, 1n]]) },
    datum: datumCore
  };
  output.value = { ...output.value, coins: computeMinimumCoinQuantity(args.buildContext.protocolParameters.coinsPerUtxoByte)(output) };

  // Declare a generous ex-unit budget (the protocol per-tx max). The node re-runs the script
  // and only requires it to SUCCEED within this ceiling; the small ssr_request mint validator
  // uses a fraction of it. (computeScriptDataHash runs over these units, so they're set here,
  // before finalize.) A precise scalus pre-eval can tighten the fee later.
  const maxExUnits = args.buildContext.protocolParameters.maxExecutionUnitsPerTransaction;
  const mintRedeemer: CardanoTypes.Redeemer = {
    data: Serialization.PlutusData.fromCbor(encodeSsrRedeemerCbor('InitiateRecovery') as HexBlob).toCore(),
    executionUnits: { memory: maxExUnits.memory, steps: maxExUnits.steps },
    index: 0,
    purpose: Cardano.RedeemerPurpose.mint
  };

  const referenceInputs = new Set<CardanoTypes.TxIn>([
    { txId: Cardano.TransactionId(args.refScriptUtxo.txId as HexBlob), index: args.refScriptUtxo.outputIndex }
  ]);

  // Conway reference-script fee (minFeeRefScriptCostPerByte × ref-script bytes) that the
  // selector's computeMinimumCost omits; ×1.5 headroom (overpay just shrinks change).
  const refScriptRate = Number(args.buildContext.protocolParameters.minFeeRefScriptCostPerByte ?? 15) || 15;
  const feeSafetyMarginLovelace = BigInt(Math.ceil(args.refScriptBytes * refScriptRate * 1.5)) + 5_000n;

  const plan: DemiTxPlan = {
    preSelectedUtxos: [args.seedUtxo],
    spareUtxos: args.spareUtxos,
    outputs: [output],
    referenceInputs,
    mint,
    redeemers: [mintRedeemer],
    usedPlutusVersions: [Cardano.PlutusLanguageVersion.V3],
    collateralUtxo: args.collateralUtxo,
    changeAddress: args.changeAddress,
    buildContext: args.buildContext,
    feeSafetyMarginLovelace
  };

  const finalized = await finalizeTxPlan(plan);
  return { unsignedTxCbor: finalized.cborHex, txHash: finalized.txHash, sessionId, stateTokenAssetId: assetId };
};

export interface CancelRecoveryRealArgs {
  networkId: number;
  ssrRequestScriptHash: string;
  refScriptUtxo: { txId: string; outputIndex: number };
  refScriptBytes: number;
  /** The Pending request UTxO being cancelled: its ref, ADA, the state token it carries, datum. */
  request: { txId: string; index: number; coins: bigint; stateTokenAssetId: string; datumCborHex: string };
  /** A read-only reference input that holds the owner Handle token (proves owner authorization). */
  ownerHandleRefUtxo: { txId: string; index: number };
  spareUtxos: CardanoTypes.Utxo[];
  collateralUtxo: CardanoTypes.Utxo;
  changeAddress: string;
  buildContext: BlockfrostBuildContext;
}

/**
 * Build an unsigned CancelRecovery tx: SPEND the Pending request UTxO and re-create it Canceled
 * (same session_id + policy_ref, carrying the same state token — no mint) at the ssr_request
 * script, while referencing the owner Handle UTxO (references_asset). References the deployed
 * ssr_request script for the spend.
 */
export const buildCancelRecoveryRealTx = async (args: CancelRecoveryRealArgs): Promise<RealizedTx> => {
  const old = decodeRecoveryRequestDatum(hexToBytes(args.request.datumCborHex));
  if (old.status !== 'Pending') throw new Error('only a Pending request can be cancelled');
  const newDatumCborHex = datumToCborHex(encodeRecoveryRequestDatum({ ...old, status: 'Canceled' }));

  const scriptAddress = scriptEnterpriseAddress(args.ssrRequestScriptHash, args.networkId) as CardanoTypes.PaymentAddress;
  const tokenAssetId = args.request.stateTokenAssetId as CardanoTypes.AssetId;

  // Resolve the script UTxO being spent (its inline datum + the state token it carries).
  const requestUtxo: CardanoTypes.Utxo = [
    { txId: args.request.txId as HexBlob, index: args.request.index, address: scriptAddress },
    {
      address: scriptAddress,
      value: { coins: args.request.coins, assets: new Map([[tokenAssetId, 1n]]) },
      datum: Serialization.PlutusData.fromCbor(args.request.datumCborHex as HexBlob).toCore()
    }
  ];

  // The Canceled output carries the same state token forward (no mint/burn).
  const output: CardanoTypes.TxOut = {
    address: scriptAddress,
    value: { coins: 0n, assets: new Map([[tokenAssetId, 1n]]) },
    datum: Serialization.PlutusData.fromCbor(newDatumCborHex as HexBlob).toCore()
  };
  output.value = { ...output.value, coins: computeMinimumCoinQuantity(args.buildContext.protocolParameters.coinsPerUtxoByte)(output) };

  const maxExUnits = args.buildContext.protocolParameters.maxExecutionUnitsPerTransaction;
  const spendRedeemer: CardanoTypes.Redeemer = {
    data: Serialization.PlutusData.fromCbor(encodeSsrRedeemerCbor('CancelRecovery') as HexBlob).toCore(),
    executionUnits: { memory: maxExUnits.memory, steps: maxExUnits.steps },
    index: 0, // remapped by finalize to the request input's sorted position
    purpose: Cardano.RedeemerPurpose.spend
  };

  const referenceInputs = new Set<CardanoTypes.TxIn>([
    { txId: Cardano.TransactionId(args.refScriptUtxo.txId as HexBlob), index: args.refScriptUtxo.outputIndex },
    { txId: Cardano.TransactionId(args.ownerHandleRefUtxo.txId as HexBlob), index: args.ownerHandleRefUtxo.index }
  ]);

  const refScriptRate = Number(args.buildContext.protocolParameters.minFeeRefScriptCostPerByte ?? 15) || 15;
  const feeSafetyMarginLovelace = BigInt(Math.ceil(args.refScriptBytes * refScriptRate * 1.5)) + 5_000n;

  const plan: DemiTxPlan = {
    preSelectedUtxos: [requestUtxo],
    spareUtxos: args.spareUtxos,
    outputs: [output],
    referenceInputs,
    redeemers: [spendRedeemer],
    usedPlutusVersions: [Cardano.PlutusLanguageVersion.V3],
    collateralUtxo: args.collateralUtxo,
    changeAddress: args.changeAddress,
    buildContext: args.buildContext,
    feeSafetyMarginLovelace,
    spendRedeemerTargetInput: { txId: args.request.txId, index: args.request.index }
  };

  const finalized = await finalizeTxPlan(plan);
  return { unsignedTxCbor: finalized.cborHex, txHash: finalized.txHash, sessionId: old.session_id, stateTokenAssetId: tokenAssetId };
};

export interface CreatePolicyRealArgs {
  networkId: number;
  /** Deployed ssr_policy script (parameterized by the (003) issuer policy): hash + ref UTxO + size. */
  ssrPolicyScriptHash: string;
  refScriptUtxo: { txId: string; outputIndex: number };
  refScriptBytes: number;
  policy: RecoveryPolicyDatum;
  /** Read-only reference inputs: the owner Handle UTxO + each guardian (003) profile UTxO. */
  ownerHandleRefUtxo: { txId: string; index: number };
  guardianProfileRefUtxos: { txId: string; index: number }[];
  walletUtxos: CardanoTypes.Utxo[];
  collateralUtxo: CardanoTypes.Utxo;
  changeAddress: string;
  buildContext: BlockfrostBuildContext;
}

/**
 * Build an unsigned CreatePolicy tx: MINT one ssr_policy state token and place the
 * RecoveryPolicyDatum at the ssr_policy script, while referencing the owner Handle + every
 * guardian's (003) profile (all_guardians_resolvable). References the deployed ssr_policy script.
 */
export const buildCreatePolicyRealTx = async (args: CreatePolicyRealArgs): Promise<RealizedTx> => {
  const policyId = Cardano.PolicyId(args.ssrPolicyScriptHash as HexBlob);
  // State-token name: the owner-handle bytes (any name satisfies carries_state_token; this is
  // traceable + lets one owner hold distinct policy tokens by nonce if extended).
  const tokenName = args.policy.owner_handle_asset_id.slice(-30);
  const assetId = Cardano.AssetId.fromParts(policyId, Cardano.AssetName(tokenName as HexBlob));
  const mint = new Map<CardanoTypes.AssetId, bigint>([[assetId, 1n]]);

  const scriptAddress = scriptEnterpriseAddress(args.ssrPolicyScriptHash, args.networkId) as CardanoTypes.PaymentAddress;
  const datumCore = Serialization.PlutusData.fromCbor(datumToCborHex(encodeRecoveryPolicyDatum(args.policy)) as HexBlob).toCore();
  const output: CardanoTypes.TxOut = { address: scriptAddress, value: { coins: 0n, assets: new Map([[assetId, 1n]]) }, datum: datumCore };
  output.value = { ...output.value, coins: computeMinimumCoinQuantity(args.buildContext.protocolParameters.coinsPerUtxoByte)(output) };

  const maxExUnits = args.buildContext.protocolParameters.maxExecutionUnitsPerTransaction;
  const mintRedeemer: CardanoTypes.Redeemer = {
    data: Serialization.PlutusData.fromCbor(encodeSsrRedeemerCbor('CreatePolicy') as HexBlob).toCore(),
    executionUnits: { memory: maxExUnits.memory, steps: maxExUnits.steps },
    index: 0,
    purpose: Cardano.RedeemerPurpose.mint
  };

  const referenceInputs = new Set<CardanoTypes.TxIn>([
    { txId: Cardano.TransactionId(args.refScriptUtxo.txId as HexBlob), index: args.refScriptUtxo.outputIndex },
    { txId: Cardano.TransactionId(args.ownerHandleRefUtxo.txId as HexBlob), index: args.ownerHandleRefUtxo.index },
    ...args.guardianProfileRefUtxos.map((u) => ({ txId: Cardano.TransactionId(u.txId as HexBlob), index: u.index }))
  ]);

  const refScriptRate = Number(args.buildContext.protocolParameters.minFeeRefScriptCostPerByte ?? 15) || 15;
  const feeSafetyMarginLovelace = BigInt(Math.ceil(args.refScriptBytes * refScriptRate * 1.5)) + 5_000n;

  const plan: DemiTxPlan = {
    preSelectedUtxos: [],
    spareUtxos: args.walletUtxos,
    outputs: [output],
    referenceInputs,
    mint,
    redeemers: [mintRedeemer],
    usedPlutusVersions: [Cardano.PlutusLanguageVersion.V3],
    collateralUtxo: args.collateralUtxo,
    changeAddress: args.changeAddress,
    buildContext: args.buildContext,
    feeSafetyMarginLovelace
  };

  const finalized = await finalizeTxPlan(plan);
  return { unsignedTxCbor: finalized.cborHex, txHash: finalized.txHash, sessionId: args.policy.owner_handle_asset_id, stateTokenAssetId: assetId };
};

export interface ApproveRecoveryRealArgs {
  networkId: number;
  /** Deployed ssr_approval script (unparameterized): hash + ref UTxO + size. */
  ssrApprovalScriptHash: string;
  refScriptUtxo: { txId: string; outputIndex: number };
  refScriptBytes: number;
  approval: GuardianApprovalDatum;
  /** Ref inputs: the policy UTxO (find_referenced_policy) + the guardian's Handle UTxO. */
  policyRefUtxo: { txId: string; index: number };
  guardianHandleRefUtxo: { txId: string; index: number };
  walletUtxos: CardanoTypes.Utxo[];
  collateralUtxo: CardanoTypes.Utxo;
  changeAddress: string;
  buildContext: BlockfrostBuildContext;
}

/**
 * Build an unsigned ApproveRecovery tx: MINT one ssr_approval state token + place the
 * GuardianApprovalDatum at the ssr_approval script, referencing the policy (find_referenced_policy)
 * and the guardian's Handle (references_asset). References the deployed ssr_approval script.
 */
export const buildApproveRecoveryRealTx = async (args: ApproveRecoveryRealArgs): Promise<RealizedTx> => {
  const policyId = Cardano.PolicyId(args.ssrApprovalScriptHash as HexBlob);
  const assetId = Cardano.AssetId.fromParts(policyId, Cardano.AssetName(args.approval.session_id as HexBlob));
  const mint = new Map<CardanoTypes.AssetId, bigint>([[assetId, 1n]]);

  const scriptAddress = scriptEnterpriseAddress(args.ssrApprovalScriptHash, args.networkId) as CardanoTypes.PaymentAddress;
  const datumCore = Serialization.PlutusData.fromCbor(datumToCborHex(encodeGuardianApprovalDatum(args.approval)) as HexBlob).toCore();
  const output: CardanoTypes.TxOut = { address: scriptAddress, value: { coins: 0n, assets: new Map([[assetId, 1n]]) }, datum: datumCore };
  output.value = { ...output.value, coins: computeMinimumCoinQuantity(args.buildContext.protocolParameters.coinsPerUtxoByte)(output) };

  const maxExUnits = args.buildContext.protocolParameters.maxExecutionUnitsPerTransaction;
  const mintRedeemer: CardanoTypes.Redeemer = {
    data: Serialization.PlutusData.fromCbor(encodeSsrRedeemerCbor('ApproveRecovery') as HexBlob).toCore(),
    executionUnits: { memory: maxExUnits.memory, steps: maxExUnits.steps },
    index: 0,
    purpose: Cardano.RedeemerPurpose.mint
  };

  const referenceInputs = new Set<CardanoTypes.TxIn>([
    { txId: Cardano.TransactionId(args.refScriptUtxo.txId as HexBlob), index: args.refScriptUtxo.outputIndex },
    { txId: Cardano.TransactionId(args.policyRefUtxo.txId as HexBlob), index: args.policyRefUtxo.index },
    { txId: Cardano.TransactionId(args.guardianHandleRefUtxo.txId as HexBlob), index: args.guardianHandleRefUtxo.index }
  ]);

  const refScriptRate = Number(args.buildContext.protocolParameters.minFeeRefScriptCostPerByte ?? 15) || 15;
  const feeSafetyMarginLovelace = BigInt(Math.ceil(args.refScriptBytes * refScriptRate * 1.5)) + 5_000n;

  const plan: DemiTxPlan = {
    preSelectedUtxos: [],
    spareUtxos: args.walletUtxos,
    outputs: [output],
    referenceInputs,
    mint,
    redeemers: [mintRedeemer],
    usedPlutusVersions: [Cardano.PlutusLanguageVersion.V3],
    collateralUtxo: args.collateralUtxo,
    changeAddress: args.changeAddress,
    buildContext: args.buildContext,
    feeSafetyMarginLovelace
  };

  const finalized = await finalizeTxPlan(plan);
  return { unsignedTxCbor: finalized.cborHex, txHash: finalized.txHash, sessionId: args.approval.session_id, stateTokenAssetId: assetId };
};

export interface CompleteRecoveryRealArgs {
  networkId: number;
  ssrRequestScriptHash: string;
  refScriptUtxo: { txId: string; outputIndex: number };
  refScriptBytes: number;
  /** The Pending request being completed: ref, ADA, the state token it carries, datum. */
  request: { txId: string; index: number; coins: bigint; stateTokenAssetId: string; datumCborHex: string };
  /** Read-only refs: the policy UTxO (find_referenced_policy) + each guardian approval UTxO
   *  (distinct_approver_count). */
  policyRefUtxo: { txId: string; index: number };
  approvalRefUtxos: { txId: string; index: number }[];
  spareUtxos: CardanoTypes.Utxo[];
  collateralUtxo: CardanoTypes.Utxo;
  changeAddress: string;
  buildContext: BlockfrostBuildContext;
}

/**
 * Build an unsigned CompleteRecovery tx: SPEND the Pending request (its value returns to the owner)
 * while referencing the policy + ≥ threshold guardian approvals (distinct_approver_count). No
 * continuing datum — the recovery is complete. References the deployed ssr_request script.
 */
export const buildCompleteRecoveryRealTx = async (args: CompleteRecoveryRealArgs): Promise<RealizedTx> => {
  const old = decodeRecoveryRequestDatum(hexToBytes(args.request.datumCborHex));
  if (old.status !== 'Pending') throw new Error('only a Pending request can be completed');

  const scriptAddress = scriptEnterpriseAddress(args.ssrRequestScriptHash, args.networkId) as CardanoTypes.PaymentAddress;
  const tokenAssetId = args.request.stateTokenAssetId as CardanoTypes.AssetId;
  const requestUtxo: CardanoTypes.Utxo = [
    { txId: args.request.txId as HexBlob, index: args.request.index, address: scriptAddress },
    { address: scriptAddress, value: { coins: args.request.coins, assets: new Map([[tokenAssetId, 1n]]) }, datum: Serialization.PlutusData.fromCbor(args.request.datumCborHex as HexBlob).toCore() }
  ];
  // The request's value (ADA + state token) returns to the owner — no continuing state output.
  const out: CardanoTypes.TxOut = { address: args.changeAddress as CardanoTypes.PaymentAddress, value: { coins: args.request.coins, assets: new Map([[tokenAssetId, 1n]]) } };

  const maxExUnits = args.buildContext.protocolParameters.maxExecutionUnitsPerTransaction;
  const spendRedeemer: CardanoTypes.Redeemer = {
    data: Serialization.PlutusData.fromCbor(encodeSsrRedeemerCbor('CompleteRecovery') as HexBlob).toCore(),
    executionUnits: { memory: maxExUnits.memory, steps: maxExUnits.steps },
    index: 0,
    purpose: Cardano.RedeemerPurpose.spend
  };

  const referenceInputs = new Set<CardanoTypes.TxIn>([
    { txId: Cardano.TransactionId(args.refScriptUtxo.txId as HexBlob), index: args.refScriptUtxo.outputIndex },
    { txId: Cardano.TransactionId(args.policyRefUtxo.txId as HexBlob), index: args.policyRefUtxo.index },
    ...args.approvalRefUtxos.map((u) => ({ txId: Cardano.TransactionId(u.txId as HexBlob), index: u.index }))
  ]);

  const refScriptRate = Number(args.buildContext.protocolParameters.minFeeRefScriptCostPerByte ?? 15) || 15;
  const feeSafetyMarginLovelace = BigInt(Math.ceil(args.refScriptBytes * refScriptRate * 1.5)) + 5_000n;

  const plan: DemiTxPlan = {
    preSelectedUtxos: [requestUtxo],
    spareUtxos: args.spareUtxos,
    outputs: [out],
    referenceInputs,
    redeemers: [spendRedeemer],
    usedPlutusVersions: [Cardano.PlutusLanguageVersion.V3],
    collateralUtxo: args.collateralUtxo,
    changeAddress: args.changeAddress,
    buildContext: args.buildContext,
    feeSafetyMarginLovelace,
    spendRedeemerTargetInput: { txId: args.request.txId, index: args.request.index }
  };

  const finalized = await finalizeTxPlan(plan);
  return { unsignedTxCbor: finalized.cborHex, txHash: finalized.txHash, sessionId: old.session_id, stateTokenAssetId: tokenAssetId };
};
