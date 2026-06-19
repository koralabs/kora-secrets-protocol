import { blake2b256, bytesToHex, hexToBytes, type Network, NETWORK_ID, SsrError, SsrErrorCode } from '@koralabs/kora-secrets-crypto';

import type { ApprovalUtxo,PolicyUtxo, RequestUtxo, UtxoRef } from './chain-provider.ts';
import {
  datumToCborHex,
  encodeGuardianApprovalDatum,
  encodeGuardianKeyProfileDatum,
  encodeRecoveryPolicyDatum,
  encodeRecoveryRequestDatum,
  type GuardianApprovalDatum,
  type GuardianKeyProfileDatum,
  type PolicyRef,
  type RecoveryPolicyDatum,
  type RecoveryRequestDatum
} from './datums.ts';
import { encodePlutusData, PD, type PlutusData } from './plutus-data.ts';

/**
 * Derive a recovery `session_id` from a consumed seed-UTxO output reference, byte-identical to
 * the on-chain `ssr/context.session_id_of` (blake2b-256 of the PlutusData-encoded
 * OutputReference). This is what InitiateRecovery binds, guaranteeing uniqueness.
 */
export function deriveSessionId(seed: UtxoRef): string {
  const ref: PlutusData = PD.constr(0, [PD.bytes(hexToBytes(seed.tx_id)), PD.int(seed.index)]);
  return bytesToHex(blake2b256(encodePlutusData(ref)));
}

/** Which SSR script address an output/input belongs to. */
export type SsrScript = 'policy' | 'request' | 'approval' | 'profile';

/** A reference input the tx MUST include to prove control (CIP-31; asset referenced, not spent). */
export interface ReferenceAssetRequirement {
  role: 'owner_handle' | 'guardian_handle' | 'guardian_profile' | 'policy' | 'approval';
  asset_id: string;
}

export interface StateOutputPlan {
  script: SsrScript;
  datum_cbor_hex: string;
}

/**
 * A network- and redeemer-tagged description of everything that must go into an SSR
 * transaction: the redeemer, the reference inputs (CIP-31 control proofs), any seed/spend
 * inputs, the minted state token, and the continuing/created state output. A CIP-30 wallet
 * layer realizes this into a signed CBOR transaction (P5/P6); keeping it as a typed plan keeps
 * the security-critical decisions pure and testable.
 */
export interface TxPlan {
  network: Network;
  network_id: number;
  redeemer: string;
  reference_assets: ReferenceAssetRequirement[];
  seed_utxo?: UtxoRef;
  mint_state_token?: SsrScript;
  spend_input?: { ref: UtxoRef; script: SsrScript };
  output: StateOutputPlan;
}

function assertNetwork(network: Network, datumNetworkId: number): void {
  if (NETWORK_ID[network] !== datumNetworkId) {
    throw new SsrError(
      SsrErrorCode.NetworkMismatch,
      `datum network_id ${datumNetworkId} does not match builder network ${network} (id ${NETWORK_ID[network]})`
    );
  }
}

function assertThreshold(d: RecoveryPolicyDatum): void {
  if (d.shares_n < 1 || d.threshold_m < 1 || d.threshold_m > d.shares_n) {
    throw new SsrError(
      SsrErrorCode.InvalidThreshold,
      `invalid threshold ${d.threshold_m}-of-${d.shares_n}`
    );
  }
}

// ---- builders -----------------------------------------------------------------

export function buildRegisterProfileTx(network: Network, datum: GuardianKeyProfileDatum): TxPlan {
  if (
    !datum.guardian_recovery_pubkey_x25519 &&
    !(datum.key_proof_cid && datum.key_proof_hash_blake2b256)
  ) {
    throw new SsrError(SsrErrorCode.ProfileUnresolvable, 'profile needs an inline key or a proof pair');
  }
  return {
    network,
    network_id: NETWORK_ID[network],
    redeemer: 'RegisterGuardianKeyProfile',
    reference_assets: [{ role: 'guardian_handle', asset_id: datum.guardian_handle_asset_id }],
    mint_state_token: 'profile',
    output: { script: 'profile', datum_cbor_hex: datumToCborHex(encodeGuardianKeyProfileDatum(datum)) }
  };
}

export function buildCreatePolicyTx(network: Network, datum: RecoveryPolicyDatum): TxPlan {
  assertNetwork(network, datum.network_id);
  assertThreshold(datum);
  if (datum.bundle_cids.length < 1) {
    throw new SsrError(SsrErrorCode.InvalidBundle, 'policy must anchor at least one bundle cid');
  }
  if (datum.policy_nonce !== 0) {
    throw new SsrError(SsrErrorCode.InvalidBundle, 'a freshly created policy must have nonce 0');
  }
  return {
    network,
    network_id: NETWORK_ID[network],
    redeemer: 'CreatePolicy',
    reference_assets: [
      { role: 'owner_handle', asset_id: datum.owner_handle_asset_id },
      ...datum.guardian_ids.map((gid) => ({ role: 'guardian_profile' as const, asset_id: gid }))
    ],
    mint_state_token: 'policy',
    output: { script: 'policy', datum_cbor_hex: datumToCborHex(encodeRecoveryPolicyDatum(datum)) }
  };
}

export function buildRotatePolicyTx(network: Network, old: PolicyUtxo, next: RecoveryPolicyDatum): TxPlan {
  assertNetwork(network, next.network_id);
  assertThreshold(next);
  if (next.owner_handle_asset_id !== old.datum.owner_handle_asset_id) {
    throw new SsrError(SsrErrorCode.InvalidBundle, 'rotation must keep the same owner');
  }
  if (next.policy_nonce !== old.datum.policy_nonce + 1) {
    throw new SsrError(SsrErrorCode.InvalidBundle, 'rotation must increment policy_nonce by 1');
  }
  return {
    network,
    network_id: NETWORK_ID[network],
    redeemer: 'RotatePolicy',
    reference_assets: [
      { role: 'owner_handle', asset_id: next.owner_handle_asset_id },
      ...next.guardian_ids.map((gid) => ({ role: 'guardian_profile' as const, asset_id: gid }))
    ],
    spend_input: { ref: old.ref, script: 'policy' },
    output: { script: 'policy', datum_cbor_hex: datumToCborHex(encodeRecoveryPolicyDatum(next)) }
  };
}

export interface InitiateRecoveryArgs {
  network: Network;
  seed_utxo: UtxoRef;
  policy_ref: PolicyRef;
  recovery_pubkey_x25519: string;
  created_slot: number;
}

/** Builds the request datum with `session_id` derived from the seed UTxO (unique by construction). */
export function buildInitiateRecoveryTx(args: InitiateRecoveryArgs): { plan: TxPlan; datum: RecoveryRequestDatum } {
  const session_id = deriveSessionId(args.seed_utxo);
  const datum: RecoveryRequestDatum = {
    version: 1,
    policy_ref: args.policy_ref,
    session_id,
    recovery_pubkey_x25519: args.recovery_pubkey_x25519,
    created_slot: args.created_slot,
    status: 'Pending'
  };
  if (hexToBytes(args.recovery_pubkey_x25519).length !== 32) {
    throw new SsrError(SsrErrorCode.InvalidKeyLength, 'recovery_pubkey_x25519 must be 32 bytes');
  }
  const plan: TxPlan = {
    network: args.network,
    network_id: NETWORK_ID[args.network],
    redeemer: 'InitiateRecovery',
    reference_assets: [],
    seed_utxo: args.seed_utxo,
    mint_state_token: 'request',
    output: { script: 'request', datum_cbor_hex: datumToCborHex(encodeRecoveryRequestDatum(datum)) }
  };
  return { plan, datum };
}

export function buildCancelRecoveryTx(network: Network, request: RequestUtxo): TxPlan {
  if (request.datum.status !== 'Pending') {
    throw new SsrError(SsrErrorCode.SessionMismatch, 'only a Pending request can be cancelled');
  }
  const canceled: RecoveryRequestDatum = { ...request.datum, status: 'Canceled' };
  return {
    network,
    network_id: NETWORK_ID[network],
    redeemer: 'CancelRecovery',
    reference_assets: [{ role: 'owner_handle', asset_id: request.datum.policy_ref.owner_handle_asset_id }],
    spend_input: { ref: request.ref, script: 'request' },
    output: { script: 'request', datum_cbor_hex: datumToCborHex(encodeRecoveryRequestDatum(canceled)) }
  };
}

export function buildApproveRecoveryTx(network: Network, datum: GuardianApprovalDatum): TxPlan {
  if (datum.reencrypted_share_cid.length === 0) {
    throw new SsrError(SsrErrorCode.InvalidArtifact, 'approval needs a non-empty re-encrypted share cid');
  }
  return {
    network,
    network_id: NETWORK_ID[network],
    redeemer: 'ApproveRecovery',
    reference_assets: [
      { role: 'guardian_handle', asset_id: datum.guardian_id },
      { role: 'policy', asset_id: datum.policy_ref.owner_handle_asset_id }
    ],
    mint_state_token: 'approval',
    output: { script: 'approval', datum_cbor_hex: datumToCborHex(encodeGuardianApprovalDatum(datum)) }
  };
}

export function buildCompleteRecoveryTx(
  network: Network,
  request: RequestUtxo,
  approvals: ApprovalUtxo[]
): TxPlan {
  const completed: RecoveryRequestDatum = { ...request.datum, status: 'Completed' };
  return {
    network,
    network_id: NETWORK_ID[network],
    redeemer: 'CompleteRecovery',
    reference_assets: [
      { role: 'policy', asset_id: request.datum.policy_ref.owner_handle_asset_id },
      ...approvals.map((a) => ({ role: 'approval' as const, asset_id: a.datum.guardian_id }))
    ],
    spend_input: { ref: request.ref, script: 'request' },
    output: { script: 'request', datum_cbor_hex: datumToCborHex(encodeRecoveryRequestDatum(completed)) }
  };
}
