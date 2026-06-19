import { bytesToHex, hexToBytes, utf8ToBytes } from '@koralabs/kora-secrets-crypto';

import { decodePlutusData, encodePlutusData, PD, type PlutusData } from './plutus-data.ts';

// Off-chain mirrors of the Aiken datums (contracts/lib/ssr/types.ak). Byte fields are hex
// strings; field order matches the on-chain types so the CBOR is byte-identical to the
// pinned fixtures (contracts/fixtures/datum-cbor-v1.json).

export type GuardianKeySource = 'HandleControlled';
export type RequestStatus = 'Pending' | 'Canceled' | 'Completed';

export interface PolicyRef {
  owner_handle_asset_id: string;
  policy_nonce: number;
}

export interface GuardianKeyProfileDatum {
  version: number;
  guardian_handle_asset_id: string;
  paired_token_label: number;
  guardian_key_source: GuardianKeySource;
  guardian_recovery_pubkey_x25519: string | null;
  key_proof_cid: string | null;
  key_proof_hash_blake2b256: string | null;
  updated_slot: number;
}

export interface RecoveryPolicyDatum {
  version: number;
  network_id: number;
  owner_handle_asset_id: string;
  threshold_m: number;
  shares_n: number;
  timelock_seconds: number;
  guardian_ids: string[];
  bundle_hash_blake2b256: string;
  bundle_cids: string[];
  policy_nonce: number;
}

export interface RecoveryRequestDatum {
  version: number;
  policy_ref: PolicyRef;
  session_id: string;
  recovery_pubkey_x25519: string;
  created_slot: number;
  status: RequestStatus;
}

export interface GuardianApprovalDatum {
  version: number;
  policy_ref: PolicyRef;
  session_id: string;
  guardian_id: string;
  reencrypted_share_cid: string;
}

// Hashes, keys, and asset ids are hex-encoded byte fields.
const b = (hex: string): PlutusData => PD.bytes(hexToBytes(hex));
// CID fields are TEXT (IPFS CID strings); on-chain they are the UTF-8 bytes of that text.
const t = (text: string): PlutusData => PD.bytes(utf8ToBytes(text));

function option(hex: string | null): PlutusData {
  return hex === null ? PD.constr(1, []) : PD.constr(0, [b(hex)]);
}

/** Option<ByteArray> where the present value is a CID (UTF-8 text), not hex. */
function optionText(text: string | null): PlutusData {
  return text === null ? PD.constr(1, []) : PD.constr(0, [t(text)]);
}

function encodePolicyRef(ref: PolicyRef): PlutusData {
  return PD.constr(0, [b(ref.owner_handle_asset_id), PD.int(ref.policy_nonce)]);
}

const REQUEST_STATUS: RequestStatus[] = ['Pending', 'Canceled', 'Completed'];

// ---- encoders -----------------------------------------------------------------

export function encodeGuardianKeyProfileDatum(d: GuardianKeyProfileDatum): PlutusData {
  return PD.constr(0, [
    PD.int(d.version),
    b(d.guardian_handle_asset_id),
    PD.int(d.paired_token_label),
    PD.constr(0, []), // GuardianKeySource::HandleControlled
    option(d.guardian_recovery_pubkey_x25519),
    optionText(d.key_proof_cid),
    option(d.key_proof_hash_blake2b256),
    PD.int(d.updated_slot)
  ]);
}

export function encodeRecoveryPolicyDatum(d: RecoveryPolicyDatum): PlutusData {
  return PD.constr(0, [
    PD.int(d.version),
    PD.int(d.network_id),
    b(d.owner_handle_asset_id),
    PD.int(d.threshold_m),
    PD.int(d.shares_n),
    PD.int(d.timelock_seconds),
    PD.list(d.guardian_ids.map(b)),
    b(d.bundle_hash_blake2b256),
    PD.list(d.bundle_cids.map(t)),
    PD.int(d.policy_nonce)
  ]);
}

export function encodeRecoveryRequestDatum(d: RecoveryRequestDatum): PlutusData {
  return PD.constr(0, [
    PD.int(d.version),
    encodePolicyRef(d.policy_ref),
    b(d.session_id),
    b(d.recovery_pubkey_x25519),
    PD.int(d.created_slot),
    PD.constr(REQUEST_STATUS.indexOf(d.status), [])
  ]);
}

export function encodeGuardianApprovalDatum(d: GuardianApprovalDatum): PlutusData {
  return PD.constr(0, [
    PD.int(d.version),
    encodePolicyRef(d.policy_ref),
    b(d.session_id),
    b(d.guardian_id),
    t(d.reencrypted_share_cid)
  ]);
}

export function datumToCborHex(d: PlutusData): string {
  return bytesToHex(encodePlutusData(d));
}

// ---- decoders -----------------------------------------------------------------

class DecodeError extends Error {}

function expectConstr(d: PlutusData, index?: number): PlutusData[] {
  if (d.kind !== 'constr' || (index !== undefined && d.index !== index)) {
    throw new DecodeError(`expected constructor ${index ?? ''}, got ${d.kind}`);
  }
  return d.fields;
}

function asInt(d: PlutusData): number {
  if (d.kind !== 'int') throw new DecodeError('expected int');
  return Number(d.value);
}

function asHex(d: PlutusData): string {
  if (d.kind !== 'bytes') throw new DecodeError('expected bytes');
  return bytesToHex(d.value);
}

function asText(d: PlutusData): string {
  if (d.kind !== 'bytes') throw new DecodeError('expected bytes');
  return new TextDecoder().decode(d.value);
}

function asOption(d: PlutusData): string | null {
  const fields = expectConstr(d);
  if ((d as { index: number }).index === 1) return null;
  return asHex(fields[0]!);
}

function asOptionText(d: PlutusData): string | null {
  const fields = expectConstr(d);
  if ((d as { index: number }).index === 1) return null;
  return asText(fields[0]!);
}

function asList(d: PlutusData): PlutusData[] {
  if (d.kind !== 'list') throw new DecodeError('expected list');
  return d.items;
}

function decodePolicyRef(d: PlutusData): PolicyRef {
  const f = expectConstr(d, 0);
  return { owner_handle_asset_id: asHex(f[0]!), policy_nonce: asInt(f[1]!) };
}

export function decodeGuardianKeyProfileDatum(bytes: Uint8Array): GuardianKeyProfileDatum {
  const f = expectConstr(decodePlutusData(bytes), 0);
  expectConstr(f[3]!, 0); // HandleControlled
  return {
    version: asInt(f[0]!),
    guardian_handle_asset_id: asHex(f[1]!),
    paired_token_label: asInt(f[2]!),
    guardian_key_source: 'HandleControlled',
    guardian_recovery_pubkey_x25519: asOption(f[4]!),
    key_proof_cid: asOptionText(f[5]!),
    key_proof_hash_blake2b256: asOption(f[6]!),
    updated_slot: asInt(f[7]!)
  };
}

export function decodeRecoveryPolicyDatum(bytes: Uint8Array): RecoveryPolicyDatum {
  const f = expectConstr(decodePlutusData(bytes), 0);
  return {
    version: asInt(f[0]!),
    network_id: asInt(f[1]!),
    owner_handle_asset_id: asHex(f[2]!),
    threshold_m: asInt(f[3]!),
    shares_n: asInt(f[4]!),
    timelock_seconds: asInt(f[5]!),
    guardian_ids: asList(f[6]!).map(asHex),
    bundle_hash_blake2b256: asHex(f[7]!),
    bundle_cids: asList(f[8]!).map(asText),
    policy_nonce: asInt(f[9]!)
  };
}

export function decodeRecoveryRequestDatum(bytes: Uint8Array): RecoveryRequestDatum {
  const f = expectConstr(decodePlutusData(bytes), 0);
  const statusIndex = (f[5] as { index: number }).index;
  const status = REQUEST_STATUS[statusIndex];
  if (status === undefined) throw new DecodeError(`unknown request status index ${statusIndex}`);
  return {
    version: asInt(f[0]!),
    policy_ref: decodePolicyRef(f[1]!),
    session_id: asHex(f[2]!),
    recovery_pubkey_x25519: asHex(f[3]!),
    created_slot: asInt(f[4]!),
    status
  };
}

export function decodeGuardianApprovalDatum(bytes: Uint8Array): GuardianApprovalDatum {
  const f = expectConstr(decodePlutusData(bytes), 0);
  return {
    version: asInt(f[0]!),
    policy_ref: decodePolicyRef(f[1]!),
    session_id: asHex(f[2]!),
    guardian_id: asHex(f[3]!),
    reencrypted_share_cid: asText(f[4]!)
  };
}
