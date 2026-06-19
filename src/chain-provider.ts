import { blake2b256, bytesEqual, bytesToHex, hexToBytes, SsrError, SsrErrorCode } from '@koralabs/kora-secrets-crypto';

import type {
  GuardianApprovalDatum,
  GuardianKeyProfileDatum,
  PolicyRef,
  RecoveryPolicyDatum,
  RecoveryRequestDatum
} from './datums.ts';

export interface UtxoRef {
  tx_id: string;
  index: number;
}

export interface PolicyUtxo {
  ref: UtxoRef;
  datum: RecoveryPolicyDatum;
}

export interface RequestUtxo {
  ref: UtxoRef;
  datum: RecoveryRequestDatum;
}

export interface ApprovalUtxo {
  ref: UtxoRef;
  datum: GuardianApprovalDatum;
}

/** A guardian's resolved share-decryption public key, with how it was sourced. */
export interface ResolvedGuardianProfile {
  guardian_handle_asset_id: string;
  /** X25519 public key (gek_pub) used to encrypt this guardian's share. */
  gek_pub: Uint8Array;
  source: 'inline' | 'proof';
}

/** Fetches an off-chain blob (e.g. an IPFS object) by content id. Injected so the resolver is
 *  storage-agnostic and testable. */
export type BlobFetcher = (cid: string) => Promise<Uint8Array>;

/**
 * Abstracts chain reads so the app/tests don't depend on a specific indexer. Secrets are
 * NEVER passed to a provider — it only reads public on-chain state.
 */
export interface ChainProvider {
  getTipSlot(): Promise<number>;
  findPolicyUtxos(owner_handle_asset_id: string): Promise<PolicyUtxo[]>;
  findActiveRequests(policy_ref: PolicyRef): Promise<RequestUtxo[]>;
  findApprovals(policy_ref: PolicyRef, session_id: string): Promise<ApprovalUtxo[]>;
  resolveGuardianProfile(guardian_handle_asset_id: string): Promise<ResolvedGuardianProfile | null>;
}

/** Shape of the off-chain key-proof blob referenced by a (003) datum in proof-cid mode. */
export interface GuardianKeyProofBlob {
  guardian_recovery_pubkey_x25519: string;
}

/**
 * Resolve a guardian's gek_pub from its (003) profile datum. Inline keys are returned
 * directly. In proof-cid mode the blob is fetched and its blake2b-256 hash MUST match the
 * on-chain `key_proof_hash_blake2b256` before any byte of it is trusted — tampered proof
 * metadata is rejected (SsrError PROOF_HASH_MISMATCH) before use. Returns null if the datum
 * carries neither a usable inline key nor a complete proof pair.
 */
export async function resolveProfileFromDatum(
  datum: GuardianKeyProfileDatum,
  fetchBlob: BlobFetcher
): Promise<ResolvedGuardianProfile | null> {
  if (datum.guardian_recovery_pubkey_x25519) {
    return {
      guardian_handle_asset_id: datum.guardian_handle_asset_id,
      gek_pub: hexToBytes(datum.guardian_recovery_pubkey_x25519),
      source: 'inline'
    };
  }
  if (datum.key_proof_cid && datum.key_proof_hash_blake2b256) {
    const blob = await fetchBlob(datum.key_proof_cid);
    const actual = blake2b256(blob);
    if (!bytesEqual(actual, hexToBytes(datum.key_proof_hash_blake2b256))) {
      throw new SsrError(
        SsrErrorCode.ProofHashMismatch,
        `guardian key-proof blob hash ${bytesToHex(actual)} != on-chain ${datum.key_proof_hash_blake2b256}`
      );
    }
    let parsed: GuardianKeyProofBlob;
    try {
      parsed = JSON.parse(new TextDecoder().decode(blob)) as GuardianKeyProofBlob;
    } catch {
      throw new SsrError(SsrErrorCode.ProfileUnresolvable, 'key-proof blob is not valid JSON');
    }
    if (typeof parsed.guardian_recovery_pubkey_x25519 !== 'string') {
      throw new SsrError(SsrErrorCode.ProfileUnresolvable, 'key-proof blob missing pubkey');
    }
    return {
      guardian_handle_asset_id: datum.guardian_handle_asset_id,
      gek_pub: hexToBytes(parsed.guardian_recovery_pubkey_x25519),
      source: 'proof'
    };
  }
  return null;
}
