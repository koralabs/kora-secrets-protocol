import {
  type Bundle,
  NETWORK_ID,
  parseShareArtifact,
  type ReencryptedShareArtifact,
  SsrError,
  SsrErrorCode,
  verifyBundleHash
} from '@koralabs/kora-secrets-crypto';

import type { PolicyRef, RecoveryPolicyDatum } from './datums.ts';

function sortedSet(values: string[]): string[] {
  return [...new Set(values)].sort();
}

function sameSet(a: string[], b: string[]): boolean {
  const sa = sortedSet(a);
  const sb = sortedSet(b);
  return sa.length === sb.length && sa.every((v, i) => v === sb[i]);
}

/**
 * Enforce that an off-chain bundle matches the on-chain policy anchor before any of its
 * contents are used. Each kind of mismatch fails with a distinct, specific error:
 * - the bundle's own integrity hash is invalid, or doesn't equal the anchored hash -> BUNDLE_HASH_MISMATCH
 * - network disagreement (bundle.network vs policy.network_id)                        -> NETWORK_MISMATCH
 * - threshold or guardian-set disagreement                                            -> CHAIN_MISMATCH
 */
export function verifyBundleAgainstChain(bundle: Bundle, policy: RecoveryPolicyDatum): void {
  if (!verifyBundleHash(bundle)) {
    throw new SsrError(SsrErrorCode.BundleHashMismatch, 'bundle integrity hash does not match its own contents');
  }
  if (bundle.integrity.bundle_hash_blake2b256_hex !== policy.bundle_hash_blake2b256) {
    throw new SsrError(
      SsrErrorCode.BundleHashMismatch,
      `bundle hash ${bundle.integrity.bundle_hash_blake2b256_hex} != on-chain anchor ${policy.bundle_hash_blake2b256}`
    );
  }
  if (NETWORK_ID[bundle.network] !== policy.network_id) {
    throw new SsrError(
      SsrErrorCode.NetworkMismatch,
      `bundle network ${bundle.network} (id ${NETWORK_ID[bundle.network]}) != on-chain network_id ${policy.network_id}`
    );
  }
  if (bundle.policy.threshold_m !== policy.threshold_m || bundle.policy.shares_n !== policy.shares_n) {
    throw new SsrError(
      SsrErrorCode.ChainMismatch,
      `bundle threshold ${bundle.policy.threshold_m}-of-${bundle.policy.shares_n} != on-chain ${policy.threshold_m}-of-${policy.shares_n}`
    );
  }
  const bundleGuardians = bundle.policy.guardians.map((g) => g.asset_id);
  if (!sameSet(bundleGuardians, policy.guardian_ids)) {
    throw new SsrError(SsrErrorCode.ChainMismatch, 'bundle guardian set does not match the on-chain guardian set');
  }
}

/**
 * Validate a guardian's re-encrypted share artifact is bound to the recovery session it claims
 * to belong to. Rejects (SESSION_MISMATCH) an artifact for a different session or policy — the
 * replay/confusion guard a requester applies before decrypting an artifact.
 */
export function validateApprovalArtifact(
  artifact: ReencryptedShareArtifact,
  expected: { policy_ref: PolicyRef; session_id: string }
): ReencryptedShareArtifact {
  const a = parseShareArtifact(artifact);
  if (a.session_id !== expected.session_id) {
    throw new SsrError(
      SsrErrorCode.SessionMismatch,
      `artifact session_id ${a.session_id} != expected ${expected.session_id}`
    );
  }
  if (a.policy_id !== expected.policy_ref.owner_handle_asset_id) {
    throw new SsrError(
      SsrErrorCode.SessionMismatch,
      `artifact policy_id ${a.policy_id} != expected ${expected.policy_ref.owner_handle_asset_id}`
    );
  }
  return a;
}
