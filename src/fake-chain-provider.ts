import { SsrError, SsrErrorCode } from '@koralabs/kora-secrets-crypto';

import {
  type ApprovalUtxo,
  type BlobFetcher,
  type ChainProvider,
  type PolicyUtxo,
  type RequestUtxo,
  type ResolvedGuardianProfile,
  resolveProfileFromDatum
} from './chain-provider.ts';
import type { GuardianKeyProfileDatum, PolicyRef } from './datums.ts';

function sameRef(a: PolicyRef, b: PolicyRef): boolean {
  return a.owner_handle_asset_id === b.owner_handle_asset_id && a.policy_nonce === b.policy_nonce;
}

/**
 * In-memory ChainProvider for tests. Holds the public on-chain state explicitly so tests can
 * exercise the full lifecycle without a network/indexer. The proof-cid resolution path uses
 * its own blob store via the shared {@link resolveProfileFromDatum} (so the hash-verification
 * security check is the same code as production).
 */
export class FakeChainProvider implements ChainProvider {
  tipSlot = 1000;
  policies: PolicyUtxo[] = [];
  requests: RequestUtxo[] = [];
  approvals: ApprovalUtxo[] = [];
  profiles = new Map<string, GuardianKeyProfileDatum>();
  blobs = new Map<string, Uint8Array>();

  setProfile(datum: GuardianKeyProfileDatum): void {
    this.profiles.set(datum.guardian_handle_asset_id, datum);
  }

  putBlob(cid: string, bytes: Uint8Array): void {
    this.blobs.set(cid, bytes);
  }

  private readonly fetchBlob: BlobFetcher = (cid) => {
    const blob = this.blobs.get(cid);
    if (!blob) return Promise.reject(new SsrError(SsrErrorCode.ProfileUnresolvable, `no blob for cid ${cid}`));
    return Promise.resolve(blob);
  };

  getTipSlot(): Promise<number> {
    return Promise.resolve(this.tipSlot);
  }

  findPolicyUtxos(owner_handle_asset_id: string): Promise<PolicyUtxo[]> {
    return Promise.resolve(
      this.policies.filter((p) => p.datum.owner_handle_asset_id === owner_handle_asset_id)
    );
  }

  findActiveRequests(policy_ref: PolicyRef): Promise<RequestUtxo[]> {
    return Promise.resolve(
      this.requests.filter((r) => sameRef(r.datum.policy_ref, policy_ref) && r.datum.status === 'Pending')
    );
  }

  findApprovals(policy_ref: PolicyRef, session_id: string): Promise<ApprovalUtxo[]> {
    return Promise.resolve(
      this.approvals.filter(
        (a) => sameRef(a.datum.policy_ref, policy_ref) && a.datum.session_id === session_id
      )
    );
  }

  resolveGuardianProfile(guardian_handle_asset_id: string): Promise<ResolvedGuardianProfile | null> {
    const datum = this.profiles.get(guardian_handle_asset_id);
    if (!datum) return Promise.resolve(null);
    return resolveProfileFromDatum(datum, this.fetchBlob);
  }
}
