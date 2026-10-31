import { hexToBytes, type Network, NETWORK_MAGIC } from '@koralabs/kora-secrets-crypto';
import { rateLimitedFetch } from './rate-limited-fetch.ts';

import {
  type ApprovalUtxo,
  type BlobFetcher,
  type ChainProvider,
  type PolicyUtxo,
  type RequestUtxo,
  type ResolvedGuardianProfile,
  resolveProfileFromDatum,
  type UtxoRef
} from './chain-provider.ts';
import {
  decodeGuardianApprovalDatum,
  decodeGuardianKeyProfileDatum,
  decodeRecoveryPolicyDatum,
  decodeRecoveryRequestDatum,
  type PolicyRef
} from './datums.ts';

/** Script addresses for the SSR validators on the target network (set per deployment). */
export interface SsrScriptAddresses {
  policy: string;
  request: string;
  approval: string;
  profile: string;
}

export interface BlockfrostConfig {
  network: Network;
  projectId: string;
  scripts: SsrScriptAddresses;
  /** Injected for tests; defaults to global fetch. */
  fetchImpl?: typeof fetch;
  /** Resolves proof-cid blobs (e.g. an IPFS gateway). Required only for proof-mode profiles. */
  blobFetcher?: BlobFetcher;
}

const BASE_URL: Readonly<Record<Network, string>> = {
  mainnet: 'https://cardano-mainnet.blockfrost.io/api/v0',
  preprod: 'https://cardano-preprod.blockfrost.io/api/v0',
  preview: 'https://cardano-preview.blockfrost.io/api/v0'
};

interface BlockfrostUtxo {
  tx_hash: string;
  output_index: number;
  inline_datum: string | null;
}

/** Blockfrost-backed ChainProvider. Reads public chain state only; never receives secrets. */
export class BlockfrostChainProvider implements ChainProvider {
  private readonly cfg: BlockfrostConfig;
  private readonly fetchImpl: typeof fetch;

  constructor(cfg: BlockfrostConfig) {
    this.cfg = cfg;
    this.fetchImpl = cfg.fetchImpl ?? fetch;
  }

  private async get(pathAndQuery: string): Promise<unknown> {
    const res = await rateLimitedFetch(`${BASE_URL[this.cfg.network]}${pathAndQuery}`, {
      headers: { project_id: this.cfg.projectId }
    }, this.fetchImpl);
    if (res.status === 404) return null;
    if (!res.ok) {
      throw new Error(`blockfrost ${pathAndQuery} -> HTTP ${res.status}`);
    }
    return res.json();
  }

  async getTipSlot(): Promise<number> {
    const latest = (await this.get('/blocks/latest')) as { slot: number } | null;
    if (!latest || typeof latest.slot !== 'number') {
      throw new Error('blockfrost: could not read tip slot');
    }
    return latest.slot;
  }

  private async utxosAt(address: string): Promise<BlockfrostUtxo[]> {
    const utxos = (await this.get(`/addresses/${address}/utxos`)) as BlockfrostUtxo[] | null;
    return utxos ?? [];
  }

  async findPolicyUtxos(owner_handle_asset_id: string): Promise<PolicyUtxo[]> {
    const out: PolicyUtxo[] = [];
    for (const u of await this.utxosAt(this.cfg.scripts.policy)) {
      if (!u.inline_datum) continue;
      const datum = decodeRecoveryPolicyDatum(hexToBytes(u.inline_datum));
      if (datum.owner_handle_asset_id === owner_handle_asset_id) {
        out.push({ ref: toRef(u), datum });
      }
    }
    return out;
  }

  async findActiveRequests(policy_ref: PolicyRef): Promise<RequestUtxo[]> {
    const out: RequestUtxo[] = [];
    for (const u of await this.utxosAt(this.cfg.scripts.request)) {
      if (!u.inline_datum) continue;
      const datum = decodeRecoveryRequestDatum(hexToBytes(u.inline_datum));
      if (refEq(datum.policy_ref, policy_ref) && datum.status === 'Pending') {
        out.push({ ref: toRef(u), datum });
      }
    }
    return out;
  }

  async findApprovals(policy_ref: PolicyRef, session_id: string): Promise<ApprovalUtxo[]> {
    const out: ApprovalUtxo[] = [];
    for (const u of await this.utxosAt(this.cfg.scripts.approval)) {
      if (!u.inline_datum) continue;
      const datum = decodeGuardianApprovalDatum(hexToBytes(u.inline_datum));
      if (refEq(datum.policy_ref, policy_ref) && datum.session_id === session_id) {
        out.push({ ref: toRef(u), datum });
      }
    }
    return out;
  }

  async resolveGuardianProfile(
    guardian_handle_asset_id: string
  ): Promise<ResolvedGuardianProfile | null> {
    for (const u of await this.utxosAt(this.cfg.scripts.profile)) {
      if (!u.inline_datum) continue;
      const datum = decodeGuardianKeyProfileDatum(hexToBytes(u.inline_datum));
      if (datum.guardian_handle_asset_id === guardian_handle_asset_id) {
        const fetchBlob: BlobFetcher =
          this.cfg.blobFetcher ??
          (() => Promise.reject(new Error('no blobFetcher configured for proof-cid profiles')));
        return resolveProfileFromDatum(datum, fetchBlob);
      }
    }
    return null;
  }

  /** Network magic for the configured network (used by tx builders for hard network isolation). */
  get networkMagic(): number {
    return NETWORK_MAGIC[this.cfg.network];
  }
}

function toRef(u: BlockfrostUtxo): UtxoRef {
  return { tx_id: u.tx_hash, index: u.output_index };
}

function refEq(a: PolicyRef, b: PolicyRef): boolean {
  return a.owner_handle_asset_id === b.owner_handle_asset_id && a.policy_nonce === b.policy_nonce;
}
