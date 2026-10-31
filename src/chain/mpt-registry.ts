import { buildTrie } from '@koralabs/handles-decentralized-minting';
import { rateLimitedFetch } from '../rate-limited-fetch.ts';

// Reconstruct the DeMi handle-registry Merkle-Patricia trie (the "minting-data MPT") that the
// demimntmpt validator anchors on-chain. This is the off-chain half of the label-asset mint path:
// to mint a (003) guardian-profile token (or a (001) subhandle-settings token) THROUGH the DeMi
// contract, the caller proves the root handle's key in this trie and advances its label set. The
// Values are each handle's sorted four-byte label set, matching the engine and contract.
// A sparse API label map means "" only after its root agrees with the reconstructed trie
// and the on-chain datum. Names alone cannot establish that a handle has no labels.

const HANDLES_API: Record<string, string> = {
  preview: 'https://preview.api.handle.me',
  preprod: 'https://preprod.api.handle.me',
  mainnet: 'https://api.handle.me'
};

export type RegistryNetwork = 'preview' | 'preprod' | 'mainnet';

/** Every handle name on the network, in ascending order (the MPT keys). */
export const fetchAllHandleNames = async (
  network: RegistryNetwork,
  userAgent: string,
  fetchFn: typeof fetch = fetch
): Promise<string[]> => {
  const baseUrl = HANDLES_API[network];
  const handles: string[] = [];
  let page = 1;
  let total = 0;
  while (handles.length < total || page === 1) {
    const res = await rateLimitedFetch(`${baseUrl}/handles?records_per_page=50000&page=${page}&sort=asc`, {
      headers: { Accept: 'text/plain', 'User-Agent': userAgent }
    }, fetchFn);
    if (!res.ok) throw new Error(`handles fetch page ${page}: HTTP ${res.status}`);
    const names = (await res.text()).split('\n').filter(Boolean);
    handles.push(...names);
    const totalHeader = res.headers.get('x-handles-search-total');
    total = totalHeader && Number.isFinite(Number(totalHeader)) ? Number(totalHeader) : handles.length;
    if (!names.length) break;
    page += 1;
  }
  return handles;
};

/** Rebuild the label-aware trie and reject API snapshots that disagree with chain truth. */
export const reconstructRegistryTrie = async (
  network: RegistryNetwork,
  userAgent: string,
  fetchFn: typeof fetch = fetch
): Promise<{ trie: Awaited<ReturnType<typeof buildTrie>>; rootHex: string; handleCount: number }> => {
  const handles = await fetchAllHandleNames(network, userAgent, fetchFn);
  const response = await rateLimitedFetch(`${HANDLES_API[network]}/mpt-root/registry-labels`, {
    headers: { Accept: 'application/json', 'User-Agent': userAgent }
  }, fetchFn);
  if (!response.ok) throw new Error(`registry labels: HTTP ${response.status}`);
  const snapshot: unknown = await response.json();
  if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot)) {
    throw new Error('invalid registry label snapshot');
  }
  const { network: snapshotNetwork, current_root: apiRoot, count, labels } = snapshot as Record<string, unknown>;
  if (snapshotNetwork !== network) throw new Error('registry label snapshot network mismatch');
  if (typeof apiRoot !== 'string' || !/^[0-9a-f]{64}$/.test(apiRoot)) {
    throw new Error('invalid registry label snapshot root');
  }
  if (!labels || typeof labels !== 'object' || Array.isArray(labels)) {
    throw new Error('invalid registry label map');
  }
  const entries = Object.entries(labels);
  if (!Number.isSafeInteger(count) || count !== entries.length) {
    throw new Error('registry label snapshot count mismatch');
  }
  const names = [...new Set(handles)];
  const nameSet = new Set(names);
  for (const [name, value] of entries) {
    if (!nameSet.has(name)) throw new Error(`registry labels reference unknown handle ${JSON.stringify(name)}`);
    if (typeof value !== 'string' || !/^(?:[0-9a-f]{8})+$/.test(value)) {
      throw new Error(`invalid registry label set for handle ${JSON.stringify(name)}`);
    }
  }
  const labelMap = labels as Record<string, string>;
  const trie = await buildTrie(names.map((name) => ({
    name,
    labels: Object.hasOwn(labelMap, name) ? labelMap[name]! : ''
  })));
  const rootHex = trie.hash.toString('hex');
  if (rootHex !== apiRoot) throw new Error('reconstructed registry root disagrees with API snapshot');
  const chainRoot = await fetchOnChainMptRoot(network, userAgent, fetchFn);
  if (rootHex !== chainRoot) throw new Error('reconstructed registry root disagrees with on-chain datum');
  return { trie, rootHex, handleCount: names.length };
};

/** The on-chain minting-data MPT root (handle_root@handle_settings datum: MintingData{mpt_root_hash}). */
export const fetchOnChainMptRoot = async (
  network: RegistryNetwork,
  userAgent: string,
  fetchFn: typeof fetch = fetch
): Promise<string> => {
  const baseUrl = HANDLES_API[network];
  const res = await rateLimitedFetch(`${baseUrl}/handles/handle_root@handle_settings/datum`, {
    headers: { 'User-Agent': userAgent }
  }, fetchFn);
  if (!res.ok) throw new Error(`minting-data datum: HTTP ${res.status}`);
  const datum = (await res.text()).replace(/^"|"$/g, '');
  // MintingData = constructor_0 [ mpt_root_hash: 32-byte ByteArray ]
  const parsed = JSON.parse(datum) as { constructor_0?: string[] };
  const root = parsed.constructor_0?.[0]?.replace(/^0x/, '');
  if (!root || !/^[0-9a-f]{64}$/.test(root)) throw new Error('could not parse mpt_root_hash from datum');
  return root;
};
