import { Trie } from '@aiken-lang/merkle-patricia-forestry';

// Reconstruct the DeMi handle-registry Merkle-Patricia trie (the "minting-data MPT") that the
// demimntmpt validator anchors on-chain. This is the off-chain half of the label-asset mint path:
// to mint a (003) guardian-profile token (or a (001) subhandle-settings token) THROUGH the DeMi
// contract, the caller proves the root handle's key in this trie and advances its label set. The
// trie is the full set of handle names (value "" for a handle with no label set yet), exactly as
// the engine builds it (decentralized-minting/src/deploymentPlan.ts computeMptRootHash). Verified
// live on preview: the rebuilt root equals the on-chain minting-data root.

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
    const res = await fetchFn(`${baseUrl}/handles?records_per_page=50000&page=${page}&sort=asc`, {
      headers: { Accept: 'text/plain', 'User-Agent': userAgent }
    });
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

/** Rebuild the registry trie from all handle names (value "" per handle, matching the engine). */
export const reconstructRegistryTrie = async (
  network: RegistryNetwork,
  userAgent: string,
  fetchFn: typeof fetch = fetch
): Promise<{ trie: Trie; rootHex: string; handleCount: number }> => {
  const handles = await fetchAllHandleNames(network, userAgent, fetchFn);
  const trie = await Trie.fromList(handles.map((key) => ({ key, value: '' })));
  return { trie, rootHex: trie.hash.toString('hex'), handleCount: handles.length };
};

/** The on-chain minting-data MPT root (handle_root@handle_settings datum: MintingData{mpt_root_hash}). */
export const fetchOnChainMptRoot = async (
  network: RegistryNetwork,
  userAgent: string,
  fetchFn: typeof fetch = fetch
): Promise<string> => {
  const baseUrl = HANDLES_API[network];
  const res = await fetchFn(`${baseUrl}/handles/handle_root@handle_settings/datum`, {
    headers: { 'User-Agent': userAgent }
  });
  if (!res.ok) throw new Error(`minting-data datum: HTTP ${res.status}`);
  const datum = (await res.text()).replace(/^"|"$/g, '');
  // MintingData = constructor_0 [ mpt_root_hash: 32-byte ByteArray ]
  const parsed = JSON.parse(datum) as { constructor_0?: string[] };
  const root = parsed.constructor_0?.[0]?.replace(/^0x/, '');
  if (!root || root.length !== 64) throw new Error(`could not parse mpt_root_hash from datum: ${datum}`);
  return root;
};
