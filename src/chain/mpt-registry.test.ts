import assert from 'node:assert/strict';
import test from 'node:test';
import { reconstructRegistryTrie } from './mpt-registry.ts';

// Golden roots use raw four-byte label values, independently constructed with the
// MPT library. Replacing labels with empty strings must fail the labeled fixture.
const labeledRoot = '583981b7af47e5bd20ad91cd26e0ffdb52898211d95c8b95e7d18272408d835b';
const emptyRoot = 'e60157ff3124e44e116d97e69c2c56d99e9a8fb006cf70d3d3e7b53dcd052f13';
const arbitraryRoot = '9aa4a6fd41127cce81ccaa94edfa419360753d4b079e2ac70072dcb98e15825e';

function fixture(overrides: Record<string, unknown> = {}, chainRoot = labeledRoot, names = 'alpha\nbeta\n'): typeof fetch {
  const snapshot = { network: 'preview', current_root: labeledRoot, count: 1, labels: { beta: '00003090' }, ...overrides };
  return (async (input: string | URL | Request) => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input : input.url);
    assert.equal(url.origin, 'https://preview.api.handle.me');
    if (url.pathname === '/handles') return new Response(names, { headers: { 'x-handles-search-total': '2' } });
    if (url.pathname === '/mpt-root/registry-labels') return Response.json(snapshot);
    if (url.pathname === '/handles/handle_root@handle_settings/datum') {
      return Response.json({ constructor_0: [`0x${chainRoot}`] });
    }
    throw new Error(`Unexpected fixture request: ${url.pathname}`);
  }) as typeof fetch;
}

test('registry reconstruction includes label bytes and validates both authoritative roots', async () => {
  const result = await reconstructRegistryTrie('preview', 'registry-test', fixture());
  assert.equal(result.rootHex, labeledRoot);
  assert.equal(result.trie.hash.toString('hex'), labeledRoot);
  assert.equal(result.handleCount, 2);
  assert.notEqual(result.rootHex, emptyRoot);
});

test('a verified empty label set is valid, but silent empty-map fallback cannot pass chain verification', async () => {
  const empty = { labels: {}, count: 0, current_root: emptyRoot };
  const result = await reconstructRegistryTrie('preview', 'registry-test', fixture(empty, emptyRoot));
  assert.equal(result.rootHex, emptyRoot);
  await assert.rejects(reconstructRegistryTrie('preview', 'registry-test', fixture(empty)), /on-chain datum/);
});

test('duplicate names are deduplicated without losing label values', async () => {
  const result = await reconstructRegistryTrie('preview', 'registry-test', fixture({}, labeledRoot, 'alpha\nbeta\nalpha\n'));
  assert.equal(result.handleCount, 2);
  assert.equal(result.rootHex, labeledRoot);
});

test('the registry supports any contract-valid four-byte label, not a fixed prefix whitelist', async () => {
  const result = await reconstructRegistryTrie('preview', 'registry-test', fixture({ labels: { alpha: 'ffffffff' }, current_root: arbitraryRoot }, arbitraryRoot));
  assert.equal(result.rootHex, arbitraryRoot);
});

for (const [name, overrides, error] of [
  ['wrong network', { network: 'mainnet' }, /network mismatch/],
  ['wrong map count', { count: 2 }, /count mismatch/],
  ['invalid root', { current_root: 'z'.repeat(64) }, /snapshot root/],
  ['missing map', { labels: undefined }, /label map/],
  ['array map', { labels: ['00003090'] }, /label map/],
  ['dangling key', { labels: { gamma: '00003090' } }, /unknown handle/],
  ['incomplete label', { labels: { beta: '000030' } }, /invalid registry label set/],
  ['unsorted labels', { labels: { beta: '0000309000000010' } }, /sorted and unique/],
  ['duplicate labels', { labels: { beta: '0000309000003090' } }, /sorted and unique/],
  ['wrong API root', { current_root: emptyRoot }, /API snapshot/]
] as const) {
  test(`registry rejects ${name} before returning minting proof state`, async () => {
    await assert.rejects(reconstructRegistryTrie('preview', 'registry-test', fixture(overrides)), error);
  });
}

test('failed label fetch cannot fall back to a names-only trie', async () => {
  const base = fixture();
  const fetchFn = (async (...args: Parameters<typeof fetch>) => String(args[0]).includes('/registry-labels')
    ? new Response('unavailable', { status: 503 }) : base(...args)) as typeof fetch;
  await assert.rejects(reconstructRegistryTrie('preview', 'registry-test', fetchFn), /registry labels: HTTP 503/);
});

test('invalid on-chain root is rejected even when API reconstruction agrees', async () => {
  await assert.rejects(reconstructRegistryTrie('preview', 'registry-test', fixture({}, 'z'.repeat(64))), /parse mpt_root_hash/);
});
