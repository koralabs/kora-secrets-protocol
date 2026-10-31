import assert from 'node:assert/strict';
import test from 'node:test';
import { BlockfrostChainProvider } from './blockfrost-chain-provider.ts';
import { getBlockfrostBuildContext } from './cardano-sdk/blockfrostContext.ts';
import { fetchBlockfrostUtxos } from './cardano-sdk/blockfrostUtxo.ts';
import { HttpPinningBlobStore } from './http-blob-store.ts';
import { RateLimitedError } from './rate-limited-fetch.ts';
import type { SsrScriptAddresses } from './chain-provider.ts';

// Each test uses its own origin because the rate-limit gate is process-wide by design.

test('a Blockfrost 429 seen by the build context makes the UTxO reader wait, without retrying the 429', async () => {
  const calls: { path: string; at: number }[] = [];
  const fetchFn = (async (input: string | URL | Request) => {
    const url = new URL(String(input));
    calls.push({ path: url.pathname, at: Date.now() });
    if (url.pathname.endsWith('/genesis')) {
      return new Response('', { status: 429, headers: { 'retry-after': '0.06' } });
    }
    if (url.pathname.includes('/utxos')) return Response.json([]);
    return Response.json({});
  }) as typeof fetch;

  await assert.rejects(getBlockfrostBuildContext('preview', 'key', { fetchFn }), RateLimitedError);
  const limitedAt = calls.find((c) => c.path.endsWith('/genesis'))!.at;
  const before = calls.length;
  assert.deepEqual(await fetchBlockfrostUtxos('addr_test1x', 'key', 'preview', fetchFn), []);
  assert.equal(calls.length, before + 1, 'the 429 must not be retried; only the UTxO page is fetched');
  assert.equal(calls.filter((c) => c.path.endsWith('/genesis')).length, 1);
  assert.ok(calls.at(-1)!.at - limitedAt >= 60, 'UTxO reader must honor the build-context Retry-After');
});

test('a long wait from the chain provider stops UTxO paging and build-context reads before any request', async () => {
  let requests = 0;
  const fetchFn = (async () => {
    requests++;
    return new Response('', { status: 429, headers: { 'retry-after': '120' } });
  }) as typeof fetch;
  const provider = new BlockfrostChainProvider({
    network: 'preprod',
    projectId: 'key',
    scripts: {} as SsrScriptAddresses,
    fetchImpl: fetchFn
  });
  await assert.rejects(provider.getTipSlot(), RateLimitedError);
  assert.equal(requests, 1);
  await assert.rejects(fetchBlockfrostUtxos('addr_test1x', 'key', 'preprod', fetchFn), (error: unknown) => {
    assert.ok(error instanceof RateLimitedError);
    assert.ok(error.retryAfterMs > 119000);
    return true;
  });
  await assert.rejects(getBlockfrostBuildContext('preprod', 'key', { fetchFn }), RateLimitedError);
  assert.equal(requests, 1, 'no caller may reach the host before the stated wait');
});

test('UTxO paging stops on an exhausted quota instead of fetching the next page', async () => {
  const pages: string[] = [];
  const item = {
    tx_hash: '00'.repeat(32),
    output_index: 0,
    amount: [{ unit: 'lovelace', quantity: '1000000' }],
    inline_datum: null,
    reference_script_hash: null
  };
  const fetchFn = (async (input: string | URL | Request) => {
    pages.push(new URL(String(input)).searchParams.get('page')!);
    if (pages.length > 1) return Response.json([]); // A broken pager terminates and fails the assertions.
    return Response.json(Array.from({ length: 100 }, (_, i) => ({ ...item, output_index: i })), {
      headers: { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset-after': '90' }
    });
  }) as typeof fetch;
  await assert.rejects(
    fetchBlockfrostUtxos('addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x', 'key', 'mainnet', fetchFn),
    RateLimitedError
  );
  assert.deepEqual(pages, ['1']);
});

test('IPFS pin and gateway calls share their host gate', async () => {
  let pinRequests = 0;
  let gatewayRequests = 0;
  const fetchFn = (async (input: string | URL | Request) => {
    const url = new URL(String(input));
    if (url.origin === 'https://pin-limit.invalid') {
      pinRequests++;
      return Response.json({ error: 'slow down' }, { status: 429, headers: { 'retry-after': '300' } });
    }
    gatewayRequests++;
    return new Response(new Uint8Array([1]));
  }) as typeof fetch;
  const store = new HttpPinningBlobStore({
    pinUrl: 'https://pin-limit.invalid/add',
    gatewayUrl: 'https://gw-ok.invalid/ipfs',
    fetchImpl: fetchFn
  });
  await assert.rejects(store.put(new Uint8Array([1])), RateLimitedError);
  await assert.rejects(store.put(new Uint8Array([2])), RateLimitedError);
  assert.equal(pinRequests, 1, 'the second pin must be refused locally');
  assert.deepEqual(await store.get('Qm-not-raw'), new Uint8Array([1]));
  assert.equal(gatewayRequests, 1, 'an unrelated gateway host is not blocked');

  const sameHost = new HttpPinningBlobStore({
    pinUrl: 'https://other-pin.invalid/add',
    gatewayUrl: 'https://pin-limit.invalid/ipfs',
    fetchImpl: fetchFn
  });
  await assert.rejects(sameHost.get('Qm-not-raw'), RateLimitedError);
  assert.equal(pinRequests, 1, 'a gateway read on the limited host must not be sent');
});
