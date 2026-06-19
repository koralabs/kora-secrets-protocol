import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildBundle,
  type Bundle,
  isSsrError,
  newRecoverySession,
  reencryptShareToSession,
  SsrErrorCode,
  utf8ToBytes
} from '@koralabs/kora-secrets-crypto';

import { cidV1Raw } from './cid.ts';
import { HttpPinningBlobStore } from './http-blob-store.ts';
import {
  getBundle,
  getBundleFromAny,
  getShareArtifact,
  InMemoryBlobStore,
  MAX_BLOB_BYTES,
  putBundle,
  putShareArtifact
} from './storage.ts';

const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'));

function sampleBundle(): Bundle {
  return buildBundle({
    network: 'preview',
    bundle_id: fromHex('00112233445566778899aabbccddeeff'),
    policy: {
      owner_handle_asset_id: 'f0f06f776e6572',
      guardians: [{ type: 'handle', asset_id: 'aa01', share_index: 1 }],
      threshold_m: 1,
      shares_n: 1,
      timelock_seconds: 172800
    },
    secret: { type: 'opaque_bytes', encoding: 'raw', bytes_len: 4 },
    shares: [
      { guardian_asset_id: 'aa01', share_index: 1, sender_ephemeral_pub: fromHex('aa'.repeat(32)), nonce: fromHex('bb'.repeat(12)), ciphertext: fromHex('cc'.repeat(20)) }
    ]
  });
}

test('bundle upload -> verified download round trip', async () => {
  const store = new InMemoryBlobStore();
  const bundle = sampleBundle();
  const cids = await putBundle(bundle, [store]);
  assert.equal(cids.length, 1);
  assert.match(cids[0]!, /^bafkrei[a-z2-7]+$/);
  const back = await getBundle(cids[0]!, store);
  assert.equal(back.integrity.bundle_hash_blake2b256_hex, bundle.integrity.bundle_hash_blake2b256_hex);
});

test('a hash-mismatched bundle blob throws before returning contents', async () => {
  const store = new InMemoryBlobStore();
  const bundle = sampleBundle();
  // Store a bundle whose attached integrity hash is wrong (tampered).
  const forged: Bundle = { ...bundle, integrity: { bundle_hash_blake2b256_hex: '00'.repeat(32) } };
  const cid = await store.put(utf8ToBytes(JSON.stringify(forged)));
  await assert.rejects(() => getBundle(cid, store), (e) => isSsrError(e, SsrErrorCode.BundleHashMismatch));
});

test('multi-CID fallback returns the bundle when the first CID is unavailable', async () => {
  const store = new InMemoryBlobStore();
  const bundle = sampleBundle();
  const [realCid] = await putBundle(bundle, [store]);
  const got = await getBundleFromAny(['bafkrei-does-not-exist', realCid!], store);
  assert.equal(got.bundle_id, bundle.bundle_id);
});

test('getBundleFromAny throws when no CID resolves', async () => {
  const store = new InMemoryBlobStore();
  await assert.rejects(() => getBundleFromAny(['nope1', 'nope2'], store));
});

test('mirrors produce identical content-addressed CIDs', async () => {
  const a = new InMemoryBlobStore();
  const b = new InMemoryBlobStore();
  const cids = await putBundle(sampleBundle(), [a, b]);
  assert.equal(cids[0], cids[1]);
});

test('oversize blob is rejected', async () => {
  const store = new InMemoryBlobStore();
  await assert.rejects(() => store.put(new Uint8Array(MAX_BLOB_BYTES + 1)), (e) => isSsrError(e, SsrErrorCode.InvalidBundle));
});

test('share artifact upload -> validated download round trip', async () => {
  const store = new InMemoryBlobStore();
  const session = newRecoverySession({ session_id: 'deadbeef' });
  const artifact = reencryptShareToSession(fromHex('0102'), session.recovery_pub, {
    policy_id: 'f0f06f776e6572',
    session_id: session.session_id,
    guardian_id: 'aa01'
  });
  const cid = await putShareArtifact(artifact, store);
  const back = await getShareArtifact(cid, store);
  assert.equal(back.session_id, 'deadbeef');
  assert.equal(back.ciphertext_b64, artifact.ciphertext_b64);
});

test('a malformed artifact blob is rejected on fetch', async () => {
  const store = new InMemoryBlobStore();
  const cid = await store.put(utf8ToBytes(JSON.stringify({ version: 1, nope: true })));
  await assert.rejects(() => getShareArtifact(cid, store), (e) => isSsrError(e, SsrErrorCode.InvalidArtifact));
});

test('an unknown CID throws (not a silent empty)', async () => {
  const store = new InMemoryBlobStore();
  await assert.rejects(() => store.get('bafkrei-unknown'), (e) => isSsrError(e, SsrErrorCode.InvalidBundle));
});

// --- HTTP pinning store against a mock gateway (network boundary) ---

function fakeGateway(stored: Map<string, Uint8Array>): typeof fetch {
  return (async (url: string | URL, init?: RequestInit) => {
    const u = String(url);
    if (init?.method === 'POST') {
      const bytes = new Uint8Array(init.body as ArrayBuffer);
      const cid = cidV1Raw(bytes);
      stored.set(cid, bytes);
      return { ok: true, status: 200, json: () => Promise.resolve({ IpfsHash: cid }) } as Response;
    }
    const cid = u.split('/').pop()!;
    const bytes = stored.get(cid);
    if (!bytes) return { ok: false, status: 404, arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)) } as Response;
    return { ok: true, status: 200, arrayBuffer: () => Promise.resolve(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength)) } as Response;
  }) as unknown as typeof fetch;
}

test('HttpPinningBlobStore put/get round trip against a mock gateway', async () => {
  const stored = new Map<string, Uint8Array>();
  const store = new HttpPinningBlobStore({
    pinUrl: 'https://pin.example/add',
    gatewayUrl: 'https://gw.example/ipfs',
    fetchImpl: fakeGateway(stored)
  });
  const payload = utf8ToBytes('hello ssr');
  const cid = await store.put(payload);
  const back = await store.get(cid);
  assert.equal(new TextDecoder().decode(back), 'hello ssr');
});

test('HttpPinningBlobStore rejects gateway bytes that do not match a CIDv1-raw cid', async () => {
  const stored = new Map<string, Uint8Array>();
  const store = new HttpPinningBlobStore({
    pinUrl: 'https://pin.example/add',
    gatewayUrl: 'https://gw.example/ipfs',
    fetchImpl: fakeGateway(stored)
  });
  const cid = await store.put(utf8ToBytes('real'));
  // Corrupt the stored bytes under the same (content-addressed) cid.
  stored.set(cid, utf8ToBytes('TAMPERED'));
  await assert.rejects(() => store.get(cid), (e) => isSsrError(e, SsrErrorCode.InvalidBundle));
});

test('HttpPinningBlobStore: pin failure, missing-CID response, and gateway 404 all throw', async () => {
  const pinFail = new HttpPinningBlobStore({
    pinUrl: 'https://pin.example/add',
    gatewayUrl: 'https://gw.example/ipfs',
    fetchImpl: (async () => ({ ok: false, status: 500, json: () => Promise.resolve({}) }) as Response) as unknown as typeof fetch
  });
  await assert.rejects(() => pinFail.put(utf8ToBytes('x')), (e) => isSsrError(e, SsrErrorCode.InvalidBundle));

  const noCid = new HttpPinningBlobStore({
    pinUrl: 'https://pin.example/add',
    gatewayUrl: 'https://gw.example/ipfs',
    fetchImpl: (async () => ({ ok: true, status: 200, json: () => Promise.resolve({ wrong: 'field' }) }) as Response) as unknown as typeof fetch
  });
  await assert.rejects(() => noCid.put(utf8ToBytes('x')), (e) => isSsrError(e, SsrErrorCode.InvalidBundle));

  const gw404 = new HttpPinningBlobStore({
    pinUrl: 'https://pin.example/add',
    gatewayUrl: 'https://gw.example/ipfs',
    fetchImpl: (async () => ({ ok: false, status: 404, arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)) }) as Response) as unknown as typeof fetch
  });
  await assert.rejects(() => gw404.get('bafkrei-x'), (e) => isSsrError(e, SsrErrorCode.InvalidBundle));
});

test('getBundle rejects a non-JSON blob (InvalidBundle)', async () => {
  const store = new InMemoryBlobStore();
  const cid = await store.put(utf8ToBytes('not json at all'));
  await assert.rejects(() => getBundle(cid, store), (e) => isSsrError(e, SsrErrorCode.InvalidBundle));
});

test('putBundle requires at least one store', async () => {
  await assert.rejects(() => putBundle(sampleBundle(), []), (e) => isSsrError(e, SsrErrorCode.InvalidBundle));
});
