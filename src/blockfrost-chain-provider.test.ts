import assert from 'node:assert/strict';
import test from 'node:test';

import { blake2b256, bytesToHex, utf8ToBytes } from '@koralabs/kora-secrets-crypto';

import { BlockfrostChainProvider, type SsrScriptAddresses } from './blockfrost-chain-provider.ts';
import { RateLimitedError } from './rate-limited-fetch.ts';
import {
  datumToCborHex,
  encodeGuardianApprovalDatum,
  encodeGuardianKeyProfileDatum,
  encodeRecoveryPolicyDatum,
  encodeRecoveryRequestDatum,
  type RecoveryPolicyDatum
} from './datums.ts';

const SCRIPTS: SsrScriptAddresses = {
  policy: 'addr_test_policy',
  request: 'addr_test_request',
  approval: 'addr_test_approval',
  profile: 'addr_test_profile'
};

// A fake fetch (network boundary mock) routing by URL path to canned JSON responses.
function fakeFetch(routes: Record<string, unknown>): typeof fetch {
  return (async (url: string | URL) => {
    const u = String(url);
    for (const [path, body] of Object.entries(routes)) {
      if (u.endsWith(path)) {
        return Response.json(body);
      }
    }
    return Response.json(null, { status: 404 });
  }) as unknown as typeof fetch;
}

function samplePolicy(owner: string): RecoveryPolicyDatum {
  return {
    version: 1,
    network_id: 0,
    owner_handle_asset_id: owner,
    threshold_m: 2,
    shares_n: 3,
    timelock_seconds: 172800,
    guardian_ids: ['aa01'],
    bundle_hash_blake2b256: '22'.repeat(32),
    bundle_cids: ['516d61'],
    policy_nonce: 0
  };
}

test('getTipSlot parses the Blockfrost latest-block response', async () => {
  const p = new BlockfrostChainProvider({
    network: 'preview',
    projectId: 'x',
    scripts: SCRIPTS,
    fetchImpl: fakeFetch({ '/blocks/latest': { slot: 12345 } })
  });
  assert.equal(await p.getTipSlot(), 12345);
});

test('findPolicyUtxos decodes inline datums and filters by owner', async () => {
  const owner = 'f0f06f776e6572';
  const datumHex = datumToCborHex(encodeRecoveryPolicyDatum(samplePolicy(owner)));
  const otherHex = datumToCborHex(encodeRecoveryPolicyDatum(samplePolicy('deadbeef')));
  const p = new BlockfrostChainProvider({
    network: 'preview',
    projectId: 'x',
    scripts: SCRIPTS,
    fetchImpl: fakeFetch({
      '/addresses/addr_test_policy/utxos': [
        { tx_hash: 'aa', output_index: 0, inline_datum: datumHex },
        { tx_hash: 'bb', output_index: 1, inline_datum: otherHex },
        { tx_hash: 'cc', output_index: 2, inline_datum: null }
      ]
    })
  });
  const found = await p.findPolicyUtxos(owner);
  assert.equal(found.length, 1);
  assert.equal(found[0]!.ref.tx_id, 'aa');
  assert.equal(found[0]!.datum.owner_handle_asset_id, owner);
});

test('findActiveRequests returns only Pending requests matching the policy_ref', async () => {
  const ref = { owner_handle_asset_id: 'f0f06f776e6572', policy_nonce: 0 };
  const pending = datumToCborHex(
    encodeRecoveryRequestDatum({ version: 1, policy_ref: ref, session_id: 'deadbeef', recovery_pubkey_x25519: '33'.repeat(32), created_slot: 1, status: 'Pending' })
  );
  const canceled = datumToCborHex(
    encodeRecoveryRequestDatum({ version: 1, policy_ref: ref, session_id: 'cafe', recovery_pubkey_x25519: '33'.repeat(32), created_slot: 1, status: 'Canceled' })
  );
  const p = new BlockfrostChainProvider({
    network: 'preview',
    projectId: 'x',
    scripts: SCRIPTS,
    fetchImpl: fakeFetch({
      '/addresses/addr_test_request/utxos': [
        { tx_hash: 'r1', output_index: 0, inline_datum: pending },
        { tx_hash: 'r2', output_index: 0, inline_datum: canceled }
      ]
    })
  });
  const active = await p.findActiveRequests(ref);
  assert.equal(active.length, 1);
  assert.equal(active[0]!.datum.session_id, 'deadbeef');
});

test('findApprovals filters by policy_ref and session_id', async () => {
  const ref = { owner_handle_asset_id: 'f0f06f776e6572', policy_nonce: 0 };
  const mk = (gid: string, session: string) =>
    datumToCborHex(encodeGuardianApprovalDatum({ version: 1, policy_ref: ref, session_id: session, guardian_id: gid, reencrypted_share_cid: '516d63' }));
  const p = new BlockfrostChainProvider({
    network: 'preview',
    projectId: 'x',
    scripts: SCRIPTS,
    fetchImpl: fakeFetch({
      '/addresses/addr_test_approval/utxos': [
        { tx_hash: 'a1', output_index: 0, inline_datum: mk('aa01', 'deadbeef') },
        { tx_hash: 'a2', output_index: 0, inline_datum: mk('aa02', 'cafe') }
      ]
    })
  });
  assert.equal((await p.findApprovals(ref, 'deadbeef')).length, 1);
});

test('resolveGuardianProfile reads an inline-key (003) datum from chain', async () => {
  const gid = 'f0f0677561726469616e';
  const pub = 'ab'.repeat(32);
  const datum = datumToCborHex(
    encodeGuardianKeyProfileDatum({ version: 1, guardian_handle_asset_id: gid, paired_token_label: 3, guardian_key_source: 'HandleControlled', guardian_recovery_pubkey_x25519: pub, key_proof_cid: null, key_proof_hash_blake2b256: null, updated_slot: 1 })
  );
  const p = new BlockfrostChainProvider({
    network: 'preview',
    projectId: 'x',
    scripts: SCRIPTS,
    fetchImpl: fakeFetch({ '/addresses/addr_test_profile/utxos': [{ tx_hash: 'p1', output_index: 0, inline_datum: datum }] })
  });
  const resolved = await p.resolveGuardianProfile(gid);
  assert.equal(bytesToHex(resolved!.gek_pub), pub);
  assert.equal(await p.resolveGuardianProfile('unknown'), null);
});

test('resolveGuardianProfile follows a proof-cid via the injected blobFetcher', async () => {
  const gid = 'f0f0677561726469616e';
  const pub = 'cd'.repeat(32);
  const blob = utf8ToBytes(JSON.stringify({ guardian_recovery_pubkey_x25519: pub }));
  const datum = datumToCborHex(
    encodeGuardianKeyProfileDatum({ version: 1, guardian_handle_asset_id: gid, paired_token_label: 3, guardian_key_source: 'HandleControlled', guardian_recovery_pubkey_x25519: null, key_proof_cid: '516d31', key_proof_hash_blake2b256: bytesToHex(blake2b256(blob)), updated_slot: 1 })
  );
  const p = new BlockfrostChainProvider({
    network: 'preview',
    projectId: 'x',
    scripts: SCRIPTS,
    fetchImpl: fakeFetch({ '/addresses/addr_test_profile/utxos': [{ tx_hash: 'p1', output_index: 0, inline_datum: datum }] }),
    blobFetcher: () => Promise.resolve(blob)
  });
  const resolved = await p.resolveGuardianProfile(gid);
  assert.equal(resolved!.source, 'proof');
  assert.equal(bytesToHex(resolved!.gek_pub), pub);
});

test('a non-OK HTTP response throws (no silent empty result)', async () => {
  const p = new BlockfrostChainProvider({
    network: 'preview',
    projectId: 'x',
    scripts: SCRIPTS,
    fetchImpl: (async () => Response.json(null, { status: 500 })) as typeof fetch
  });
  await assert.rejects(() => p.getTipSlot(), /HTTP 500/);
});

test('networkMagic reflects the configured network (isolation aid)', () => {
  const preview = new BlockfrostChainProvider({ network: 'preview', projectId: 'x', scripts: SCRIPTS });
  const preprod = new BlockfrostChainProvider({ network: 'preprod', projectId: 'x', scripts: SCRIPTS });
  assert.equal(preview.networkMagic, 2);
  assert.equal(preprod.networkMagic, 1);
  assert.notEqual(preview.networkMagic, preprod.networkMagic);
});

test('provider instances share rate-limit waits before reading the next real tip response', async () => {
  const times: number[] = [];
  const fetchImpl = (async () => {
    times.push(Date.now());
    return times.length === 1
      ? new Response('', { status: 429, headers: { 'retry-after': '0.03' } })
      : Response.json({ slot: 123456789 });
  }) as typeof fetch;
  const first = new BlockfrostChainProvider({ network: 'preprod', projectId: 'test-key', scripts: SCRIPTS, fetchImpl });
  const second = new BlockfrostChainProvider({ network: 'preprod', projectId: 'test-key', scripts: SCRIPTS, fetchImpl });
  await assert.rejects(first.getTipSlot(), RateLimitedError);
  assert.equal(times.length, 1);
  assert.equal(await second.getTipSlot(), 123456789);
  assert.ok(times[1]! - times[0]! >= 30);
});

// Flag-gated live integration test: only runs when a real preview Blockfrost key is provided.
// e.g. BLOCKFROST_PROJECT_ID_PREVIEW=preview... node --test ...
const liveKey = process.env.BLOCKFROST_PROJECT_ID_PREVIEW;
test('LIVE: getTipSlot against the real preview indexer', { skip: !liveKey }, async () => {
  const p = new BlockfrostChainProvider({ network: 'preview', projectId: liveKey!, scripts: SCRIPTS });
  const slot = await p.getTipSlot();
  assert.ok(slot > 0, 'preview tip slot should be positive');
});
