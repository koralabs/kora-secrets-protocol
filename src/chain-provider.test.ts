import assert from 'node:assert/strict';
import test from 'node:test';

import { blake2b256, bytesToHex, isSsrError, SsrErrorCode, utf8ToBytes } from '@koralabs/kora-secrets-crypto';

import { resolveProfileFromDatum } from './chain-provider.ts';
import type { GuardianKeyProfileDatum } from './datums.ts';
import { FakeChainProvider } from './fake-chain-provider.ts';

function inlineProfile(gid: string, pubHex: string): GuardianKeyProfileDatum {
  return {
    version: 1,
    guardian_handle_asset_id: gid,
    paired_token_label: 3,
    guardian_key_source: 'HandleControlled',
    guardian_recovery_pubkey_x25519: pubHex,
    key_proof_cid: null,
    key_proof_hash_blake2b256: null,
    updated_slot: 1
  };
}

function proofProfile(gid: string, cid: string, hashHex: string): GuardianKeyProfileDatum {
  return {
    version: 1,
    guardian_handle_asset_id: gid,
    paired_token_label: 3,
    guardian_key_source: 'HandleControlled',
    guardian_recovery_pubkey_x25519: null,
    key_proof_cid: cid,
    key_proof_hash_blake2b256: hashHex,
    updated_slot: 1
  };
}

test('resolveGuardianProfile resolves an inline key', async () => {
  const p = new FakeChainProvider();
  const pub = 'ab'.repeat(32);
  p.setProfile(inlineProfile('g1', pub));
  const resolved = await p.resolveGuardianProfile('g1');
  assert.ok(resolved);
  assert.equal(resolved!.source, 'inline');
  assert.equal(bytesToHex(resolved!.gek_pub), pub);
});

test('resolveGuardianProfile resolves a proof-cid key after hash verification', async () => {
  const p = new FakeChainProvider();
  const pub = 'cd'.repeat(32);
  const blob = utf8ToBytes(JSON.stringify({ guardian_recovery_pubkey_x25519: pub }));
  const cid = 'Qm-proof-1';
  p.putBlob(cid, blob);
  p.setProfile(proofProfile('g2', cid, bytesToHex(blake2b256(blob))));
  const resolved = await p.resolveGuardianProfile('g2');
  assert.ok(resolved);
  assert.equal(resolved!.source, 'proof');
  assert.equal(bytesToHex(resolved!.gek_pub), pub);
});

test('negative control: tampered proof blob is rejected before use', async () => {
  const p = new FakeChainProvider();
  const pub = 'ef'.repeat(32);
  const blob = utf8ToBytes(JSON.stringify({ guardian_recovery_pubkey_x25519: pub }));
  const cid = 'Qm-proof-2';
  // Anchor the hash of the ORIGINAL blob, then store a tampered blob under the same cid.
  const anchoredHash = bytesToHex(blake2b256(blob));
  const tampered = utf8ToBytes(JSON.stringify({ guardian_recovery_pubkey_x25519: '00'.repeat(32) }));
  p.putBlob(cid, tampered);
  p.setProfile(proofProfile('g3', cid, anchoredHash));
  await assert.rejects(
    () => p.resolveGuardianProfile('g3'),
    (e) => isSsrError(e, SsrErrorCode.ProofHashMismatch)
  );
});

test('proof blob that is not valid JSON is rejected (PROFILE_UNRESOLVABLE)', async () => {
  const blob = utf8ToBytes('not json');
  const resolve = () =>
    resolveProfileFromDatum(proofProfile('g', 'cid', bytesToHex(blake2b256(blob))), () => Promise.resolve(blob));
  await assert.rejects(resolve, (e) => isSsrError(e, SsrErrorCode.ProfileUnresolvable));
});

test('proof blob missing the pubkey field is rejected (PROFILE_UNRESOLVABLE)', async () => {
  const blob = utf8ToBytes(JSON.stringify({ wrong: 'field' }));
  const resolve = () =>
    resolveProfileFromDatum(proofProfile('g', 'cid', bytesToHex(blake2b256(blob))), () => Promise.resolve(blob));
  await assert.rejects(resolve, (e) => isSsrError(e, SsrErrorCode.ProfileUnresolvable));
});

test('a proof profile pointing at a missing blob is rejected by the fake', async () => {
  const p = new FakeChainProvider();
  p.setProfile(proofProfile('gm', 'absent-cid', '00'.repeat(32)));
  await assert.rejects(() => p.resolveGuardianProfile('gm'), (e) => isSsrError(e, SsrErrorCode.ProfileUnresolvable));
});

test('resolveGuardianProfile returns null for an unknown guardian', async () => {
  const p = new FakeChainProvider();
  assert.equal(await p.resolveGuardianProfile('nope'), null);
});

test('a datum with neither inline key nor proof pair resolves to null', async () => {
  const datum = proofProfile('g4', '', '');
  datum.key_proof_cid = null;
  datum.key_proof_hash_blake2b256 = null;
  const resolved = await resolveProfileFromDatum(datum, () => Promise.reject(new Error('unused')));
  assert.equal(resolved, null);
});

test('findPolicyUtxos / findActiveRequests / findApprovals filter correctly', async () => {
  const p = new FakeChainProvider();
  const owner = 'f0f0owner';
  const ref = { owner_handle_asset_id: owner, policy_nonce: 0 };
  p.policies.push({
    ref: { tx_id: 'aa', index: 0 },
    datum: {
      version: 1,
      network_id: 0,
      owner_handle_asset_id: owner,
      threshold_m: 2,
      shares_n: 3,
      timelock_seconds: 1,
      guardian_ids: ['g1'],
      bundle_hash_blake2b256: '00',
      bundle_cids: ['cid'],
      policy_nonce: 0
    }
  });
  p.requests.push({
    ref: { tx_id: 'bb', index: 0 },
    datum: { version: 1, policy_ref: ref, session_id: 'sess', recovery_pubkey_x25519: '11', created_slot: 1, status: 'Pending' }
  });
  p.requests.push({
    ref: { tx_id: 'cc', index: 0 },
    datum: { version: 1, policy_ref: ref, session_id: 'old', recovery_pubkey_x25519: '11', created_slot: 1, status: 'Canceled' }
  });
  p.approvals.push({
    ref: { tx_id: 'dd', index: 0 },
    datum: { version: 1, policy_ref: ref, session_id: 'sess', guardian_id: 'g1', reencrypted_share_cid: 'c' }
  });

  assert.equal((await p.findPolicyUtxos(owner)).length, 1);
  assert.equal((await p.findPolicyUtxos('other')).length, 0);
  // Only the Pending request is "active".
  const active = await p.findActiveRequests(ref);
  assert.equal(active.length, 1);
  assert.equal(active[0]!.datum.session_id, 'sess');
  // Approvals filtered by session.
  assert.equal((await p.findApprovals(ref, 'sess')).length, 1);
  assert.equal((await p.findApprovals(ref, 'nope')).length, 0);
});
