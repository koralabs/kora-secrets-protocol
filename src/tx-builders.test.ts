import assert from 'node:assert/strict';
import test from 'node:test';

import { isSsrError, SsrErrorCode } from '@koralabs/kora-secrets-crypto';

import type { PolicyUtxo, RequestUtxo } from './chain-provider.ts';
import {
  decodeRecoveryRequestDatum,
  type GuardianKeyProfileDatum,
  type RecoveryPolicyDatum
} from './datums.ts';
import {
  buildApproveRecoveryTx,
  buildCancelRecoveryTx,
  buildCompleteRecoveryTx,
  buildCreatePolicyTx,
  buildInitiateRecoveryTx,
  buildRegisterProfileTx,
  buildRotatePolicyTx,
  deriveSessionId
} from './tx-builders.ts';

const owner = 'f0f06f776e6572';
const guardian = 'f0f067756172';

function profile(): GuardianKeyProfileDatum {
  return {
    version: 1,
    guardian_handle_asset_id: guardian,
    paired_token_label: 3,
    guardian_key_source: 'HandleControlled',
    guardian_recovery_pubkey_x25519: '11'.repeat(32),
    key_proof_cid: null,
    key_proof_hash_blake2b256: null,
    updated_slot: 1
  };
}

function policy(overrides: Partial<RecoveryPolicyDatum> = {}): RecoveryPolicyDatum {
  return {
    version: 1,
    network_id: 0, // preview/preprod
    owner_handle_asset_id: owner,
    threshold_m: 2,
    shares_n: 3,
    timelock_seconds: 172800,
    guardian_ids: [guardian, 'aa02', 'aa03'],
    bundle_hash_blake2b256: '22'.repeat(32),
    bundle_cids: ['516d61'],
    policy_nonce: 0,
    ...overrides
  };
}

test('deriveSessionId matches the on-chain Aiken vector (cross-layer pin)', () => {
  assert.equal(
    deriveSessionId({ tx_id: 'ab'.repeat(32), index: 3 }),
    'eefc453a50a290d5336c806d6bf5a15e439f5a2749887d9efb358090cd5a6373'
  );
});

test('register profile: references the guardian Handle and outputs the profile datum', () => {
  const plan = buildRegisterProfileTx('preview', profile());
  assert.equal(plan.redeemer, 'RegisterGuardianKeyProfile');
  assert.deepEqual(plan.reference_assets, [{ role: 'guardian_handle', asset_id: guardian }]);
  assert.equal(plan.mint_state_token, 'profile');
  assert.ok(plan.output.datum_cbor_hex.length > 0);
});

test('register profile: rejects a profile with neither key nor proof', () => {
  const p = { ...profile(), guardian_recovery_pubkey_x25519: null };
  assert.throws(() => buildRegisterProfileTx('preview', p), (e) => isSsrError(e, SsrErrorCode.ProfileUnresolvable));
});

test('create policy: references owner + every guardian profile, mints policy state', () => {
  const plan = buildCreatePolicyTx('preview', policy());
  assert.equal(plan.redeemer, 'CreatePolicy');
  assert.equal(plan.reference_assets[0]!.role, 'owner_handle');
  assert.equal(plan.reference_assets.filter((r) => r.role === 'guardian_profile').length, 3);
  assert.equal(plan.network_id, 0);
});

test('create policy: wrong network is hard-blocked', () => {
  // policy.network_id 0 (testnet) but building for mainnet (id 1) must fail.
  assert.throws(
    () => buildCreatePolicyTx('mainnet', policy({ network_id: 0 })),
    (e) => isSsrError(e, SsrErrorCode.NetworkMismatch)
  );
});

test('create policy: invalid threshold and empty cids are rejected', () => {
  assert.throws(() => buildCreatePolicyTx('preview', policy({ threshold_m: 4, shares_n: 3 })), (e) => isSsrError(e, SsrErrorCode.InvalidThreshold));
  assert.throws(() => buildCreatePolicyTx('preview', policy({ bundle_cids: [] })), (e) => isSsrError(e, SsrErrorCode.InvalidBundle));
  assert.throws(() => buildCreatePolicyTx('preview', policy({ policy_nonce: 1 })), (e) => isSsrError(e, SsrErrorCode.InvalidBundle));
});

test('rotate policy: requires nonce+1 and same owner', () => {
  const old: PolicyUtxo = { ref: { tx_id: 'aa'.repeat(32), index: 0 }, datum: policy() };
  const plan = buildRotatePolicyTx('preview', old, policy({ policy_nonce: 1 }));
  assert.equal(plan.redeemer, 'RotatePolicy');
  assert.deepEqual(plan.spend_input, { ref: old.ref, script: 'policy' });

  assert.throws(() => buildRotatePolicyTx('preview', old, policy({ policy_nonce: 0 })), (e) => isSsrError(e, SsrErrorCode.InvalidBundle));
  assert.throws(() => buildRotatePolicyTx('preview', old, policy({ policy_nonce: 1, owner_handle_asset_id: 'dead' })), (e) => isSsrError(e, SsrErrorCode.InvalidBundle));
});

test('initiate recovery: session_id is derived from the seed UTxO and status is Pending', () => {
  const seed = { tx_id: 'cd'.repeat(32), index: 1 };
  const { plan, datum } = buildInitiateRecoveryTx({
    network: 'preview',
    seed_utxo: seed,
    policy_ref: { owner_handle_asset_id: owner, policy_nonce: 0 },
    recovery_pubkey_x25519: '33'.repeat(32),
    created_slot: 100
  });
  assert.equal(datum.session_id, deriveSessionId(seed));
  assert.equal(datum.status, 'Pending');
  assert.deepEqual(plan.seed_utxo, seed);
  assert.equal(plan.mint_state_token, 'request');
});

test('initiate recovery: a non-32-byte recovery key is rejected', () => {
  assert.throws(
    () =>
      buildInitiateRecoveryTx({
        network: 'preview',
        seed_utxo: { tx_id: 'cd'.repeat(32), index: 1 },
        policy_ref: { owner_handle_asset_id: owner, policy_nonce: 0 },
        recovery_pubkey_x25519: '3333',
        created_slot: 100
      }),
    (e) => isSsrError(e, SsrErrorCode.InvalidKeyLength)
  );
});

test('cancel recovery: only a Pending request, transitions to Canceled, references owner', () => {
  const req: RequestUtxo = {
    ref: { tx_id: 'ee'.repeat(32), index: 0 },
    datum: {
      version: 1,
      policy_ref: { owner_handle_asset_id: owner, policy_nonce: 0 },
      session_id: 'deadbeef',
      recovery_pubkey_x25519: '33'.repeat(32),
      created_slot: 10,
      status: 'Pending'
    }
  };
  const plan = buildCancelRecoveryTx('preview', req);
  assert.equal(decodeRecoveryRequestDatum(Uint8Array.from(Buffer.from(plan.output.datum_cbor_hex, 'hex'))).status, 'Canceled');
  assert.deepEqual(plan.reference_assets, [{ role: 'owner_handle', asset_id: owner }]);

  const canceledReq: RequestUtxo = { ...req, datum: { ...req.datum, status: 'Canceled' } };
  assert.throws(() => buildCancelRecoveryTx('preview', canceledReq), (e) => isSsrError(e, SsrErrorCode.SessionMismatch));
});

test('approve recovery: references guardian + policy, non-empty cid required', () => {
  const datum = {
    version: 1,
    policy_ref: { owner_handle_asset_id: owner, policy_nonce: 0 },
    session_id: 'deadbeef',
    guardian_id: guardian,
    reencrypted_share_cid: '516d63'
  };
  const plan = buildApproveRecoveryTx('preview', datum);
  assert.equal(plan.reference_assets.filter((r) => r.role === 'guardian_handle').length, 1);
  assert.throws(() => buildApproveRecoveryTx('preview', { ...datum, reencrypted_share_cid: '' }), (e) => isSsrError(e, SsrErrorCode.InvalidArtifact));
});

test('complete recovery: spends the request, references the policy + each approval', () => {
  const req: RequestUtxo = {
    ref: { tx_id: 'ff'.repeat(32), index: 0 },
    datum: { version: 1, policy_ref: { owner_handle_asset_id: owner, policy_nonce: 0 }, session_id: 'deadbeef', recovery_pubkey_x25519: '33'.repeat(32), created_slot: 10, status: 'Pending' }
  };
  const approvals = [
    { ref: { tx_id: 'a1'.repeat(32), index: 0 }, datum: { version: 1, policy_ref: req.datum.policy_ref, session_id: 'deadbeef', guardian_id: guardian, reencrypted_share_cid: '516d63' } },
    { ref: { tx_id: 'a2'.repeat(32), index: 0 }, datum: { version: 1, policy_ref: req.datum.policy_ref, session_id: 'deadbeef', guardian_id: 'aa02', reencrypted_share_cid: '516d64' } }
  ];
  const plan = buildCompleteRecoveryTx('preview', req, approvals);
  assert.equal(plan.redeemer, 'CompleteRecovery');
  assert.equal(plan.reference_assets.filter((r) => r.role === 'approval').length, 2);
  assert.equal(decodeRecoveryRequestDatum(Uint8Array.from(Buffer.from(plan.output.datum_cbor_hex, 'hex'))).status, 'Completed');
});
