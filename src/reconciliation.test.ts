import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildBundle,
  type Bundle,
  isSsrError,
  newRecoverySession,
  reencryptShareToSession,
  SsrErrorCode
} from '@koralabs/kora-secrets-crypto';

import type { RecoveryPolicyDatum } from './datums.ts';
import { validateApprovalArtifact, verifyBundleAgainstChain } from './reconciliation.ts';

const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'));
const OWNER = 'f0f06f776e6572';
const G1 = 'aa01';
const G2 = 'aa02';

function makeBundle(): Bundle {
  return buildBundle({
    network: 'preview',
    bundle_id: fromHex('00112233445566778899aabbccddeeff'),
    policy: {
      owner_handle_asset_id: OWNER,
      guardians: [
        { type: 'handle', asset_id: G1, share_index: 1 },
        { type: 'handle', asset_id: G2, share_index: 2 }
      ],
      threshold_m: 2,
      shares_n: 2,
      timelock_seconds: 172800
    },
    secret: { type: 'opaque_bytes', encoding: 'raw', bytes_len: 4 },
    shares: [
      { guardian_asset_id: G1, share_index: 1, sender_ephemeral_pub: fromHex('aa'.repeat(32)), nonce: fromHex('bb'.repeat(12)), ciphertext: fromHex('cc'.repeat(20)) },
      { guardian_asset_id: G2, share_index: 2, sender_ephemeral_pub: fromHex('dd'.repeat(32)), nonce: fromHex('ee'.repeat(12)), ciphertext: fromHex('ff'.repeat(20)) }
    ]
  });
}

function matchingPolicy(bundle: Bundle): RecoveryPolicyDatum {
  return {
    version: 1,
    network_id: 0, // preview
    owner_handle_asset_id: OWNER,
    threshold_m: 2,
    shares_n: 2,
    timelock_seconds: 172800,
    guardian_ids: [G1, G2],
    bundle_hash_blake2b256: bundle.integrity.bundle_hash_blake2b256_hex,
    bundle_cids: ['516d61'],
    policy_nonce: 0
  };
}

test('verifyBundleAgainstChain accepts a bundle matching its policy anchor', () => {
  const bundle = makeBundle();
  assert.doesNotThrow(() => verifyBundleAgainstChain(bundle, matchingPolicy(bundle)));
});

test('mismatched bundle hash hard-fails with BUNDLE_HASH_MISMATCH', () => {
  const bundle = makeBundle();
  const policy = { ...matchingPolicy(bundle), bundle_hash_blake2b256: '00'.repeat(32) };
  assert.throws(() => verifyBundleAgainstChain(bundle, policy), (e) => isSsrError(e, SsrErrorCode.BundleHashMismatch));
});

test('a self-inconsistent bundle (tampered after hashing) fails BUNDLE_HASH_MISMATCH', () => {
  const bundle = makeBundle();
  const tampered: Bundle = { ...bundle, secret: { ...bundle.secret, bytes_len: 99 } };
  assert.throws(() => verifyBundleAgainstChain(tampered, matchingPolicy(bundle)), (e) => isSsrError(e, SsrErrorCode.BundleHashMismatch));
});

test('network disagreement hard-fails with NETWORK_MISMATCH', () => {
  const bundle = makeBundle(); // preview -> network_id 0
  const policy = { ...matchingPolicy(bundle), network_id: 1 }; // mainnet id
  assert.throws(() => verifyBundleAgainstChain(bundle, policy), (e) => isSsrError(e, SsrErrorCode.NetworkMismatch));
});

test('threshold disagreement hard-fails with CHAIN_MISMATCH', () => {
  const bundle = makeBundle();
  const policy = { ...matchingPolicy(bundle), threshold_m: 1 };
  assert.throws(() => verifyBundleAgainstChain(bundle, policy), (e) => isSsrError(e, SsrErrorCode.ChainMismatch));
});

test('guardian-set disagreement hard-fails with CHAIN_MISMATCH', () => {
  const bundle = makeBundle();
  const policy = { ...matchingPolicy(bundle), guardian_ids: [G1, 'different'] };
  assert.throws(() => verifyBundleAgainstChain(bundle, policy), (e) => isSsrError(e, SsrErrorCode.ChainMismatch));
});

test('validateApprovalArtifact accepts an artifact bound to the expected session', () => {
  const session = newRecoverySession({ session_id: 'deadbeef' });
  const artifact = reencryptShareToSession(fromHex('010203'), session.recovery_pub, {
    policy_id: OWNER,
    session_id: session.session_id,
    guardian_id: G1
  });
  const ok = validateApprovalArtifact(artifact, {
    policy_ref: { owner_handle_asset_id: OWNER, policy_nonce: 0 },
    session_id: 'deadbeef'
  });
  assert.equal(ok.guardian_asset_id, G1);
});

test('an artifact bound to a different session is rejected (SESSION_MISMATCH)', () => {
  const session = newRecoverySession({ session_id: 'cafebabe' });
  const artifact = reencryptShareToSession(fromHex('010203'), session.recovery_pub, {
    policy_id: OWNER,
    session_id: session.session_id,
    guardian_id: G1
  });
  assert.throws(
    () => validateApprovalArtifact(artifact, { policy_ref: { owner_handle_asset_id: OWNER, policy_nonce: 0 }, session_id: 'deadbeef' }),
    (e) => isSsrError(e, SsrErrorCode.SessionMismatch)
  );
});

test('an artifact for a different policy is rejected (SESSION_MISMATCH)', () => {
  const session = newRecoverySession({ session_id: 'deadbeef' });
  const artifact = reencryptShareToSession(fromHex('010203'), session.recovery_pub, {
    policy_id: 'someoneelse',
    session_id: session.session_id,
    guardian_id: G1
  });
  assert.throws(
    () => validateApprovalArtifact(artifact, { policy_ref: { owner_handle_asset_id: OWNER, policy_nonce: 0 }, session_id: 'deadbeef' }),
    (e) => isSsrError(e, SsrErrorCode.SessionMismatch)
  );
});
