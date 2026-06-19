import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildBundle,
  type Bundle,
  combineShares,
  decodeBundleShare,
  decryptShare,
  encryptShare,
  isSsrError,
  newX25519Keypair,
  splitSecret,
  SsrErrorCode,
  utf8ToBytes
} from '@koralabs/kora-secrets-crypto';

import { type RequestUtxo } from './chain-provider.ts';
import { type RecoveryPolicyDatum } from './datums.ts';
import { verifyBundleAgainstChain } from './reconciliation.ts';
import { getBundle, getBundleFromAny, InMemoryBlobStore, putBundle } from './storage.ts';
import { buildCancelRecoveryTx, buildCreatePolicyTx } from './tx-builders.ts';
import { deriveSessionId } from './tx-builders.ts';

const OWNER = 'f0f06f776e6572';
const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'));

function guardians(n: number) {
  return Array.from({ length: n }, (_u, i) => {
    const kp = newX25519Keypair();
    return { asset_id: 'f0f0' + i.toString(16).padStart(2, '0') + '67756172', gek_pub: kp.pub, gek_priv: kp.priv };
  });
}

async function buildPolicyBundle(gs: ReturnType<typeof guardians>, m: number, secret: Uint8Array) {
  const bundle_id = fromHex('00112233445566778899aabbccddeeff');
  const shares = await splitSecret(secret, { m, n: gs.length });
  const enc = shares.map((s, i) => ({
    guardian_asset_id: gs[i]!.asset_id,
    share_index: s.index,
    ...encryptShare({ policy_id: OWNER, guardian_id: gs[i]!.asset_id, share_index: s.index, bundle_id, share: s.data, guardian_gek_pub: gs[i]!.gek_pub })
  }));
  return buildBundle({
    network: 'preview',
    bundle_id,
    policy: { owner_handle_asset_id: OWNER, guardians: gs.map((g, i) => ({ type: 'handle' as const, asset_id: g.asset_id, share_index: i + 1 })), threshold_m: m, shares_n: gs.length, timelock_seconds: 172800 },
    secret: { type: 'opaque_bytes', encoding: 'raw', bytes_len: secret.length },
    shares: enc
  });
}

function policyFor(bundle: Bundle, gs: ReturnType<typeof guardians>, m: number, nonce = 0, cids = ['Qm']): RecoveryPolicyDatum {
  return {
    version: 1, network_id: 0, owner_handle_asset_id: OWNER, threshold_m: m, shares_n: gs.length,
    timelock_seconds: 172800, guardian_ids: gs.map((g) => g.asset_id),
    bundle_hash_blake2b256: bundle.integrity.bundle_hash_blake2b256_hex, bundle_cids: cids, policy_nonce: nonce
  };
}

// 1) Cancel marks Canceled; a new attempt needs a NEW seed UTxO -> different session_id.
test('cancel transitions Pending->Canceled, and a post-cancel attempt needs a fresh session', () => {
  const req: RequestUtxo = {
    ref: { tx_id: 'ee'.repeat(32), index: 0 },
    datum: { version: 1, policy_ref: { owner_handle_asset_id: OWNER, policy_nonce: 0 }, session_id: deriveSessionId({ tx_id: 'a1'.repeat(32), index: 0 }), recovery_pubkey_x25519: '33'.repeat(32), created_slot: 1, status: 'Pending' }
  };
  const plan = buildCancelRecoveryTx('preview', req);
  assert.equal(plan.redeemer, 'CancelRecovery');
  // A new session must consume a different seed UTxO, yielding a different session_id.
  const newSession = deriveSessionId({ tx_id: 'b2'.repeat(32), index: 0 });
  assert.notEqual(newSession, req.datum.session_id);
  // Cancelling an already-Canceled request is refused.
  const canceled: RequestUtxo = { ...req, datum: { ...req.datum, status: 'Canceled' } };
  assert.throws(() => buildCancelRecoveryTx('preview', canceled), (e) => isSsrError(e, SsrErrorCode.SessionMismatch));
});

// 2) Guardians withholding shares during the alert window -> fewer than M -> cannot reconstruct.
test('withheld shares (fewer than M published) cannot reconstruct', async () => {
  const gs = guardians(5);
  const secret = utf8ToBytes('the protected secret');
  const bundle = await buildPolicyBundle(gs, 3, secret);
  // Only 2 of 3 guardians "publish" (decrypt their share); collect 2 plaintext shares.
  const shares = gs.slice(0, 2).map((g) => {
    const entry = bundle.shares.find((s) => s.guardian_asset_id === g.asset_id)!;
    return { index: entry.share_index, data: decryptShare({ policy_id: OWNER, guardian_id: g.asset_id, share_index: entry.share_index, bundle_id: fromHex(bundle.bundle_id), guardian_gek_priv: g.gek_priv, ...decodeBundleShare(entry) }) };
  });
  let recovered = false;
  try {
    recovered = Buffer.from(await combineShares(shares)).equals(Buffer.from(secret));
  } catch {
    recovered = false;
  }
  assert.equal(recovered, false);
});

// 3) Rotation supersedes: the old bundle no longer matches the rotated (new-guardian) policy.
test('rotation supersedes — old bundle fails reconciliation against the new policy', async () => {
  const gs1 = guardians(3);
  const gs2 = guardians(3); // new guardian set after rotation
  const secret = utf8ToBytes('seed words');
  const oldBundle = await buildPolicyBundle(gs1, 2, secret);
  const newBundle = await buildPolicyBundle(gs2, 2, secret);
  const newPolicy = policyFor(newBundle, gs2, 2, 1);
  // The new bundle matches the rotated policy...
  assert.doesNotThrow(() => verifyBundleAgainstChain(newBundle, newPolicy));
  // ...but the superseded old bundle no longer matches the new anchor (its hash differs), so a
  // client resolving the new policy will reject the stale bundle. (Guardian-set divergence is
  // covered as CHAIN_MISMATCH in reconciliation.test.ts.)
  assert.throws(() => verifyBundleAgainstChain(oldBundle, newPolicy), (e) => isSsrError(e, SsrErrorCode.BundleHashMismatch));
});

// 4) Guardian Handle transfer: the new owner's key cannot decrypt the old share.
test('a transferred guardian Handle (new gek) cannot decrypt the original share', async () => {
  const gs = guardians(2);
  const secret = utf8ToBytes('protect me');
  const bundle = await buildPolicyBundle(gs, 2, secret);
  const entry = bundle.shares[0]!;
  const newOwnerKey = newX25519Keypair(); // the Handle was sold; new owner has a different GEK
  assert.throws(
    () => decryptShare({ policy_id: OWNER, guardian_id: gs[0]!.asset_id, share_index: entry.share_index, bundle_id: fromHex(bundle.bundle_id), guardian_gek_priv: newOwnerKey.priv, ...decodeBundleShare(entry) }),
    (e) => isSsrError(e, SsrErrorCode.DecryptionFailed)
  );
});

// 5) IPFS bundle unavailable -> owner-file fallback, still verified against the on-chain hash.
test('IPFS-unavailable -> fallback CID resolves and verifies against the anchor', async () => {
  const gs = guardians(2);
  const bundle = await buildPolicyBundle(gs, 1, utf8ToBytes('x'));
  const store = new InMemoryBlobStore();
  const [realCid] = await putBundle(bundle, [store]); // the "owner file" / mirror copy
  // The primary IPFS cid is unavailable; fallback to the mirror succeeds and verifies.
  const fetched = await getBundleFromAny(['bafkrei-unreachable', realCid!], store);
  assert.doesNotThrow(() => verifyBundleAgainstChain(fetched, policyFor(bundle, gs, 1, 0, ['bafkrei-unreachable', realCid!])));
  // A blob that does not match its anchor is rejected before use.
  const forged: Bundle = { ...bundle, integrity: { bundle_hash_blake2b256_hex: '00'.repeat(32) } };
  const badCid = await store.put(utf8ToBytes(JSON.stringify(forged)));
  await assert.rejects(() => getBundle(badCid, store), (e) => isSsrError(e, SsrErrorCode.BundleHashMismatch));
});

// 6) Network mismatch is hard-blocked.
test('network mismatch is hard-blocked at policy build and at reconciliation', async () => {
  const gs = guardians(1);
  const bundle = await buildPolicyBundle(gs, 1, utf8ToBytes('x'));
  // Build for mainnet with a testnet policy datum -> blocked.
  assert.throws(() => buildCreatePolicyTx('mainnet', policyFor(bundle, gs, 1)), (e) => isSsrError(e, SsrErrorCode.NetworkMismatch));
  // A preview bundle vs a mainnet (network_id 1) policy -> blocked.
  assert.throws(() => verifyBundleAgainstChain(bundle, { ...policyFor(bundle, gs, 1), network_id: 1 }), (e) => isSsrError(e, SsrErrorCode.NetworkMismatch));
});

// 7) No-friend 1-of-2: either single guardian can reconstruct.
test('no-friend 1-of-2: either guardian alone reconstructs', async () => {
  const gs = guardians(2);
  const secret = utf8ToBytes('lonely secret');
  const bundle = await buildPolicyBundle(gs, 1, secret);
  for (const g of gs) {
    const entry = bundle.shares.find((s) => s.guardian_asset_id === g.asset_id)!;
    const share = decryptShare({ policy_id: OWNER, guardian_id: g.asset_id, share_index: entry.share_index, bundle_id: fromHex(bundle.bundle_id), guardian_gek_priv: g.gek_priv, ...decodeBundleShare(entry) });
    const recovered = await combineShares([{ index: entry.share_index, data: share }]);
    assert.ok(Buffer.from(recovered).equals(Buffer.from(secret)));
  }
});