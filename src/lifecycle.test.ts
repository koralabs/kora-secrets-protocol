import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildBundle,
  combineShares,
  decodeBundleShare,
  decryptSessionShare,
  decryptShare,
  encodeSecret,
  encryptShare,
  newRecoverySession,
  newX25519Keypair,
  reencryptShareToSession,
  splitSecret,
  type SssShare
} from '@koralabs/kora-secrets-crypto';

import type { GuardianKeyProfileDatum, RecoveryPolicyDatum } from './datums.ts';
import { FakeChainProvider } from './fake-chain-provider.ts';
import { validateApprovalArtifact,verifyBundleAgainstChain } from './reconciliation.ts';
import { getBundle, getShareArtifact, InMemoryBlobStore, putBundle, putShareArtifact } from './storage.ts';
import { buildInitiateRecoveryTx, deriveSessionId } from './tx-builders.ts';

const OWNER = 'f0f06f776e6572';
const toHex = (b: Uint8Array) => Buffer.from(b).toString('hex');

interface Guardian {
  asset_id: string;
  priv: Uint8Array;
  pub: Uint8Array;
}

// A full, UI-less SSR lifecycle wired across crypto + protocol + storage with the in-memory
// chain provider and blob store. This is the Milestone M3 proof: enroll guardians -> create
// policy -> initiate recovery -> collect M approvals -> reconstruct, all locally.
async function runLifecycle(m: number, n: number, secretBytes: Uint8Array, network: 'preview' = 'preview') {
  const provider = new FakeChainProvider();
  const store = new InMemoryBlobStore();

  // 1) Guardian enrollment: each guardian creates a GEK and publishes a (003) inline profile.
  const guardians: Guardian[] = [];
  for (let i = 0; i < n; i++) {
    const kp = newX25519Keypair();
    const asset_id = `aa${i}.${'67756172'}`;
    guardians.push({ asset_id, priv: kp.priv, pub: kp.pub });
    const profile: GuardianKeyProfileDatum = {
      version: 1,
      guardian_handle_asset_id: asset_id,
      paired_token_label: 3,
      guardian_key_source: 'HandleControlled',
      guardian_recovery_pubkey_x25519: toHex(kp.pub),
      key_proof_cid: null,
      key_proof_hash_blake2b256: null,
      updated_slot: 1
    };
    provider.setProfile(profile);
  }

  // 2) Owner creates the policy: resolve each guardian's gek_pub from chain, split + encrypt.
  const bundleId = crypto.getRandomValues(new Uint8Array(16));
  const shares = await splitSecret(secretBytes, { m, n });
  const encryptedShares = [];
  for (let i = 0; i < n; i++) {
    const g = guardians[i]!;
    const resolved = await provider.resolveGuardianProfile(g.asset_id);
    assert.ok(resolved, 'guardian profile must resolve');
    const enc = encryptShare({
      policy_id: OWNER,
      guardian_id: g.asset_id,
      share_index: shares[i]!.index,
      bundle_id: bundleId,
      share: shares[i]!.data,
      guardian_gek_pub: resolved!.gek_pub
    });
    encryptedShares.push({ guardian_asset_id: g.asset_id, share_index: shares[i]!.index, ...enc });
  }

  const bundle = buildBundle({
    network,
    bundle_id: bundleId,
    policy: {
      owner_handle_asset_id: OWNER,
      guardians: guardians.map((g, i) => ({ type: 'handle' as const, asset_id: g.asset_id, share_index: i + 1 })),
      threshold_m: m,
      shares_n: n,
      timelock_seconds: 172800
    },
    secret: { type: 'opaque_bytes', encoding: 'raw', bytes_len: secretBytes.length },
    shares: encryptedShares
  });

  const cids = await putBundle(bundle, [store]);

  const policyDatum: RecoveryPolicyDatum = {
    version: 1,
    network_id: 0,
    owner_handle_asset_id: OWNER,
    threshold_m: m,
    shares_n: n,
    timelock_seconds: 172800,
    guardian_ids: guardians.map((g) => g.asset_id),
    bundle_hash_blake2b256: bundle.integrity.bundle_hash_blake2b256_hex,
    bundle_cids: cids,
    policy_nonce: 0
  };
  provider.policies.push({ ref: { tx_id: 'a'.repeat(64), index: 0 }, datum: policyDatum });

  // 3) The bundle reconciles against the on-chain anchor.
  verifyBundleAgainstChain(bundle, policyDatum);

  // 4) Requester initiates a recovery session bound to a seed UTxO.
  const seed = { tx_id: 'b'.repeat(64), index: 2 };
  const session = newRecoverySession({ session_id: deriveSessionId(seed) });
  const { datum: requestDatum } = buildInitiateRecoveryTx({
    network,
    seed_utxo: seed,
    policy_ref: { owner_handle_asset_id: OWNER, policy_nonce: 0 },
    recovery_pubkey_x25519: toHex(session.recovery_pub),
    created_slot: 100
  });
  provider.requests.push({ ref: { tx_id: 'c'.repeat(64), index: 0 }, datum: requestDatum });

  // 5) The first M guardians approve: verify bundle, decrypt their share, re-encrypt, publish.
  const approvers = guardians.slice(0, m);
  for (const g of approvers) {
    const fetched = await getBundle(cids[0]!, store); // verifies bundle_hash before use
    const entry = fetched.shares.find((s) => s.guardian_asset_id === g.asset_id)!;
    const sharePlain = decryptShare({
      policy_id: OWNER,
      guardian_id: g.asset_id,
      share_index: entry.share_index,
      bundle_id: Uint8Array.from(Buffer.from(fetched.bundle_id, 'hex')),
      guardian_gek_priv: g.priv,
      ...decodeBundleShare(entry)
    });
    const artifact = reencryptShareToSession(sharePlain, session.recovery_pub, {
      policy_id: OWNER,
      session_id: session.session_id,
      guardian_id: g.asset_id
    });
    const shareCid = await putShareArtifact(artifact, store);
    provider.approvals.push({
      ref: { tx_id: g.asset_id.slice(0, 2).repeat(32), index: 0 },
      datum: { version: 1, policy_ref: requestDatum.policy_ref, session_id: session.session_id, guardian_id: g.asset_id, reencrypted_share_cid: shareCid }
    });
  }

  // 6) Requester collects M approvals, fetches + validates artifacts, decrypts, reconstructs.
  const approvals = await provider.findApprovals(requestDatum.policy_ref, session.session_id);
  assert.equal(approvals.length, m);
  const recoveredShares: SssShare[] = [];
  for (const a of approvals) {
    const artifact = await getShareArtifact(a.datum.reencrypted_share_cid, store);
    validateApprovalArtifact(artifact, { policy_ref: requestDatum.policy_ref, session_id: session.session_id });
    const idx = guardians.findIndex((g) => g.asset_id === a.datum.guardian_id) + 1;
    recoveredShares.push({ index: idx, data: decryptSessionShare(artifact, session.recovery_priv) });
  }
  return toHex(await combineShares(recoveredShares));
}

test('M3: scripted full lifecycle reconstructs a 3-of-5 secret end to end', async () => {
  const enc = encodeSecret({ type: 'bip39_entropy', input: 'legal winner thank year wave sausage worth useful legal winner thank yellow' });
  const recovered = await runLifecycle(3, 5, enc.secret_bytes);
  assert.equal(recovered, toHex(enc.secret_bytes));
});

test('M3: scripted lifecycle reconstructs a no-friend 1-of-1 text secret', async () => {
  const enc = encodeSecret({ type: 'utf8_text', input: 'super-secret-passphrase' });
  const recovered = await runLifecycle(1, 1, enc.secret_bytes);
  assert.equal(recovered, toHex(enc.secret_bytes));
});
