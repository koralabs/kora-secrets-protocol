import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  datumToCborHex,
  decodeGuardianApprovalDatum,
  decodeGuardianKeyProfileDatum,
  decodeRecoveryPolicyDatum,
  decodeRecoveryRequestDatum,
  encodeGuardianApprovalDatum,
  encodeGuardianKeyProfileDatum,
  encodeRecoveryPolicyDatum,
  encodeRecoveryRequestDatum,
  type GuardianApprovalDatum,
  type GuardianKeyProfileDatum,
  type RecoveryPolicyDatum,
  type RecoveryRequestDatum
} from './datums.ts';
import { decodePlutusData,encodePlutusData } from './plutus-data.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixtures = JSON.parse(
  readFileSync(path.resolve(__dirname, '__fixtures__/datum-cbor-v1.json'), 'utf8')
);

const profile: GuardianKeyProfileDatum = {
  version: 1,
  guardian_handle_asset_id: 'f0f0677561726469616e',
  paired_token_label: 3,
  guardian_key_source: 'HandleControlled',
  guardian_recovery_pubkey_x25519: '1111111111111111111111111111111111111111111111111111111111111111',
  key_proof_cid: null,
  key_proof_hash_blake2b256: null,
  updated_slot: 1000
};

const policy: RecoveryPolicyDatum = {
  version: 1,
  network_id: 0,
  owner_handle_asset_id: 'f0f06f776e6572',
  threshold_m: 2,
  shares_n: 3,
  timelock_seconds: 172800,
  guardian_ids: ['aa01', 'aa02', 'aa03'],
  bundle_hash_blake2b256: '2222222222222222222222222222222222222222222222222222222222222222',
  bundle_cids: ['Qma', 'Qmb'], // CID text; UTF-8 bytes are 516d61 / 516d62 (same on-chain CBOR)
  policy_nonce: 0
};

const request: RecoveryRequestDatum = {
  version: 1,
  policy_ref: { owner_handle_asset_id: 'f0f06f776e6572', policy_nonce: 0 },
  session_id: 'deadbeef',
  recovery_pubkey_x25519: '3333333333333333333333333333333333333333333333333333333333333333',
  created_slot: 500,
  status: 'Pending'
};

const approval: GuardianApprovalDatum = {
  version: 1,
  policy_ref: { owner_handle_asset_id: 'f0f06f776e6572', policy_nonce: 0 },
  session_id: 'deadbeef',
  guardian_id: 'aa01',
  reencrypted_share_cid: 'Qmc'
};

test('TS-encoded datum CBOR === Aiken fixture for every datum type', () => {
  // Invariant: the off-chain codec produces byte-identical PlutusData to the on-chain Aiken
  // types, so datums built off-chain are read correctly by the validators.
  // Negative control: the field-reorder test below proves a wrong layout changes the bytes.
  assert.equal(datumToCborHex(encodeGuardianKeyProfileDatum(profile)), fixtures.GuardianKeyProfileDatum.cbor_hex);
  assert.equal(datumToCborHex(encodeRecoveryPolicyDatum(policy)), fixtures.RecoveryPolicyDatum.cbor_hex);
  assert.equal(datumToCborHex(encodeRecoveryRequestDatum(request)), fixtures.RecoveryRequestDatum.cbor_hex);
  assert.equal(datumToCborHex(encodeGuardianApprovalDatum(approval)), fixtures.GuardianApprovalDatum.cbor_hex);
});

test('decode(encode(x)) round-trips each datum to an equal typed object', () => {
  const enc = (d: ReturnType<typeof encodeRecoveryPolicyDatum>) => encodePlutusData(d);
  assert.deepEqual(decodeGuardianKeyProfileDatum(enc(encodeGuardianKeyProfileDatum(profile))), profile);
  assert.deepEqual(decodeRecoveryPolicyDatum(enc(encodeRecoveryPolicyDatum(policy))), policy);
  assert.deepEqual(decodeRecoveryRequestDatum(enc(encodeRecoveryRequestDatum(request))), request);
  assert.deepEqual(decodeGuardianApprovalDatum(enc(encodeGuardianApprovalDatum(approval))), approval);
});

test('decoding an on-chain-sourced datum (the fixture bytes) yields the correct object', () => {
  const bytes = Uint8Array.from(Buffer.from(fixtures.RecoveryPolicyDatum.cbor_hex, 'hex'));
  assert.deepEqual(decodeRecoveryPolicyDatum(bytes), policy);
});

test('negative control: reordering a field changes the CBOR (mismatch with fixture)', () => {
  // Swap shares_n and threshold_m positions by hand-building the wrong layout.
  const wrong = encodePlutusData({
    kind: 'constr',
    index: 0,
    fields: [
      { kind: 'int', value: 1n },
      { kind: 'int', value: 0n },
      { kind: 'bytes', value: Uint8Array.from(Buffer.from('f0f06f776e6572', 'hex')) },
      { kind: 'int', value: 3n }, // shares_n where threshold_m should be
      { kind: 'int', value: 2n },
      { kind: 'int', value: 172800n },
      { kind: 'list', items: [] },
      { kind: 'bytes', value: new Uint8Array(32) },
      { kind: 'list', items: [] },
      { kind: 'int', value: 0n }
    ]
  });
  assert.notEqual(Buffer.from(wrong).toString('hex'), fixtures.RecoveryPolicyDatum.cbor_hex);
});

test('status enum maps to the correct constructor index (Pending/Canceled/Completed)', () => {
  const canceled = { ...request, status: 'Canceled' as const };
  const completed = { ...request, status: 'Completed' as const };
  // Re-decode to confirm the index round-trips to the right variant.
  assert.equal(decodeRecoveryRequestDatum(encodePlutusData(encodeRecoveryRequestDatum(canceled))).status, 'Canceled');
  assert.equal(decodeRecoveryRequestDatum(encodePlutusData(encodeRecoveryRequestDatum(completed))).status, 'Completed');
  // And the Pending/Canceled encodings differ.
  assert.notEqual(
    datumToCborHex(encodeRecoveryRequestDatum(request)),
    datumToCborHex(encodeRecoveryRequestDatum(canceled))
  );
});

test('decodePlutusData rejects truncated input', () => {
  assert.throws(() => decodePlutusData(Uint8Array.from([0xd8])));
});
