import assert from 'node:assert/strict';
import test from 'node:test';

import { decodePlutusData, encodePlutusData, PD, type PlutusData } from './plutus-data.ts';

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const roundtrip = (d: PlutusData) => decodePlutusData(encodePlutusData(d));

test('integer width encodings round-trip across CBOR size classes', () => {
  // inline (<24), 1-byte (24..255), 2-byte, 4-byte, 8-byte, and negative.
  for (const n of [0, 1, 23, 24, 255, 256, 65535, 65536, 0xffffffff, 0x1_0000_0000, -1, -1000]) {
    const back = roundtrip(PD.int(n));
    assert.equal(back.kind, 'int');
    assert.equal((back as { value: bigint }).value, BigInt(n));
  }
});

test('known int encodings match CBOR exactly', () => {
  assert.equal(hex(encodePlutusData(PD.int(1000))), '1903e8'); // 2-byte
  assert.equal(hex(encodePlutusData(PD.int(24))), '1818'); // 1-byte
  assert.equal(hex(encodePlutusData(PD.int(0x01020304))), '1a01020304'); // 4-byte
  assert.equal(hex(encodePlutusData(PD.int(-1))), '20'); // negative inline
});

test('constructors: empty uses 0x80, non-empty uses indefinite array', () => {
  assert.equal(hex(encodePlutusData(PD.constr(0, []))), 'd87980');
  assert.equal(hex(encodePlutusData(PD.constr(1, []))), 'd87a80');
  assert.equal(hex(encodePlutusData(PD.constr(0, [PD.int(1)]))), 'd8799f01ff');
});

test('lists are indefinite arrays and round-trip', () => {
  const d = PD.list([PD.int(1), PD.bytes(Uint8Array.from([0xaa])), PD.int(2)]);
  assert.equal(hex(encodePlutusData(d)), '9f0141aa02ff');
  assert.deepEqual(roundtrip(d), d);
});

test('constructor index 7 uses tag 1280 and round-trips', () => {
  const d = PD.constr(7, [PD.int(9)]);
  // tag 1280 = 0xd9 0x05 0x00
  assert.equal(hex(encodePlutusData(d)).startsWith('d90500'), true);
  assert.deepEqual(roundtrip(d), d);
});

test('decoder accepts a definite-array constructor body (other encoders)', () => {
  // d8799f01ff is our indefinite form; the equivalent definite form is d87981 01.
  const definite = Uint8Array.from(Buffer.from('d8798101', 'hex'));
  assert.deepEqual(decodePlutusData(definite), PD.constr(0, [PD.int(1)]));
});

test('64-byte byte string is allowed; 65 is rejected (Plutus chunking unused)', () => {
  assert.doesNotThrow(() => encodePlutusData(PD.bytes(new Uint8Array(64))));
  assert.throws(() => encodePlutusData(PD.bytes(new Uint8Array(65))), /chunking/);
});

test('decoder rejects unsupported major types and bad constructor tags', () => {
  assert.throws(() => decodePlutusData(Uint8Array.from([0xe0]))); // major 7 (float/simple)
  assert.throws(() => decodePlutusData(Uint8Array.from([0xc0, 0x00]))); // tag 0, not a constr tag
});

test('encoder rejects a negative constructor index', () => {
  assert.throws(() => encodePlutusData(PD.constr(-1, [])));
});
