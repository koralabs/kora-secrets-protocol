import { test } from "node:test";
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { locateWitnessSet, mergeVkeysIntoTxCbor, skipCborItem, spliceVkeysIntoWitnessSet } from "./cborSplice.ts";

const hex = (h: string) => Buffer.from(h, "hex");

// Expected sizes are hand-counted from RFC 8949, not produced by the code under test.
test("skipCborItem returns the offset after each CBOR shape, including indefinite containers", () => {
  assert.equal(skipCborItem(hex("17"), 0), 1); // uint 23
  assert.equal(skipCborItem(hex("1819"), 0), 2); // uint8
  assert.equal(skipCborItem(hex("190100"), 0), 3); // uint16
  assert.equal(skipCborItem(hex("1a00010000"), 0), 5); // uint32
  assert.equal(skipCborItem(hex("1b0000000100000000"), 0), 9); // uint64
  assert.equal(skipCborItem(hex("43010203"), 0), 4); // bytes(3)
  assert.equal(skipCborItem(hex("820102"), 0), 3); // array [1,2]
  assert.equal(skipCborItem(hex("a1010203"), 0), 3); // map {1:2} then trailing byte
  assert.equal(skipCborItem(hex("c11a514b67b0"), 0), 6); // tagged item
  assert.equal(skipCborItem(hex("9f0102ff"), 0), 4); // indefinite array
  assert.equal(skipCborItem(hex("bf0102ff"), 0), 4); // indefinite map (key+value)
  assert.equal(skipCborItem(hex("5f41014102ff"), 0), 6); // chunked indefinite bytes
  assert.throws(() => skipCborItem(hex("1c"), 0), /Unsupported CBOR additional info/);
});

const body = "a10080"; // {0: []}
const oldWs = "a20081824101410205" + "9f0102ff"; // {0: [[h'01',h'02']], 5: indefinite [1,2]}
const tx = "84" + body + oldWs + "f5f6";
const sigOnly = "a100818242" + "0a0b" + "410c"; // {0: [[h'0a0b', h'0c']]}

test("locateWitnessSet finds the witness set after the body", () => {
  const { start, end } = locateWitnessSet(hex(tx));
  assert.equal(hex(tx).subarray(start, end).toString("hex"), oldWs);
});

test("merge replaces vkeys and keeps redeemer bytes (indefinite length) untouched", () => {
  const merged = mergeVkeysIntoTxCbor(tx, sigOnly);
  assert.equal(merged, "84" + body + "a2" + "00818242" + "0a0b410c" + "059f0102ff" + "f5f6");
});

test("splice into an empty witness set returns the signatures as given", () => {
  assert.equal(spliceVkeysIntoWitnessSet(hex("a0"), sigOnly), sigOnly);
});

test("splice adds vkeys when the original witness set has none", () => {
  assert.equal(spliceVkeysIntoWitnessSet(hex("a1059f01ff"), sigOnly), "a2" + "00818242" + "0a0b410c" + "059f01ff");
});
