import assert from "node:assert/strict";
import { test } from "node:test";
import {
  ensureDoubleCbor,
  plutusDataJsonToCbor,
  plutusDataJsonToCore,
} from "./scriptParams.ts";

// Invariant: PlutusData JSON encodes to the exact CBOR the chain expects.
// Expected hex is hand-derived from the CBOR / Plutus data spec, not from the code.
test("plutusDataJsonToCbor encodes int, bytes, constructor, list and map", () => {
  assert.equal(plutusDataJsonToCbor({ int: 1 }), "01");
  assert.equal(plutusDataJsonToCbor({ bytes: "abcd" }), "42abcd");
  assert.equal(plutusDataJsonToCbor({ constructor: 0, fields: [] }), "d87980");
  assert.equal(
    plutusDataJsonToCbor({ constructor: 1, fields: [{ int: 2 }] }),
    "d87a9f02ff",
  );
  assert.equal(plutusDataJsonToCbor({ list: [{ int: 1 }, { int: 2 }] }), "9f0102ff");
  assert.equal(
    plutusDataJsonToCbor({ map: [{ k: { int: 1 }, v: { bytes: "ff" } }] }),
    "a10141ff",
  );
});

test("plutusDataJsonToCore rejects a value of no known shape", () => {
  assert.throws(() => plutusDataJsonToCore({} as never), /invalid PlutusDataJson/);
});

// Invariant: single-wrapped script CBOR gets exactly one more byte-string header; double stays.
test("ensureDoubleCbor wraps single CBOR with the correct header width and leaves double alone", () => {
  const single = (n: number) => {
    const body = "00".repeat(n);
    const h = n <= 23 ? (0x40 | n).toString(16).padStart(2, "0")
      : n <= 0xff ? "58" + n.toString(16).padStart(2, "0")
      : n <= 0xffff ? "59" + n.toString(16).padStart(4, "0")
      : "5a" + n.toString(16).padStart(8, "0");
    return h + body;
  };
  // inner flat UPLC begins with 0x01 (not a byte string), so the input is single-wrapped
  for (const n of [5, 30, 300, 70000]) {
    const inner = "01" + "00".repeat(n - 1);
    const hdr = single(n).slice(0, single(n).length - n * 2);
    const singleCbor = hdr + inner;
    const wrapped = ensureDoubleCbor(singleCbor);
    const total = singleCbor.length / 2;
    const expectedHdr = total <= 23 ? (0x40 | total).toString(16).padStart(2, "0")
      : total <= 0xff ? "58" + total.toString(16).padStart(2, "0")
      : total <= 0xffff ? "59" + total.toString(16).padStart(4, "0")
      : "5a" + total.toString(16).padStart(8, "0");
    assert.equal(wrapped, expectedHdr + singleCbor);
    assert.equal(ensureDoubleCbor(wrapped), wrapped);
  }
});

test("ensureDoubleCbor rejects empty, non-bytestring and unsupported-length input", () => {
  assert.throws(() => ensureDoubleCbor(""), /empty script cbor/);
  assert.throws(() => ensureDoubleCbor("01"), /expected CBOR byte string/);
  assert.throws(() => ensureDoubleCbor("5c00"), /unsupported CBOR byte string length encoding: 28/);
});
