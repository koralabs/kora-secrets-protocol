// Invariant: the script-data hash is taken over the Conway MAP-encoded redeemers (not the Alonzo
// array), so a tx built here is not rejected with PPViewHashesDontMatch.
// Failure caught: layout drift (array vs map redeemers, datum placement, empty-map wrappers).
// Expected preimages are written out by hand as CBOR hex; only the blake2b primitive is shared.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { test } from "node:test";

import { computeScriptDataHash } from "./computeScriptDataHash.ts";
import { Cardano } from "./index.ts";

const { blake2b } = createRequire(import.meta.url)("@cardano-sdk/crypto") as any;
const h = (hex: string) => blake2b.hash(hex, 32) as string;

const redeemer = (purpose: any, index: number) =>
  ({ purpose, index, data: 1n, executionUnits: { memory: 5, steps: 6 } }) as any;

test("returns undefined when there are no redeemers and no datums", () => {
  assert.equal(computeScriptDataHash(new Map(), [], [], []), undefined);
  assert.equal(computeScriptDataHash(new Map(), [], undefined, undefined), undefined);
});

test("datums only: hash(empty_map || [datums] || empty_map)", () => {
  // datum 1 -> 01; datums array [1] -> 81 01
  assert.equal(computeScriptDataHash(new Map(), [], undefined, [1n]), h("a0" + "8101" + "a0"));
});

test("redeemers use the Conway map form and end with the language views", () => {
  // { [spend,0]: [1, [5,6]] } -> a1 82 00 00 82 01 82 05 06 ; no cost models -> a0
  const expected = h("a1" + "82" + "00" + "00" + "82" + "01" + "82" + "05" + "06" + "a0");
  const got = computeScriptDataHash(new Map(), [], [redeemer(Cardano.RedeemerPurpose.spend, 0)]);
  assert.equal(got, expected);
  // the old Alonzo array form must NOT be what we hash
  assert.notEqual(got, h("81" + "840000" + "01" + "8205" + "06" + "a0"));
});

test("purpose maps to tags 0 spend, 1 mint, 2 cert, 3 otherwise", () => {
  const tagOf = (purpose: any) =>
    computeScriptDataHash(new Map(), [], [redeemer(purpose, 7)]);
  const hashFor = (tag: string) => h("a1" + "82" + tag + "07" + "82" + "01" + "82" + "05" + "06" + "a0");
  assert.equal(tagOf(Cardano.RedeemerPurpose.spend), hashFor("00"));
  assert.equal(tagOf(Cardano.RedeemerPurpose.mint), hashFor("01"));
  assert.equal(tagOf(Cardano.RedeemerPurpose.certificate), hashFor("02"));
  assert.equal(tagOf(Cardano.RedeemerPurpose.withdrawal), hashFor("03"));
});

test("redeemers plus datums put the datums between redeemers and language views", () => {
  const got = computeScriptDataHash(new Map(), [], [redeemer(Cardano.RedeemerPurpose.spend, 0)], [1n]);
  assert.equal(got, h("a1" + "8200" + "00" + "82" + "01" + "82" + "05" + "06" + "8101" + "a0"));
});
