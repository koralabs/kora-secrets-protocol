import assert from "node:assert/strict";
import { test } from "node:test";

import { Serialization } from "@cardano-sdk/core";
import { Cardano, getBlockfrostBuildContext, finalizeTxPlan } from "./index.ts";

// Feature: finalizeTxPlan turns a declarative plan into an unsigned tx whose fee, change and
// collateral return satisfy the ledger's value-conservation and collateral rules.
// Failure caught: wrong change/fee/collateral arithmetic (ValueNotConservedUTxO on submit).

const params = {
  coins_per_utxo_size: 4310, collateral_percent: 150, e_max: 18, key_deposit: 2000000,
  max_block_ex_mem: 62000000, max_block_ex_steps: 20000000000, max_block_header_size: 1100,
  max_block_size: 90112, max_collateral_inputs: 3, pool_deposit: 500000000,
  max_tx_ex_mem: 14000000, max_tx_ex_steps: 10000000000, max_tx_size: 16384, max_val_size: 5000,
  min_fee_a: 44, min_fee_b: 155381, min_pool_cost: 170000000, n_opt: 500, price_mem: 0.0577,
  price_step: 0.0000721, protocol_major_ver: 10, protocol_minor_ver: 0, a0: 0.3, rho: 0.003, tau: 0.2,
};
const fakeFetch = (async (url: string) => {
  const u = String(url);
  const body = u.endsWith("/blocks/latest")
    ? { hash: "00", epoch: 1, epoch_slot: 1, height: 1, slot: 1, time: 1 }
    : u.endsWith("/genesis")
      ? { slot_length: 1, active_slots_coefficient: 0.05, epoch_length: 432000, max_kes_evolutions: 62, max_lovelace_supply: 1, network_magic: 2, security_param: 2160, slots_per_kes_period: 129600, system_start: 1, update_quorum: 5 }
      : params;
  return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
}) as unknown as typeof fetch;

const addr = (byte: number): string =>
  Cardano.EnterpriseAddress.fromCredentials(0, {
    type: Cardano.CredentialType.KeyHash,
    hash: byte.toString(16).padStart(2, "0").repeat(28) as never,
  }).toAddress().toBech32();

const utxo = (txByte: string, index: number, coins: bigint, address: string): Cardano.Utxo => [
  { address: address as never, txId: txByte.repeat(32) as never, index },
  { address: address as never, value: { coins } },
];

const ctx = await getBlockfrostBuildContext("preview", "key", { fetchFn: fakeFetch });
const wallet = addr(1);
const dest = addr(2);

test("finalizeTxPlan conserves value, pays the fee from change and fills a 0-coin output to the min", async () => {
  const input = utxo("aa", 0, 50_000_000n, wallet);
  const res = await finalizeTxPlan({
    preSelectedUtxos: [], spareUtxos: [input], changeAddress: wallet, buildContext: ctx,
    outputs: [{ address: dest as never, value: { coins: 0n } }],
  });
  const decoded = Serialization.Transaction.fromCbor(res.cborHex as never).toCore();
  const out = decoded.body.outputs;
  const paid = out.find((o) => o.address === dest)!;
  const change = out.find((o) => o.address === wallet)!;
  assert.ok(paid.value.coins > 0n, "0-coin output filled to min UTxO");
  assert.equal(paid.value.coins + change.value.coins + decoded.body.fee, 50_000_000n);
  assert.deepEqual([...res.consumedInputs], [`${"aa".repeat(32)}#0`]);
  assert.equal(res.txHash, decoded.id);
  assert.ok(res.estimatedSignedTxSize > res.cborHex.length / 2, "estimate includes vkey witnesses");
  assert.equal(decoded.witness.signatures.size, 0);
});

test("feeSafetyMarginLovelace raises the fee by exactly the margin and shrinks change", async () => {
  const run = (margin?: bigint) => finalizeTxPlan({
    preSelectedUtxos: [], spareUtxos: [utxo("aa", 0, 50_000_000n, wallet)], changeAddress: wallet, buildContext: ctx,
    outputs: [{ address: dest as never, value: { coins: 5_000_000n } }], feeSafetyMarginLovelace: margin,
  }).then(async (r) => Serialization.Transaction.fromCbor(r.cborHex as never).toCore().body.fee);
  assert.equal((await run(300_000n)) - (await run()), 300_000n);
});

test("collateral excess is returned and the fee delta comes out of change", async () => {
  const col = utxo("bb", 0, 100_000_000n, wallet);
  const res = await finalizeTxPlan({
    preSelectedUtxos: [], spareUtxos: [utxo("aa", 0, 50_000_000n, wallet)], changeAddress: wallet, buildContext: ctx,
    outputs: [{ address: dest as never, value: { coins: 5_000_000n } }], collateralUtxo: col,
  });
  const body = Serialization.Transaction.fromCbor(res.cborHex as never).toCore().body;
  const required = (body.fee * 150n + 99n) / 100n;
  assert.equal(body.totalCollateral, required);
  assert.equal(body.collateralReturn!.value.coins, 100_000_000n - required);
  const outs = body.outputs.reduce((s, o) => s + o.value.coins, 0n);
  assert.equal(outs + body.fee, 50_000_000n, "value conserved after the +5000 fee bump");
});

test("a spend redeemer without spendRedeemerTargetInput is rejected", async () => {
  await assert.rejects(
    finalizeTxPlan({
      preSelectedUtxos: [], spareUtxos: [utxo("aa", 0, 50_000_000n, wallet)], changeAddress: wallet, buildContext: ctx,
      outputs: [{ address: dest as never, value: { coins: 5_000_000n } }],
      redeemers: [{ purpose: "spend", index: 0, data: 0n as never, executionUnits: { memory: 1, steps: 1 } } as never],
    }),
    /spendRedeemerTargetInput/,
  );
});
