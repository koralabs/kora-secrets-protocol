import { Buffer } from 'node:buffer';

import * as Crypto from '@cardano-sdk/crypto';
import type { HexBlob } from '@cardano-sdk/util';
import { bech32 } from '@scure/base';
import { mnemonicToEntropy } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';

import { Cardano, Serialization, transactionHashFromCore } from '../cardano-sdk/index.ts';

// CIP-1852 key derivation + Ed25519 signing for a Node-side signer (preview deploy/lifecycle
// scripts). Pure-JS only: @scure/bip39 for the mnemonic, @cardano-sdk/crypto for BIP32-Ed25519
// + signing — no WASM, no Lucid. Browser flows sign via CIP-30; this is for the funded e2e
// wallet that publishes reference scripts and exercises the lifecycle off a seed phrase.

const HARDENED = 0x80000000;
const PURPOSE = 1852;
const COIN_TYPE = 1815;
const ROLE_EXTERNAL = 0;
const ROLE_STAKE = 2;

export interface SsrSigner {
  /** bech32 base address (payment + stake), on the requested network. */
  address: string;
  /** Sign a hex-encoded message (a tx body hash) → Ed25519 signature hex. */
  sign(messageHex: string): Promise<string>;
  /** The signer's Ed25519 public key hex (for the vkey witness + required-signer hash). */
  publicKeyHex(): Promise<string>;
  /** The payment credential key hash (hex) — for required-signers / address ownership checks. */
  paymentKeyHashHex(): Promise<string>;
}

/**
 * Derive a single-address signer from a BIP-39 mnemonic at m/1852'/1815'/account'/role/index.
 * networkId: 0 = testnet (preview/preprod), 1 = mainnet.
 */
export async function signerFromMnemonic(
  mnemonic: string,
  networkId: number,
  opts: { account?: number; index?: number } = {}
): Promise<SsrSigner> {
  const account = opts.account ?? 0;
  const index = opts.index ?? 0;
  await Crypto.ready(); // init @cardano-sdk/crypto's BIP32-Ed25519 backend before derivation
  const entropy = mnemonicToEntropy(mnemonic.trim(), wordlist);
  const rootKey = await Crypto.Bip32PrivateKey.fromBip39Entropy(Buffer.from(entropy), '');
  const accountKey = await rootKey.derive([HARDENED + PURPOSE, HARDENED + COIN_TYPE, HARDENED + account]);
  const paymentKey = await accountKey.derive([ROLE_EXTERNAL, index]);
  const stakeKey = await accountKey.derive([ROLE_STAKE, 0]);

  const paymentPrv = paymentKey.toRawKey();
  const paymentPub = await paymentPrv.toPublic();
  const stakePub = await (stakeKey.toRawKey()).toPublic();
  const paymentKeyHash = (await paymentPub).hash();
  const stakeKeyHash = stakePub.hash();

  const address = Cardano.BaseAddress.fromCredentials(
    networkId,
    { type: Cardano.CredentialType.KeyHash, hash: paymentKeyHash.hex() },
    { type: Cardano.CredentialType.KeyHash, hash: stakeKeyHash.hex() }
  )
    .toAddress()
    .toBech32();

  return {
    address,
    sign: async (messageHex: string) => (await paymentPrv.sign(messageHex as HexBlob)).hex(),
    publicKeyHex: async () => (await paymentPub).hex(),
    paymentKeyHashHex: async () => paymentKeyHash.hex()
  };
}

/**
 * Derive a signer from a bech32 `xprv` BIP32 key (the handle.me/minting-engine POLICY_KEY),
 * following the minting engine's layout (minting.handle.me getPolicyWallet): derivation 0 is the
 * root policy key itself; any other index N is m/1852'/1815'/0'/0/N — notably 13 = "Approved
 * Minter" (the DeMi allowed_minter that co-signs every label-asset mint). The key never leaves
 * this process; only its signature/hash are surfaced.
 */
export async function signerFromXprv(xprvBech32: string, derivation: number, networkId: number): Promise<SsrSigner> {
  await Crypto.ready();
  const decoded = bech32.decode(xprvBech32.trim() as `${string}1${string}`, 1023);
  if (decoded.prefix !== 'xprv') throw new Error('expected an xprv bech32 key');
  const root = Crypto.Bip32PrivateKey.fromBytes(Buffer.from(bech32.fromWords(decoded.words)));
  const node =
    derivation === 0
      ? root
      : await (await root.derive([HARDENED + PURPOSE, HARDENED + COIN_TYPE, HARDENED + 0])).derive([ROLE_EXTERNAL, derivation]);
  const prv = node.toRawKey();
  const pub = await prv.toPublic();
  const keyHash = pub.hash();
  const address = Cardano.EnterpriseAddress.fromCredentials(networkId, {
    type: Cardano.CredentialType.KeyHash,
    hash: keyHash.hex()
  })
    .toAddress()
    .toBech32();
  return {
    address,
    sign: async (messageHex: string) => (await prv.sign(messageHex as HexBlob)).hex(),
    publicKeyHex: async () => pub.hex(),
    paymentKeyHashHex: async () => keyHash.hex()
  };
}

/** Derivation index of the DeMi "Approved Minter" off the POLICY_KEY root (minting.handle.me). */
export const APPROVED_MINTER_DERIVATION = 13;

/**
 * Sign an unsigned tx whose body hash (txHash) is already known (e.g. from finalizeTxPlan) and
 * byte-splice the vkey witness in — never re-encoding redeemer/datum bytes, so script_data_hash
 * stays valid. Returns the signed-tx CBOR.
 */
export async function signTxWithHash(
  unsignedTxCbor: string,
  txHash: string,
  signer: SsrSigner,
  mergeVkeysIntoTxCbor: (txCborHex: string, sigOnlyCborHex: string) => string
): Promise<string> {
  const signature = await signer.sign(txHash);
  const publicKey = await signer.publicKeyHex();
  const witnessSetCbor = Serialization.TransactionWitnessSet.fromCore({
    signatures: new Map([[publicKey as never, signature as never]])
  } as never).toCbor() as string;
  return mergeVkeysIntoTxCbor(unsignedTxCbor, witnessSetCbor);
}

/**
 * Build a complete signed-tx CBOR from an unsigned core tx + a signer, by hashing the body,
 * signing it, and byte-splicing the vkey witness in (never re-encoding redeemer/datum bytes, so
 * script_data_hash stays valid). Returns { signedTxCbor, txId }.
 */
export async function signCoreTx(
  tx: { body: import('@cardano-sdk/core').Cardano.TxBody },
  unsignedTxCbor: string,
  signer: SsrSigner,
  mergeVkeysIntoTxCbor: (txCborHex: string, sigOnlyCborHex: string) => string
): Promise<{ signedTxCbor: string; txId: string }> {
  const txId = transactionHashFromCore(tx);
  const signature = await signer.sign(txId);
  const publicKey = await signer.publicKeyHex();
  const witnessSetCbor = Serialization.TransactionWitnessSet.fromCore({
    signatures: new Map([[publicKey as never, signature as never]])
  } as never).toCbor() as string;
  const signedTxCbor = mergeVkeysIntoTxCbor(unsignedTxCbor, witnessSetCbor);
  return { signedTxCbor, txId };
}
