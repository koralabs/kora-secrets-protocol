import { sha256 } from '@noble/hashes/sha2';
import { base32 } from '@scure/base';

// Compute a CIDv1 (raw codec, sha2-256) for a byte payload — the same content address IPFS
// produces for `ipfs add --cid-version=1 --raw-leaves` on small blobs. Content-addressing
// makes "fetch by CID" tamper-evident on its own (CID == hash of bytes), independent of the
// separate bundle_hash anchor.

const CIDV1 = 0x01;
const RAW_CODEC = 0x55;
const SHA2_256 = 0x12;
const SHA2_256_LEN = 0x20;

export function cidV1Raw(bytes: Uint8Array): string {
  const digest = sha256(bytes);
  const multihash = new Uint8Array([SHA2_256, SHA2_256_LEN, ...digest]);
  const cidBytes = new Uint8Array([CIDV1, RAW_CODEC, ...multihash]);
  // multibase 'b' = base32 (RFC 4648, lowercase, no padding).
  return 'b' + base32.encode(cidBytes).toLowerCase().replace(/=+$/, '');
}

/** True iff `cid` is the CIDv1-raw content address of `bytes`. */
export function cidMatches(cid: string, bytes: Uint8Array): boolean {
  return cidV1Raw(bytes) === cid;
}
