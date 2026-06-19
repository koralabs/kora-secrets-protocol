import {
  type Bundle,
  canonicalJson,
  parseShareArtifact,
  type ReencryptedShareArtifact,
  SsrError,
  SsrErrorCode,
  utf8ToBytes,
  verifyBundleHash
} from '@koralabs/kora-secrets-crypto';

import { cidMatches, cidV1Raw } from './cid.ts';

/** Content-addressed blob storage (an IPFS-like put/get). Stores ciphertext-only blobs. */
export interface BlobStore {
  put(bytes: Uint8Array): Promise<string>;
  get(cid: string): Promise<Uint8Array>;
}

/** Max bytes accepted for a single artifact/bundle blob — guards against oversize uploads. */
export const MAX_BLOB_BYTES = 1024 * 1024; // 1 MiB; bundles are ciphertext-only and small

/**
 * In-memory content-addressed store for local runs/tests. CIDs are real CIDv1-raw addresses,
 * and `get` re-verifies the content against the CID, so a corrupted entry is caught.
 */
export class InMemoryBlobStore implements BlobStore {
  private readonly blobs = new Map<string, Uint8Array>();

  put(bytes: Uint8Array): Promise<string> {
    if (bytes.length > MAX_BLOB_BYTES) {
      return Promise.reject(new SsrError(SsrErrorCode.InvalidBundle, `blob exceeds ${MAX_BLOB_BYTES} bytes`));
    }
    const cid = cidV1Raw(bytes);
    this.blobs.set(cid, bytes.slice());
    return Promise.resolve(cid);
  }

  get(cid: string): Promise<Uint8Array> {
    const bytes = this.blobs.get(cid);
    if (!bytes) return Promise.reject(new SsrError(SsrErrorCode.InvalidBundle, `no blob for cid ${cid}`));
    if (!cidMatches(cid, bytes)) {
      return Promise.reject(new SsrError(SsrErrorCode.InvalidBundle, `stored blob does not match cid ${cid}`));
    }
    return Promise.resolve(bytes);
  }
}

function bundleBytes(bundle: Bundle): Uint8Array {
  const json = canonicalJson(bundle);
  if (typeof json !== 'string') {
    throw new SsrError(SsrErrorCode.InvalidBundle, 'bundle is not serializable');
  }
  return utf8ToBytes(json);
}

/**
 * Upload an encrypted bundle and return its CID(s). Multiple stores act as mirrors (never rely
 * on a single pinning provider); the same content yields the same CID across them.
 */
export async function putBundle(bundle: Bundle, stores: BlobStore[]): Promise<string[]> {
  if (stores.length === 0) throw new SsrError(SsrErrorCode.InvalidBundle, 'at least one store required');
  const bytes = bundleBytes(bundle);
  return Promise.all(stores.map((s) => s.put(bytes)));
}

/**
 * Fetch a bundle by CID and VERIFY its integrity hash before returning any contents (a
 * hash-mismatched blob throws BUNDLE_HASH_MISMATCH and is never returned).
 */
export async function getBundle(cid: string, store: BlobStore): Promise<Bundle> {
  const bytes = await store.get(cid);
  let bundle: Bundle;
  try {
    bundle = JSON.parse(new TextDecoder().decode(bytes)) as Bundle;
  } catch {
    throw new SsrError(SsrErrorCode.InvalidBundle, 'bundle blob is not valid JSON');
  }
  if (!verifyBundleHash(bundle)) {
    throw new SsrError(SsrErrorCode.BundleHashMismatch, 'fetched bundle failed integrity verification');
  }
  return bundle;
}

/** Fetch a verified bundle, trying each CID in turn (mirror fallback). */
export async function getBundleFromAny(cids: string[], store: BlobStore): Promise<Bundle> {
  let lastErr: unknown;
  for (const cid of cids) {
    try {
      return await getBundle(cid, store);
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr ?? new SsrError(SsrErrorCode.InvalidBundle, 'no bundle cids provided');
}

function artifactBytes(artifact: ReencryptedShareArtifact): Uint8Array {
  const json = canonicalJson(artifact);
  if (typeof json !== 'string') {
    throw new SsrError(SsrErrorCode.InvalidArtifact, 'artifact is not serializable');
  }
  return utf8ToBytes(json);
}

/** Upload a re-encrypted share artifact (after validating its shape) and return its CID. */
export function putShareArtifact(artifact: ReencryptedShareArtifact, store: BlobStore): Promise<string> {
  parseShareArtifact(artifact); // reject malformed before storing
  return store.put(artifactBytes(artifact));
}

/** Fetch a re-encrypted share artifact by CID and validate its shape before returning it. */
export async function getShareArtifact(cid: string, store: BlobStore): Promise<ReencryptedShareArtifact> {
  const bytes = await store.get(cid);
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new SsrError(SsrErrorCode.InvalidArtifact, 'artifact blob is not valid JSON');
  }
  return parseShareArtifact(parsed);
}
