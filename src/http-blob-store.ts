import { SsrError, SsrErrorCode } from '@koralabs/kora-secrets-crypto';

import { cidMatches } from './cid.ts';
import type { BlobStore } from './storage.ts';

export interface HttpPinningConfig {
  /** Pinning endpoint that accepts a blob POST and returns a JSON body containing the CID. */
  pinUrl: string;
  /** Auth headers for the pinning endpoint (never logged). */
  pinHeaders?: Record<string, string>;
  /** Field in the pin response JSON holding the CID (e.g. "IpfsHash" for Pinata). */
  cidField?: string;
  /** Gateway base for reads, e.g. https://ipfs.io/ipfs — the CID is appended. */
  gatewayUrl: string;
  /** Injected for tests; defaults to global fetch. */
  fetchImpl?: typeof fetch;
}

/**
 * BlobStore backed by an HTTP pinning service + IPFS gateway. Reads are content-verified
 * against the requested CID, so a gateway returning the wrong bytes is rejected. Used for real
 * IPFS; the in-memory store covers local runs/tests.
 */
export class HttpPinningBlobStore implements BlobStore {
  private readonly cfg: HttpPinningConfig;
  private readonly fetchImpl: typeof fetch;

  constructor(cfg: HttpPinningConfig) {
    this.cfg = cfg;
    this.fetchImpl = cfg.fetchImpl ?? fetch;
  }

  async put(bytes: Uint8Array): Promise<string> {
    const res = await this.fetchImpl(this.cfg.pinUrl, {
      method: 'POST',
      headers: this.cfg.pinHeaders,
      // Uint8Array is a valid fetch body; cast through unknown to avoid a DOM-lib dependency.
      body: bytes as unknown as ArrayBuffer
    });
    if (!res.ok) throw new SsrError(SsrErrorCode.InvalidBundle, `pin failed: HTTP ${res.status}`);
    const json = (await res.json()) as Record<string, unknown>;
    const cid = json[this.cfg.cidField ?? 'IpfsHash'];
    if (typeof cid !== 'string' || cid.length === 0) {
      throw new SsrError(SsrErrorCode.InvalidBundle, 'pin response missing CID');
    }
    return cid;
  }

  async get(cid: string): Promise<Uint8Array> {
    const res = await this.fetchImpl(`${this.cfg.gatewayUrl}/${cid}`);
    if (!res.ok) throw new SsrError(SsrErrorCode.InvalidBundle, `gateway get failed: HTTP ${res.status}`);
    const bytes = new Uint8Array(await res.arrayBuffer());
    // Content-verify when the CID is a CIDv1-raw address we can recompute; CIDv0/dag-pb CIDs
    // from some pinning services are not raw-leaf addresses, so only enforce when it applies.
    if (cid.startsWith('bafkrei') && !cidMatches(cid, bytes)) {
      throw new SsrError(SsrErrorCode.InvalidBundle, `gateway returned bytes not matching cid ${cid}`);
    }
    return bytes;
  }
}
