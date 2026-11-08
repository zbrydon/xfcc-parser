import { rejectPeer } from './errors.ts';
import { PARSE_OPTION_KEYS } from './validate.ts';

import type { ParseOptions, XfccElement } from './index.ts';

/** Maximum length of a SPIFFE ID in bytes, per the SPIFFE-ID standard. */
const MAX_SPIFFE_ID_LENGTH = 2048;

/** A validated SPIFFE ID, split into its parts. */
export interface SpiffeId {
  /** The full ID, e.g. `spiffe://cluster.local/ns/payments/sa/api`. */
  readonly id: string;
  /** The trust domain, e.g. `cluster.local`. */
  readonly trustDomain: string;
  /** The path, e.g. `/ns/payments/sa/api`. Always starts with `/`. */
  readonly path: string;
  /**
   * `payments` when the path is exactly `/ns/<namespace>/sa/<account>` (Istio),
   * else `null`. Not unique across trust domains: compare `trustDomain` too, or
   * match on `id`.
   */
  readonly namespace: string | null;
  /**
   * `api` when the path is exactly `/ns/<namespace>/sa/<account>` (Istio), else
   * `null`. Not unique across trust domains: compare `trustDomain` too, or match
   * on `id`.
   */
  readonly serviceAccount: string | null;
}

// Anchored, no nested quantifiers: linear time. A trust domain is at most 255
// bytes, per the SPIFFE-ID standard.
const SPIFFE_ID = /^spiffe:\/\/([a-z0-9._-]{1,255})(\/[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*)$/;
const ISTIO_PATH = /^\/ns\/([A-Za-z0-9._-]+)\/sa\/([A-Za-z0-9._-]+)$/;

const isDotSegment = (path: string): boolean =>
  path.split('/').some((segment) => segment === '.' || segment === '..');

/** The options of `getPeerSpiffeId`: those of `parseXfcc`, plus `requireSingleSan`. */
export interface PeerSpiffeIdOptions extends ParseOptions {
  /**
   * Reject an element with any DNS SAN. Defaults to `true` in the text format,
   * where a crafted URI SAN `spiffe://td/a;DNS=b` reads as both, and `false`
   * in JSON, where Envoy escapes each SAN. Set it to `false` only if your
   * workload certificates also carry DNS SANs.
   */
  readonly requireSingleSan?: boolean;
}

export const PEER_KEYS: ReadonlySet<string> = new Set([...PARSE_OPTION_KEYS, 'requireSingleSan']);

export const readSpiffeId = (element: XfccElement, requireSingleSan: boolean): SpiffeId => {
  const [uri, ...rest] = element.uri;
  if (uri === undefined || rest.length > 0) {
    throw rejectPeer('NOT_ONE_URI');
  }
  if (requireSingleSan && element.dns.length > 0) {
    throw rejectPeer('NOT_ONE_SAN');
  }
  if (!uri.startsWith('spiffe://')) {
    throw rejectPeer('NOT_SPIFFE');
  }
  // The regex only admits ASCII, so the string length is the byte length.
  const match = uri.length > MAX_SPIFFE_ID_LENGTH ? null : SPIFFE_ID.exec(uri);
  const trustDomain = match?.[1];
  const path = match?.[2];
  if (trustDomain === undefined || path === undefined || isDotSegment(path)) {
    throw rejectPeer('INVALID_SPIFFE_ID');
  }
  const istio = ISTIO_PATH.exec(path);
  return Object.freeze({
    id: uri,
    trustDomain,
    path,
    namespace: istio?.[1] ?? null,
    serviceAccount: istio?.[2] ?? null,
  });
};
