import { XfccError } from './errors.ts';
import { PARSE_OPTION_KEYS, readOptions } from './validate.ts';

import { parseXfcc, type ParseOptions, type XfccElement } from './index.ts';

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
  /** `payments` when the path is exactly `/ns/<namespace>/sa/<account>` (Istio), else `null`. */
  readonly namespace: string | null;
  /** `api` when the path is exactly `/ns/<namespace>/sa/<account>` (Istio), else `null`. */
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
   * Also reject an element with any DNS SAN. Defaults to `false`, since many
   * real certificates have both. In the text format a crafted URI SAN
   * `spiffe://td/a;DNS=b` reads as both, so set this if you read `dns` too.
   */
  readonly requireSingleSan?: boolean;
}

const PEER_KEYS: ReadonlySet<string> = new Set([...PARSE_OPTION_KEYS, 'requireSingleSan']);

const readSpiffeId = (element: XfccElement, requireSingleSan: boolean): SpiffeId => {
  const [uri, ...rest] = element.uri;
  if (uri === undefined || rest.length > 0) {
    throw new XfccError('NOT_ONE_URI', 'expected exactly one URI SAN');
  }
  if (requireSingleSan && element.dns.length > 0) {
    throw new XfccError('NOT_ONE_SAN', 'expected no SAN besides the URI SAN');
  }
  if (!uri.startsWith('spiffe://')) {
    throw new XfccError('NOT_SPIFFE', 'URI SAN is not a SPIFFE ID');
  }
  // The regex only admits ASCII, so the string length is the byte length.
  const match = uri.length > MAX_SPIFFE_ID_LENGTH ? null : SPIFFE_ID.exec(uri);
  const trustDomain = match?.[1];
  const path = match?.[2];
  if (trustDomain === undefined || path === undefined || isDotSegment(path)) {
    throw new XfccError('INVALID_SPIFFE_ID', 'URI SAN is not a valid SPIFFE ID');
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

/**
 * Returns the SPIFFE ID of the mTLS peer that connected to the proxy closest
 * to this service: the last element of the header.
 *
 * Takes the options of `parseXfcc`, so `format` is required and `maxElements`
 * defaults to 1 (set it to the exact number of proxy hops), plus
 * `requireSingleSan`. If a proxy that is not the caller sits between the
 * caller and this service, this returns that proxy's ID.
 *
 * The element must have exactly one URI SAN: in the text format, a crafted SAN
 * can look like two. That check cannot tell whether a crafted SAN forged the
 * whole element, so it is only as safe as `maxElements`. The ID must be a
 * workload ID (trust domain plus a non-empty path) that matches the SPIFFE-ID
 * standard, with a lowercase scheme. `issuer` is ignored, and so is `dns`
 * unless `requireSingleSan` is set; the README explains why.
 *
 * @throws {XfccError} if the header is malformed, has no element, or its last
 *   element does not carry exactly one valid SPIFFE ID.
 */
export const getPeerSpiffeId = (
  header: string | readonly string[] | undefined,
  options: PeerSpiffeIdOptions,
): SpiffeId => {
  const own = readOptions(options, PEER_KEYS);
  if (typeof own === 'string') {
    throw new XfccError('INVALID_OPTION', own);
  }
  const { requireSingleSan = false, ...parseOptions } = own;
  if (typeof requireSingleSan !== 'boolean') {
    throw new XfccError('INVALID_OPTION', 'requireSingleSan is out of range');
  }
  // The LAST element was appended by the proxy closest to this service.
  const nearest = parseXfcc(header, parseOptions).at(-1);
  if (nearest === undefined) {
    throw new XfccError('NO_PEER', 'header has no elements');
  }
  return readSpiffeId(nearest, requireSingleSan);
};
