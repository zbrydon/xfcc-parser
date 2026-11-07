import { parseDn, type DnAttribute } from './dn.ts';
import { reject, XfccError } from './errors.ts';
import { parseJson } from './json.ts';
import { parseText } from './text.ts';
import { PARSE_OPTION_KEYS, readOptions } from './validate.ts';

export { XfccError, type XfccErrorCode } from './errors.ts';
export type { DnAttribute } from './dn.ts';

/** Hard ceiling for `maxLength` (1 MiB). */
export const MAX_LENGTH_LIMIT: number = 1 << 20;
/** Hard ceiling for `maxElements`. */
export const MAX_ELEMENTS_LIMIT: number = 1024;

const DEFAULT_MAX_LENGTH = 64 * 1024;
// One hop, because in the text format a crafted URI SAN can add a forged last
// element: a larger value should be the exact hop count.
const DEFAULT_MAX_ELEMENTS = 1;

/** The certificate details one proxy added to the header. */
export interface XfccElement {
  /** URI SANs of the proxy's own certificate. */
  readonly by: readonly string[];
  /** Lowercase hex SHA-256 of the client certificate's DER encoding. */
  readonly hash: string | null;
  /** The client certificate as PEM. */
  readonly cert: string | null;
  /**
   * The certificate chain the client presented, one PEM per certificate, leaf
   * first. This is NOT the chain Envoy validated; do not authorize on it.
   */
  readonly presentedChain: readonly string[];
  /** The client certificate's subject as an RFC 4514 string. */
  readonly subject: string | null;
  /** URI SANs of the client certificate. */
  readonly uri: readonly string[];
  /** DNS SANs of the client certificate. */
  readonly dns: readonly string[];
  /**
   * The client certificate's issuer as an RFC 4514 string. Always `null` in
   * the text format unless `allowTextIssuer` is set.
   */
  readonly issuer: string | null;
}

export interface ParseOptions {
  /** Maximum header length in bytes. Defaults to 65536. */
  readonly maxLength?: number;
  /**
   * Maximum number of elements (proxy hops). Defaults to 1. In the text
   * format, set it to the exact hop count: a crafted URI SAN can add a forged
   * last element.
   */
  readonly maxElements?: number;
  /**
   * `text` or `json`, matching the Envoy listener's
   * `set_current_client_cert_details.format`. Required: it is never
   * auto-detected, because a text header can be crafted to look like JSON.
   */
  readonly format: 'text' | 'json';
  /**
   * Require `Cert` and `Hash` in every element and check that `Hash` is the
   * SHA-256 of `Cert`. Defaults to `false`. This does not prove an element is
   * genuine: a crafted SAN can carry a copy of any public certificate.
   */
  readonly requireCertHash?: boolean;
  /**
   * Return `issuer` from the text format. Defaults to `false`, because a
   * crafted URI SAN `a;Issuer="..."` sets it. Has no effect on JSON.
   */
  readonly allowTextIssuer?: boolean;
}

/** A relative distinguished name: one or more attributes joined by `+`. */
export type Rdn = readonly DnAttribute[];

const invalidOption = (name: string): XfccError =>
  new XfccError('INVALID_OPTION', `${name} is out of range`);

const checkInteger = (
  name: string,
  value: unknown,
  max: number,
): number | undefined | XfccError => {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1 || value > max) {
    return invalidOption(name);
  }
  return value;
};

interface NormalizedOptions {
  readonly maxLength: number;
  readonly maxElements: number;
  readonly format: 'text' | 'json';
  readonly requireCertHash: boolean;
  readonly allowTextIssuer: boolean;
}

// Plain JavaScript can omit `options`, which then fails like any invalid one.
const normalizeOptions = (
  options: ParseOptions | null | undefined,
): NormalizedOptions | XfccError => {
  const own = readOptions(options, PARSE_OPTION_KEYS);
  if (typeof own === 'string') {
    return new XfccError('INVALID_OPTION', own);
  }
  const { format, requireCertHash, allowTextIssuer } = own;
  if (format === undefined) {
    return new XfccError('INVALID_OPTION', 'format is required');
  }
  if (format !== 'text' && format !== 'json') {
    return invalidOption('format');
  }
  if (requireCertHash !== undefined && typeof requireCertHash !== 'boolean') {
    return invalidOption('requireCertHash');
  }
  if (allowTextIssuer !== undefined && typeof allowTextIssuer !== 'boolean') {
    return invalidOption('allowTextIssuer');
  }
  const maxLength = checkInteger('maxLength', own.maxLength, MAX_LENGTH_LIMIT);
  if (maxLength instanceof XfccError) {
    return maxLength;
  }
  const maxElements = checkInteger('maxElements', own.maxElements, MAX_ELEMENTS_LIMIT);
  if (maxElements instanceof XfccError) {
    return maxElements;
  }
  return {
    maxLength: maxLength ?? DEFAULT_MAX_LENGTH,
    maxElements: maxElements ?? DEFAULT_MAX_ELEMENTS,
    format,
    requireCertHash: requireCertHash ?? false,
    allowTextIssuer: allowTextIssuer ?? false,
  };
};

const parseHeader = (value: string, options: NormalizedOptions): XfccElement[] => {
  // A string's UTF-16 length never exceeds its UTF-8 length.
  if (value.length > options.maxLength || Buffer.byteLength(value) > options.maxLength) {
    throw reject('TOO_LONG', options.maxLength);
  }
  // RFC 9110 field-value: visible ASCII plus SP / HTAB. obs-text is rejected.
  // Everything before the first bad character is ASCII, so this is a byte offset.
  let blank = true;
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code !== 9 && (code < 0x20 || code > 0x7e)) {
      throw reject('INVALID_CHAR', i);
    }
    blank &&= code === 9 || code === 0x20;
  }
  if (blank) {
    throw reject('EMPTY', 0);
  }
  return options.format === 'text' ? parseText(value, options) : parseJson(value, options);
};

/**
 * Parses an `x-forwarded-client-cert` header value.
 *
 * Elements are returned in header order, so the LAST element is the one
 * appended by the proxy closest to this service. Only trust elements your own
 * proxy added.
 *
 * @param header The header value. `undefined` (header absent) returns `[]`.
 *   An array (multiple header lines) is joined with `,` per RFC 9110.
 * @param options `format` is required. `maxElements` defaults to 1.
 * @throws {XfccError} if the header is malformed in any way.
 */
export const parseXfcc = (
  header: string | readonly string[] | undefined,
  options: ParseOptions,
): readonly XfccElement[] => {
  const normalized = normalizeOptions(options);
  if (normalized instanceof XfccError) {
    throw normalized;
  }
  if (header === undefined) {
    return Object.freeze([]);
  }
  const value = typeof header === 'string' ? header : joinHeaderLines(header);
  return Object.freeze(parseHeader(value, normalized));
};

export { getPeerSpiffeId, type SpiffeId, type PeerSpiffeIdOptions } from './spiffe.ts';

const joinHeaderLines = (lines: readonly string[]): string => {
  if (!Array.isArray(lines) || !lines.every((line) => typeof line === 'string')) {
    throw new TypeError('header must be a string, an array of strings or undefined');
  }
  return lines.join(',');
};

/**
 * Parses an RFC 4514 distinguished name, such as `XfccElement.subject`, into
 * RDNs in string order (most specific first; the reverse of ASN.1 order).
 * Escapes are decoded, so `CN=a\,O=b` is one RDN with value `a,O=b`. A value
 * can then hold control or bidi characters (`\09` decodes to a tab), so escape
 * values before logging or displaying them.
 *
 * @throws {XfccError} with code `INVALID_DN` if `dn` is not valid RFC 4514, or
 *   `TOO_LONG` if it is longer than `MAX_LENGTH_LIMIT` bytes.
 */
export const parseDistinguishedName = (dn: string): readonly Rdn[] => {
  if (typeof dn !== 'string') {
    throw new TypeError('dn must be a string');
  }
  // A string's UTF-16 length never exceeds its UTF-8 length.
  if (dn.length > MAX_LENGTH_LIMIT || Buffer.byteLength(dn) > MAX_LENGTH_LIMIT) {
    throw reject('TOO_LONG', MAX_LENGTH_LIMIT);
  }
  // Encoding it would silently turn a lone surrogate into U+FFFD. With the `u`
  // flag `\p{Cs}` matches only a lone one, and everything before it encodes.
  if (!dn.isWellFormed()) {
    throw reject('INVALID_DN', Buffer.byteLength(dn.slice(0, dn.search(/\p{Cs}/u))));
  }
  return Object.freeze(
    parseDn(dn).map((rdn) => Object.freeze(rdn.map((attr) => Object.freeze(attr)))),
  );
};
