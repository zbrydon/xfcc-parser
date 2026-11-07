import { parseDn, type DnAttribute } from './dn.ts';
import { reject } from './errors.ts';
import { parseJson } from './json.ts';
import { parseText } from './text.ts';
import { PARSE_OPTION_KEYS, readOptions } from './validate.ts';

export { XfccError, type XfccErrorCode } from './errors.ts';
export type { DnAttribute } from './dn.ts';

/** Hard ceiling for `maxLength` (1 MiB). */
const MAX_LENGTH_LIMIT = 1 << 20;
/** Hard ceiling for `maxElements`. */
const MAX_ELEMENTS_LIMIT = 1024;

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
   * the text format, where a crafted URI SAN `a;Issuer="..."` can set it.
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
}

/** A relative distinguished name: one or more attributes joined by `+`. */
export type Rdn = readonly DnAttribute[];

const invalidOption = (name: string): TypeError => new TypeError(`${name} is out of range`);

const checkInteger = (name: string, value: unknown, max: number): number | undefined => {
  if (
    value !== undefined &&
    (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1 || value > max)
  ) {
    throw invalidOption(name);
  }
  return value;
};

interface NormalizedOptions {
  readonly maxLength: number;
  readonly maxElements: number;
  readonly format: 'text' | 'json';
}

// Plain JavaScript can omit `options`, which then fails like any invalid one.
// An invalid option is a bug in the caller, not untrusted input, so it throws
// `TypeError`: an `XfccError` would read as a rejected caller.
const normalizeOptions = (options: ParseOptions | null | undefined): NormalizedOptions => {
  const own = readOptions(options, PARSE_OPTION_KEYS);
  const { format } = own;
  if (format === undefined) {
    throw new TypeError('format is required');
  }
  if (format !== 'text' && format !== 'json') {
    throw invalidOption('format');
  }
  return {
    maxLength: checkInteger('maxLength', own.maxLength, MAX_LENGTH_LIMIT) ?? DEFAULT_MAX_LENGTH,
    maxElements:
      checkInteger('maxElements', own.maxElements, MAX_ELEMENTS_LIMIT) ?? DEFAULT_MAX_ELEMENTS,
    format,
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
 * @throws {TypeError} if `options` or the type of `header` is invalid.
 */
export const parseXfcc = (
  header: string | readonly string[] | undefined,
  options: ParseOptions,
): readonly XfccElement[] => {
  const normalized = normalizeOptions(options);
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
 *   `TOO_LONG` if it is longer than 1 MiB.
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
