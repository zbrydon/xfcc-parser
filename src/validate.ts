// Validators for single XFCC values.
import { isIPv6 } from 'node:net';

const SHA256_HEX_LEN = 64;
const MAX_DNS_NAME_LEN = 253;
const MAX_DNS_LABEL_LEN = 63;
// `ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255`
const MAX_IPV6_LEN = 45;

/** A lookup table indexed by char code; anything else reads as `undefined`. */
export const charTable = (chars: string): Uint8Array => {
  const table = new Uint8Array(128);
  for (let i = 0; i < chars.length; i++) {
    table[chars.charCodeAt(i)] = 1;
  }
  return table;
};

const has = (table: Uint8Array, code: number): boolean => table[code] === 1;

const DIGIT = '0123456789';
const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
const UNRESERVED = `${ALPHA}${DIGIT}-._~`;
const SUB_DELIMS = "!$&'()*+,;=";

const ALPHA_TABLE = charTable(ALPHA);
const DIGIT_TABLE = charTable(DIGIT);
const HEX_TABLE = charTable(`${DIGIT}ABCDEFabcdef`);
const LOWER_HEX_TABLE = charTable(`${DIGIT}abcdef`);
const LDH_TABLE = charTable(`${ALPHA}${DIGIT}-`);
const ALNUM_TABLE = charTable(`${ALPHA}${DIGIT}`);
const IPV6_TABLE = charTable(`${DIGIT}ABCDEFabcdef:.`);
const SCHEME_TABLE = charTable(`${ALPHA}${DIGIT}+-.`);
const IPV_FUTURE_TABLE = charTable(`${UNRESERVED}${SUB_DELIMS}:`);
// `%` is ordinary in these: `validUri` checks every percent-encoding up front.
const AUTHORITY_TABLE = charTable(`${UNRESERVED}${SUB_DELIMS}:%`);
const REG_NAME_TABLE = charTable(`${UNRESERVED}${SUB_DELIMS}%`);
const PATH_TABLE = charTable(`${UNRESERVED}${SUB_DELIMS}:@/%`);
const QUERY_TABLE = charTable(`${UNRESERVED}${SUB_DELIMS}:@/?%`);

/** The value of a hex digit's char code, or -1. */
export const hexVal = (code: number): number => {
  if (code >= 48 && code <= 57) {
    return code - 48;
  }
  if (code >= 97 && code <= 102) {
    return code - 87;
  }
  return code >= 65 && code <= 70 ? code - 55 : -1;
};

const every = (value: string, table: Uint8Array): boolean => skip(value, 0, table) === value.length;

/** The first index at or after `from` whose char is not in `table`. */
const skip = (value: string, from: number, table: Uint8Array): number => {
  let i = from;
  while (has(table, value.charCodeAt(i))) {
    i++;
  }
  return i;
};

/** `Hash`: hex SHA-256 digest, lowercase as Envoy emits it. */
export const validHash = (value: string): boolean =>
  value.length === SHA256_HEX_LEN && every(value, LOWER_HEX_TABLE);

const isLdhLabel = (label: string): boolean =>
  label.length <= MAX_DNS_LABEL_LEN &&
  has(ALNUM_TABLE, label.charCodeAt(0)) &&
  has(ALNUM_TABLE, label.charCodeAt(label.length - 1)) &&
  every(label, LDH_TABLE);

/**
 * `DNS`: RFC 5280 §4.2.1.6 dNSName in RFC 1034 preferred name syntax (as
 * relaxed by RFC 1123 §2.1 to allow a leading digit, but not an all-numeric
 * top-level label), with an optional RFC 9525 §6.3 wildcard as the complete
 * leftmost label. Underscores, partial wildcards, empty labels, a trailing dot
 * and dotted-decimal names such as `1.2.3.4` are rejected.
 */
export const validDns = (value: string): boolean => {
  if (value.length > MAX_DNS_NAME_LEN) {
    return false;
  }
  const rest = value.startsWith('*.') ? value.slice(2) : value;
  return (
    rest.split('.').every(isLdhLabel) &&
    skip(value, value.lastIndexOf('.') + 1, DIGIT_TABLE) !== value.length
  );
};

const validPercentEncoding = (value: string): boolean => {
  for (let i = value.indexOf('%'); i !== -1; i = value.indexOf('%', i + 3)) {
    if (!has(HEX_TABLE, value.charCodeAt(i + 1)) || !has(HEX_TABLE, value.charCodeAt(i + 2))) {
      return false;
    }
  }
  return true;
};

/** `IP-literal`, with `start` just past the `[`. Returns the index after the `]`, or -1. */
const skipIpLiteral = (value: string, start: number): number => {
  const end = value.indexOf(']', start);
  if (end === -1) {
    return -1;
  }
  const first = value.charCodeAt(start);
  if (first === 118 || first === 86) {
    // IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
    const dot = skip(value, start + 1, HEX_TABLE);
    const rest = dot + 1;
    return dot > start + 1 &&
      value.charCodeAt(dot) === 46 &&
      rest < end &&
      skip(value, rest, IPV_FUTURE_TABLE) === end
      ? end + 1
      : -1;
  }
  // The guard rejects a zone identifier, which `isIPv6` would accept.
  return end - start <= MAX_IPV6_LEN &&
    skip(value, start, IPV6_TABLE) === end &&
    isIPv6(value.slice(start, end))
    ? end + 1
    : -1;
};

const skipPort = (value: string, start: number): number =>
  value.charCodeAt(start) === 58 ? skip(value, start + 1, DIGIT_TABLE) : start;

const countColons = (value: string, start: number, end: number): number => {
  let count = 0;
  for (let i = value.indexOf(':', start); i !== -1 && i < end; i = value.indexOf(':', i + 1)) {
    count++;
  }
  return count;
};

/** `authority`, with `start` just past the `//`. Returns the index after it, or -1. */
const skipAuthority = (value: string, start: number): number => {
  const end = skip(value, start, AUTHORITY_TABLE);
  if (value.charCodeAt(end) === 64) {
    const host = end + 1;
    const hostEnd =
      value.charCodeAt(host) === 91
        ? skipIpLiteral(value, host + 1)
        : skip(value, host, REG_NAME_TABLE);
    return hostEnd === -1 ? -1 : skipPort(value, hostEnd);
  }
  if (end === start) {
    if (value.charCodeAt(start) !== 91) {
      return start;
    }
    const hostEnd = skipIpLiteral(value, start + 1);
    return hostEnd === -1 ? -1 : skipPort(value, hostEnd);
  }
  const colons = countColons(value, start, end);
  if (colons === 0) {
    return end;
  }
  // The authority has no `@`, so a colon starts the port.
  return colons === 1 && skip(value, value.indexOf(':', start) + 1, DIGIT_TABLE) === end ? end : -1;
};

/**
 * `By` / `URI`: an RFC 3986 `URI` (absolute, scheme required) with the
 * non-empty scheme-specific-part RFC 5280 §4.2.1.6 requires, so `urn:` is
 * rejected. Any non-ASCII character is outside every table.
 */
export const validUri = (value: string): boolean => {
  if (!validPercentEncoding(value) || !has(ALPHA_TABLE, value.charCodeAt(0))) {
    return false;
  }
  const colon = skip(value, 0, SCHEME_TABLE);
  if (value.charCodeAt(colon) !== 58) {
    return false;
  }
  const hierPart = colon + 1;
  const hasAuthority = value.startsWith('//', hierPart);
  let path = hierPart;
  if (hasAuthority) {
    path = skipAuthority(value, hierPart + 2);
    if (path === -1) {
      return false;
    }
  }
  const pathEnd = skip(value, path, PATH_TABLE);
  // After an authority, a path is empty or starts with "/".
  if (hasAuthority && pathEnd > path && value.charCodeAt(path) !== 47) {
    return false;
  }
  const hasQuery = value.charCodeAt(pathEnd) === 63;
  const queryEnd = hasQuery ? skip(value, pathEnd + 1, QUERY_TABLE) : pathEnd;
  const end = value.charCodeAt(queryEnd) === 35 ? skip(value, queryEnd + 1, QUERY_TABLE) : queryEnd;
  return end === value.length && (hasAuthority || pathEnd > hierPart || hasQuery);
};

/** The keys of `ParseOptions`. */
export const PARSE_OPTION_KEYS: ReadonlySet<string> = new Set([
  'maxLength',
  'maxElements',
  'format',
  'requireCertHash',
  'allowTextIssuer',
]);

/**
 * Copies the keys of `options` into a null-prototype object, or throws
 * `TypeError` if it cannot without silently dropping an option, which could
 * turn off a check like `requireCertHash`. `options` must be a plain object, from any realm, or
 * have a `null` prototype: a class getter or parent object would be dropped.
 * A key inherited from a polluted `Object.prototype` is ignored. Every own key
 * must be one of `keys` and enumerable.
 */
export const readOptions = <T extends object>(
  options: T | null | undefined,
  keys: ReadonlySet<string>,
): T => {
  if (typeof options !== 'object' || options === null) {
    throw new TypeError('options must be a plain object');
  }
  const proto = Reflect.getPrototypeOf(options);
  // Another realm's `Object.prototype` has a null prototype too. One that
  // holds an option key is rejected, polluted or not.
  const plain =
    proto === null ||
    proto === Object.prototype ||
    (Reflect.getPrototypeOf(proto) === null && ![...keys].some((key) => Object.hasOwn(proto, key)));
  if (!plain) {
    throw new TypeError('options must be a plain object');
  }
  // `Reflect.ownKeys` also lists symbols and non-enumerable keys, which the
  // spread below would drop.
  const own = Object.keys(options);
  if (Reflect.ownKeys(options).length !== own.length || !own.every((key) => keys.has(key))) {
    throw new TypeError('options has an unknown or non-enumerable key');
  }
  return { __proto__: null, ...options };
};
