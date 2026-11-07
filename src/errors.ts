// The code strings are public API. A message never includes input, so errors
// are safe to log.
const MESSAGES = {
  EMPTY: 'header value is empty',
  TOO_LONG: 'header value exceeds maxLength',
  TOO_MANY_ELEMENTS: 'header has more elements than maxElements',
  INVALID_CHAR: 'header contains a byte outside visible ASCII, SP and HTAB',
  EMPTY_ELEMENT: 'empty element',
  EMPTY_PAIR: 'empty key/value pair',
  MISSING_EQUALS: "key/value pair has no '='",
  UNKNOWN_KEY: 'unknown key',
  DUPLICATE_KEY: 'single-valued key appears more than once in an element',
  EMPTY_VALUE: 'key has an empty value',
  UNTERMINATED_QUOTE: 'quoted value is not terminated',
  UNEXPECTED_AFTER_VALUE: 'unexpected character after value',
  INVALID_QUOTING:
    'quoting does not match Envoy (Cert, Chain, Subject and Issuer quoted, other keys not)',
  INVALID_ESCAPE: 'value contains a backslash or quote',
  INVALID_HASH: 'Hash is not a lowercase hex SHA-256 digest',
  INVALID_URI: 'value is not an RFC 3986 URI',
  INVALID_DNS: 'value is not a valid DNS name',
  INVALID_PERCENT_ENCODING: 'invalid percent-encoding',
  INVALID_PEM: 'value is not a strict PEM certificate',
  INVALID_DN: 'value is not an RFC 4514 distinguished name',
  KEY_ORDER: 'keys are not in the order Envoy writes them',
  MISSING_HASH: 'element has no Hash',
  INVALID_JSON: 'invalid JSON-format XFCC value',
  // `getPeerSpiffeId`'s checks of a parsed element, which have no offset.
  NO_PEER: 'header has no elements',
  NOT_ONE_URI: 'expected exactly one URI SAN',
  NOT_ONE_SAN: 'expected no SAN besides the URI SAN',
  NOT_SPIFFE: 'URI SAN is not a SPIFFE ID',
  INVALID_SPIFFE_ID: 'URI SAN is not a valid SPIFFE ID',
} as const;

export type XfccErrorCode = keyof typeof MESSAGES;

/**
 * Thrown for any header, distinguished name or SPIFFE ID that does not
 * strictly match the format. The message never contains input, so it is safe
 * to log. It has no stack trace.
 */
export class XfccError extends Error {
  override readonly name = 'XfccError';
  readonly code: XfccErrorCode;
  /**
   * Byte offset into the input where the problem was found. Unset for
   * `getPeerSpiffeId`'s own codes.
   */
  readonly offset: number | undefined;

  constructor(code: XfccErrorCode, message: string, offset?: number) {
    // Capturing a stack trace is most of the cost of rejecting a header, and
    // the stack of an error about untrusted input says nothing useful.
    // `Reflect.set` fails quietly where `Error` is frozen (SES lockdown, say).
    const { stackTraceLimit } = Error;
    Reflect.set(Error, 'stackTraceLimit', 0);
    super(offset === undefined ? `${code}: ${message}` : `${code}: ${message} (at byte ${offset})`);
    Reflect.set(Error, 'stackTraceLimit', stackTraceLimit);
    this.code = code;
    this.offset = offset;
  }
}

/** Builds the error for `code`, with its fixed message. */
export const reject = (code: XfccErrorCode, offset?: number): XfccError =>
  new XfccError(code, MESSAGES[code], offset);
