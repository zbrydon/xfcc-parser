// `Cert` / `Chain` decoding: Envoy-style percent-decoding, strict RFC 7468 PEM,
// canonical base64 and a DER SEQUENCE framing check. The X.509 contents are
// deliberately not parsed.
import { charTable, hexVal } from './validate.ts';

const BEGIN = '-----BEGIN CERTIFICATE-----';
const END = '-----END CERTIFICATE-----';
const END_PREFIX = '-----END ';
const BASE64_LINE_LEN = 64;

const URL_SAFE = charTable('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789*-._');
const BASE64 = charTable('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=');

/**
 * Decodes Envoy's `PercentEncoding::urlEncode` output, or returns `null`. Envoy
 * encodes every byte except `ALPHA / DIGIT / "*" / "-" / "." / "_"`, so anything
 * else unencoded (including `+`) is rejected. Bytes decode as latin1: PEM is
 * ASCII, so `parseCertificates` rejects any byte above 0x7f.
 */
export const percentDecode = (value: string): string | null => {
  const out = Buffer.alloc(value.length);
  let length = 0;
  let i = 0;
  while (i < value.length) {
    const code = value.charCodeAt(i);
    if (code === 37) {
      const hi = hexVal(value.charCodeAt(i + 1));
      const lo = hexVal(value.charCodeAt(i + 2));
      if (hi === -1 || lo === -1) {
        return null;
      }
      out[length++] = hi * 16 + lo;
      i += 3;
    } else if (URL_SAFE[code] === 1) {
      out[length++] = code;
      i++;
    } else {
      return null;
    }
  }
  return out.toString('latin1', 0, length);
};

/** `value` without trailing SP and HTAB, which `trimEnd` would go beyond. */
const trimWsp = (value: string): string => {
  let end = value.length;
  while (value.charCodeAt(end - 1) === 32 || value.charCodeAt(end - 1) === 9) {
    end--;
  }
  return value.slice(0, end);
};

/**
 * Checks that `der` is exactly one DER SEQUENCE (tag 0x30) with a minimally
 * encoded definite length that covers the rest of the input.
 */
const isDerSequence = (der: Buffer): boolean => {
  if (der.length < 2 || der.readUInt8(0) !== 0x30) {
    return false;
  }
  const first = der.readUInt8(1);
  if (first < 0x80) {
    return first === der.length - 2;
  }
  const lengthBytes = first - 0x80;
  if (lengthBytes < 1 || lengthBytes > 4 || der.length < 2 + lengthBytes) {
    return false;
  }
  // Minimal encoding: no leading zero byte, and long form only for >= 0x80.
  const lead = der.readUInt8(2);
  if (lead === 0 || (lengthBytes === 1 && lead < 0x80)) {
    return false;
  }
  return der.readUIntBE(2, lengthBytes) === der.length - 2 - lengthBytes;
};

/** Splits on RFC 7468 `eol = CRLF / CR / LF`, tracking offsets. */
class Lines {
  /** Offset just past the current line's line ending. */
  next = 0;
  start = 0;
  text = '';
  hasEol = false;
  readonly #input: string;

  constructor(input: string) {
    this.#input = input;
  }

  /** Moves to the next line, or returns false at the end of the input. */
  advance(): boolean {
    const input = this.#input;
    this.start = this.next;
    if (this.start >= input.length) {
      return false;
    }
    let end = this.start;
    let code = input.charCodeAt(end);
    while (end < input.length && code !== 13 && code !== 10) {
      end++;
      code = input.charCodeAt(end);
    }
    this.text = input.slice(this.start, end);
    this.hasEol = end < input.length;
    this.next = code === 13 && input.charCodeAt(end + 1) === 10 ? end + 2 : end + 1;
    return true;
  }
}

/**
 * Parses one or more concatenated certificates with the `CERTIFICATE` label.
 * The body follows the RFC 7468 §3 `stricttextualmsg` grammar, but trailing
 * whitespace after the `BEGIN` / `END` lines and a missing final line break
 * are accepted, as RFC 7468 parsers should. Nothing else may appear before,
 * between or after the blocks. Each block runs from `-----BEGIN` up to and
 * including the line ending after the `END` line, if any. An empty list means
 * the text is not valid.
 */
export const parseCertificates = (text: string): string[] => {
  const lines = new Lines(text);
  const blocks: string[] = [];
  while (lines.advance()) {
    if (trimWsp(lines.text) !== BEGIN || !lines.hasEol) {
      return [];
    }
    const blockStart = lines.start;
    let body = '';
    let lastLength = BASE64_LINE_LEN;
    for (;;) {
      if (!lines.advance()) {
        return [];
      }
      const line = lines.text;
      if (line.startsWith(END_PREFIX)) {
        break;
      }
      // Only the final body line may be shorter than 64 characters.
      if (
        lastLength !== BASE64_LINE_LEN ||
        line.length === 0 ||
        line.length > BASE64_LINE_LEN ||
        !lines.hasEol
      ) {
        return [];
      }
      for (let i = 0; i < line.length; i++) {
        if (BASE64[line.charCodeAt(i)] !== 1) {
          return [];
        }
      }
      body += line;
      lastLength = line.length;
    }
    if (trimWsp(lines.text) !== END) {
      return [];
    }
    const der = Buffer.from(body, 'base64');
    // `Buffer.from` is lenient, so the round trip enforces canonical base64.
    if (der.toString('base64') !== body || !isDerSequence(der)) {
      return [];
    }
    blocks.push(text.slice(blockStart, lines.next));
  }
  return blocks;
};

/** Parses exactly one certificate, or returns `undefined`. */
export const parseCertificate = (text: string): string | undefined => {
  const [block, extra] = parseCertificates(text);
  return extra === undefined ? block : undefined;
};
