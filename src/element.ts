import { parseDn } from './dn.ts';
import { reject, XfccError } from './errors.ts';
import { parseCertificate, parseCertificates, percentDecode } from './pem.ts';
import { validDns, validHash, validUri } from './validate.ts';

import type { XfccElement } from './index.ts';

/** The keys Envoy defines. The numeric order is the order Envoy writes them. */
export const KEY = {
  BY: 0,
  HASH: 1,
  CERT: 2,
  CHAIN: 3,
  SUBJECT: 4,
  URI: 5,
  DNS: 6,
  ISSUER: 7,
} as const;

export type Key = (typeof KEY)[keyof typeof KEY];

/** The options the format parsers read. */
export interface ElementOptions {
  readonly maxElements: number;
}

/**
 * Rejects a `Subject` / `Issuer` that is not RFC 4514, or that holds a raw
 * control or non-ASCII character. Envoy escapes control characters (a tab is
 * written `\09`) and every non-ASCII byte (`\C3\A9`), so a raw one means the
 * value did not come from Envoy, and it must not reach consumers that may log
 * it. A blocklist of invisible characters would always be incomplete.
 */
const checkDn = (value: string, offset: number): void => {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code >= 0x7f) {
      throw reject('INVALID_CHAR', offset);
    }
  }
  try {
    parseDn(value);
  } catch (error) {
    if (error instanceof XfccError) {
      // The offset of the value in the header, not of the problem in the value.
      throw reject('INVALID_DN', offset);
    }
    throw error;
  }
};

export class ElementBuilder {
  #hash: string | null = null;
  readonly #by: string[] = [];
  #cert: string | null = null;
  readonly #presentedChain: string[] = [];
  #subject: string | null = null;
  readonly #uri: string[] = [];
  #emptyUri = false;
  readonly #dns: string[] = [];
  #issuer: string | null = null;
  readonly #text: boolean;

  /** In the `text` format every element must have a `Hash`. */
  constructor(format: 'text' | 'json') {
    this.#text = format === 'text';
  }

  /**
   * Validates and stores one value. In the `text` format `Cert` / `Chain` are
   * percent-encoded and `Chain` is concatenated; JSON has raw PEM, one
   * certificate per value. Empty values are rejected except for the text
   * format's `Subject` / `Issuer`, which Envoy emits as `""` when absent, and
   * its lone `URI=`, emitted when there are no URI SANs.
   */
  set(key: Key, value: string, offset: number): void {
    if (
      value === '' &&
      !(this.#text && (key === KEY.SUBJECT || key === KEY.ISSUER || key === KEY.URI))
    ) {
      throw reject('EMPTY_VALUE', offset);
    }
    switch (key) {
      case KEY.BY:
        if (!validUri(value)) {
          throw reject('INVALID_URI', offset);
        }
        this.#by.push(value);
        break;
      case KEY.URI:
        // Any other URI pair beside a lone `URI=` came from a crafted SAN such
        // as `spiffe://td/admin;URI=`.
        if (this.#emptyUri || (value === '' && this.#uri.length > 0)) {
          throw reject('DUPLICATE_KEY', offset);
        }
        if (value === '') {
          this.#emptyUri = true;
        } else if (validUri(value)) {
          this.#uri.push(value);
        } else {
          throw reject('INVALID_URI', offset);
        }
        break;
      case KEY.DNS:
        if (!validDns(value)) {
          throw reject('INVALID_DNS', offset);
        }
        this.#dns.push(value);
        break;
      case KEY.HASH:
        if (!validHash(value)) {
          throw reject('INVALID_HASH', offset);
        }
        if (this.#hash !== null) {
          throw reject('DUPLICATE_KEY', offset);
        }
        this.#hash = value;
        break;
      case KEY.SUBJECT:
        checkDn(value, offset);
        if (this.#subject !== null) {
          throw reject('DUPLICATE_KEY', offset);
        }
        this.#subject = value;
        break;
      case KEY.ISSUER:
        checkDn(value, offset);
        if (this.#issuer !== null) {
          throw reject('DUPLICATE_KEY', offset);
        }
        this.#issuer = value;
        break;
      case KEY.CERT: {
        if (this.#cert !== null) {
          throw reject('DUPLICATE_KEY', offset);
        }
        const block = parseCertificate(this.#text ? decode(value, offset) : value);
        if (block === undefined) {
          throw reject('INVALID_PEM', offset);
        }
        this.#cert = block.pem;
        break;
      }
      case KEY.CHAIN:
        if (this.#text) {
          // A valid `Chain` is never an empty list, so a non-empty chain means
          // `Chain` was already seen.
          if (this.#presentedChain.length > 0) {
            throw reject('DUPLICATE_KEY', offset);
          }
          const blocks = parseCertificates(decode(value, offset));
          if (blocks.length === 0) {
            throw reject('INVALID_PEM', offset);
          }
          this.#presentedChain.push(...blocks.map((block) => block.pem));
        } else {
          const block = parseCertificate(value);
          if (block === undefined) {
            throw reject('INVALID_PEM', offset);
          }
          this.#presentedChain.push(block.pem);
        }
        break;
    }
  }

  /** The frozen element, once the format's checks hold. */
  finish(offset: number): XfccElement {
    if (this.#text && this.#hash === null) {
      throw reject('MISSING_HASH', offset);
    }
    return Object.freeze({
      by: Object.freeze(this.#by),
      hash: this.#hash,
      cert: this.#cert,
      presentedChain: Object.freeze(this.#presentedChain),
      subject: this.#subject,
      uri: Object.freeze(this.#uri),
      dns: Object.freeze(this.#dns),
      // In the text format a URI SAN `a;Issuer="..."` is indistinguishable
      // from a real Issuer, so it is validated but never returned.
      issuer: this.#text ? null : this.#issuer,
    });
  }
}

const decode = (value: string, offset: number): string => {
  const decoded = percentDecode(value);
  if (decoded === null) {
    throw reject('INVALID_PERCENT_ENCODING', offset);
  }
  return decoded;
};
