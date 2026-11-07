// The text format: `,`-separated elements of `;`-separated `key=value` pairs.
//
// Grammar enforced (one pass, no backtracking):
//
//   header   = OWS element *( OWS "," OWS element ) OWS
//   element  = pair *( ";" pair )
//   pair     = key "=" ( quoted / unquoted )
//   key      = By / Hash / Cert / Chain / Subject / URI / DNS / Issuer   ; case-insensitive
//   quoted   = DQUOTE *( qchar / "\" VCHAR-or-SP ) DQUOTE
//   unquoted = *( VCHAR except "," ";" DQUOTE "\" )
//
// Keys must appear in the order above (the order Envoy writes them; `By`, `URI`
// and `DNS` may repeat), every element needs a `Hash`, and quoting must match
// Envoy exactly: `Cert`, `Chain`, `Subject` and `Issuer` are always quoted, the
// other keys never are.
//
// These rules reject a `;` or `,` smuggled into a SAN only when it reorders
// keys, adds a `URI=` beside another URI pair (Envoy writes `URI=` only when
// there are no URI SANs) or starts an element without a `Hash`. Envoy writes
// SANs unescaped, so other crafted SANs are byte-for-byte identical to real
// output; the README's "Security / trust model" lists them.
//
// `=` is allowed unquoted because Envoy does not quote `By`/`URI` values. A
// quoted value's backslash escapes are only used to find the closing quote:
// `Subject`/`Issuer` keep them verbatim for the RFC 4514 parser, and every other
// key rejects them, since none of those values can contain `\` or `"`.
//
// The caller has checked that the input is visible ASCII, SP and HTAB, so a
// string index is a byte offset.
import { ElementBuilder, KEY, type ElementOptions, type Key } from './element.ts';
import { reject } from './errors.ts';

import type { XfccElement } from './index.ts';

const TAB = 9;
const SPACE = 32;
const QUOTE = 34;
const COMMA = 44;
const SEMICOLON = 59;
const EQUALS = 61;
const BACKSLASH = 92;

const KEYS: ReadonlyMap<string, Key> = new Map([
  ['by', KEY.BY],
  ['hash', KEY.HASH],
  ['cert', KEY.CERT],
  ['chain', KEY.CHAIN],
  ['subject', KEY.SUBJECT],
  ['uri', KEY.URI],
  ['dns', KEY.DNS],
  ['issuer', KEY.ISSUER],
]);

const isOws = (code: number): boolean => code === SPACE || code === TAB;

class Parser {
  #pos = 0;
  readonly #input: string;
  readonly #options: ElementOptions;

  constructor(input: string, options: ElementOptions) {
    this.#input = input;
    this.#options = options;
  }

  /** The next char code, or NaN at the end of the input. */
  #peek(): number {
    return this.#input.charCodeAt(this.#pos);
  }

  #atEnd(): boolean {
    return this.#pos >= this.#input.length;
  }

  #skipOws(): void {
    while (isOws(this.#peek())) {
      this.#pos++;
    }
  }

  header(): XfccElement[] {
    const elements: XfccElement[] = [];
    for (;;) {
      this.#skipOws();
      // Checked before the element cap, so a trailing comma reports
      // EMPTY_ELEMENT whatever `maxElements` is.
      if (this.#atEnd() || this.#peek() === COMMA) {
        throw reject('EMPTY_ELEMENT', this.#pos);
      }
      if (elements.length >= this.#options.maxElements) {
        throw reject('TOO_MANY_ELEMENTS', this.#pos);
      }
      elements.push(this.#element());
      if (this.#atEnd()) {
        return elements;
      }
      // A pair only ends at `;`, `,` or the end of the input.
      this.#pos++;
    }
  }

  #element(): XfccElement {
    const start = this.#pos;
    const builder = new ElementBuilder('text');
    let lastKey = -1;
    for (;;) {
      lastKey = this.#pair(builder, lastKey);
      if (this.#peek() !== SEMICOLON) {
        break;
      }
      this.#pos++;
      const next = this.#peek();
      if (this.#atEnd() || next === COMMA || next === SEMICOLON) {
        throw reject('EMPTY_PAIR', this.#pos);
      }
    }
    return builder.finish(start);
  }

  #pair(builder: ElementBuilder, lastKey: number): Key {
    const keyStart = this.#pos;
    for (;;) {
      const code = this.#peek();
      if (this.#atEnd() || code === EQUALS || code === SEMICOLON || code === COMMA) {
        break;
      }
      this.#pos++;
    }
    if (this.#peek() !== EQUALS) {
      throw reject('MISSING_EQUALS', keyStart);
    }
    // The input is ASCII, so this is an ASCII case-insensitive match.
    const key = KEYS.get(this.#input.slice(keyStart, this.#pos).toLowerCase());
    if (key === undefined) {
      throw reject('UNKNOWN_KEY', keyStart);
    }
    if (key < lastKey) {
      throw reject('KEY_ORDER', keyStart);
    }
    this.#pos++;

    const valueStart = this.#pos;
    const quoted = this.#peek() === QUOTE;
    const value = quoted ? this.#quoted() : this.#unquoted();
    this.#endOfValue();

    const mustQuote =
      key === KEY.CERT || key === KEY.CHAIN || key === KEY.SUBJECT || key === KEY.ISSUER;
    if (mustQuote !== quoted) {
      throw reject('INVALID_QUOTING', valueStart);
    }
    if ((key === KEY.CERT || key === KEY.CHAIN) && value.includes('\\')) {
      throw reject('INVALID_ESCAPE', valueStart);
    }
    builder.set(key, value, valueStart);
    return key;
  }

  /** The text between the quotes, escapes intact. */
  #quoted(): string {
    const open = this.#pos;
    this.#pos++;
    const innerStart = this.#pos;
    for (;;) {
      if (this.#atEnd()) {
        throw reject('UNTERMINATED_QUOTE', open);
      }
      const code = this.#peek();
      if (code === QUOTE) {
        break;
      }
      this.#pos += code === BACKSLASH ? 2 : 1;
    }
    const inner = this.#input.slice(innerStart, this.#pos);
    this.#pos++;
    const next = this.#peek();
    if (!this.#atEnd() && next !== SEMICOLON && next !== COMMA && !isOws(next)) {
      throw reject('UNEXPECTED_AFTER_VALUE', this.#pos);
    }
    return inner;
  }

  #unquoted(): string {
    const start = this.#pos;
    for (;;) {
      const code = this.#peek();
      if (this.#atEnd() || code === SEMICOLON || code === COMMA || isOws(code)) {
        return this.#input.slice(start, this.#pos);
      }
      if (code === QUOTE || code === BACKSLASH) {
        throw reject('INVALID_ESCAPE', this.#pos);
      }
      this.#pos++;
    }
  }

  /** Whitespace may only appear around the element separator. */
  #endOfValue(): void {
    if (isOws(this.#peek())) {
      this.#skipOws();
      if (!this.#atEnd() && this.#peek() !== COMMA) {
        throw reject('UNEXPECTED_AFTER_VALUE', this.#pos);
      }
    }
  }
}

export const parseText = (input: string, options: ElementOptions): XfccElement[] =>
  new Parser(input, options).header();
