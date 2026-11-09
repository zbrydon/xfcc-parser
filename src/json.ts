// The JSON format: an array with one object per proxy, lowercase keys.
//
// `JSON.parse` is not an option: it keeps the last of a duplicate key and
// accepts lone surrogates. Unknown, duplicate and escaped keys, `null`, empty
// strings, arrays and objects are rejected; Envoy omits empty fields rather
// than emitting them. A `by` or `uri` value containing `Hash=` is rejected as a text-format
// element nested in a JSON string (see `toElement`).
//
// The whole shape is checked before any value is validated. The caller has
// checked that the input is visible ASCII, SP and HTAB, so a string index is a
// byte offset, and the only JSON whitespace left is SP and HTAB.
import { ElementBuilder, KEY, type Key } from './element.ts';
import { reject, type XfccError } from './errors.ts';
import { hexVal } from './validate.ts';

import type { XfccElement } from './index.ts';

const TAB = 9;
const SPACE = 32;
const QUOTE = 34;
const COMMA = 44;
const COLON = 58;
const OPEN_ARRAY = 91;
const BACKSLASH = 92;
const CLOSE_ARRAY = 93;
const OPEN_OBJECT = 123;
const CLOSE_OBJECT = 125;

const LIST_KEYS: ReadonlyMap<string, Key> = new Map([
  ['by', KEY.BY],
  ['chain', KEY.CHAIN],
  ['uri', KEY.URI],
  ['dns', KEY.DNS],
]);
const SINGLE_KEYS: ReadonlyMap<string, Key> = new Map([
  ['hash', KEY.HASH],
  ['cert', KEY.CERT],
  ['subject', KEY.SUBJECT],
  ['issuer', KEY.ISSUER],
]);

const ESCAPES: ReadonlyMap<number, string> = new Map([
  [QUOTE, '"'],
  [BACKSLASH, '\\'],
  [47, '/'],
  [98, '\b'],
  [102, '\f'],
  [110, '\n'],
  [114, '\r'],
  [116, '\t'],
]);

/** A decoded string and the offset of its opening quote. */
interface Value {
  readonly text: string;
  readonly offset: number;
}

interface RawList {
  readonly offset: number;
  readonly values: Value[];
}

interface RawElement {
  readonly lists: Map<Key, RawList>;
  readonly singles: Map<Key, Value>;
}

class Parser {
  #pos = 0;
  readonly #input: string;

  constructor(input: string) {
    this.#input = input;
  }

  #peek(): number {
    return this.#input.charCodeAt(this.#pos);
  }

  #err(): XfccError {
    return reject('INVALID_JSON', this.#pos);
  }

  #skipWhitespace(): void {
    let code = this.#peek();
    while (code === SPACE || code === TAB) {
      this.#pos++;
      code = this.#peek();
    }
  }

  /** Skips whitespace and consumes `code`, or throws. */
  #expect(code: number): void {
    this.#skipWhitespace();
    if (this.#peek() !== code) {
      throw this.#err();
    }
    this.#pos++;
  }

  /** Skips whitespace, then consumes `,` (true) or `close` (false), or throws. */
  #more(close: number): boolean {
    this.#skipWhitespace();
    const code = this.#peek();
    if (code !== COMMA && code !== close) {
      throw this.#err();
    }
    this.#pos++;
    return code === COMMA;
  }

  /** Skips whitespace, then consumes `close` if it is next. */
  #tryClose(close: number): boolean {
    this.#skipWhitespace();
    if (this.#peek() !== close) {
      return false;
    }
    this.#pos++;
    return true;
  }

  header(maxElements: number): RawElement[] {
    const elements: RawElement[] = [];
    this.#expect(OPEN_ARRAY);
    if (!this.#tryClose(CLOSE_ARRAY)) {
      do {
        this.#skipWhitespace();
        // A trailing comma or the end of the input is not an extra element.
        if (elements.length === maxElements && this.#startsValue()) {
          throw reject('TOO_MANY_ELEMENTS', this.#pos);
        }
        elements.push(this.#element());
      } while (this.#more(CLOSE_ARRAY));
    }
    this.#skipWhitespace();
    if (this.#pos !== this.#input.length) {
      throw this.#err();
    }
    return elements;
  }

  #startsValue(): boolean {
    return this.#pos < this.#input.length && this.#peek() !== CLOSE_ARRAY;
  }

  #element(): RawElement {
    const lists = new Map<Key, RawList>();
    const singles = new Map<Key, Value>();
    // Only a non-empty object: an array or `{}` is not a shape Envoy writes.
    this.#expect(OPEN_OBJECT);
    do {
      this.#field(lists, singles);
    } while (this.#more(CLOSE_OBJECT));
    return { lists, singles };
  }

  #field(lists: Map<Key, RawList>, singles: Map<Key, Value>): void {
    this.#skipWhitespace();
    const keyStart = this.#pos;
    const name = this.#string();
    // Envoy never escapes a key, so `"h\u0061sh"` is not `hash`.
    // Every escape decodes shorter than it is written, so a key shorter than
    // its source (less the quotes) had one.
    const escaped = name.length !== this.#pos - keyStart - 2;
    const listKey = escaped ? undefined : LIST_KEYS.get(name);
    const singleKey = escaped ? undefined : SINGLE_KEYS.get(name);
    if (listKey !== undefined && !lists.has(listKey)) {
      this.#colon();
      lists.set(listKey, this.#list());
    } else if (singleKey !== undefined && !singles.has(singleKey)) {
      this.#colon();
      singles.set(singleKey, this.#value());
    } else {
      // Unknown, escaped or duplicate.
      throw reject('INVALID_JSON', keyStart);
    }
  }

  #colon(): void {
    this.#expect(COLON);
    this.#skipWhitespace();
  }

  #list(): RawList {
    const offset = this.#pos;
    const values: Value[] = [];
    this.#expect(OPEN_ARRAY);
    if (!this.#tryClose(CLOSE_ARRAY)) {
      do {
        this.#skipWhitespace();
        values.push(this.#value());
      } while (this.#more(CLOSE_ARRAY));
    }
    return { offset, values };
  }

  #value(): Value {
    const offset = this.#pos;
    return { text: this.#string(), offset };
  }

  /** A JSON string, decoded. */
  #string(): string {
    if (this.#peek() !== QUOTE) {
      throw this.#err();
    }
    this.#pos++;
    let value = '';
    let start = this.#pos;
    for (;;) {
      const code = this.#peek();
      if (code === QUOTE) {
        value += this.#input.slice(start, this.#pos);
        this.#pos++;
        return value;
      }
      if (code === BACKSLASH) {
        value += this.#input.slice(start, this.#pos);
        this.#pos++;
        value += this.#escape();
        start = this.#pos;
      } else if (code >= SPACE) {
        this.#pos++;
      } else {
        // A raw control character, or NaN at the end of the input.
        throw this.#err();
      }
    }
  }

  #escape(): string {
    const code = this.#peek();
    if (code === 117) {
      this.#pos++;
      const unit = this.#hex4();
      if (unit >= 0xdc00 && unit <= 0xdfff) {
        throw this.#err();
      }
      if (unit < 0xd800 || unit > 0xdbff) {
        return String.fromCharCode(unit);
      }
      // A leading surrogate must be followed by a trailing one.
      if (this.#peek() !== BACKSLASH || this.#input.charCodeAt(this.#pos + 1) !== 117) {
        throw this.#err();
      }
      this.#pos += 2;
      const trail = this.#hex4();
      if (trail < 0xdc00 || trail > 0xdfff) {
        throw this.#err();
      }
      return String.fromCharCode(unit, trail);
    }
    const escaped = ESCAPES.get(code);
    if (escaped === undefined) {
      throw this.#err();
    }
    this.#pos++;
    return escaped;
  }

  #hex4(): number {
    let unit = 0;
    for (let i = 0; i < 4; i++) {
      const digit = hexVal(this.#peek());
      if (digit === -1) {
        throw this.#err();
      }
      unit = unit * 16 + digit;
      this.#pos++;
    }
    return unit;
  }
}

// In the order Envoy writes them, as far as lists before singles allows.
const LIST_ORDER = [KEY.BY, KEY.CHAIN, KEY.URI, KEY.DNS] as const;
const SINGLE_ORDER = [KEY.HASH, KEY.CERT, KEY.SUBJECT, KEY.ISSUER] as const;

const toElement = (raw: RawElement): XfccElement => {
  const builder = new ElementBuilder('json');
  for (const key of LIST_ORDER) {
    const list = raw.lists.get(key);
    if (list?.values.length === 0) {
      throw reject('EMPTY_VALUE', list.offset);
    }
    for (const { text, offset } of list?.values ?? []) {
      // With APPEND_FORWARD, Envoy appends in the text format when the incoming
      // header is not a bracketed array. A client-forwarded prefix can open a
      // `by`/`uri` string that swallows that text, and a crafted URI SAN can
      // close it and write the rest of the element. Envoy writes `Hash=` in
      // every text element, and no other field's validator accepts the text,
      // so this rejects every such header.
      if ((key === KEY.BY || key === KEY.URI) && text.includes('Hash=')) {
        throw reject('INVALID_URI', offset);
      }
      builder.set(key, text, offset);
    }
  }
  for (const key of SINGLE_ORDER) {
    const value = raw.singles.get(key);
    if (value !== undefined) {
      builder.set(key, value.text, value.offset);
    }
  }
  return builder.finish();
};

export const parseJson = (input: string, maxElements: number): XfccElement[] => {
  const raw = new Parser(input).header(maxElements);
  if (raw.length === 0) {
    throw reject('EMPTY', 0);
  }
  return raw.map(toElement);
};
