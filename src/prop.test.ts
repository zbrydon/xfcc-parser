// Property tests: anything an Envoy-equivalent emitter produces must parse back
// to the same value, and no input may escape as anything but an `XfccError`.
import * as fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { CA_PEM, CLIENT_PEM, errorOf, urlEncode } from '../test/helpers.ts';

import {
  parseDistinguishedName,
  parseXfcc,
  XfccError,
  type ParseOptions,
  type XfccElement,
} from './index.ts';

fc.configureGlobal({ numRuns: 512 });

// Several hops, so round trips cover multi-element headers.
const TEXT = { format: 'text', maxElements: 32, maxLength: 1 << 20 } as const;
const JSON_FORMAT = { format: 'json', maxElements: 32, maxLength: 1 << 20 } as const;

const char = (chars: string) => fc.constantFrom(...chars.split(''));
const stringOf = (chars: string, minLength: number, maxLength: number) =>
  fc.string({ unit: char(chars), minLength, maxLength });

const LOWER_ALNUM = 'abcdefghijklmnopqrstuvwxyz0123456789';

const uri = fc
  .tuple(
    stringOf('abcdefghijklmnopqrstuvwxyz', 1, 1),
    stringOf(`${LOWER_ALNUM}+.-`, 0, 5),
    stringOf(`${LOWER_ALNUM}.-`, 1, 10),
    fc.array(stringOf(`${LOWER_ALNUM}ABC._~-`, 0, 8), { maxLength: 3 }),
    fc.option(fc.tuple(stringOf('abc', 1, 1), stringOf(`${LOWER_ALNUM}=`, 0, 4))),
  )
  .map(([first, scheme, host, path, query]) => {
    const segments = path.map((segment) => `/${segment}`).join('');
    return `${first}${scheme}://${host}${segments}${query === null ? '' : `?${query[0]}=${query[1]}`}`;
  });

const label = fc
  .tuple(
    stringOf(LOWER_ALNUM, 1, 1),
    stringOf(`${LOWER_ALNUM}-`, 0, 8),
    stringOf(LOWER_ALNUM, 1, 1),
  )
  .map(([first, middle, last]) => `${first}${middle}${last}`);

// RFC 1123 §2.1: the top-level label is never all-numeric.
const dns = fc
  .tuple(fc.boolean(), fc.array(label, { minLength: 1, maxLength: 4 }))
  .filter(([, labels]) => !/^[0-9]+$/.test(labels.at(-1) ?? ''))
  .map(([wildcard, labels]) => `${wildcard ? '*.' : ''}${labels.join('.')}`);

const hash = stringOf('0123456789abcdef', 64, 64);

/** Escapes an attribute value the way OpenSSL's `XN_FLAG_RFC2253` does. */
const escapeDnValue = (value: string): string => {
  const bytes = Buffer.from(value, 'utf8');
  return [...bytes]
    .map((byte, i) => {
      const character = String.fromCodePoint(byte);
      if (',+"\\<>;'.includes(character)) {
        return `\\${character}`;
      }
      if (
        ((character === '#' || character === ' ') && i === 0) ||
        (character === ' ' && i === bytes.length - 1)
      ) {
        return `\\${character}`;
      }
      return byte >= 0x20 && byte <= 0x7e
        ? character
        : `\\${byte.toString(16).toUpperCase().padStart(2, '0')}`;
    })
    .join('');
};

const dnRdns = fc.array(
  fc.array(
    fc.tuple(
      fc.constantFrom('CN', 'O', 'OU', 'C', 'L', 'ST', 'UID', '2.5.4.3', 'emailAddress'),
      fc.string({ unit: 'grapheme', maxLength: 12 }).filter((value) => !value.includes('\0')),
    ),
    { minLength: 1, maxLength: 2 },
  ),
  { maxLength: 3 },
);

const formatDn = (rdns: readonly (readonly (readonly [string, string])[])[]) =>
  rdns
    .map((rdn) => rdn.map(([type, value]) => `${type}=${escapeDnValue(value)}`).join('+'))
    .join(',');

const element: fc.Arbitrary<XfccElement> = fc
  .record({
    by: fc.array(uri, { maxLength: 2 }),
    hash,
    cert: fc.option(fc.constant(CLIENT_PEM)),
    presentedChain: fc.constantFrom([], [CLIENT_PEM], [CLIENT_PEM, CA_PEM]),
    subject: fc.option(dnRdns.map(formatDn)),
    uri: fc.array(uri, { maxLength: 2 }),
    dns: fc.array(dns, { maxLength: 2 }),
    issuer: fc.option(dnRdns.map(formatDn)),
  })
  .map((value) => value);

/** Emits the text format exactly as Envoy's `mutateXfccRequestHeader` does. */
const emitText = (elements: readonly XfccElement[]) =>
  elements
    .map((el) =>
      [
        ...el.by.map((value) => `By=${value}`),
        `Hash=${el.hash ?? ''}`,
        ...(el.cert === null ? [] : [`Cert="${urlEncode(el.cert)}"`]),
        ...(el.presentedChain.length === 0
          ? []
          : [`Chain="${urlEncode(el.presentedChain.join(''))}"`]),
        ...(el.subject === null ? [] : [`Subject="${el.subject}"`]),
        ...(el.uri.length === 0 ? ['URI='] : el.uri.map((value) => `URI=${value}`)),
        ...el.dns.map((value) => `DNS=${value}`),
        ...(el.issuer === null ? [] : [`Issuer="${el.issuer}"`]),
      ].join(';'),
    )
    .join(',');

// Escapes control and non-ASCII characters, as Envoy's JSON writer does.
const jsonString = (value: string) =>
  JSON.stringify(value).replaceAll(
    /[^\x20-\x7e]/g,
    (unit) => `\\u${unit.charCodeAt(0).toString(16).padStart(4, '0')}`,
  );

const jsonList = (key: string, values: readonly string[]) =>
  values.length === 0 ? [] : [`"${key}":[${values.map(jsonString).join(',')}]`];
const jsonSingle = (key: string, value: string | null) =>
  value === null || value === '' ? [] : [`"${key}":${jsonString(value)}`];

/** Emits the JSON format, with empty fields omitted. */
const emitJson = (elements: readonly XfccElement[]) =>
  `[${elements
    .map(
      (el) =>
        `{${[
          ...jsonList('by', el.by),
          ...jsonSingle('hash', el.hash),
          ...jsonSingle('cert', el.cert),
          ...jsonList('chain', el.presentedChain),
          ...jsonSingle('subject', el.subject),
          ...jsonList('uri', el.uri),
          ...jsonList('dns', el.dns),
          ...jsonSingle('issuer', el.issuer),
        ].join(',')}}`,
    )
    .join(',')}]`;

/** `fn` may reject, but only with an `XfccError`, which reads as `null`. */
const orNull = <T>(fn: () => T): T | null => {
  try {
    return fn();
  } catch (error) {
    if (error instanceof XfccError) {
      return null;
    }
    throw error;
  }
};

const parseOrNull = (input: string, options: ParseOptions) =>
  orNull(() => parseXfcc(input, options));

describe('round trips', () => {
  it('parses what the text emitter writes', () => {
    fc.assert(
      fc.property(fc.array(element, { minLength: 1, maxLength: 3 }), (elements) => {
        // The text format validates `Issuer` but never returns it.
        expect(parseXfcc(emitText(elements), TEXT)).toEqual(
          elements.map((el) => ({ ...el, issuer: null })),
        );
      }),
    );
  });

  it('rejects a text Issuer the DN parser rejects', () => {
    fc.assert(
      fc.property(
        fc.array(element, { maxLength: 2 }),
        element,
        dnRdns.map(formatDn),
        fc.constantFrom(',', '+'),
        (rest, last, issuer, suffix) => {
          const header = emitText([...rest, { ...last, issuer: `${issuer}${suffix}` }]);
          const { code, offset } = errorOf(() => parseXfcc(header, TEXT));
          expect({ code, offset }).toEqual({
            code: 'INVALID_DN',
            offset: header.lastIndexOf('Issuer="') + 'Issuer='.length,
          });
        },
      ),
    );
  });

  it('parses what the JSON emitter writes', () => {
    fc.assert(
      fc.property(fc.array(element, { minLength: 1, maxLength: 3 }), (elements) => {
        const expected = elements.map((el) => ({
          ...el,
          // JSON omits empty values.
          subject: el.subject === '' ? null : el.subject,
          issuer: el.issuer === '' ? null : el.issuer,
        }));
        expect(parseXfcc(emitJson(elements), JSON_FORMAT)).toEqual(expected);
      }),
    );
  });

  it('decodes what the DN formatter escapes', () => {
    fc.assert(
      fc.property(dnRdns, (rdns) => {
        expect(parseDistinguishedName(formatDn(rdns))).toEqual(
          rdns.map((rdn) => rdn.map(([type, value]) => ({ type, value, encoding: 'string' }))),
        );
      }),
    );
  });
});

describe('arbitrary input', () => {
  it('never throws anything but an XfccError', () => {
    fc.assert(
      fc.property(fc.string({ unit: 'binary', maxLength: 256 }), (input) => {
        for (const format of ['text', 'json'] as const) {
          expect(() => parseOrNull(input, { format })).not.toThrow();
        }
        expect(() => orNull(() => parseDistinguishedName(input))).not.toThrow();
      }),
    );
  });

  it('never accepts a mutated header without the invariants holding', () => {
    fc.assert(
      fc.property(
        fc.array(element, { minLength: 1, maxLength: 2 }),
        fc.nat(),
        char(' \t",;=\\%[]{}:#+'),
        fc.boolean(),
        (elements, index, replacement, json) => {
          const header = json ? emitJson(elements) : emitText(elements);
          const i = index % header.length;
          const mutated = `${header.slice(0, i)}${replacement}${header.slice(i + 1)}`;
          for (const el of parseOrNull(mutated, json ? JSON_FORMAT : TEXT) ?? []) {
            expect(el.hash ?? '0'.repeat(64)).toMatch(/^[0-9a-f]{64}$/);
            // Anything accepted has a parseable, plain-ASCII DN.
            for (const dn of [el.subject, el.issuer].filter((value) => value !== null)) {
              expect(dn).toMatch(/^[\x20-\x7e]*$/);
              expect(() => parseDistinguishedName(dn)).not.toThrow();
            }
          }
        },
      ),
    );
  });
});
