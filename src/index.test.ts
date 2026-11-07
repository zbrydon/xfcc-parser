import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

import { describe, expect, it } from 'vitest';

import {
  CA_PEM,
  CLIENT_PEM,
  CLIENT_SHA256,
  errorOf,
  HASH_A,
  NASTY_SUBJECT,
  urlEncode,
} from '../test/helpers.ts';

import {
  MAX_ELEMENTS_LIMIT,
  MAX_LENGTH_LIMIT,
  parseDistinguishedName,
  getPeerSpiffeId,
  parseXfcc,
  type XfccErrorCode,
} from './index.ts';

const HASH = HASH_A;

describe('package.json', () => {
  it('has no runtime dependencies or install scripts', () => {
    const manifest: unknown = JSON.parse(
      readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
    );
    expect(manifest).not.toHaveProperty('dependencies');
    expect(manifest).not.toHaveProperty('optionalDependencies');
    expect(manifest).not.toHaveProperty('peerDependencies');
    for (const script of ['preinstall', 'install', 'postinstall', 'prepare']) {
      expect(manifest).not.toHaveProperty(['scripts', script]);
    }
  });
});

describe('limits', () => {
  it('exposes the documented limits', () => {
    expect(MAX_LENGTH_LIMIT).toBe(1 << 20);
    expect(MAX_ELEMENTS_LIMIT).toBe(1024);
  });

  it('defaults maxLength to 64 KiB', () => {
    const atLimit = `Hash=${HASH};URI=a:`.padEnd(64 * 1024, 'a');
    expect(parseXfcc(atLimit, TEXT)).toHaveLength(1);
    expect(codeOf(() => parseXfcc(`${atLimit}a`, TEXT))).toBe('TOO_LONG');
  });
});

const TEXT = { format: 'text' } as const;
const JSON_FORMAT = { format: 'json' } as const;

const codeOf = (fn: () => unknown): XfccErrorCode => errorOf(fn).code;

describe('parseXfcc', () => {
  it('parses the Envoy documentation example', () => {
    expect(
      parseXfcc(
        `By=http://frontend.lyft.com;Hash=${HASH};Subject="CN=Test Client,OU=Lyft,L=San Francisco,ST=CA,C=US";URI=http://testclient.lyft.com;DNS=lyft.com;DNS=www.lyft.com`,
        TEXT,
      ),
    ).toEqual([
      {
        by: ['http://frontend.lyft.com'],
        hash: HASH,
        cert: null,
        presentedChain: [],
        subject: 'CN=Test Client,OU=Lyft,L=San Francisco,ST=CA,C=US',
        uri: ['http://testclient.lyft.com'],
        dns: ['lyft.com', 'www.lyft.com'],
        issuer: null,
      },
    ]);
  });

  it('returns a null hash when the JSON element has no hash', () => {
    expect(parseXfcc('[{"by":["spiffe://edge"]}]', { format: 'json' })[0]?.hash).toBeNull();
  });

  it('parses the JSON format', () => {
    const [element] = parseXfcc(
      `[{"by":["http://frontend.lyft.com"],"hash":"${HASH}","uri":["http://testclient.lyft.com"]}]`,
      { format: 'json' },
    );
    expect(element?.by).toEqual(['http://frontend.lyft.com']);
    expect(element?.uri).toEqual(['http://testclient.lyft.com']);
  });

  it('keeps element order so the last element is the nearest proxy', () => {
    const elements = parseXfcc(
      `By=spiffe://edge;Hash=${HASH};URI=spiffe://client,By=spiffe://mesh;Hash=${HASH};URI=spiffe://edge`,
      { format: 'text', maxElements: 2 },
    );
    expect(elements.map((e) => e.by[0])).toEqual(['spiffe://edge', 'spiffe://mesh']);
  });

  it('decodes Cert and Chain', () => {
    const header = `Hash=${CLIENT_SHA256};Cert="${urlEncode(CLIENT_PEM)}";Chain="${urlEncode(CLIENT_PEM + CA_PEM)}"`;
    const [element] = parseXfcc(header, TEXT);
    expect(element?.cert).toBe(CLIENT_PEM);
    expect(element?.presentedChain).toEqual([CLIENT_PEM, CA_PEM]);
  });

  it('keeps Subject escapes so a forged RDN stays inside its value', () => {
    const [element] = parseXfcc(`Hash=${HASH};Subject="${NASTY_SUBJECT}"`, TEXT);
    expect(element?.subject).toBe(NASTY_SUBJECT);
    const rdns = parseDistinguishedName(NASTY_SUBJECT);
    expect(rdns[1]).toEqual([
      { type: 'UID', value: '  #pad ', encoding: 'string' },
      { type: 'CN', value: 'evil,O=Admin', encoding: 'string' },
    ]);
    expect(rdns.some((rdn) => rdn.some((a) => a.type === 'O' && a.value === 'Admin'))).toBe(false);
  });

  it('returns an empty list when the header is absent', () => {
    expect(parseXfcc(undefined, TEXT)).toEqual([]);
  });

  it('allows one element by default', () => {
    expect(codeOf(() => parseXfcc(`Hash=${HASH},Hash=${HASH}`, TEXT))).toBe('TOO_MANY_ELEMENTS');
    expect(codeOf(() => parseXfcc('[{"uri":["a:"]},{"uri":["b:"]}]', JSON_FORMAT))).toBe(
      'TOO_MANY_ELEMENTS',
    );
  });

  it('never returns a text-format Issuer', () => {
    // A URI SAN `spiffe://td/x;Issuer="CN=Trusted CA"` emits exactly this.
    const header = `Hash=${HASH};URI=spiffe://td/x;Issuer="CN=Trusted CA"`;
    expect(parseXfcc(header, TEXT)[0]?.issuer).toBeNull();
    // It is still validated.
    expect(codeOf(() => parseXfcc(`Hash=${HASH};Issuer="CN"`, TEXT))).toBe('INVALID_DN');
    expect(parseXfcc('[{"issuer":"CN=CA"}]', JSON_FORMAT)[0]?.issuer).toBe('CN=CA');
  });

  it.each([undefined, null, {}, { maxElements: 1 }])(
    'requires format with options %j',
    (options) => {
      // @ts-expect-error -- deliberately invalid at runtime
      expect(() => parseXfcc(undefined, options)).toThrow(TypeError);
      // @ts-expect-error -- deliberately invalid at runtime
      expect(() => parseXfcc(`Hash=${HASH}`, options)).toThrow(TypeError);
    },
  );

  it('ignores options inherited from Object.prototype', () => {
    const inherited = { format: 'text', maxElements: 2, maxLength: 1 << 20 };
    Object.assign(Object.prototype, inherited);
    try {
      // @ts-expect-error -- deliberately invalid at runtime
      expect(() => parseXfcc(`Hash=${HASH}`, {})).toThrow(TypeError);
      const twoHops = `Hash=${HASH};URI=spiffe://td/a,Hash=${HASH};URI=spiffe://td/b`;
      expect(codeOf(() => parseXfcc(twoHops, { format: 'text' }))).toBe('TOO_MANY_ELEMENTS');
      expect(codeOf(() => getPeerSpiffeId(twoHops, { format: 'text' }))).toBe('TOO_MANY_ELEMENTS');
      expect(codeOf(() => parseXfcc('a'.repeat(64 * 1024 + 1), { format: 'text' }))).toBe(
        'TOO_LONG',
      );
    } finally {
      for (const key of Object.keys(inherited)) {
        Reflect.deleteProperty(Object.prototype, key);
      }
    }
  });

  it('rejects options that are not a plain or null-prototype object', () => {
    const inherited = { __proto__: { maxLength: 16 }, format: 'text' } as const;
    class Getter {
      format = 'text';
      get maxLength() {
        return 16;
      }
    }
    for (const options of [inherited, new Getter(), [], new Date()]) {
      // @ts-expect-error -- deliberately invalid at runtime
      expect(() => parseXfcc(`Hash=${HASH}`, options)).toThrow(TypeError);
      // @ts-expect-error -- deliberately invalid at runtime
      expect(() => getPeerSpiffeId(`Hash=${HASH}`, options)).toThrow(TypeError);
    }
    const bare = { __proto__: null, format: 'text' } as const;
    expect(parseXfcc(`Hash=${HASH}`, bare)[0]?.hash).toBe(HASH);
    expect(() => getPeerSpiffeId(`Hash=${HASH}`, bare)).toThrow('NOT_ONE_URI');
  });

  it('rejects a non-enumerable or symbol option key rather than ignoring it', () => {
    const hidden = { format: 'text' } as const;
    Object.defineProperty(hidden, 'maxLength', { value: 16 });
    const symbol = { format: 'text', [Symbol('maxLength')]: 16 } as const;
    for (const options of [hidden, symbol]) {
      expect(() => parseXfcc(`Hash=${HASH}`, options)).toThrow(TypeError);
      expect(() => getPeerSpiffeId(`Hash=${HASH}`, options)).toThrow(TypeError);
    }
  });

  it('accepts a plain options object from another realm', () => {
    const options: unknown = runInNewContext('({ format: "text" })');
    // @ts-expect-error -- typed unknown, a plain object at runtime
    expect(parseXfcc(`Hash=${HASH}`, options)[0]?.hash).toBe(HASH);
    // @ts-expect-error -- typed unknown, a plain object at runtime
    expect(() => getPeerSpiffeId(`Hash=${HASH}`, options)).toThrow('NOT_ONE_URI');
    // A null-prototype parent that holds an option is not a realm's Object.prototype.
    const parent = Object.defineProperty({ __proto__: null }, 'maxLength', { value: 1 << 20 });
    const forged = { __proto__: parent, format: 'text' } as const;
    expect(() => parseXfcc(`Hash=${HASH}`, forged)).toThrow(TypeError);
  });

  it('still returns errors when Error.stackTraceLimit is read-only', () => {
    const { stackTraceLimit } = Error;
    Object.defineProperty(Error, 'stackTraceLimit', { writable: false });
    try {
      expect(codeOf(() => parseXfcc(' ', TEXT))).toBe('EMPTY');
      expect(() => getPeerSpiffeId(`Hash=${HASH}`, TEXT)).toThrow('NOT_ONE_URI');
    } finally {
      Object.defineProperty(Error, 'stackTraceLimit', { writable: true, value: stackTraceLimit });
    }
  });

  it('joins repeated header lines with commas', () => {
    const elements = parseXfcc([`Hash=${HASH};URI=spiffe://a`, `Hash=${HASH};URI=spiffe://b`], {
      format: 'text',
      maxElements: 2,
    });
    expect(elements.map((e) => e.uri[0])).toEqual(['spiffe://a', 'spiffe://b']);
    expect(codeOf(() => parseXfcc([], TEXT))).toBe('EMPTY');
    expect(
      codeOf(() => parseXfcc(['[{"uri":["a:"]}]', '[{"uri":["b:"]}]'], { format: 'json' })),
    ).toBe('INVALID_JSON');
  });

  it('returns deeply frozen results', () => {
    const elements = parseXfcc(`Hash=${HASH};URI=spiffe://a;DNS=a.example`, TEXT);
    expect(Object.isFrozen(elements)).toBe(true);
    expect(Object.isFrozen(elements[0])).toBe(true);
    expect(Object.isFrozen(elements[0]?.uri)).toBe(true);
    expect(Object.isFrozen(elements[0]?.dns)).toBe(true);
    expect(Object.isFrozen(elements[0]?.by)).toBe(true);
    expect(Object.isFrozen(elements[0]?.presentedChain)).toBe(true);
  });

  it.each([
    ['', 'EMPTY'],
    ['Foo=bar', 'UNKNOWN_KEY'],
    [`Hash=${HASH};URI=http://a,,URI=http://b`, 'EMPTY_ELEMENT'],
    [`Hash=${HASH};DNS=a.com;URI=spiffe://admin`, 'KEY_ORDER'],
    [`Hash=${HASH};URI=spiffe://a,URI=spiffe://admin`, 'MISSING_HASH'],
    ['Subject=CN=a', 'INVALID_QUOTING'],
    ['Subject="CN=a', 'UNTERMINATED_QUOTE'],
    ['Hash=abc', 'INVALID_HASH'],
    [`Hash=${HASH};Hash=${HASH}`, 'DUPLICATE_KEY'],
    [`Hash=${HASH};URI=spiffe://td/admin;URI=`, 'DUPLICATE_KEY'],
    ['URI=http://aé', 'INVALID_CHAR'],
    ['URI=http://a\n', 'INVALID_CHAR'],
    ['URI=http://\ud800', 'INVALID_CHAR'],
    [`Hash=${HASH};Cert=abc`, 'INVALID_QUOTING'],
    [`Hash=${HASH};URI="spiffe://a"`, 'INVALID_QUOTING'],
    // A text header made to look like JSON is still parsed as text.
    ['[{"uri":["a:"]}]', 'MISSING_EQUALS'],
  ] as const)('rejects %j with %s', (header, code) => {
    // Several hops, so errors in a later element are reached.
    expect(codeOf(() => parseXfcc(header, { format: 'text', maxElements: 32 }))).toBe(code);
  });

  it('rejects malformed JSON when format is json', () => {
    expect(codeOf(() => parseXfcc('[{"uri":["a:"],"uri":["b:"]}]', { format: 'json' }))).toBe(
      'INVALID_JSON',
    );
  });

  it('reports byte offsets and never echoes input', () => {
    const error = errorOf(() => parseXfcc('URI=http://a;secret-token=x', TEXT));
    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe('XfccError');
    expect(error.code).toBe('UNKNOWN_KEY');
    expect(error.offset).toBe(13);
    expect(error.message).toBe('UNKNOWN_KEY: unknown key (at byte 13)');
    expect(error.message).not.toContain('secret');
  });

  it.each([
    ['[{"uri":["a:b", "relative"]}]', 'INVALID_URI', 16],
    ['[{"uri":["a:Hash=x"]}]', 'INVALID_URI', 9],
    ['[{"hash":"x"}]', 'INVALID_HASH', 9],
    ['[{"subject":""}]', 'EMPTY_VALUE', 12],
    ['[{"dns": [ ]}]', 'EMPTY_VALUE', 9],
    ['[ ]', 'EMPTY', 0],
  ])('reports the offset of JSON error %j', (header, expected, offset) => {
    const error = errorOf(() => parseXfcc(header, JSON_FORMAT));
    expect(error.code).toBe(expected);
    expect(error.offset).toBe(offset);
    expect(error.message).toContain(`(at byte ${offset})`);
  });

  it('rejects oversized headers', () => {
    const error = errorOf(() =>
      parseXfcc(`URI=http://${'a'.repeat(100)}`, { format: 'text', maxLength: 50 }),
    );
    expect(error.code).toBe('TOO_LONG');
    expect(error.offset).toBe(50);
    expect(codeOf(() => parseXfcc('a'.repeat(64 * 1024 + 1), TEXT))).toBe('TOO_LONG');
  });

  it('enforces the byte limit for multi-byte input', () => {
    // 4 UTF-16 units, but more than 4 UTF-8 bytes.
    expect(codeOf(() => parseXfcc('éééé', { format: 'text', maxLength: 4 }))).toBe('TOO_LONG');
  });

  it('applies maxElements and format', () => {
    expect(
      codeOf(() =>
        parseXfcc(`Hash=${HASH},Hash=${HASH},Hash=${HASH}`, { format: 'text', maxElements: 2 }),
      ),
    ).toBe('TOO_MANY_ELEMENTS');
    expect(codeOf(() => parseXfcc('[{"uri":["a:"]}]', TEXT))).toBe('MISSING_EQUALS');
    expect(codeOf(() => parseXfcc('URI=a:', { format: 'json' }))).toBe('INVALID_JSON');
    expect(
      parseXfcc(`Hash=${HASH}`, {
        format: 'text',
        maxLength: MAX_LENGTH_LIMIT,
        maxElements: MAX_ELEMENTS_LIMIT,
      }),
    ).toHaveLength(1);
  });

  it.each([
    { maxLength: 0 },
    { maxLength: -1 },
    { maxLength: 1.5 },
    { maxLength: Number.NaN },
    { maxLength: MAX_LENGTH_LIMIT + 1 },
    { maxElements: 0 },
    { maxElements: MAX_ELEMENTS_LIMIT + 1 },
    { maxElements: 2 ** 32 + 1 },
    { format: 'xml' },
    { format: 'auto' },
    { requireCertHash: 'yes' },
    { allowTextIssuer: 1 },
    { maxLength: '10' },
    { maxElement: 1 },
    { verifyHash: true },
    { require_cert_hash: true },
  ])('rejects invalid option %j', (option) => {
    // @ts-expect-error -- deliberately invalid at runtime
    expect(() => parseXfcc('URI=a:', { format: 'text', ...option })).toThrow(TypeError);
  });

  it.each(['text', 1, []])('rejects non-object options %j', (options) => {
    // @ts-expect-error -- deliberately invalid at runtime
    expect(() => parseXfcc('URI=a:', options)).toThrow(TypeError);
  });

  it('validates options even when the header is absent', () => {
    expect(() => parseXfcc(undefined, { format: 'text', maxLength: 0 })).toThrow(TypeError);
  });

  it.each([42, null, {}, [1], ['a', 2]])('throws TypeError for header %j', (header) => {
    // @ts-expect-error -- deliberately invalid at runtime
    expect(() => parseXfcc(header, TEXT)).toThrow(TypeError);
  });
});

describe('XfccError', () => {
  it('does not capture a stack trace and restores the limit', () => {
    const limit = Error.stackTraceLimit;
    const error = errorOf(() => parseXfcc('Foo=bar', TEXT));
    expect(error.stack).not.toMatch(/\n\s+at /);
    expect(Error.stackTraceLimit).toBe(limit);
  });
});

describe('parseDistinguishedName', () => {
  it('parses RDNs in string order with decoded values', () => {
    expect(
      parseDistinguishedName('CN=James \\"Jim\\" Smith\\, III,DC=example+DC=net,1.2.3=#04024869'),
    ).toEqual([
      [{ type: 'CN', value: 'James "Jim" Smith, III', encoding: 'string' }],
      [
        { type: 'DC', value: 'example', encoding: 'string' },
        { type: 'DC', value: 'net', encoding: 'string' },
      ],
      [{ type: '1.2.3', value: '04024869', encoding: 'hex' }],
    ]);
  });

  it('returns frozen results', () => {
    const rdns = parseDistinguishedName('CN=a');
    expect(Object.isFrozen(rdns)).toBe(true);
    expect(Object.isFrozen(rdns[0])).toBe(true);
    expect(Object.isFrozen(rdns[0]?.[0])).toBe(true);
  });

  it('parses an empty DN', () => {
    expect(parseDistinguishedName('')).toEqual([]);
  });

  it.each(['CN', 'CN=a;O=b', 'CN=a,', 'CN=a\\00'])('rejects %j', (dn) => {
    const error = errorOf(() => parseDistinguishedName(dn));
    expect(error.code).toBe('INVALID_DN');
    expect(typeof error.offset).toBe('number');
  });

  it('throws TypeError for non-strings', () => {
    // @ts-expect-error -- deliberately invalid at runtime
    expect(() => parseDistinguishedName(undefined)).toThrow(TypeError);
  });

  it.each([
    ['CN=\ud800', 3],
    ['CN=\udc00', 3],
    ['CN=a,O=\ud83d', 7],
    ['CN=😀\udc00', 7],
  ])('rejects the lone surrogate in %j at byte %i', (dn, offset) => {
    const error = errorOf(() => parseDistinguishedName(dn));
    expect(error.code).toBe('INVALID_DN');
    expect(error.offset).toBe(offset);
  });

  it('accepts a surrogate pair', () => {
    expect(parseDistinguishedName('CN=😀')[0]?.[0]?.value).toBe('😀');
  });

  it('rejects input over the byte limit', () => {
    const atLimit = `CN=${'a'.repeat(MAX_LENGTH_LIMIT - 3)}`;
    expect(parseDistinguishedName(atLimit)).toHaveLength(1);
    const error = errorOf(() => parseDistinguishedName(`${atLimit}a`));
    expect(error.code).toBe('TOO_LONG');
    expect(error.offset).toBe(MAX_LENGTH_LIMIT);
    // Under the limit in UTF-16 units, over it in UTF-8 bytes.
    expect(codeOf(() => parseDistinguishedName('é'.repeat(MAX_LENGTH_LIMIT / 2 + 1)))).toBe(
      'TOO_LONG',
    );
  });
});
