import { describe, expect, it } from 'vitest';

import {
  CA_PEM,
  CLIENT_PEM,
  CLIENT_SHA256,
  errorOf,
  HASH_A,
  HASH_B,
  NASTY_SUBJECT,
  urlEncode,
} from '../test/helpers.ts';

import { parseDistinguishedName, parseXfcc, type ParseOptions } from './index.ts';

// Several hops and a text-format Issuer, so the grammar tests see every key.
const TEXT = { format: 'text', maxElements: 32, allowTextIssuer: true } as const;
const JSON_FORMAT = { format: 'json', maxElements: 32 } as const;
const ONE_HOP = { format: 'text' } as const;

const code = (header: string, options: ParseOptions = TEXT) =>
  errorOf(() => parseXfcc(header, options)).code;
const codeJson = (header: string) => code(header, JSON_FORMAT);

const element = {
  by: [],
  hash: null,
  cert: null,
  presentedChain: [],
  subject: null,
  uri: [],
  dns: [],
  issuer: null,
};

const SUBJECT = 'CN=Test Client,OU=Lyft,L=San Francisco,ST=CA,C=US';

describe('Envoy documentation examples', () => {
  it('parses text example 1', () => {
    expect(
      parseXfcc(
        `By=http://frontend.lyft.com;Hash=${HASH_A};Subject="${SUBJECT}";URI=http://testclient.lyft.com`,
        TEXT,
      ),
    ).toEqual([
      {
        ...element,
        by: ['http://frontend.lyft.com'],
        hash: HASH_A,
        subject: SUBJECT,
        uri: ['http://testclient.lyft.com'],
      },
    ]);
  });

  it('parses text example 2', () => {
    expect(
      parseXfcc(
        `By=http://frontend.lyft.com;Hash=${HASH_A};URI=http://testclient.lyft.com,By=http://backend.lyft.com;Hash=${HASH_B};URI=http://frontend.lyft.com`,
        TEXT,
      ),
    ).toEqual([
      {
        ...element,
        by: ['http://frontend.lyft.com'],
        hash: HASH_A,
        uri: ['http://testclient.lyft.com'],
      },
      {
        ...element,
        by: ['http://backend.lyft.com'],
        hash: HASH_B,
        uri: ['http://frontend.lyft.com'],
      },
    ]);
  });

  it('parses JSON example 1', () => {
    expect(
      parseXfcc(
        `[{"by":["http://frontend.lyft.com"],"hash":"${HASH_A}","subject":"${SUBJECT}","uri":["http://testclient.lyft.com"],"dns":["lyft.com","www.lyft.com"]}]`,
        JSON_FORMAT,
      ),
    ).toEqual([
      {
        ...element,
        by: ['http://frontend.lyft.com'],
        hash: HASH_A,
        subject: SUBJECT,
        uri: ['http://testclient.lyft.com'],
        dns: ['lyft.com', 'www.lyft.com'],
      },
    ]);
  });

  it('rejects JSON example 2 verbatim, which abbreviates its digests', () => {
    expect(
      codeJson(
        '[{"by":["http://frontend.lyft.com"],"hash":"468ed33be74eee6556d90c0149c1309e","uri":["http://testclient.lyft.com"]}]',
      ),
    ).toBe('INVALID_HASH');
  });
});

describe('text format as Envoy writes it', () => {
  it('accepts an empty URI, Subject and Issuer', () => {
    expect(parseXfcc(`Hash=${HASH_A};Subject="";URI=;Issuer=""`, TEXT)).toEqual([
      { ...element, hash: HASH_A, subject: '', issuer: '' },
    ]);
  });

  it('requires quoting to match Envoy', () => {
    const cert = urlEncode(CLIENT_PEM);
    expect(code(`Hash=${CLIENT_SHA256};Cert=${cert}`)).toBe('INVALID_QUOTING');
    expect(code(`Hash=${CLIENT_SHA256};Chain=${cert}`)).toBe('INVALID_QUOTING');
    for (const quoted of [
      `By="http://x";Hash=${HASH_A}`,
      `Hash="${HASH_A}"`,
      `Hash=${HASH_A};URI="http://x"`,
      `Hash=${HASH_A};DNS="lyft.com"`,
    ]) {
      expect(code(quoted)).toBe('INVALID_QUOTING');
    }
  });

  it('rejects a backslash in a quoted Cert or Chain', () => {
    expect(code('Cert="a\\b"')).toBe('INVALID_ESCAPE');
    expect(code('Chain="a\\b"')).toBe('INVALID_ESCAPE');
  });

  it('allows an unquoted = in a URI', () => {
    const [parsed] = parseXfcc(`By=http://y/?k==v;Hash=${HASH_A};URI=http://x/?a=b&c=d`, TEXT);
    expect(parsed?.uri).toEqual(['http://x/?a=b&c=d']);
    expect(parsed?.by).toEqual(['http://y/?k==v']);
  });

  it('matches keys case-insensitively, but not values', () => {
    const [parsed] = parseXfcc(
      `by=http://A;HASH=${HASH_A};sUbJeCt="CN=X";uRi=http://B;dns=Lyft.Com`,
      TEXT,
    );
    expect(parsed?.by).toEqual(['http://A']);
    expect(parsed?.dns).toEqual(['Lyft.Com']);
    expect(parsed?.subject).toBe('CN=X');
  });

  it('does not treat object members as keys', () => {
    for (const key of ['constructor', '__proto__', 'toString', 'hasOwnProperty']) {
      expect(code(`${key}=x`)).toBe('UNKNOWN_KEY');
    }
  });

  it('allows optional whitespace around commas', () => {
    const elements = parseXfcc(
      ` Hash=${HASH_A} , Hash=${HASH_A},\tHash=${HASH_A};URI=http://c `,
      TEXT,
    );
    expect(elements).toHaveLength(3);
    expect(elements[2]?.uri).toEqual(['http://c']);
    expect(
      parseXfcc(`Hash=${HASH_A};Subject="CN=a" , Hash=${HASH_A};Subject="CN=b"`, TEXT)[1]?.subject,
    ).toBe('CN=b');
  });
});

describe('DN injection', () => {
  it('keeps RFC 4514 escapes verbatim', () => {
    expect(NASTY_SUBJECT).toMatch(/\\".*\\\\/);
    const [parsed] = parseXfcc(
      `Hash=${HASH_A};Subject="${NASTY_SUBJECT}";URI=spiffe://cluster.local/ns/default/sa/nasty`,
      TEXT,
    );
    expect(parsed?.subject).toBe(NASTY_SUBJECT);
    expect(parseDistinguishedName(NASTY_SUBJECT)[1]?.[1]?.value).toBe('evil,O=Admin');
  });

  it('handles a trailing escaped backslash', () => {
    const [parsed] = parseXfcc(`Hash=${HASH_A};Subject="CN=a\\\\";URI=http://x`, TEXT);
    expect(parsed?.subject).toBe('CN=a\\\\');
    expect(parsed?.uri).toEqual(['http://x']);
  });

  it('cannot be broken out of with an escaped quote', () => {
    // `\"` keeps the string open, so the injected `;URI=` stays inside the DN,
    // which is then rejected as an invalid DN (an unescaped `;`).
    expect(code(`Hash=${HASH_A};Subject="CN=a\\";URI=http://admin"`)).toBe('INVALID_DN');
    expect(code('Subject="CN=a\\"')).toBe('UNTERMINATED_QUOTE');
    expect(code('Subject="CN=a\\')).toBe('UNTERMINATED_QUOTE');
  });

  it('rejects a raw tab or control character, in both formats', () => {
    expect(code(`Hash=${HASH_A};Subject="CN=ad\tmin,O=Lyft"`)).toBe('INVALID_CHAR');
    expect(code(`Hash=${HASH_A};Issuer="CN=a\tb"`)).toBe('INVALID_CHAR');
    expect(codeJson(`[{"hash":"${HASH_A}","subject":"CN=ad\\tmin"}]`)).toBe('INVALID_CHAR');
    expect(parseXfcc(`Hash=${HASH_A};Subject="CN=ad\\09min"`, TEXT)[0]?.subject).toBe(
      'CN=ad\\09min',
    );
  });
});

describe('SAN injection', () => {
  it('rejects a SAN that breaks the key order or omits Hash', () => {
    expect(
      code(`By=spiffe://p;Hash=${HASH_A};URI=spiffe://legit;DNS=a.com;URI=spiffe://admin`),
    ).toBe('KEY_ORDER');
    expect(code(`By=spiffe://p;Hash=${HASH_A};URI=spiffe://x,URI=spiffe://admin`)).toBe(
      'MISSING_HASH',
    );
    expect(code(`URI=spiffe://x;Hash=${HASH_A}`)).toBe('KEY_ORDER');
  });

  it('rejects an empty URI beside another URI pair', () => {
    expect(code(`By=spiffe://p;Hash=${HASH_A};URI=spiffe://td/admin;URI=`)).toBe('DUPLICATE_KEY');
    expect(code(`Hash=${HASH_A};URI=;URI=spiffe://td/admin`)).toBe('DUPLICATE_KEY');
    expect(code(`Hash=${HASH_A};URI=;URI=`)).toBe('DUPLICATE_KEY');
    expect(code(`Hash=${HASH_A};URI=spiffe://td/admin;URI=;DNS=a.com`)).toBe('DUPLICATE_KEY');
  });

  it('cannot tell a crafted SAN from extra SANs', () => {
    // Nothing can reject these; consumers must require exactly one SAN.
    expect(
      parseXfcc(`By=spiffe://p;Hash=${HASH_A};URI=spiffe://td/x;URI=spiffe://td/admin`, TEXT)[0]
        ?.uri,
    ).toEqual(['spiffe://td/x', 'spiffe://td/admin']);
    expect(
      parseXfcc(`By=spiffe://p;Hash=${HASH_A};URI=;DNS=a.com;DNS=admin.internal`, TEXT)[0]?.dns,
    ).toEqual(['a.com', 'admin.internal']);
    const [cross] = parseXfcc(
      `By=spiffe://p;Hash=${HASH_A};URI=https://x.example/;DNS=admin.internal`,
      ONE_HOP,
    );
    expect(cross?.uri).toEqual(['https://x.example/']);
    expect(cross?.dns).toEqual(['admin.internal']);
  });

  it('returns a text-format Issuer only when asked', () => {
    const issuer = `By=spiffe://p;Hash=${HASH_A};URI=spiffe://td/x;Issuer="CN=Trusted Root CA"`;
    expect(parseXfcc(issuer, TEXT)[0]?.issuer).toBe('CN=Trusted Root CA');
    expect(parseXfcc(issuer, ONE_HOP)[0]?.issuer).toBeNull();
    expect(code(`Hash=${HASH_A};Issuer="CN"`, ONE_HOP)).toBe('INVALID_DN');
    expect(parseXfcc('[{"issuer":"CN=CA"}]', { format: 'json' })[0]?.issuer).toBe('CN=CA');
  });

  it('only maxElements stops a forged element', () => {
    const forged = `By=spiffe://p;Hash=${HASH_A};URI=spiffe://td/x,By=spiffe://p;Hash=${HASH_B};URI=spiffe://td/admin`;
    expect(parseXfcc(forged, TEXT)[1]?.uri).toEqual(['spiffe://td/admin']);
    expect(code(forged, ONE_HOP)).toBe('TOO_MANY_ELEMENTS');

    // A SAN that may contain `"` can carry any public certificate with its hash.
    const cert = urlEncode(CLIENT_PEM);
    const real = `By=spiffe://p;Hash=${CLIENT_SHA256};Cert="${cert}";URI=spiffe://td/x`;
    const quoted = `${real},By=spiffe://p;Hash=${CLIENT_SHA256};Cert="${cert}";URI=spiffe://td/admin`;
    expect(parseXfcc(quoted, TEXT)[1]?.uri).toEqual(['spiffe://td/admin']);
    expect(code(quoted, ONE_HOP)).toBe('TOO_MANY_ELEMENTS');
  });

  it('parses a text header crafted to look like JSON as text', () => {
    expect(
      code(
        `[{"uri":["spiffe://x/,By=spiffe://test/proxy;Hash=${HASH_A};URI=a"]},{"uri":["spiffe://test/victim"]}]`,
      ),
    ).toBe('MISSING_EQUALS');
  });

  it('rejects a JSON string that swallows an Envoy text append', () => {
    const tail = `,By=spiffe://td/gw;Hash=${HASH_A};URI=x`;
    expect(codeJson(`[{"uri":["a:${tail}"]},{"uri":["spiffe://td/admin"]}]`)).toBe('INVALID_URI');
    expect(
      code(`[{"by":["a:${tail}"],"uri":["spiffe://td/ns/admin/sa/root"]}]`, { format: 'json' }),
    ).toBe('INVALID_URI');
    expect(codeJson(`[{"uri":["a:,Hash=${HASH_A};URI=x","spiffe://td/admin"]}]`)).toBe(
      'INVALID_URI',
    );
  });
});

describe('text format rejections', () => {
  it.each([
    ['', 'EMPTY'],
    ['  \t ', 'EMPTY'],
    [',', 'EMPTY_ELEMENT'],
    [`Hash=${HASH_A};URI=http://a,`, 'EMPTY_ELEMENT'],
    [',URI=http://a', 'EMPTY_ELEMENT'],
    [`Hash=${HASH_A};URI=http://a,,URI=http://b`, 'EMPTY_ELEMENT'],
    [`Hash=${HASH_A};URI=http://a, ,URI=http://b`, 'EMPTY_ELEMENT'],
    ['URI=http://a;', 'EMPTY_PAIR'],
    ['URI=http://a;;URI=http://b', 'EMPTY_PAIR'],
    ['URI=http://a;,URI=http://b', 'EMPTY_PAIR'],
    [';URI=http://a', 'MISSING_EQUALS'],
    ['URI', 'MISSING_EQUALS'],
    ['URI=http://a;DNS', 'MISSING_EQUALS'],
    ['=http://a', 'UNKNOWN_KEY'],
    ['Foo=bar', 'UNKNOWN_KEY'],
    [' URI =http://a', 'UNKNOWN_KEY'],
    ['URI=http://a; DNS=lyft.com', 'UNKNOWN_KEY'],
    ['URI=http://a ;DNS=lyft.com', 'UNEXPECTED_AFTER_VALUE'],
    ['URI= http://a', 'UNEXPECTED_AFTER_VALUE'],
    ['URI=http://a b', 'UNEXPECTED_AFTER_VALUE'],
    ['Subject=CN=a', 'INVALID_QUOTING'],
    ['Issuer=CN=a', 'INVALID_QUOTING'],
    ['Subject="CN=a', 'UNTERMINATED_QUOTE'],
    ['Subject="CN=a"x', 'UNEXPECTED_AFTER_VALUE'],
    ['Subject="CN=a""', 'UNEXPECTED_AFTER_VALUE'],
    ['Subject="CN=a" ;URI=http://b', 'UNEXPECTED_AFTER_VALUE'],
    ['URI=http://a"b', 'INVALID_ESCAPE'],
    ['URI=http://a\\b', 'INVALID_ESCAPE'],
    ['URI="http://a\\"b"', 'INVALID_QUOTING'],
    ['By=', 'EMPTY_VALUE'],
    ['DNS=', 'EMPTY_VALUE'],
    ['Hash=', 'EMPTY_VALUE'],
    ['Cert=', 'INVALID_QUOTING'],
    ['Cert=""', 'EMPTY_VALUE'],
    ['Chain=""', 'EMPTY_VALUE'],
    ['Hash=abc', 'INVALID_HASH'],
    ['URI=relative/path', 'INVALID_URI'],
    ['By=relative', 'INVALID_URI'],
    ['DNS=-bad.com', 'INVALID_DNS'],
    ['DNS=*.*.com', 'INVALID_DNS'],
    ['Subject="CN=a;O=b"', 'INVALID_DN'],
    ['Subject="not a dn"', 'INVALID_DN'],
    ['Cert="%ZZ"', 'INVALID_PERCENT_ENCODING'],
    ['Cert="abc+def"', 'INVALID_PERCENT_ENCODING'],
    ['Chain="%ZZ"', 'INVALID_PERCENT_ENCODING'],
    ['Cert="abc"', 'INVALID_PEM'],
    ['Chain="abc"', 'INVALID_PEM'],
  ] as const)('rejects %j with %s', (header, expected) => {
    expect(code(header)).toBe(expected);
  });

  it('rejects duplicate single-valued keys', () => {
    const cert = urlEncode(CLIENT_PEM);
    for (const header of [
      `Hash=${HASH_A};Hash=${HASH_A}`,
      `Hash=${HASH_A};hash=${HASH_B}`,
      'Subject="CN=a";Subject="CN=a"',
      'Issuer="CN=a";ISSUER="CN=b"',
      `Cert="${cert}";Cert="${cert}"`,
      `Chain="${cert}";Chain="${cert}"`,
    ]) {
      expect(code(header)).toBe('DUPLICATE_KEY');
    }
    expect(parseXfcc(`Hash=${HASH_A},Hash=${HASH_A}`, TEXT)).toHaveLength(2);
  });

  it.each([
    ['URI=http://a\n', 12],
    ['URI=http://a\r\n', 12],
    ['URI=\0', 4],
    ['URI=http://é', 11],
    ['\x7f', 0],
  ])('rejects the character in %j at byte %i', (header, offset) => {
    const error = errorOf(() => parseXfcc(header, TEXT));
    expect(error.code).toBe('INVALID_CHAR');
    expect(error.offset).toBe(offset);
  });

  it('treats a trailing comma as an empty element at any cap', () => {
    for (const maxElements of [1, 2]) {
      expect(code(`Hash=${HASH_A},`, { format: 'text', maxElements })).toBe('EMPTY_ELEMENT');
    }
  });

  it('points offsets at the problem', () => {
    expect(errorOf(() => parseXfcc('URI=http://a;Foo=x', TEXT)).offset).toBe(13);
    const error = errorOf(() => parseXfcc(`Hash=${HASH_A},Hash=zz`, TEXT));
    expect(error.code).toBe('INVALID_HASH');
    expect(error.offset).toBe(75);
  });
});

describe('Cert and Chain', () => {
  const cert = urlEncode(CLIENT_PEM);

  it('decodes Cert and Chain', () => {
    const header = `By=spiffe://mesh/proxy;Hash=${CLIENT_SHA256};Cert="${cert}";Chain="${urlEncode(`${CLIENT_PEM}${CA_PEM}`)}"`;
    const [parsed] = parseXfcc(header, TEXT);
    expect(parsed?.cert).toBe(CLIENT_PEM);
    expect(parsed?.presentedChain).toEqual([CLIENT_PEM, CA_PEM]);
    expect(code(`Cert="${cert}"`)).toBe('MISSING_HASH');
  });

  it('does not compare Hash with Cert', () => {
    // Anyone able to forge an element can make the two agree, so the parser
    // does not pretend a match proves anything.
    expect(parseXfcc(`Hash=${HASH_A};Cert="${cert}"`, TEXT)[0]?.cert).toBe(CLIENT_PEM);
    const certJson = JSON.stringify(CLIENT_PEM);
    expect(parseXfcc(`[{"hash":"${HASH_A}","cert":${certJson}}]`, JSON_FORMAT)[0]?.cert).toBe(
      CLIENT_PEM,
    );
  });
});

describe('JSON format', () => {
  it('parses Cert, Chain, Subject and Issuer', () => {
    const header = `[{"hash":"${CLIENT_SHA256}","cert":${JSON.stringify(CLIENT_PEM)},"chain":${JSON.stringify([CLIENT_PEM, CA_PEM])},"subject":${JSON.stringify(NASTY_SUBJECT)},"issuer":"CN=Test CA,O=Lyft,C=US"}]`;
    const [parsed] = parseXfcc(header, JSON_FORMAT);
    expect(parsed?.cert).toBe(CLIENT_PEM);
    expect(parsed?.presentedChain).toEqual([CLIENT_PEM, CA_PEM]);
    expect(parsed?.subject).toBe(NASTY_SUBJECT);
    expect(parsed?.issuer).toBe('CN=Test CA,O=Lyft,C=US');
  });

  it.each([
    ['[]', 'EMPTY'],
    ['[ ] ', 'EMPTY'],
    ['[{"uri":[]}]', 'EMPTY_VALUE'],
    ['[{"subject":""}]', 'EMPTY_VALUE'],
    ['[{"hash":""}]', 'EMPTY_VALUE'],
    ['[{"uri":[""]}]', 'EMPTY_VALUE'],
    ['[{"uri":["a:\\u0000"]}]', 'INVALID_URI'],
    ['[{"dns":["lyft.com\\u002c"]}]', 'INVALID_DNS'],
    ['[{"subject":"CN=a\\u0000"}]', 'INVALID_CHAR'],
    ['[{"subject":"CN=a\\nb"}]', 'INVALID_CHAR'],
    ['[{"issuer":"CN=a\\u202eb"}]', 'INVALID_CHAR'],
    ['[{"cert":"x"}]', 'INVALID_PEM'],
    ['[{"chain":["x"]}]', 'INVALID_PEM'],
  ] as const)('rejects %j with %s', (header, expected) => {
    expect(codeJson(header)).toBe(expected);
  });

  it.each([
    ['[1]', 1],
    ['[null]', 1],
    ['[', 1],
    ['[{]', 2],
    ['[{}', 2],
    ['[{"uri":["a:b"]}', 16],
    ['{"uri":["a:b"]}', 0],
    ['URI=a:', 0],
    ['[{"uri":["a:b"]}]x', 17],
    ['[{"uri":["a:b"]}],[{"uri":["b:"]}]', 17],
    ['[{"uri":["a:b"],}]', 16],
    ['[{"uri":["a:b"]},]', 17],
    ['[{"uri":["a:b",]}]', 15],
    ['[{"uri":["a:b"] "dns":[]}]', 16],
    ['[{"by":["a:b"]} {}]', 16],
    ['[{"URI":["a:"]}]', 2],
    ['[{"foo":"x"}]', 2],
    ['[{"__proto__":["a:b"]}]', 2],
    ['[{"constructor":"x"}]', 2],
    ['[{"toString":["a:b"]}]', 2],
    ['[{"uri":["a:b"],"uri":["c:d"]}]', 16],
    ['[{"hash":"a","hash":"b"}]', 13],
    ['[{"uri":null}]', 8],
    ['[{"uri":1}]', 8],
    ['[{"uri":[null]}]', 9],
    ['[{"uri":"a:"}]', 8],
    ['[{"hash":["x"]}]', 9],
    ['[{"uri" ["a:b"]}]', 8],
    ['[{uri:[]}]', 2],
    ['[{"uri', 6],
    ['[{"uri":["a\tb"]}]', 11],
    ['[{"uri":["\\x"]}]', 11],
    ['[{"uri":["\\', 11],
    ['[{"uri":["\\u12"]}]', 14],
    ['[{"uri":["\\u12G4"]}]', 14],
    ['[{"uri":["\\ud800"]}]', 16],
    ['[{"uri":["\\udc00"]}]', 16],
    ['[{"uri":["\\ud83dx"]}]', 16],
    ['[{"uri":["\\ud83d\\u0041"]}]', 22],
    ['[{"uri":["\\ud83d\\uZZZZ"]}]', 18],
    // An array is not a shape Envoy writes, whatever its contents.
    ['[[]]', 1],
    ['[["a:b"]]', 1],
    ['[{"by":["a:b"]},[]]', 16],
    // Envoy omits an element's empty fields, but never writes an empty element.
    ['[{}]', 2],
    ['[{ }]', 3],
    // Nor does it escape a key.
    ['[{"h\\u0061sh":"x"}]', 2],
    ['[{"ur\\u0069":["a:b"]}]', 2],
  ])('rejects %j as INVALID_JSON at byte %i', (header, offset) => {
    const error = errorOf(() => parseXfcc(header, JSON_FORMAT));
    expect(error.code).toBe('INVALID_JSON');
    expect(error.offset).toBe(offset);
  });

  it('allows insignificant whitespace', () => {
    expect(
      parseXfcc(' [ { "uri" : [ "a:a" , "b:b" ] , "by" : [ "c:c" ] } ]\t', JSON_FORMAT)[0]?.by,
    ).toEqual(['c:c']);
    expect(codeJson('[ { "uri" : [ ] } ]')).toBe('EMPTY_VALUE');
    expect(
      parseXfcc(' [ { "uri" : [ "a:a" ] } , { "by" : [ "b:b" ] } ]\t', JSON_FORMAT)[0]?.uri,
    ).toEqual(['a:a']);
  });

  it('decodes every string escape', () => {
    expect(parseXfcc('[{"uri":["a:\\/\\u0062"]}]', JSON_FORMAT)[0]?.uri).toEqual(['a:/b']);
    expect(parseXfcc(String.raw`[{"subject":"CN=a\\,O=b"}]`, JSON_FORMAT)[0]?.subject).toBe(
      'CN=a\\,O=b',
    );
    for (const escape of ['\\"', '\\b', '\\f', '\\n', '\\r', '\\t', '\\ud83d\\ude00']) {
      expect(codeJson(`[{"uri":["a:${escape}"]}]`)).toBe('INVALID_URI');
    }
  });

  it('requires non-ASCII to be escaped, then validates it', () => {
    expect(codeJson('[{"subject":"CN=é"}]')).toBe('INVALID_CHAR');
    expect(codeJson('[{"subject":"CN=caf\\u00e9"}]')).toBe('INVALID_CHAR');
    expect(codeJson('[{"subject":"CN=a\\u2062b"}]')).toBe('INVALID_CHAR');
    expect(parseXfcc('[{"subject":"CN=caf\\\\C3\\\\A9"}]', JSON_FORMAT)[0]?.subject).toBe(
      'CN=caf\\C3\\A9',
    );
    expect(codeJson('[{"uri":["http://caf\\u00e9"]}]')).toBe('INVALID_URI');
  });

  it('requires each chain entry to be one certificate', () => {
    expect(codeJson(`[{"chain":${JSON.stringify([`${CLIENT_PEM}${CA_PEM}`])}}]`)).toBe(
      'INVALID_PEM',
    );
  });

  it.each(['\\u2028', '\\u2029', '\\u200b', '\\u200d', '\\u2060', '\\ufeff', '\\u00a0', '\\u00ad'])(
    'rejects %s in a DN',
    (character) => {
      expect(codeJson(`[{"subject":"CN=a${character}b"}]`)).toBe('INVALID_CHAR');
    },
  );

  it('finds shape errors in every element before validating any value', () => {
    expect(codeJson('[{"uri":["bad"]},{"foo":1}]')).toBe('INVALID_JSON');
  });

  it('validates values in a fixed order, not the order written', () => {
    const fields = [
      ['"by":["bad"]', 'INVALID_URI'],
      ['"chain":["x"]', 'INVALID_PEM'],
      ['"uri":["bad"]', 'INVALID_URI'],
      ['"dns":["-"]', 'INVALID_DNS'],
      ['"hash":"x"', 'INVALID_HASH'],
      ['"cert":"x"', 'INVALID_PEM'],
      ['"subject":"x"', 'INVALID_DN'],
      ['"issuer":"x"', 'INVALID_DN'],
    ] as const;
    for (const [i, [, expected]] of fields.entries()) {
      const rest = fields.slice(i).map(([field]) => field);
      expect(codeJson(`[{${rest.toReversed().join(',')}}]`)).toBe(expected);
    }
  });

  describe('a surplus element', () => {
    const ONE = { format: 'json' } as const;

    const E = '{"by":["a:b"]}';

    it.each([`[${E},${E}]`, `[${E},{"x":1}]`, `[${E},x]`, `[${E},[]]`, `[${E}, 1e`])(
      'reports %j as TOO_MANY_ELEMENTS at the surplus element',
      (header) => {
        const error = errorOf(() => parseXfcc(header, ONE));
        expect(error.code).toBe('TOO_MANY_ELEMENTS');
        expect(error.offset).toBe(header.indexOf(E) + E.length + (header.includes(', ') ? 2 : 1));
      },
    );

    it.each([`[${E},]`, `[${E}, ]`, `[${E},`])(
      'does not count the trailing comma in %j',
      (header) => {
        expect(code(header, ONE)).toBe('INVALID_JSON');
      },
    );

    it('accepts exactly the cap', () => {
      expect(parseXfcc(`[${E},${E}]`, { format: 'json', maxElements: 2 })).toHaveLength(2);
    });
  });
});
