// Inputs for `parse.bench.ts`. The 1 MiB cases are the worst the size limits
// allow, and are here to catch anything that is not linear in the input.
import { readFileSync } from 'node:fs';

import type { ParseOptions } from '../dist/index.mjs';

const fixture = (name: string) =>
  readFileSync(new URL(`../test/fixtures/${name}`, import.meta.url), 'utf8');

const CLIENT_PEM = fixture('client.pem');
const CA_PEM = fixture('ca.pem');
const CLIENT_SHA256 = fixture('client.sha256').trim();
const LIMIT = 1 << 20;

const hashA = '468ed33be74eee6556d90c0149c1309e9ba61d6425303443c0748a02dd8de688';
const hashB = '9ba61d6425303443c0748a02dd8de688468ed33be74eee6556d90c0149c1309e';

const urlEncode = (value: string) =>
  [...Buffer.from(value, 'utf8')]
    .map((byte) =>
      /[A-Za-z0-9*._-]/.test(String.fromCodePoint(byte))
        ? String.fromCodePoint(byte)
        : `%${byte.toString(16).toUpperCase().padStart(2, '0')}`,
    )
    .join('');

const TEXT = { format: 'text' } as const;
const JSON_FORMAT = { format: 'json' } as const;
const LARGE = { format: 'text', maxLength: LIMIT } as const;
const LARGE_JSON = { format: 'json', maxLength: LIMIT } as const;

const cert = `Hash=${CLIENT_SHA256};Cert="${urlEncode(CLIENT_PEM)}";Chain="${urlEncode(`${CLIENT_PEM}${CA_PEM}`)}"`;

/** Repeats `unit` until `prefix` + repeats + `suffix` is just under the limit. */
const fill = (prefix: string, unit: string, suffix: string) =>
  `${prefix}${unit.repeat(Math.floor((LIMIT - prefix.length - suffix.length) / unit.length))}${suffix}`;

export const HEADER_CASES: readonly (readonly [string, string, ParseOptions])[] = [
  [
    'text, single element',
    `By=http://frontend.lyft.com;Hash=${hashA};Subject="CN=Test Client,OU=Lyft,L=San Francisco,ST=CA,C=US";URI=http://testclient.lyft.com`,
    TEXT,
  ],
  [
    'text, two elements',
    `By=http://frontend.lyft.com;Hash=${hashA};URI=http://testclient.lyft.com,By=http://backend.lyft.com;Hash=${hashB};URI=http://frontend.lyft.com`,
    { format: 'text', maxElements: 2 },
  ],
  [
    'json',
    `[{"by":["http://frontend.lyft.com"],"hash":"${hashA}","uri":["http://testclient.lyft.com"],"dns":["lyft.com","www.lyft.com"]}]`,
    JSON_FORMAT,
  ],
  ['text, Cert and Chain', cert, TEXT],
  ['reject, unknown key', 'Foo=bar', TEXT],
  ['reject, invalid character', `Hash=${hashA};URI=http://a\n`, TEXT],
  ['reject, too long', 'a'.repeat(64 * 1024 + 1), TEXT],
  ['1 MiB, long URI', fill(`Hash=${hashA};URI=a:`, 'a', ''), LARGE],
  ['1 MiB, percent-encoded URI', fill(`Hash=${hashA};URI=a:`, '%41', ''), LARGE],
  ['1 MiB, many colons in an authority', fill(`Hash=${hashA};URI=a://`, ':', ''), LARGE],
  ['1 MiB, unterminated quote', fill(`Hash=${hashA};Subject="`, '\\"', ''), LARGE],
  ['1 MiB, percent-encoded Cert', fill(`Hash=${hashA};Cert="`, '%41', '"'), LARGE],
  ['1 MiB, Subject of escapes', fill(`Hash=${hashA};Subject="CN=`, '\\,', '"'), LARGE],
  ['1 MiB, many DNS pairs', fill(`Hash=${hashA}`, ';DNS=a.b', ''), LARGE],
  ['1 MiB, JSON escapes', fill('[{"uri":["a:', '\\u0061', '"]}]'), LARGE_JSON],
  ['1 MiB, JSON list', fill('[{"dns":["a.b"', ',"a.b"', ']}]'), LARGE_JSON],
  ['1 MiB, whitespace', fill('', ' ', 'x'), LARGE],
];

const nasty = fixture('nasty.subject').trimEnd();

export const DN_CASES: readonly (readonly [string, string])[] = [
  ['simple', 'CN=Test Client,OU=Lyft,L=San Francisco,ST=CA,C=US'],
  ['escapes and a multi-valued RDN', nasty],
  ['1 MiB, escapes', fill('CN=', '\\,', '')],
  ['1 MiB, many RDNs', fill('', 'C=a,', 'C=a')],
  ['1 MiB, non-ASCII', `CN=${'é'.repeat(LIMIT / 2 - 2)}`],
];
