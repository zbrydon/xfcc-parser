// Checks the built package works, since the tests import from `src/`.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { getPeerSpiffeId, parseDistinguishedName, parseXfcc, XfccError } from '../dist/index.mjs';

const hash = '468ed33be74eee6556d90c0149c1309e9ba61d6425303443c0748a02dd8de688';

assert.deepEqual(parseXfcc(`Hash=${hash};URI=spiffe://a/b`, { format: 'text' })[0]?.uri, [
  'spiffe://a/b',
]);
assert.deepEqual(parseXfcc('[{"uri":["spiffe://a/b"]}]', { format: 'json' })[0]?.uri, [
  'spiffe://a/b',
]);
assert.throws(() => parseXfcc('Foo=bar', { format: 'text' }), XfccError);
assert.equal(parseDistinguishedName('CN=a,O=b').length, 2);
assert.equal(getPeerSpiffeId(`Hash=${hash};URI=spiffe://a/b`, { format: 'text' }).trustDomain, 'a');

// A real certificate and its digest, which goes through `node:crypto` in the bundle.
const fixture = (name: string) =>
  readFileSync(new URL(`../test/fixtures/${name}`, import.meta.url), 'utf8');
const header = `[{"hash":"${fixture('client.sha256').trim()}","cert":${JSON.stringify(fixture('client.pem'))}}]`;
assert.equal(parseXfcc(header, { format: 'json', requireCertHash: true }).length, 1);
assert.throws(
  () => parseXfcc(header.replace(/"hash":"./, '"hash":"x'), { format: 'json' }),
  XfccError,
);
