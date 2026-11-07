import { describe, expect, it } from 'vitest';

import {
  getPeerSpiffeId,
  SpiffeError,
  XfccError,
  type PeerSpiffeIdOptions,
  type SpiffeErrorCode,
} from './index.ts';

const HASH = '468ed33be74eee6556d90c0149c1309e9ba61d6425303443c0748a02dd8de688';
const API = 'spiffe://cluster.local/ns/payments/sa/api';

const TEXT = { format: 'text' } as const;
const JSON_FORMAT = { format: 'json' } as const;

const json = (...uris: string[][]) => JSON.stringify(uris.map((uri) => ({ hash: HASH, uri })));

const errorOf = (fn: () => unknown): SpiffeError | XfccError => {
  try {
    fn();
  } catch (error) {
    if (error instanceof SpiffeError || error instanceof XfccError) {
      return error;
    }
    throw error;
  }
  throw new Error('expected an error');
};

const codeOf = (fn: () => unknown): string => errorOf(fn).code;

/** The peer of a one-element header whose client certificate has `uri` as its URI SANs. */
const peerOf = (...uri: string[]) =>
  uri.length === 0
    ? getPeerSpiffeId(`Hash=${HASH}`, TEXT)
    : getPeerSpiffeId(json(uri), JSON_FORMAT);

describe('getPeerSpiffeId', () => {
  it('splits an Istio ID', () => {
    expect(getPeerSpiffeId(json([API]), { format: 'json' })).toEqual({
      id: API,
      trustDomain: 'cluster.local',
      path: '/ns/payments/sa/api',
      namespace: 'payments',
      serviceAccount: 'api',
    });
  });

  it('works with the text format', () => {
    expect(getPeerSpiffeId(`Hash=${HASH};URI=${API}`, TEXT).trustDomain).toBe('cluster.local');
  });

  it('leaves namespace and service account null for other paths', () => {
    const id = getPeerSpiffeId(json(['spiffe://td/workload/billing']), { format: 'json' });
    expect(id.path).toBe('/workload/billing');
    expect(id.namespace).toBeNull();
    expect(id.serviceAccount).toBeNull();
    expect(peerOf('spiffe://td/ns/a/sa/b/extra').namespace).toBeNull();
  });

  it('uses the last element', () => {
    const header = json(['spiffe://td/ns/client/sa/x'], [API]);
    expect(getPeerSpiffeId(header, { format: 'json', maxElements: 2 }).id).toBe(API);
  });

  const defaults: PeerSpiffeIdOptions[] = [
    TEXT,
    { format: 'text', requireSingleSan: true },
    // @ts-expect-error -- an explicit undefined, possible from plain JavaScript
    { format: 'text', maxElements: undefined },
  ];
  it.each(defaults)('defaults maxElements to 1 with options %j', (options) => {
    const header = `Hash=${HASH};URI=spiffe://td/a,Hash=${HASH};URI=${API}`;
    expect(codeOf(() => getPeerSpiffeId(header, options))).toBe('TOO_MANY_ELEMENTS');
  });

  it.each([undefined, null, {}, { requireSingleSan: true }])(
    'requires format with options %j',
    (options) => {
      // @ts-expect-error -- deliberately invalid at runtime
      expect(codeOf(() => getPeerSpiffeId(`Hash=${HASH};URI=${API}`, options))).toBe(
        'INVALID_OPTION',
      );
    },
  );

  it('rejects an element forged by a crafted text-format URI SAN by default', () => {
    // One URI SAN `https://attacker.example/x,By=..;Hash=..;URI=<admin>` is a
    // valid RFC 3986 URI, not a SPIFFE ID, and forges a clean last element.
    const proxy = 'spiffe://cluster.local/ns/gw/sa/envoy';
    const admin = 'spiffe://cluster.local/ns/admin/sa/root';
    const header = `By=${proxy};Hash=${HASH};URI=https://attacker.example/x,By=${proxy};Hash=${HASH};URI=${admin}`;
    expect(codeOf(() => getPeerSpiffeId(header, TEXT))).toBe('TOO_MANY_ELEMENTS');
    // A maxElements above the real hop count lets it through.
    expect(getPeerSpiffeId(header, { format: 'text', maxElements: 2 }).id).toBe(admin);
  });

  it('rejects a JSON string that swallows an Envoy text append', () => {
    const tail = `,By=spiffe://cluster.local/ns/gw/sa/envoy;Hash=${HASH};URI=x`;
    const header = `[{"by":["a:${tail}"],"uri":["spiffe://cluster.local/ns/admin/sa/root"]}]`;
    expect(codeOf(() => getPeerSpiffeId(header, { format: 'json' }))).toBe('INVALID_URI');
  });

  it('freezes its result', () => {
    expect(Object.isFrozen(getPeerSpiffeId(json([API]), { format: 'json' }))).toBe(true);
  });

  it('rejects an absent header', () => {
    expect(codeOf(() => getPeerSpiffeId(undefined, TEXT))).toBe('NO_PEER');
  });

  it('rejects a malformed header with the XfccError', () => {
    expect(codeOf(() => getPeerSpiffeId('nonsense', TEXT))).toBe('MISSING_EQUALS');
  });

  it('rejects a header with more elements than maxElements', () => {
    expect(
      codeOf(() => getPeerSpiffeId(json([API], [API]), { format: 'json', maxElements: 1 })),
    ).toBe('TOO_MANY_ELEMENTS');
  });

  it('rejects a smuggled second URI in the text format', () => {
    const header = `Hash=${HASH};URI=spiffe://td/x;URI=spiffe://td/admin`;
    expect(codeOf(() => getPeerSpiffeId(header, TEXT))).toBe('NOT_ONE_URI');
  });

  it('rejects a smuggled empty URI in the text format', () => {
    const header = `Hash=${HASH};URI=spiffe://td/admin;URI=`;
    expect(codeOf(() => getPeerSpiffeId(header, TEXT))).toBe('DUPLICATE_KEY');
  });

  it('returns the part before a smuggled DNS SAN in the text format', () => {
    // Byte-identical to a certificate with both SANs, so it cannot be rejected
    // by default.
    const header = `Hash=${HASH};URI=spiffe://td/x;DNS=admin.internal`;
    expect(getPeerSpiffeId(header, TEXT).id).toBe('spiffe://td/x');
  });

  it('ignores requireSingleSan inherited from Object.prototype', () => {
    Object.assign(Object.prototype, { requireSingleSan: 'yes' });
    try {
      const header = `Hash=${HASH};URI=spiffe://td/x;DNS=admin.internal`;
      expect(getPeerSpiffeId(header, TEXT).id).toBe('spiffe://td/x');
    } finally {
      Reflect.deleteProperty(Object.prototype, 'requireSingleSan');
    }
  });

  it('rejects any DNS SAN when requireSingleSan is set', () => {
    const header = `Hash=${HASH};URI=spiffe://td/x;DNS=admin.internal`;
    expect(codeOf(() => getPeerSpiffeId(header, { format: 'text', requireSingleSan: true }))).toBe(
      'NOT_ONE_SAN',
    );
    expect(
      getPeerSpiffeId(`Hash=${HASH};URI=${API}`, { format: 'text', requireSingleSan: false }).id,
    ).toBe(API);
  });
});

describe('SPIFFE ID validation', () => {
  const cases: [string, string[], SpiffeErrorCode][] = [
    ['no URI', [], 'NOT_ONE_URI'],
    ['two URIs', [API, API], 'NOT_ONE_URI'],
    ['a non-SPIFFE URI', ['http://td/ns/a/sa/b'], 'NOT_SPIFFE'],
    ['an uppercase scheme', ['SPIFFE://td/a'], 'NOT_SPIFFE'],
    ['a trust domain only', ['spiffe://td'], 'INVALID_SPIFFE_ID'],
    ['an empty trust domain', ['spiffe:///a'], 'INVALID_SPIFFE_ID'],
    ['an uppercase trust domain', ['spiffe://TD/a'], 'INVALID_SPIFFE_ID'],
    ['userinfo', ['spiffe://user@td/a'], 'INVALID_SPIFFE_ID'],
    ['a port', ['spiffe://td:8080/a'], 'INVALID_SPIFFE_ID'],
    ['a query', ['spiffe://td/a?x=1'], 'INVALID_SPIFFE_ID'],
    ['a fragment', ['spiffe://td/a#x'], 'INVALID_SPIFFE_ID'],
    ['a trailing slash', ['spiffe://td/a/'], 'INVALID_SPIFFE_ID'],
    ['an empty segment', ['spiffe://td/a//b'], 'INVALID_SPIFFE_ID'],
    ['a dot segment', ['spiffe://td/a/./b'], 'INVALID_SPIFFE_ID'],
    ['a dot-dot segment', ['spiffe://td/a/../b'], 'INVALID_SPIFFE_ID'],
    ['a percent escape', ['spiffe://td/a%2Fb'], 'INVALID_SPIFFE_ID'],
    ['a semicolon', ['spiffe://td/x;URI=spiffe://td/admin'], 'INVALID_SPIFFE_ID'],
    ['a comma', ['spiffe://td/x,By=a'], 'INVALID_SPIFFE_ID'],
    ['more than 2048 bytes', [`spiffe://td/${'a'.repeat(2048)}`], 'INVALID_SPIFFE_ID'],
    ['a trust domain over 255 bytes', [`spiffe://${'a'.repeat(256)}/a`], 'INVALID_SPIFFE_ID'],
  ];

  it.each(cases)('rejects %s', (_name, uris, code) => {
    expect(codeOf(() => peerOf(...uris))).toBe(code);
  });

  it('rejects a DNS SAN only when requireSingleSan is set', () => {
    const both = JSON.stringify([{ uri: [API], dns: ['api.example'] }]);
    expect(getPeerSpiffeId(both, JSON_FORMAT).id).toBe(API);
    expect(codeOf(() => getPeerSpiffeId(both, { ...JSON_FORMAT, requireSingleSan: true }))).toBe(
      'NOT_ONE_SAN',
    );
  });

  it.each([
    { format: 'text', maxElements: 0 },
    { format: 'text', maxElement: 2 },
    { format: 'text', requireSingleSan: 'yes' },
    { format: 'text', requireSingleSan: 1 },
    { format: 'text', require_single_san: true },
    {},
    null,
    'json',
    [1],
  ])('rejects invalid options %j', (options) => {
    // @ts-expect-error -- deliberately invalid at runtime
    expect(codeOf(() => getPeerSpiffeId(undefined, options))).toBe('INVALID_OPTION');
  });

  it('rejects a requireSingleSan it would otherwise ignore', () => {
    class Getter {
      format = 'text';
      get requireSingleSan() {
        return true;
      }
    }
    const hidden = { format: 'text' };
    Object.defineProperty(hidden, 'requireSingleSan', { value: true });
    const header = `Hash=${HASH};URI=${API};DNS=admin.internal`;
    for (const options of [
      { __proto__: { requireSingleSan: true }, format: 'text' },
      new Getter(),
      hidden,
    ]) {
      // @ts-expect-error -- deliberately invalid at runtime
      expect(codeOf(() => getPeerSpiffeId(header, options))).toBe('INVALID_OPTION');
    }
  });

  it('accepts a 2048 byte ID', () => {
    const id = `spiffe://td/${'a'.repeat(2048 - 'spiffe://td/'.length)}`;
    expect(peerOf(id).id).toBe(id);
  });

  it('accepts a 255 byte trust domain', () => {
    const trustDomain = 'a'.repeat(255);
    expect(peerOf(`spiffe://${trustDomain}/a`).trustDomain).toBe(trustDomain);
  });

  it('keeps input out of error messages', () => {
    const error = errorOf(() => peerOf('spiffe://td/secret;x'));
    expect(error).toBeInstanceOf(SpiffeError);
    expect(error.message).not.toContain('secret');
  });
});
