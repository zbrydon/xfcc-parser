import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { CA_PEM, CLIENT_PEM, CLIENT_SHA256, urlEncode } from '../test/helpers.ts';

import { parseCertificate, parseCertificates, percentDecode } from './pem.ts';

const BEGIN = '-----BEGIN CERTIFICATE-----';
const END = '-----END CERTIFICATE-----';

const pemOf = (der: readonly number[]) => {
  const lines =
    Buffer.from(der)
      .toString('base64')
      .match(/.{1,64}/g) ?? [];
  return `${BEGIN}\n${lines.join('\n')}\n${END}\n`;
};

describe('percentDecode', () => {
  it('round trips Envoy encoding', () => {
    const encoded = urlEncode(CLIENT_PEM);
    expect(encoded).not.toMatch(/[+/\n]/);
    expect(percentDecode(encoded)).toBe(CLIENT_PEM);
    expect(percentDecode('%2b%2F')).toBe('+/');
    expect(percentDecode('aZ09*-._')).toBe('aZ09*-._');
  });

  it.each(['%', '%2', '%zz', '%2G', '%G2', 'a+b', 'a b', 'a/b', 'a=b', 'a"b', 'a%', 'é'])(
    'rejects %j',
    (value) => {
      expect(percentDecode(value)).toBeNull();
    },
  );

  it('leaves non-ASCII bytes for the PEM check to reject', () => {
    const decoded = percentDecode('%C3%A9');
    expect(decoded).not.toBeNull();
    expect(parseCertificates(decoded ?? '')).toEqual([]);
  });
});

describe('parseCertificate', () => {
  it('parses one certificate', () => {
    const block = parseCertificate(CLIENT_PEM);
    expect(block?.pem).toBe(CLIENT_PEM);
    expect(block && createHash('sha256').update(block.der).digest('hex')).toBe(CLIENT_SHA256);
  });

  it('accepts CRLF, CR and a missing final line break', () => {
    const der = parseCertificate(CLIENT_PEM)?.der;
    expect(parseCertificate(CLIENT_PEM.replaceAll('\n', '\r\n'))?.der).toEqual(der);
    expect(parseCertificate(CLIENT_PEM.replaceAll('\n', '\r'))?.der).toEqual(der);
    const trimmed = CLIENT_PEM.trimEnd();
    expect(parseCertificate(trimmed)?.pem).toBe(trimmed);
  });

  it('parses a chain in order, and only as a chain', () => {
    const chain = `${CLIENT_PEM}${CA_PEM}`;
    expect(parseCertificates(chain).map((block) => block.pem)).toEqual([CLIENT_PEM, CA_PEM]);
    expect(parseCertificate(chain)).toBeUndefined();
  });

  it('accepts trailing whitespace on the boundary lines only', () => {
    const padded = CLIENT_PEM.replace(BEGIN, `${BEGIN} \t`).replace(END, `${END} `);
    expect(parseCertificate(padded)).toBeDefined();
    // `trimEnd` would accept this.
    expect(parseCertificate(CLIENT_PEM.replace(BEGIN, `${BEGIN}\u00a0`))).toBeUndefined();
  });

  const bodyLine = CLIENT_PEM.split('\n')[1] ?? '';

  it.each([
    ['empty', ''],
    ['blank line', '\n'],
    ['text before', `junk\n${CLIENT_PEM}`],
    ['text after', `${CLIENT_PEM}junk`],
    ['blank line after', `${CLIENT_PEM}\n`],
    ['wrong label', CLIENT_PEM.replaceAll('CERTIFICATE', 'PRIVATE KEY')],
    ['wrong END label', CLIENT_PEM.replace(END, '-----END KEY-----')],
    ['trailing text on BEGIN', CLIENT_PEM.replace(BEGIN, `${BEGIN} x`)],
    ['BEGIN without a line ending', BEGIN],
    ['no END', `${BEGIN}\nMAA=\n`],
    ['short body line', CLIENT_PEM.replace(bodyLine, bodyLine.slice(0, 60))],
    ['long body line', CLIENT_PEM.replace(bodyLine, `${bodyLine}AAAA`)],
    ['space in a body line', CLIENT_PEM.replace(bodyLine, ` ${bodyLine.slice(1)}`)],
    ['bad character', CLIENT_PEM.replace(bodyLine, `${bodyLine.slice(0, 63)}*`)],
    ['blank body line', CLIENT_PEM.replace(`${bodyLine}\n`, `${bodyLine}\n\n`)],
    ['body without a line ending', `${BEGIN}\nMAA=`],
    ['empty body', `${BEGIN}\n${END}\n`],
    ['not a SEQUENCE', `${BEGIN}\nAAAA\n${END}\n`],
    ['non-canonical trailing bits', `${BEGIN}\nMAB=\n${END}\n`],
    ['missing padding', `${BEGIN}\nMAA\n${END}\n`],
    ['padding in the middle', `${BEGIN}\nMA==MAA=\n${END}\n`],
  ])('rejects %s', (_name, value) => {
    expect(parseCertificates(value)).toEqual([]);
  });
});

const accepts = (der: readonly number[]) => parseCertificate(pemOf(der)) !== undefined;

describe('DER framing', () => {
  it('accepts one minimally encoded SEQUENCE', () => {
    expect(accepts([0x30, 0x00])).toBe(true);
    expect(accepts([0x30, 0x01, 0x05])).toBe(true);
    expect(accepts([0x30, 0x81, 0x80, ...Array.from({ length: 0x80 }, () => 0)])).toBe(true);
    expect(accepts([0x30, 0x82, 0x01, 0x00, ...Array.from({ length: 0x100 }, () => 0)])).toBe(true);
  });

  it.each([
    ['a tag alone', [0x30]],
    ['the wrong tag', [0x31, 0x00]],
    ['a short content', [0x30, 0x02, 0x05]],
    ['indefinite length', [0x30, 0x80]],
    ['long form for a short length', [0x30, 0x81, 0x01, 0x05]],
    ['a leading zero length byte', [0x30, 0x82, 0x00, 0x80]],
    ['a truncated length', [0x30, 0x82, 0x01]],
    ['too many length bytes', [0x30, 0x85, 0, 0, 0, 0, 1, 0]],
    // Reads as negative if the length is computed with `<<`.
    ['a 4-byte length with the top bit set', [0x30, 0x84, 0xff, 0xff, 0xff, 0xff]],
    ['a long-form length that does not match', [0x30, 0x81, 0x80, 0]],
  ])('rejects %s', (_name, der) => {
    expect(accepts(der)).toBe(false);
  });
});
