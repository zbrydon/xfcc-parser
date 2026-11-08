import { ok, tryParse, urlEncode } from './common.mjs';

/** A DER SEQUENCE around `content`. */
const der = (content) => {
  const n = content.length;
  const head = n <= 0x7f ? [0x30, n] : n <= 0xff ? [0x30, 0x81, n] : [0x30, 0x82, n >> 8, n & 0xff];
  return Buffer.concat([Buffer.from(head), content]);
};

const pem = (bytes) => {
  const lines = bytes.toString('base64').match(/.{1,64}/g) ?? [];
  return `-----BEGIN CERTIFICATE-----\n${lines.map((line) => `${line}\n`).join('')}-----END CERTIFICATE-----\n`;
};

// Hash is not compared with Cert, so any valid hash will do.
const hash = 'a'.repeat(64);

const isAccepted = (header, options) => tryParse(header, options).ok;

// Random bytes almost never form valid PEM, so build well-formed headers from
// the input and check the whole Cert / Chain path accepts them.
export const fuzz = (data) => {
  if (data.length === 0) {
    return;
  }
  const rest = data.subarray(1);
  const split = Math.min(rest.length, data[0] * 8);
  const leaf = pem(der(rest.subarray(0, Math.min(split, 1500))));
  const chain = [];
  for (let i = split; i < rest.length && chain.length < 4; i += 200) {
    chain.push(pem(der(rest.subarray(i, i + 200))));
  }

  const textHeader = `Hash=${hash};Cert="${urlEncode(leaf)}"${chain.length === 0 ? '' : `;Chain="${urlEncode(chain.join(''))}"`}`;
  const jsonHeader = `[{"hash":"${hash}","cert":${JSON.stringify(leaf)}${chain.length === 0 ? '' : `,"chain":${JSON.stringify(chain)}`}}]`;

  for (const [format, header] of [
    ['text', textHeader],
    ['json', jsonHeader],
  ]) {
    const options = { format, maxLength: 1 << 20 };
    const result = tryParse(header, options);
    ok(result.ok, `${format}: ${header}`);
    ok(result.value[0].hash === hash);
    ok(result.value[0].cert === leaf);

    // Near-valid headers must be rejected: a stray control byte, a missing
    // closing delimiter, and (text) a trailing separator or repeated Hash.
    const broken = [`\u0001${header}`, header.slice(0, -1)];
    if (format === 'text') {
      broken.push(`${header},`, `${header};`, `${header};Hash=${hash}`);
    }
    for (const near of broken) {
      ok(!isAccepted(near, options), `${format}: accepted ${near}`);
    }
  }
};
