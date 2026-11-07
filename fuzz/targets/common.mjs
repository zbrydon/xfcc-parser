import { deepStrictEqual, ok } from 'node:assert/strict';

import { parseXfcc, XfccError } from '../../dist/index.mjs';

export { deepStrictEqual, ok };

/** `parseXfcc` as `{ ok, value }` or `{ ok, error }`. Rethrows anything but an `XfccError`. */
export const safeParseXfcc = (header, options) => {
  try {
    return { ok: true, value: parseXfcc(header, options) };
  } catch (error) {
    if (error instanceof XfccError) {
      return { ok: false, error };
    }
    throw error;
  }
};

/** A fuzz input as text, the way the parser sees it once Node has decoded it. */
export const text = (data) => data.toString('utf8');

const ALLOWED = /^[\x20-\x7e\t]*$/;

/** The input can only be accepted if it would survive the header-level check. */
export const isFieldValue = (value) => ALLOWED.test(value);

/** Mirrors Envoy's `PercentEncoding::urlEncode`. */
export const urlEncode = (value) =>
  [...Buffer.from(value, 'utf8')]
    .map((byte) =>
      /[A-Za-z0-9*._-]/.test(String.fromCodePoint(byte))
        ? String.fromCodePoint(byte)
        : `%${byte.toString(16).toUpperCase().padStart(2, '0')}`,
    )
    .join('');
