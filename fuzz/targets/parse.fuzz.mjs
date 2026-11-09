import { parseDistinguishedName, XfccError } from '../../dist/index.mjs';

import { ok, tryParse, text } from './common.mjs';

const HASH = /^[0-9a-f]{64}$/;
const DN_CHARS = /^[\x20-\x7e]*$/;

export const fuzz = (data) => {
  const input = text(data);
  for (const format of ['text', 'json']) {
    const result = tryParse(input, { format, maxElements: 8 });
    if (!result.ok) {
      // The options are valid, so every error is about input and has an offset.
      ok(result.error instanceof XfccError);
      ok(Number.isSafeInteger(result.error.offset) && result.error.offset >= 0);
      continue;
    }
    // Fail-closed invariants of every accepted element.
    for (const element of result.value) {
      ok(element.hash === null || HASH.test(element.hash));
      ok(format === 'json' || element.hash !== null);
      ok(format === 'json' || element.issuer === null);
      // Anything accepted must also have parseable, plain-ASCII DNs.
      for (const dn of [element.subject, element.issuer]) {
        if (dn !== null) {
          ok(DN_CHARS.test(dn));
          parseDistinguishedName(dn);
        }
      }
    }
  }
};
