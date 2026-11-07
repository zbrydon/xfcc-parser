import { MAX_ELEMENTS_LIMIT, MAX_LENGTH_LIMIT } from '../../dist/index.mjs';

import { ok, safeParseXfcc } from './common.mjs';

// The first 7 bytes pick the options, the rest is the header. Sizes are reduced
// so both sides of every limit (including invalid ones) are reachable.
export const fuzz = (data) => {
  if (data.length < 7) {
    return;
  }
  const input = data.subarray(7).toString('utf8');
  const maxLength = data.readUIntLE(0, 3) % (MAX_LENGTH_LIMIT + 64);
  const maxElements = data.readUInt16LE(3) % (MAX_ELEMENTS_LIMIT + 8);
  const options = {
    maxLength: (data[6] & 4) !== 0 ? maxLength % 256 : maxLength,
    maxElements: (data[6] & 8) !== 0 ? maxElements % 4 : maxElements,
    format: (data[5] & 1) === 0 ? 'text' : 'json',
  };
  const valid =
    options.maxLength >= 1 &&
    options.maxLength <= MAX_LENGTH_LIMIT &&
    options.maxElements >= 1 &&
    options.maxElements <= MAX_ELEMENTS_LIMIT;
  const bytes = Buffer.byteLength(input);
  let result;
  try {
    result = safeParseXfcc(input, options);
  } catch (error) {
    // An invalid option is a caller bug, so it throws TypeError, never XfccError.
    ok(error instanceof TypeError && !valid);
    return;
  }
  ok(valid);
  if (result.ok) {
    ok(bytes <= options.maxLength);
    ok(result.value.length >= 1 && result.value.length <= options.maxElements);
  } else if (bytes > options.maxLength) {
    ok(result.error.code === 'TOO_LONG');
  }
};
