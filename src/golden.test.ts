// Recorded inputs and results that pin the parser's behaviour. An INVALID_JSON
// offset is not compared: it is covered in `header.test.ts`.
import { describe, expect, it } from 'vitest';

import { fixture } from '../test/helpers.ts';

import { parseDistinguishedName, parseXfcc, XfccError, type ParseOptions } from './index.ts';

interface Expected {
  readonly value?: unknown;
  readonly code?: string;
  readonly offset?: number | undefined;
}

interface HeaderVector {
  readonly input: string;
  // The file is checked in: `options` holds only valid `ParseOptions`.
  readonly options: ParseOptions;
  readonly expected: Expected;
}

interface Golden {
  readonly headers: readonly HeaderVector[];
  readonly dns: readonly { readonly input: string; readonly expected: Expected }[];
}

// Not an import: Vite's JSON plugin rejects the lone surrogate in one vector.
// oxlint-disable-next-line typescript/no-unsafe-type-assertion -- a checked-in file
const { headers, dns } = JSON.parse(fixture('golden.json')) as Golden;

/** What the parser did, in the form the vectors record it. */
const outcome = (fn: () => unknown, isJson = false): Expected => {
  try {
    return { value: fn() };
  } catch (error) {
    if (!(error instanceof XfccError)) {
      throw error;
    }
    return isJson && error.code === 'INVALID_JSON'
      ? { code: error.code }
      : { code: error.code, offset: error.offset };
  }
};

describe('golden vectors', () => {
  it.each(headers)('parses header %#', ({ input, options, expected }) => {
    expect(outcome(() => parseXfcc(input, options), options.format === 'json')).toEqual(
      expected.code === 'INVALID_JSON' ? { code: expected.code } : expected,
    );
  });

  it.each(dns)('parses DN %#', ({ input, expected }) => {
    expect(outcome(() => parseDistinguishedName(input))).toEqual(expected);
  });
});
