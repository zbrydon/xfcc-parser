// Run with `pnpm bench`. `bench/results.md` holds the latest recorded numbers.
import { describe, test } from 'vitest';

import * as xfcc from '../dist/index.mjs';

import { DN_CASES, HEADER_CASES } from './cases.ts';

// Bind the exports once: reading a module export in the loop adds getter overhead.
const { parseDistinguishedName, parseXfcc } = xfcc;

describe('parse', () => {
  for (const [name, header, options] of HEADER_CASES) {
    test(name, async ({ bench }) => {
      await bench('parseXfcc', () => {
        try {
          parseXfcc(header, options);
        } catch {
          // Measuring the cost of building the XfccError.
        }
      }).run();
    });
  }
});

describe('distinguished name', () => {
  for (const [name, dn] of DN_CASES) {
    test(name, async ({ bench }) => {
      await bench('parseDistinguishedName', () => {
        try {
          parseDistinguishedName(dn);
        } catch {
          // Measuring the cost of building the XfccError.
        }
      }).run();
    });
  }
});
