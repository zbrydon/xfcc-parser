import { describe, expect, it, vi } from 'vitest';

vi.mock('./dn.ts', () => ({
  parseDn: () => {
    throw new RangeError('unexpected');
  },
}));

const { parseXfcc } = await import('./index.ts');

describe('parseXfcc', () => {
  it('does not report a defect in the DN parser as INVALID_DN', () => {
    expect(() => parseXfcc('[{"subject":"CN=a"}]', { format: 'json' })).toThrow(RangeError);
  });
});
