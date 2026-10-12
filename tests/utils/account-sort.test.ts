import { describe, it, expect } from 'vitest';
import { sortAccounts } from '../../src/utils/account-sort';
import type { PublicAccount } from '../../src/types';

describe('Account Sort Utility', () => {
  const mockAccounts: PublicAccount[] = [
    {
      id: '1',
      issuer: 'Google',
      account: 'charlie@gmail.com',
      digits: 6,
      period: 30,
      code: '123456',
      secondsRemaining: 25,
      type: 'totp',
      createdAt: 1000,
    },
    {
      id: '2',
      issuer: 'AWS',
      account: 'admin@amazon.com',
      digits: 6,
      period: 30,
      code: '234567',
      secondsRemaining: 20,
      type: 'totp',
      createdAt: 3000,
    },
    {
      id: '3',
      issuer: 'GitHub',
      account: 'dev@github.com',
      digits: 6,
      period: 30,
      code: '345678',
      secondsRemaining: 15,
      type: 'totp',
      createdAt: 2000,
    },
    {
      id: '4',
      issuer: 'Google',
      account: 'alice@gmail.com',
      digits: 6,
      period: 30,
      code: '456789',
      secondsRemaining: 10,
      type: 'totp',
      createdAt: 4000,
    },
    {
      id: '5',
      issuer: '',
      account: 'zebra@domain.com',
      digits: 6,
      period: 30,
      code: '567890',
      secondsRemaining: 5,
      type: 'totp',
      createdAt: 500,
    },
  ];

  it('sorts alphabetically ascending (A to Z) with fallback to account', () => {
    const sorted = sortAccounts(mockAccounts, 'asc');
    const order = sorted.map((a) => a.issuer || a.account);

    expect(order).toEqual([
      'AWS',
      'GitHub',
      'Google', // alice@gmail.com
      'Google', // charlie@gmail.com
      'zebra@domain.com',
    ]);
    expect(sorted[2].account).toBe('alice@gmail.com');
    expect(sorted[3].account).toBe('charlie@gmail.com');
  });

  it('sorts alphabetically descending (Z to A) with fallback to account', () => {
    const sorted = sortAccounts(mockAccounts, 'desc');
    const order = sorted.map((a) => a.issuer || a.account);

    expect(order).toEqual([
      'zebra@domain.com',
      'Google', // charlie@gmail.com
      'Google', // alice@gmail.com
      'GitHub',
      'AWS',
    ]);
    expect(sorted[1].account).toBe('charlie@gmail.com');
    expect(sorted[2].account).toBe('alice@gmail.com');
  });

  it('sorts by recently added (newest createdAt first)', () => {
    const sorted = sortAccounts(mockAccounts, 'recent');
    const ids = sorted.map((a) => a.id);

    // createdAt order: id 4 (4000), id 2 (3000), id 3 (2000), id 1 (1000), id 5 (500)
    expect(ids).toEqual(['4', '2', '3', '1', '5']);
  });

  it('does not mutate original array', () => {
    const originalClone = [...mockAccounts];
    sortAccounts(mockAccounts, 'desc');
    expect(mockAccounts).toEqual(originalClone);
  });
});
