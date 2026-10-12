import type { PublicAccount } from '../types';

export type SortMode = 'asc' | 'desc' | 'recent';

/**
 * Sorts public accounts according to the selected mode.
 * - 'asc': Alphabetical by Issuer (then Account), A to Z
 * - 'desc': Alphabetical by Issuer (then Account), Z to A
 * - 'recent': Recently added first (by createdAt timestamp)
 */
export function sortAccounts(accounts: PublicAccount[], mode: SortMode = 'asc'): PublicAccount[] {
  return [...accounts].sort((a, b) => {
    if (mode === 'desc') {
      const nameA = (a.issuer || a.account || '').toLowerCase();
      const nameB = (b.issuer || b.account || '').toLowerCase();
      const comp = nameB.localeCompare(nameA, undefined, { sensitivity: 'base' });
      if (comp !== 0) return comp;
      return (b.account || '').localeCompare(a.account || '', undefined, { sensitivity: 'base' });
    }

    if (mode === 'recent') {
      const diff = (b.createdAt || 0) - (a.createdAt || 0);
      if (diff !== 0) return diff;
    }

    // Default 'asc'
    const nameA = (a.issuer || a.account || '').toLowerCase();
    const nameB = (b.issuer || b.account || '').toLowerCase();
    const comp = nameA.localeCompare(nameB, undefined, { sensitivity: 'base' });
    if (comp !== 0) return comp;
    return (a.account || '').localeCompare(b.account || '', undefined, { sensitivity: 'base' });
  });
}
