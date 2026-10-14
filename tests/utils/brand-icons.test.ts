import { describe, it, expect } from 'vitest';
import { getBrandInfo } from '../../src/utils/brand-icons';

describe('getBrandInfo', () => {
  it('returns official brand info for popular tech services', () => {
    const google = getBrandInfo('Google');
    expect(google.svg).toBeDefined();
    expect(google.label).toBe('G');

    const github = getBrandInfo('GitHub');
    expect(github.svg).toContain('M12 2C6.477');

    const discord = getBrandInfo('Discord');
    expect(discord.color).toBe('#5865F2');

    const steam = getBrandInfo('Steam');
    expect(steam.svg).toBeDefined();

    const binance = getBrandInfo('Binance');
    expect(binance.color).toBe('#F0B90B');
  });

  it('handles fallback for unknown issuers gracefully', () => {
    const fallback = getBrandInfo('Custom Corporate VPN');
    expect(fallback.label).toBe('CU');
    expect(fallback.bg).toContain('hsl(');
    expect(fallback.color).toContain('hsl(');
  });

  it('handles empty or whitespace strings without error', () => {
    const fallback = getBrandInfo('');
    expect(fallback.label).toBe('2F');
    expect(fallback.bg).toBeDefined();
  });
});
