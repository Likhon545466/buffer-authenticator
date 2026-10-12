/**
 * i18n Helper
 * Wraps chrome.i18n.getMessage with safe fallbacks
 */

export function t(key: string, fallback?: string): string {
  if (typeof chrome !== 'undefined' && chrome.i18n && typeof chrome.i18n.getMessage === 'function') {
    const msg = chrome.i18n.getMessage(key);
    if (msg) return msg;
  }
  return fallback || key;
}
