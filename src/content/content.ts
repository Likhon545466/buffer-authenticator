/**
 * Content Script: Contextual In-Field 2FA Autofill & Live Code Popover
 *
 * Security & Functional Guarantees:
 * - Isolated from secrets: Content script NEVER receives secrets, only public TOTP codes.
 * - Uses Shadow DOM to isolate styles and prevent any host page CSS interference.
 * - Native In-Field Icon: Docked cleanly inside the right edge of OTP fields (position: fixed)
 *   so it NEVER distorts or breaks form layouts or vertical spacing in congested places.
 * - Interactive Popover: Clicking the icon opens a tethered floating card showing the
 *   specific matched account, live 6-digit code, and real-time countdown progress bar.
 * - Supports multiple accounts per domain (e.g. multiple Google or GitHub accounts).
 * - Multi-input OTP handling: Populates both single 6-digit inputs and segmented digit inputs.
 * - Dispatches standard DOM events ('input', 'change') for compatibility with SPA frameworks.
 */

import type { MessageRequest, MessageResponse, DomainMatchResult, DomainAutofillAccount } from '../types';

const HOST_CONTAINER_CLASS = 'buffer-auth-inline-host';
const PROCESSED_ATTR = 'data-buffer-auth-detected';

/**
 * Heuristic check if an input field is an OTP / 2FA field
 */
function isOtpField(el: HTMLInputElement): boolean {
  if (el.hasAttribute(PROCESSED_ATTR)) return false;
  if (el.type === 'password' || el.type === 'hidden' || el.type === 'checkbox' || el.type === 'radio') {
    return false;
  }
  if (el.disabled || el.readOnly) return false;

  const autocomplete = (el.getAttribute('autocomplete') || '').toLowerCase();
  if (autocomplete === 'one-time-code') {
    return true;
  }

  const name = (el.name || '').toLowerCase();
  const id = (el.id || '').toLowerCase();
  const placeholder = (el.placeholder || '').toLowerCase();
  const ariaLabel = (el.getAttribute('aria-label') || '').toLowerCase();

  const keywords = ['otp', '2fa', 'mfa', 'totp', 'token', 'verification_code', 'security code', 'authenticator', 'two-factor', 'two_factor'];
  const matched = keywords.some(
    (kw) => name.includes(kw) || id.includes(kw) || placeholder.includes(kw) || ariaLabel.includes(kw)
  );
  if (matched) return true;

  // Pattern or maxlength check (e.g. 6 or 8 digits)
  const maxLength = el.maxLength;
  if ((maxLength === 6 || maxLength === 8) && (el.type === 'tel' || el.type === 'number' || el.inputMode === 'numeric')) {
    return true;
  }

  return false;
}

/**
 * Brand color/initial resolver for avatars
 */
function getBrandInfo(name: string): { bg: string; color: string; label: string } {
  const norm = (name || '').toLowerCase().trim();
  if (norm.includes('google')) return { bg: '#1a2332', color: '#4285F4', label: 'G' };
  if (norm.includes('github')) return { bg: '#24292e', color: '#ffffff', label: 'GH' };
  if (norm.includes('microsoft')) return { bg: '#182538', color: '#00a4ef', label: 'MS' };
  if (norm.includes('facebook') || norm.includes('meta')) return { bg: '#0c2e59', color: '#1877f2', label: 'FB' };
  if (norm.includes('twitter') || norm.includes('x')) return { bg: '#1b222d', color: '#ffffff', label: 'X' };

  let hash = 0;
  for (let i = 0; i < norm.length; i++) {
    hash = norm.charCodeAt(i) + ((hash << 5) - hash);
  }
  const hue = Math.abs(hash % 360);
  return {
    bg: `hsl(${hue}, 40%, 18%)`,
    color: `hsl(${hue}, 85%, 75%)`,
    label: (name.slice(0, 2) || '2F').toUpperCase(),
  };
}

/**
 * Format OTP code with space separation (e.g. '714 281')
 */
function formatCode(code: string): string {
  if (code.length === 6) {
    return `${code.slice(0, 3)} ${code.slice(3)}`;
  }
  if (code.length === 8) {
    return `${code.slice(0, 4)} ${code.slice(4)}`;
  }
  return code;
}

/**
 * Safely escape HTML to prevent XSS injection in dynamic text
 */
function escapeHtml(str: string): string {
  return str.replace(/[&<>"']/g, (m) => {
    switch (m) {
      case '&': return '&amp;';
      case '<': return '&lt;';
      case '>': return '&gt;';
      case '"': return '&quot;';
      case "'": return '&#39;';
      default: return m;
    }
  });
}

/**
 * Safely fill OTP code into target input and dispatch native events
 */
function fillOtpIntoInput(input: HTMLInputElement, code: string) {
  const cleanCode = code.replace(/\s+/g, '');

  // Handle segmented inputs (e.g. 6 separate 1-digit boxes)
  if (input.maxLength === 1) {
    const parentForm = input.form || input.closest('form') || input.parentElement;
    if (parentForm) {
      const singleDigitInputs = Array.from(parentForm.querySelectorAll<HTMLInputElement>('input')).filter(
        (i) => i.maxLength === 1 && (i.type === 'tel' || i.type === 'text' || i.type === 'number' || i.inputMode === 'numeric')
      );
      if (singleDigitInputs.length >= cleanCode.length) {
        singleDigitInputs.forEach((inp, idx) => {
          if (idx < cleanCode.length) {
            inp.value = cleanCode[idx];
            inp.dispatchEvent(new Event('input', { bubbles: true }));
            inp.dispatchEvent(new Event('change', { bubbles: true }));
          }
        });
        const targetFocus = singleDigitInputs[Math.min(cleanCode.length - 1, singleDigitInputs.length - 1)];
        targetFocus?.focus();
        return;
      }
    }
  }

  // Standard input fill
  input.value = cleanCode;
  input.dispatchEvent(new Event('input', { bubbles: true }));
  input.dispatchEvent(new Event('change', { bubbles: true }));
  input.focus();
}

/**
 * Attach in-field icon and popover tethered to target OTP input
 */
function attachAutofillTrigger(input: HTMLInputElement) {
  input.setAttribute(PROCESSED_ATTR, 'true');

  // Prevent input text from colliding with the icon badge
  const computedStyle = window.getComputedStyle(input);
  const currentPaddingRight = parseFloat(computedStyle.paddingRight) || 0;
  if (currentPaddingRight < 34) {
    input.style.paddingRight = `${currentPaddingRight + 30}px`;
  }

  // Create isolated container in document body
  const host = document.createElement('div');
  host.className = HOST_CONTAINER_CLASS;
  host.style.position = 'fixed';
  host.style.top = '0px';
  host.style.left = '0px';
  host.style.width = '0px';
  host.style.height = '0px';
  host.style.zIndex = '2147483646';
  host.style.pointerEvents = 'none';

  const shadow = host.attachShadow({ mode: 'open' });

  shadow.innerHTML = `
    <style>
      * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
      }

      /* In-Field Shield App Icon Badge */
      .badge-btn {
        position: fixed;
        width: 24px;
        height: 24px;
        background: #111318;
        border: 1px solid rgba(168, 199, 250, 0.35);
        border-radius: 6px;
        color: #a8c7fa;
        display: flex;
        align-items: center;
        justify-content: center;
        cursor: pointer;
        pointer-events: auto;
        box-shadow: 0 2px 5px rgba(0, 0, 0, 0.35);
        transition: all 0.2s cubic-bezier(0.2, 0, 0, 1);
        user-select: none;
        z-index: 2147483646;
      }
      .badge-btn:hover {
        background: #1e222a;
        border-color: #a8c7fa;
        color: #ffffff;
        transform: scale(1.08);
        box-shadow: 0 0 10px rgba(168, 199, 250, 0.45);
      }
      .badge-btn:active {
        transform: scale(0.96);
      }
      .badge-btn.active {
        background: #0842a0;
        border-color: #a8c7fa;
        color: #ffffff;
      }
      .shield-icon {
        width: 14px;
        height: 14px;
        fill: none;
        stroke: currentColor;
        stroke-width: 2;
      }

      /* Interactive 2FA Live Card Popover */
      .autofill-popover {
        position: fixed;
        width: 320px;
        background: #171a21;
        border: 1px solid rgba(255, 255, 255, 0.14);
        border-radius: 14px;
        box-shadow: 0 16px 36px rgba(0, 0, 0, 0.75), 0 4px 12px rgba(0, 0, 0, 0.5);
        backdrop-filter: blur(20px);
        color: #e2e2e9;
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        padding: 12px;
        pointer-events: auto;
        z-index: 2147483647;
        opacity: 0;
        transform: translateY(-6px) scale(0.97);
        pointer-events: none;
        transition: all 0.18s cubic-bezier(0.2, 0, 0, 1);
      }
      .autofill-popover.open {
        opacity: 1;
        transform: translateY(0) scale(1);
        pointer-events: auto;
      }

      /* Popover Header */
      .popover-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding-bottom: 8px;
        border-bottom: 1px solid rgba(255, 255, 255, 0.08);
        margin-bottom: 10px;
      }
      .popover-title-row {
        display: flex;
        align-items: center;
        gap: 6px;
      }
      .popover-brand {
        font-size: 12px;
        font-weight: 700;
        color: #a8c7fa;
        letter-spacing: 0.2px;
      }
      .popover-domain {
        font-size: 10px;
        color: #9aa0a6;
        background: rgba(255, 255, 255, 0.06);
        padding: 2px 6px;
        border-radius: 4px;
        max-width: 140px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .btn-close-popover {
        background: transparent;
        border: none;
        color: #9aa0a6;
        cursor: pointer;
        padding: 2px 4px;
        border-radius: 4px;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: color 0.15s ease;
      }
      .btn-close-popover:hover {
        color: #ffffff;
      }
      .popover-actions-row {
        display: flex;
        align-items: center;
        gap: 2px;
      }
      .btn-popover-lock {
        background: transparent;
        border: none;
        color: #9aa0a6;
        cursor: pointer;
        padding: 2px 4px;
        border-radius: 4px;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: color 0.15s ease, background-color 0.15s ease;
      }
      .btn-popover-lock:hover {
        color: #ffb4ab;
        background: rgba(255, 255, 255, 0.06);
      }
      .btn-popover-lock.hidden {
        display: none;
      }

      /* Accounts List */
      .accounts-list {
        display: flex;
        flex-direction: column;
        gap: 8px;
        max-height: 260px;
        overflow-y: auto;
      }
      .account-card {
        background: #20242e;
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 10px;
        padding: 10px 12px;
        transition: all 0.15s ease;
      }
      .account-card:hover {
        border-color: rgba(168, 199, 250, 0.35);
        background: #252a36;
      }

      .card-top {
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 8px;
      }
      .card-avatar {
        width: 22px;
        height: 22px;
        border-radius: 6px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 10px;
        font-weight: 700;
        flex-shrink: 0;
      }
      .card-info {
        display: flex;
        flex-direction: column;
        overflow: hidden;
      }
      .card-issuer {
        font-size: 12px;
        font-weight: 700;
        color: #ffffff;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      .card-account {
        font-size: 10.5px;
        color: #9aa0a6;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }

      .card-middle {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 8px;
      }
      .card-code {
        font-family: "SFMono-Regular", Consolas, Menlo, monospace;
        font-size: 19px;
        font-weight: 700;
        letter-spacing: 2px;
        color: #a8c7fa;
      }
      .btn-fill-action {
        background: #0842a0;
        color: #d3e3fd;
        border: none;
        border-radius: 6px;
        padding: 5px 12px;
        font-size: 11.5px;
        font-weight: 700;
        cursor: pointer;
        display: flex;
        align-items: center;
        gap: 4px;
        transition: all 0.15s ease;
      }
      .btn-fill-action:hover {
        background: #0c4fa0;
        color: #ffffff;
        transform: translateY(-1px);
      }
      .btn-fill-action:active {
        transform: translateY(0);
      }
      .btn-fill-action.filled {
        background: #137333 !important;
        color: #ffffff !important;
      }

      /* Progress Bar & Countdown Timer */
      .card-timer-row {
        display: flex;
        align-items: center;
        gap: 8px;
      }
      .timer-track {
        flex: 1;
        height: 4px;
        background: rgba(255, 255, 255, 0.1);
        border-radius: 9999px;
        overflow: hidden;
      }
      .timer-fill {
        height: 100%;
        background: #a8c7fa;
        border-radius: 9999px;
        transition: width 0.3s linear, background-color 0.3s ease;
      }
      .timer-fill.warning {
        background: #ffb951;
      }
      .timer-fill.danger {
        background: #ffb4ab;
      }
      .timer-label {
        font-size: 10px;
        font-weight: 600;
        color: #9aa0a6;
        min-width: 22px;
        text-align: right;
      }

      /* Locked or Empty State */
      .empty-box {
        text-align: center;
        padding: 16px 8px;
        color: #9aa0a6;
        font-size: 11.5px;
        line-height: 1.4;
      }
      .empty-box svg {
        margin-bottom: 6px;
        color: #a8c7fa;
      }
      .empty-box .empty-sub {
        font-size: 10px;
        color: #6c727d;
        margin-top: 4px;
      }

      /* In-Popover Unlock Form */
      .unlock-panel {
        display: flex;
        flex-direction: column;
        gap: 10px;
        padding: 2px;
      }
      .unlock-header {
        display: flex;
        align-items: center;
        gap: 10px;
      }
      .unlock-icon-badge {
        width: 34px;
        height: 34px;
        border-radius: 8px;
        background: rgba(168, 199, 250, 0.12);
        border: 1px solid rgba(168, 199, 250, 0.25);
        display: flex;
        align-items: center;
        justify-content: center;
        color: #a8c7fa;
        flex-shrink: 0;
      }
      .unlock-text {
        display: flex;
        flex-direction: column;
        overflow: hidden;
      }
      .unlock-title {
        font-size: 13px;
        font-weight: 700;
        color: #ffffff;
        line-height: 1.2;
        margin-bottom: 2px;
      }
      .unlock-desc {
        font-size: 11px;
        color: #9aa0a6;
        line-height: 1.3;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      .unlock-desc strong {
        color: #a8c7fa;
      }
      .unlock-form {
        display: flex;
        flex-direction: column;
        gap: 8px;
        margin-top: 2px;
      }
      .unlock-input-row {
        position: relative;
        display: flex;
        align-items: center;
        width: 100%;
      }
      .unlock-password-input {
        width: 100%;
        background: #0e1015;
        border: 1px solid rgba(255, 255, 255, 0.16);
        border-radius: 8px;
        padding: 8px 34px 8px 10px;
        font-size: 12.5px;
        color: #ffffff;
        outline: none;
        font-family: inherit;
        box-sizing: border-box;
        transition: border-color 0.15s ease, box-shadow 0.15s ease;
      }
      .unlock-password-input:focus {
        border-color: #a8c7fa;
        box-shadow: 0 0 0 2px rgba(168, 199, 250, 0.25);
      }
      .unlock-password-input::placeholder {
        color: #6c727d;
      }
      .btn-toggle-eye {
        position: absolute;
        right: 6px;
        background: transparent;
        border: none;
        color: #80868b;
        cursor: pointer;
        padding: 4px;
        display: flex;
        align-items: center;
        justify-content: center;
        border-radius: 4px;
        transition: color 0.15s ease;
      }
      .btn-toggle-eye:hover {
        color: #ffffff;
      }
      .unlock-error-msg {
        font-size: 11px;
        color: #ffb4ab;
        background: rgba(147, 0, 10, 0.25);
        border: 1px solid rgba(255, 180, 171, 0.25);
        border-radius: 6px;
        padding: 6px 8px;
        line-height: 1.3;
        animation: shake 0.25s cubic-bezier(0.36, 0.07, 0.19, 0.97) both;
      }
      .unlock-error-msg.hidden {
        display: none;
      }
      @keyframes shake {
        10%, 90% { transform: translate3d(-1px, 0, 0); }
        20%, 80% { transform: translate3d(2px, 0, 0); }
        30%, 50%, 70% { transform: translate3d(-3px, 0, 0); }
        40%, 60% { transform: translate3d(3px, 0, 0); }
      }
      .btn-unlock-action {
        background: #0842a0;
        color: #d3e3fd;
        border: none;
        border-radius: 8px;
        padding: 8px 14px;
        font-size: 12px;
        font-weight: 700;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 6px;
        width: 100%;
        transition: all 0.15s ease;
      }
      .btn-unlock-action:hover:not(:disabled) {
        background: #0b57d0;
        color: #ffffff;
        box-shadow: 0 2px 8px rgba(11, 87, 208, 0.4);
      }
      .btn-unlock-action:active:not(:disabled) {
        transform: scale(0.98);
      }
      .btn-unlock-action:disabled {
        opacity: 0.65;
        cursor: not-allowed;
      }
      .spin-icon {
        animation: spin 1s linear infinite;
      }
      @keyframes spin {
        from { transform: rotate(0deg); }
        to { transform: rotate(360deg); }
      }
    </style>

    <button type="button" class="badge-btn" id="badge-trigger" title="Buffer Authenticator (Click to view live 2FA code)">
      <svg class="shield-icon" viewBox="0 0 24 24">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
    </button>

    <div class="autofill-popover" id="popover-panel">
      <div class="popover-header">
        <div class="popover-title-row">
          <svg class="shield-icon" style="width: 13px; height: 13px; color: #a8c7fa;" viewBox="0 0 24 24">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
          <span class="popover-brand">Buffer Authenticator</span>
          <span class="popover-domain" id="domain-label"></span>
        </div>
        <div class="popover-actions-row">
          <button type="button" class="btn-popover-lock hidden" id="btn-popover-lock" title="Lock Vault">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
              <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
          </button>
          <button type="button" class="btn-close-popover" id="btn-close" title="Close">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
              <line x1="18" y1="6" x2="6" y2="18"/>
              <line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
          </button>
        </div>
      </div>

      <div class="accounts-list" id="accounts-list-container">
        <!-- Rendered dynamically -->
      </div>
    </div>
  `;

  document.body.appendChild(host);

  const badgeBtn = shadow.getElementById('badge-trigger') as HTMLButtonElement;
  const popover = shadow.getElementById('popover-panel') as HTMLDivElement;
  const domainLabel = shadow.getElementById('domain-label') as HTMLSpanElement;
  const accountsContainer = shadow.getElementById('accounts-list-container') as HTMLDivElement;
  const btnClose = shadow.getElementById('btn-close') as HTMLButtonElement;
  const btnLock = shadow.getElementById('btn-popover-lock') as HTMLButtonElement;

  domainLabel.textContent = window.location.hostname;

  let currentAccounts: DomainAutofillAccount[] = [];
  let tickerTimer: ReturnType<typeof setInterval> | null = null;
  let isPopoverOpen = false;
  let isVaultLocked = false;
  let isVaultInitialized = true;

  /**
   * Position the in-field badge at the right edge of the input
   */
  function updateBadgePosition() {
    if (!document.contains(input)) {
      host.remove();
      return;
    }

    const rect = input.getBoundingClientRect();
    const style = window.getComputedStyle(input);
    if (rect.width === 0 || rect.height === 0 || style.display === 'none' || style.visibility === 'hidden') {
      badgeBtn.style.display = 'none';
      if (isPopoverOpen) closePopover();
      return;
    }

    badgeBtn.style.display = 'flex';
    const badgeSize = 24;
    const top = Math.round(rect.top + (rect.height - badgeSize) / 2);
    const left = Math.round(rect.right - badgeSize - 6);

    badgeBtn.style.top = `${top}px`;
    badgeBtn.style.left = `${left}px`;

    if (isPopoverOpen) {
      updatePopoverPosition(rect);
    }
  }

  /**
   * Position the popover tethered below (or flipped above) the input
   */
  function updatePopoverPosition(inputRect?: DOMRect) {
    const rect = inputRect || input.getBoundingClientRect();
    const popoverWidth = 320;
    const popoverHeight = popover.offsetHeight || 160;

    const left = Math.max(8, Math.min(rect.left, window.innerWidth - popoverWidth - 12));
    const spaceBelow = window.innerHeight - rect.bottom;

    if (spaceBelow >= popoverHeight + 10 || rect.top < popoverHeight + 10) {
      popover.style.top = `${Math.round(rect.bottom + 6)}px`;
    } else {
      popover.style.top = `${Math.round(rect.top - popoverHeight - 6)}px`;
    }
    popover.style.left = `${Math.round(left)}px`;
  }

  /**
   * Start live countdown ticker
   */
  function startTicker() {
    if (tickerTimer) clearInterval(tickerTimer);
    if (isVaultLocked || !isVaultInitialized || currentAccounts.length === 0) {
      return;
    }
    tickerTimer = setInterval(async () => {
      let needsRefresh = false;
      currentAccounts.forEach((acc) => {
        acc.secondsRemaining -= 1;
        if (acc.secondsRemaining <= 0) {
          needsRefresh = true;
        }
      });

      if (needsRefresh) {
        await fetchDomainAccounts();
        renderPopoverAccounts();
      } else {
        updateLiveTimers();
      }
    }, 1000);
  }

  /**
   * Render accounts list with live TOTP code & progress bar, or unlock view if locked
   */
  function renderPopoverAccounts() {
    accountsContainer.innerHTML = '';

    if (!isVaultInitialized) {
      btnLock.classList.add('hidden');
      accountsContainer.innerHTML = `
        <div class="empty-box">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="24" height="24">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </svg>
          <p>Vault is not set up</p>
          <p class="empty-sub">Open Buffer Authenticator from your toolbar to set up your master password.</p>
        </div>
      `;
      return;
    }

    if (isVaultLocked) {
      btnLock.classList.add('hidden');
      accountsContainer.innerHTML = `
        <div class="unlock-panel">
          <div class="unlock-header">
            <div class="unlock-icon-badge">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
              </svg>
            </div>
            <div class="unlock-text">
              <div class="unlock-title">Vault is Locked</div>
              <div class="unlock-desc">Enter password to unlock 2FA codes</div>
            </div>
          </div>

          <form id="popover-unlock-form" class="unlock-form">
            <div class="unlock-input-row">
              <input
                type="password"
                id="popover-password-input"
                class="unlock-password-input"
                placeholder="Enter master password"
                autocomplete="current-password"
                required
              />
              <button type="button" id="popover-btn-toggle-eye" class="btn-toggle-eye" title="Show/Hide password">
                <svg class="eye-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="15" height="15">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                  <circle cx="12" cy="12" r="3"/>
                </svg>
              </button>
            </div>

            <div id="popover-unlock-error" class="unlock-error-msg hidden"></div>

            <button type="submit" id="popover-btn-unlock" class="btn-unlock-action">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                <path d="M7 11V7a5 5 0 0 1 9.9-1"/>
              </svg>
              <span>Unlock Vault</span>
            </button>
          </form>
        </div>
      `;

      // Wire up unlock form controls
      const toggleEyeBtn = accountsContainer.querySelector('#popover-btn-toggle-eye') as HTMLButtonElement | null;
      const pwdInput = accountsContainer.querySelector('#popover-password-input') as HTMLInputElement | null;
      const errBox = accountsContainer.querySelector('#popover-unlock-error') as HTMLDivElement | null;
      const unlockForm = accountsContainer.querySelector('#popover-unlock-form') as HTMLFormElement | null;
      const unlockSubmitBtn = accountsContainer.querySelector('#popover-btn-unlock') as HTMLButtonElement | null;

      let isPasswordVisible = false;
      if (toggleEyeBtn && pwdInput) {
        toggleEyeBtn.addEventListener('click', (e) => {
          e.preventDefault();
          e.stopPropagation();
          isPasswordVisible = !isPasswordVisible;
          pwdInput.type = isPasswordVisible ? 'text' : 'password';
          toggleEyeBtn.innerHTML = isPasswordVisible
            ? `<svg class="eye-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="15" height="15">
                <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
                <line x1="1" y1="1" x2="23" y2="23"/>
              </svg>`
            : `<svg class="eye-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="15" height="15">
                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                <circle cx="12" cy="12" r="3"/>
              </svg>`;
        });
      }

      if (pwdInput) {
        // Prevent keypresses from bubbling to host page keyboard shortcuts
        pwdInput.addEventListener('keydown', (e) => e.stopPropagation());
        pwdInput.addEventListener('keyup', (e) => e.stopPropagation());
        pwdInput.addEventListener('keypress', (e) => e.stopPropagation());

        setTimeout(() => {
          if (isPopoverOpen && isVaultLocked) {
            pwdInput.focus();
          }
        }, 50);
      }

      if (unlockForm && pwdInput && errBox && unlockSubmitBtn) {
        unlockForm.addEventListener('submit', async (e) => {
          e.preventDefault();
          e.stopPropagation();

          const pwd = pwdInput.value;
          if (!pwd) return;

          errBox.classList.add('hidden');
          errBox.textContent = '';
          unlockSubmitBtn.disabled = true;
          unlockSubmitBtn.innerHTML = `
            <svg class="spin-icon" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.25"/>
              <path d="M12 2a10 10 0 0 1 10 10"/>
            </svg>
            <span>Unlocking...</span>
          `;

          try {
            const unlockRes: MessageResponse = await chrome.runtime.sendMessage({
              type: 'UNLOCK_VAULT',
              payload: { password: pwd },
            });

            if (unlockRes && unlockRes.success) {
              isVaultLocked = false;
              await fetchDomainAccounts();
              renderPopoverAccounts();
              updatePopoverPosition();
              startTicker();
            } else {
              unlockSubmitBtn.disabled = false;
              unlockSubmitBtn.innerHTML = `
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                  <path d="M7 11V7a5 5 0 0 1 9.9-1"/>
                </svg>
                <span>Unlock Vault</span>
              `;
              errBox.textContent = unlockRes?.error || 'Incorrect master password';
              errBox.classList.remove('hidden');
              pwdInput.focus();
              pwdInput.select();
              updatePopoverPosition();
            }
          } catch (err: any) {
            unlockSubmitBtn.disabled = false;
            unlockSubmitBtn.innerHTML = `
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                <path d="M7 11V7a5 5 0 0 1 9.9-1"/>
              </svg>
              <span>Unlock Vault</span>
            `;
            errBox.textContent = err?.message || 'Failed to unlock vault';
            errBox.classList.remove('hidden');
            pwdInput.focus();
            updatePopoverPosition();
          }
        });
      }

      return;
    }

    // Vault is unlocked
    btnLock.classList.remove('hidden');

    if (currentAccounts.length === 0) {
      accountsContainer.innerHTML = `
        <div class="empty-box">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="24" height="24">
            <circle cx="11" cy="11" r="8"/>
            <line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <p>No 2FA account found for <strong>${escapeHtml(window.location.hostname)}</strong></p>
          <p class="empty-sub">Add this account in Buffer Authenticator popup</p>
        </div>
      `;
      return;
    }

    currentAccounts.forEach((acc) => {
      const card = document.createElement('div');
      card.className = 'account-card';
      card.setAttribute('data-id', acc.id);

      const brand = getBrandInfo(acc.issuer || acc.account);
      const period = acc.period || 30;
      const remaining = Math.max(0, acc.secondsRemaining);
      const percent = Math.max(0, Math.min(100, (remaining / period) * 100));

      let stateClass = '';
      if (remaining <= 5) stateClass = 'danger';
      else if (remaining <= 10) stateClass = 'warning';

      card.innerHTML = `
        <div class="card-top">
          <div class="card-avatar" style="background: ${brand.bg}; color: ${brand.color};">
            ${brand.label}
          </div>
          <div class="card-info">
            <span class="card-issuer" title="${acc.issuer || 'Account'}">${acc.issuer || 'Account'}</span>
            <span class="card-account" title="${acc.account}">${acc.account}</span>
          </div>
        </div>

        <div class="card-middle">
          <span class="card-code" data-code="${acc.code}">${formatCode(acc.code)}</span>
          <button type="button" class="btn-fill-action" data-fill="${acc.code}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="12" height="12">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            <span>Fill Code</span>
          </button>
        </div>

        <div class="card-timer-row">
          <div class="timer-track">
            <div class="timer-fill ${stateClass}" style="width: ${percent}%;"></div>
          </div>
          <span class="timer-label">${remaining}s</span>
        </div>
      `;

      // Fill button handler
      const fillBtn = card.querySelector('.btn-fill-action') as HTMLButtonElement;
      const handleFill = (e: Event) => {
        e.stopPropagation();
        fillOtpIntoInput(input, acc.code);
        fillBtn.classList.add('filled');
        fillBtn.innerHTML = `
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" width="12" height="12">
            <polyline points="20 6 9 17 4 12"/>
          </svg>
          <span>Filled!</span>
        `;
        setTimeout(() => {
          closePopover();
        }, 400);
      };

      fillBtn.addEventListener('click', handleFill);
      card.addEventListener('click', (e) => {
        if ((e.target as HTMLElement).closest('.btn-fill-action')) return;
        handleFill(e);
      });

      accountsContainer.appendChild(card);
    });
  }

  /**
   * Update timer bars in real time without tearing down cards
   */
  function updateLiveTimers() {
    currentAccounts.forEach((acc) => {
      const card = accountsContainer.querySelector(`.account-card[data-id="${acc.id}"]`);
      if (!card) return;

      const period = acc.period || 30;
      const remaining = Math.max(0, acc.secondsRemaining);
      const percent = Math.max(0, Math.min(100, (remaining / period) * 100));

      const fillEl = card.querySelector('.timer-fill') as HTMLElement | null;
      const labelEl = card.querySelector('.timer-label') as HTMLElement | null;
      const codeEl = card.querySelector('.card-code') as HTMLElement | null;

      if (fillEl) {
        fillEl.style.width = `${percent}%`;
        fillEl.className = 'timer-fill';
        if (remaining <= 5) fillEl.classList.add('danger');
        else if (remaining <= 10) fillEl.classList.add('warning');
      }

      if (labelEl) {
        labelEl.textContent = `${remaining}s`;
      }

      if (codeEl) {
        codeEl.textContent = formatCode(acc.code);
      }
    });
  }

  /**
   * Fetch matching 2FA accounts from background service worker
   */
  async function fetchDomainAccounts(): Promise<boolean> {
    try {
      const msg: MessageRequest = {
        type: 'GET_CODE_FOR_DOMAIN',
        payload: { domain: window.location.hostname },
      };
      const res: MessageResponse<DomainMatchResult | null> = await chrome.runtime.sendMessage(msg);
      if (res && res.success && res.data) {
        isVaultLocked = Boolean(res.data.isLocked);
        isVaultInitialized = res.data.isInitialized !== false;

        // If exact matches exist, display them; otherwise fallback to other vault accounts
        if (res.data.matched && res.data.matched.length > 0) {
          currentAccounts = res.data.matched;
        } else if (res.data.all && res.data.all.length > 0) {
          currentAccounts = res.data.all;
        } else {
          currentAccounts = [];
        }
        return true;
      } else {
        // Fallback status check
        try {
          const statusRes: MessageResponse<any> = await chrome.runtime.sendMessage({ type: 'GET_STATUS' });
          if (statusRes && statusRes.success && statusRes.data) {
            isVaultLocked = Boolean(statusRes.data.isLocked);
            isVaultInitialized = Boolean(statusRes.data.isInitialized);
          }
        } catch {
          isVaultLocked = false;
        }
        currentAccounts = [];
        return false;
      }
    } catch {
      currentAccounts = [];
      isVaultLocked = false;
      return false;
    }
  }

  /**
   * Open the popover and start the live countdown ticker
   */
  async function openPopover() {
    isPopoverOpen = true;
    badgeBtn.classList.add('active');

    accountsContainer.innerHTML = `
      <div class="empty-box">
        <p>Loading live 2FA code...</p>
      </div>
    `;

    popover.classList.add('open');
    updatePopoverPosition();

    await fetchDomainAccounts();
    renderPopoverAccounts();
    updatePopoverPosition();

    startTicker();
  }

  /**
   * Close the popover and clear ticker
   */
  function closePopover() {
    isPopoverOpen = false;
    badgeBtn.classList.remove('active');
    popover.classList.remove('open');
    if (tickerTimer) {
      clearInterval(tickerTimer);
      tickerTimer = null;
    }
  }

  // Event Listeners
  badgeBtn.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (isPopoverOpen) {
      closePopover();
    } else {
      openPopover();
    }
  });

  btnClose.addEventListener('click', (e) => {
    e.stopPropagation();
    closePopover();
  });

  btnLock.addEventListener('click', async (e) => {
    e.stopPropagation();
    try {
      await chrome.runtime.sendMessage({ type: 'LOCK_VAULT' });
    } catch {
      // Ignored
    }
    isVaultLocked = true;
    currentAccounts = [];
    if (tickerTimer) {
      clearInterval(tickerTimer);
      tickerTimer = null;
    }
    renderPopoverAccounts();
    updatePopoverPosition();
  });

  popover.addEventListener('click', (e) => {
    e.stopPropagation();
  });

  // Global dismiss on click outside or Escape
  document.addEventListener('click', (e) => {
    if (!isPopoverOpen) return;
    const target = e.target as HTMLElement;
    if (target !== input && !host.contains(target)) {
      closePopover();
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && isPopoverOpen) {
      closePopover();
    }
  });

  // Update positions on window scroll or resize
  window.addEventListener('scroll', updateBadgePosition, { passive: true, capture: true });
  window.addEventListener('resize', updateBadgePosition, { passive: true });

  const resizeObserver = new ResizeObserver(() => {
    updateBadgePosition();
  });
  resizeObserver.observe(input);

  input.addEventListener('focus', updateBadgePosition);
  input.addEventListener('input', updateBadgePosition);

  // Initial positioning
  updateBadgePosition();
}

/**
 * Scan document for OTP input fields
 */
const OTP_TARGETED_SELECTOR =
  'input[autocomplete="one-time-code"], input[name*="otp" i], input[name*="2fa" i], input[name*="mfa" i], input[name*="code" i], input[id*="otp" i], input[id*="2fa" i], input[id*="code" i], input[placeholder*="code" i], input[type="tel"], input[type="number"]';

function scanForOtpFields(root: ParentNode = document) {
  const candidates = root.querySelectorAll<HTMLInputElement>(OTP_TARGETED_SELECTOR);
  candidates.forEach((input) => {
    if (isOtpField(input)) {
      attachAutofillTrigger(input);
    }
  });

  if (root === document) {
    const allInputs = document.querySelectorAll<HTMLInputElement>('input');
    if (allInputs.length < 60) {
      allInputs.forEach((input) => {
        if (isOtpField(input)) {
          attachAutofillTrigger(input);
        }
      });
    }
  }
}

// Initial scan
scanForOtpFields();

// Lightweight incremental MutationObserver
const observer = new MutationObserver((mutations) => {
  for (let m = 0; m < mutations.length; m++) {
    const added = mutations[m].addedNodes;
    for (let i = 0; i < added.length; i++) {
      const node = added[i];
      if (node.nodeType === 1) {
        const el = node as Element;
        if (el.tagName === 'INPUT' && isOtpField(el as HTMLInputElement)) {
          attachAutofillTrigger(el as HTMLInputElement);
        } else if (el.firstElementChild) {
          scanForOtpFields(el);
        }
      }
    }
  }
});

function startObserver() {
  const target = document.body || document.documentElement;
  if (target) {
    observer.observe(target, { childList: true, subtree: true });
  }
}

startObserver();

document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    observer.disconnect();
  } else {
    scanForOtpFields();
    startObserver();
  }
});
