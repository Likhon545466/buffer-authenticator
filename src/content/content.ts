/**
 * Content Script: Contextual Inline 2FA Autofill
 *
 * Security & Functional Guarantees:
 * - Isolated from secrets: Content script NEVER receives secrets, only the current generated code.
 * - Uses Shadow DOM to isolate styles from the host page.
 * - Detects 2FA/OTP inputs via standard autocomplete attributes and heuristic signatures.
 * - Dispatches standard DOM events ('input', 'change') for compatibility with SPA frameworks.
 */

import type { MessageRequest, MessageResponse } from '../types';

const CHIP_CONTAINER_CLASS = 'aegis-auth-chip-host';
const PROCESSED_ATTR = 'data-aegis-detected';

/**
 * Heuristic check if an input field is likely an OTP / 2FA field
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

  const keywords = ['otp', '2fa', 'mfa', 'totp', 'token', 'verification_code', 'security code', 'authenticator'];
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
 * Attach inline autofill chip next to the input
 */
function attachAutofillChip(input: HTMLInputElement) {
  input.setAttribute(PROCESSED_ATTR, 'true');

  const wrapper = document.createElement('div');
  wrapper.className = CHIP_CONTAINER_CLASS;
  wrapper.style.display = 'inline-flex';
  wrapper.style.position = 'relative';
  wrapper.style.verticalAlign = 'middle';
  wrapper.style.marginLeft = '8px';
  wrapper.style.zIndex = '2147483640';

  const shadow = wrapper.attachShadow({ mode: 'closed' });

  // Embedded isolated styles and chip markup
  shadow.innerHTML = `
    <style>
      .chip-btn {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: linear-gradient(135deg, #1e293b, #0f172a);
        color: #38bdf8;
        border: 1px solid rgba(56, 189, 248, 0.4);
        border-radius: 9999px;
        padding: 5px 12px;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        font-size: 12px;
        font-weight: 600;
        cursor: pointer;
        user-select: none;
        box-shadow: 0 2px 6px rgba(0, 0, 0, 0.25);
        transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      }
      .chip-btn:hover {
        background: linear-gradient(135deg, #0284c7, #0369a1);
        color: #ffffff;
        border-color: #38bdf8;
        box-shadow: 0 4px 12px rgba(2, 132, 199, 0.4);
        transform: translateY(-1px);
      }
      .chip-btn:active {
        transform: translateY(0);
      }
      .icon {
        width: 14px;
        height: 14px;
        fill: currentColor;
      }
      .chip-tooltip {
        position: absolute;
        bottom: calc(100% + 6px);
        left: 50%;
        transform: translateX(-50%);
        background: #0f172a;
        color: #f8fafc;
        border: 1px solid #334155;
        border-radius: 6px;
        padding: 4px 8px;
        font-size: 11px;
        white-space: nowrap;
        opacity: 0;
        pointer-events: none;
        transition: opacity 0.2s;
        box-shadow: 0 4px 10px rgba(0,0,0,0.3);
      }
      .chip-tooltip.show {
        opacity: 1;
      }
      .success {
        background: #10b981 !important;
        color: #ffffff !important;
        border-color: #059669 !important;
      }
    </style>
    <div style="position: relative;">
      <button type="button" class="chip-btn" id="autofill-btn" title="Fill 2FA code with Buffer Authenticator">
        <svg class="icon" viewBox="0 0 24 24">
          <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/>
        </svg>
        <span id="label-text">Fill 2FA</span>
      </button>
      <div class="chip-tooltip" id="tooltip"></div>
    </div>
  `;

  const btn = shadow.getElementById('autofill-btn') as HTMLButtonElement;
  const labelText = shadow.getElementById('label-text') as HTMLSpanElement;
  const tooltip = shadow.getElementById('tooltip') as HTMLDivElement;

  function showMessage(msg: string, duration = 2500) {
    tooltip.textContent = msg;
    tooltip.classList.add('show');
    setTimeout(() => {
      tooltip.classList.remove('show');
    }, duration);
  }

  btn.addEventListener('click', async (e) => {
    e.preventDefault();
    e.stopPropagation();

    try {
      const msg: MessageRequest = {
        type: 'GET_CODE_FOR_DOMAIN',
        payload: { domain: window.location.hostname },
      };

      const response: MessageResponse<{ code: string; issuer: string; account: string } | null> =
        await chrome.runtime.sendMessage(msg);

      if (!response || !response.success) {
        showMessage(response?.error || 'Vault locked. Open Buffer Authenticator to unlock.');
        return;
      }

      const match = response.data;
      if (!match || !match.code) {
        showMessage(`No 2FA account found for ${window.location.hostname}`);
        return;
      }

      // Populate input value safely
      input.value = match.code;
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true }));

      // Visual feedback
      btn.classList.add('success');
      labelText.textContent = 'Filled!';
      setTimeout(() => {
        btn.classList.remove('success');
        labelText.textContent = 'Fill 2FA';
      }, 2000);
    } catch {
      showMessage('Please unlock Buffer Authenticator');
    }
  });

  // Insert wrapper after input
  if (input.parentNode) {
    if (input.nextSibling) {
      input.parentNode.insertBefore(wrapper, input.nextSibling);
    } else {
      input.parentNode.appendChild(wrapper);
    }
  }
}

/**
 * Fast targeted scan for OTP input fields within a specific root element
 */
const OTP_TARGETED_SELECTOR =
  'input[autocomplete="one-time-code"], input[name*="otp" i], input[name*="2fa" i], input[name*="mfa" i], input[name*="code" i], input[id*="otp" i], input[id*="2fa" i], input[id*="code" i], input[placeholder*="code" i], input[type="tel"], input[type="number"]';

function scanForOtpFields(root: ParentNode = document) {
  // Fast path: query targeted candidates first
  const candidates = root.querySelectorAll<HTMLInputElement>(OTP_TARGETED_SELECTOR);
  candidates.forEach((input) => {
    if (isOtpField(input)) {
      attachAutofillChip(input);
    }
  });

  // Secondary sweep only on small subtrees or initial page load
  if (root === document) {
    const allInputs = document.querySelectorAll<HTMLInputElement>('input');
    // Only check if document hasn't an overwhelming number of inputs
    if (allInputs.length < 50) {
      allInputs.forEach((input) => {
        if (isOtpField(input)) {
          attachAutofillChip(input);
        }
      });
    }
  }
}

// Initial scan
scanForOtpFields();

// Lightweight incremental MutationObserver (only checks added nodes)
const observer = new MutationObserver((mutations) => {
  for (let m = 0; m < mutations.length; m++) {
    const added = mutations[m].addedNodes;
    for (let i = 0; i < added.length; i++) {
      const node = added[i];
      if (node.nodeType === 1) {
        const el = node as Element;
        if (el.tagName === 'INPUT' && isOtpField(el as HTMLInputElement)) {
          attachAutofillChip(el as HTMLInputElement);
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

// Disconnect observer on hidden tabs to save CPU and RAM across background tabs
document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    observer.disconnect();
  } else {
    scanForOtpFields();
    startObserver();
  }
});
