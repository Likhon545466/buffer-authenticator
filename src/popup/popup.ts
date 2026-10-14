/**
 * Popup UI Controller
 *
 * Security Invariants:
 * - Never stores or touches raw secrets.
 * - Requests codes on-demand from the background service worker.
 * - Automatically locks on user command or background trigger.
 */

import { formatOTPCode, parseOtpAuthUri } from '../crypto/totp';
import { parseGoogleAuthMigration } from '../utils/backup-parser';
import { sortAccounts, type SortMode } from '../utils/account-sort';
import { getBrandInfo } from '../utils/brand-icons';
import type { MessageRequest, MessageResponse, PublicAccount, VaultSettings, VaultStatus } from '../types';

// DOM Elements
const viewInit = document.getElementById('view-init') as HTMLDivElement;
const viewLock = document.getElementById('view-lock') as HTMLDivElement;
const viewMain = document.getElementById('view-main') as HTMLDivElement;

const btnHeaderExport = document.getElementById('btn-header-export') as HTMLButtonElement | null;
const btnHeaderLock = document.getElementById('btn-header-lock') as HTMLButtonElement;
const btnHeaderSettings = document.getElementById('btn-header-settings') as HTMLButtonElement;

const formInit = document.getElementById('form-init') as HTMLFormElement;
const initPassword = document.getElementById('init-password') as HTMLInputElement;
const initConfirm = document.getElementById('init-confirm') as HTMLInputElement;
const initError = document.getElementById('init-error') as HTMLDivElement;

const formUnlock = document.getElementById('form-unlock') as HTMLFormElement;
const unlockPassword = document.getElementById('unlock-password') as HTMLInputElement;
const unlockError = document.getElementById('unlock-error') as HTMLDivElement;

const searchInput = document.getElementById('search-input') as HTMLInputElement;
const btnClearSearch = document.getElementById('btn-clear-search') as HTMLButtonElement | null;
const btnSort = document.getElementById('btn-sort') as HTMLButtonElement | null;
const sortCurrentIcon = document.getElementById('sort-current-icon') as HTMLSpanElement | null;
const sortCurrentLabel = document.getElementById('sort-current-label') as HTMLSpanElement | null;
const sortDropdownMenu = document.getElementById('sort-dropdown-menu') as HTMLDivElement | null;
const btnAddAccount = document.getElementById('btn-add-account') as HTMLButtonElement;
const accountsContainer = document.getElementById('accounts-container') as HTMLDivElement;
const emptyState = document.getElementById('empty-state') as HTMLDivElement;
const btnEmptyAdd = document.getElementById('btn-empty-add') as HTMLButtonElement;

const modalAdd = document.getElementById('modal-add') as HTMLDivElement;
const btnCloseModal = document.getElementById('btn-close-modal') as HTMLButtonElement;
const modalError = document.getElementById('modal-error') as HTMLDivElement;
const formAddUri = document.getElementById('form-add-uri') as HTMLFormElement;
const uriInput = document.getElementById('uri-input') as HTMLInputElement;
const formAddManual = document.getElementById('form-add-manual') as HTMLFormElement;

const modalEdit = document.getElementById('modal-edit') as HTMLDivElement;
const btnCloseEditModal = document.getElementById('btn-close-edit-modal') as HTMLButtonElement;
const btnCancelEdit = document.getElementById('btn-cancel-edit') as HTMLButtonElement;
const formEditAccount = document.getElementById('form-edit-account') as HTMLFormElement;
const editId = document.getElementById('edit-id') as HTMLInputElement;
const editIssuer = document.getElementById('edit-issuer') as HTMLInputElement;
const editAccount = document.getElementById('edit-account') as HTMLInputElement;
const editSecret = document.getElementById('edit-secret') as HTMLInputElement;
const editDigits = document.getElementById('edit-digits') as HTMLSelectElement;
const editPeriod = document.getElementById('edit-period') as HTMLSelectElement;
const modalEditError = document.getElementById('modal-edit-error') as HTMLDivElement;

const modalDetails = document.getElementById('modal-details') as HTMLDivElement;
const btnCloseDetailsModal = document.getElementById('btn-close-details-modal') as HTMLButtonElement;
const btnDoneDetails = document.getElementById('btn-done-details') as HTMLButtonElement;
const detailsIssuer = document.getElementById('details-issuer') as HTMLSpanElement;
const detailsAccount = document.getElementById('details-account') as HTMLSpanElement;
const detailsParams = document.getElementById('details-params') as HTMLSpanElement;
const detailsSecret = document.getElementById('details-secret') as HTMLInputElement;
const btnToggleSecret = document.getElementById('btn-toggle-secret') as HTMLButtonElement;
const btnCopySecret = document.getElementById('btn-copy-secret') as HTMLButtonElement;
const detailsNextCode = document.getElementById('details-next-code') as HTMLSpanElement | null;

const modalExport = document.getElementById('modal-export') as HTMLDivElement | null;
const btnCloseExportModal = document.getElementById('btn-close-export-modal') as HTMLButtonElement | null;
const modalExportError = document.getElementById('modal-export-error') as HTMLDivElement | null;
const formExportBackup = document.getElementById('form-export-backup') as HTMLFormElement | null;
const exportPasswordInput = document.getElementById('export-password-input') as HTMLInputElement | null;

const btnBiometricUnlock = document.getElementById('btn-biometric-unlock') as HTMLButtonElement | null;

const btnScanTabQr = document.getElementById('btn-scan-tab-qr') as HTMLButtonElement | null;
const dropzoneQr = document.getElementById('dropzone-qr') as HTMLDivElement | null;
const inputQrFile = document.getElementById('input-qr-file') as HTMLInputElement | null;
const btnBrowseQr = document.getElementById('btn-browse-qr') as HTMLButtonElement | null;
const qrFeedback = document.getElementById('qr-feedback') as HTMLDivElement | null;

const toast = document.getElementById('toast') as HTMLDivElement;
const toastText = document.getElementById('toast-text') as HTMLSpanElement;

// Local transient state
let accounts: PublicAccount[] = [];
let timerInterval: ReturnType<typeof setInterval> | null = null;
let toastTimeout: ReturnType<typeof setTimeout> | null = null;
let clipboardClearTimeout: ReturnType<typeof setTimeout> | null = null;
let activeSecretValue = '';
let activeMenuId: string | null = null;
let currentSortMode: SortMode = 'asc';

/**
 * Send typed message to Service Worker
 */
async function sendMessage<T>(msg: MessageRequest): Promise<MessageResponse<T>> {
  return chrome.runtime.sendMessage(msg);
}

/**
 * Show a toast notification
 */
function showToast(message: string, duration = 2000) {
  toastText.textContent = message;
  toast.classList.add('show');
  if (toastTimeout) clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => {
    toast.classList.remove('show');
  }, duration);
}

/**
 * Display specific view
 */
function switchView(view: 'init' | 'lock' | 'main') {
  viewInit.classList.add('hidden');
  viewLock.classList.add('hidden');
  viewMain.classList.add('hidden');

  if (view === 'init') {
    viewInit.classList.remove('hidden');
    btnHeaderLock.classList.add('hidden');
    btnHeaderExport?.classList.add('hidden');
    btnHeaderSettings.classList.add('hidden');
    initPassword.focus();
  } else if (view === 'lock') {
    viewLock.classList.remove('hidden');
    btnHeaderLock.classList.add('hidden');
    btnHeaderExport?.classList.add('hidden');
    btnHeaderSettings.classList.add('hidden');
    unlockPassword.value = '';
    unlockPassword.focus();

    if (btnBiometricUnlock) {
      sendMessage<VaultStatus>({ type: 'GET_STATUS' })
        .then((statusRes) => {
          if (!statusRes?.success || !statusRes.data?.settings?.biometricEnabled) {
            btnBiometricUnlock.classList.add('hidden');
            chrome.storage.session.remove('biometricToken').catch(() => {});
            return;
          }
          chrome.storage.session.get('biometricToken', (res) => {
            if (res && res.biometricToken) {
              btnBiometricUnlock.classList.remove('hidden');
            } else {
              btnBiometricUnlock.classList.add('hidden');
            }
          });
        })
        .catch(() => {
          btnBiometricUnlock.classList.add('hidden');
        });
    }
  } else if (view === 'main') {
    viewMain.classList.remove('hidden');
    btnHeaderLock.classList.remove('hidden');
    btnHeaderExport?.classList.remove('hidden');
    btnHeaderSettings.classList.remove('hidden');
    searchInput.focus();
  }
}

/**
 * Refresh accounts from background
 */
async function loadAccounts() {
  const res = await sendMessage<PublicAccount[]>({ type: 'GET_ACCOUNTS' });
  if (res.success && res.data) {
    accounts = res.data;
    renderAccounts();
  } else if (res.error?.includes('locked')) {
    switchView('lock');
  }
}



/**
 * Update the sort button appearance and active state in the dropdown menu
 */
function updateSortButtonUI() {
  if (sortCurrentLabel) {
    if (currentSortMode === 'desc') {
      sortCurrentLabel.textContent = 'Z–A';
    } else if (currentSortMode === 'recent') {
      sortCurrentLabel.textContent = 'Recent';
    } else {
      sortCurrentLabel.textContent = 'A–Z';
    }
  }

  if (btnSort) {
    if (currentSortMode === 'desc') {
      btnSort.title = 'Sort accounts: Z to A (Descending)';
    } else if (currentSortMode === 'recent') {
      btnSort.title = 'Sort accounts: Recently Added';
    } else {
      btnSort.title = 'Sort accounts: A to Z (Ascending)';
    }
  }

  if (sortCurrentIcon) {
    if (currentSortMode === 'desc') {
      sortCurrentIcon.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
          <path d="M11 5h4"/>
          <path d="M11 9h7"/>
          <path d="M11 13h10"/>
          <path d="M3 7l3-3 3 3"/>
          <path d="M6 6v14"/>
        </svg>
      `;
    } else if (currentSortMode === 'recent') {
      sortCurrentIcon.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
          <circle cx="12" cy="12" r="10"/>
          <polyline points="12 6 12 12 16 14"/>
        </svg>
      `;
    } else {
      sortCurrentIcon.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
          <path d="M11 5h10"/>
          <path d="M11 9h7"/>
          <path d="M11 13h4"/>
          <path d="M3 17l3 3 3-3"/>
          <path d="M6 18V4"/>
        </svg>
      `;
    }
  }

  if (sortDropdownMenu) {
    sortDropdownMenu.querySelectorAll('.sort-option').forEach((btn) => {
      const mode = btn.getAttribute('data-sort');
      if (mode === currentSortMode) {
        btn.classList.add('active');
      } else {
        btn.classList.remove('active');
      }
    });
  }
}

function openSortMenu() {
  document.querySelectorAll('.account-dropdown-menu').forEach((m) => m.classList.add('hidden'));
  document.querySelectorAll('.btn-card-menu').forEach((b) => b.classList.remove('active'));
  document.querySelectorAll('.account-card').forEach((c) => c.classList.remove('menu-open'));
  activeMenuId = null;

  if (!sortDropdownMenu || !btnSort) return;
  sortDropdownMenu.classList.remove('hidden');
  btnSort.classList.add('active');
  btnSort.setAttribute('aria-expanded', 'true');
}

function closeSortMenu() {
  if (!sortDropdownMenu || !btnSort) return;
  sortDropdownMenu.classList.add('hidden');
  btnSort.classList.remove('active');
  btnSort.setAttribute('aria-expanded', 'false');
}

function toggleSortMenu() {
  if (sortDropdownMenu?.classList.contains('hidden')) {
    openSortMenu();
  } else {
    closeSortMenu();
  }
}

function setSortMode(mode: SortMode) {
  currentSortMode = mode;
  chrome.storage.local.set({ accountSortOrder: mode }).catch(() => {});
  updateSortButtonUI();
  closeSortMenu();
  renderAccounts();

  if (mode === 'asc') {
    showToast('Sorted: Name (A → Z)');
  } else if (mode === 'desc') {
    showToast('Sorted: Name (Z → A)');
  } else if (mode === 'recent') {
    showToast('Sorted: Recently Added');
  }
}

/**
 * Close all active card dropdown menus
 */
function closeAllMenus() {
  document.querySelectorAll('.account-dropdown-menu').forEach((m) => m.classList.add('hidden'));
  document.querySelectorAll('.btn-card-menu').forEach((b) => b.classList.remove('active'));
  document.querySelectorAll('.account-card').forEach((c) => c.classList.remove('menu-open'));
  activeMenuId = null;
  closeSortMenu();
}

/**
 * Copy code to clipboard with visual feedback
 */
function copyAccountCode(acc: PublicAccount, card?: HTMLElement) {
  navigator.clipboard.writeText(acc.code).then(() => {
    if (card) {
      card.classList.add('copied-flash');
      setTimeout(() => card.classList.remove('copied-flash'), 350);
    }
    showToast(`Copied ${acc.issuer || 'code'} (${acc.code}) • Clears in 30s`);

    if (clipboardClearTimeout) clearTimeout(clipboardClearTimeout);
    clipboardClearTimeout = setTimeout(async () => {
      try {
        const text = await navigator.clipboard.readText();
        if (text === acc.code) {
          await navigator.clipboard.writeText('');
        }
      } catch {}
    }, 30000);
  });
}

/**
 * Copy secret key to clipboard
 */
async function handleCopySecret(acc: PublicAccount) {
  const res = await sendMessage<any>({ type: 'GET_ACCOUNT_DETAIL', payload: { id: acc.id } });
  if (res.success && res.data?.secret) {
    const sec = res.data.secret;
    await navigator.clipboard.writeText(sec);
    showToast('Secret key copied! • Clears in 30s');

    if (clipboardClearTimeout) clearTimeout(clipboardClearTimeout);
    clipboardClearTimeout = setTimeout(async () => {
      try {
        const text = await navigator.clipboard.readText();
        if (text === sec) {
          await navigator.clipboard.writeText('');
        }
      } catch {}
    }, 30000);
  } else {
    showToast(res.error || 'Failed to retrieve secret key');
  }
}



/**
 * Delete account with confirmation
 */
async function handleDeleteAccount(acc: PublicAccount) {
  if (confirm(`Remove "${acc.issuer || acc.account}" from Buffer Authenticator?`)) {
    const res = await sendMessage({ type: 'DELETE_ACCOUNT', payload: { id: acc.id } });
    if (res.success) {
      showToast('Account removed');
      await loadAccounts();
    } else {
      showToast(res.error || 'Failed to remove account');
    }
  }
}

/**
 * Open Edit Account Modal
 */
function openEditModal(acc: PublicAccount) {
  modalEdit.classList.remove('hidden');
  modalEditError.classList.add('hidden');
  editId.value = acc.id;
  editIssuer.value = acc.issuer;
  editAccount.value = acc.account;
  editSecret.value = '';
  editDigits.value = String(acc.digits || 6);
  editPeriod.value = String(acc.period || 30);
  editIssuer.focus();
}

function closeEditModal() {
  modalEdit.classList.add('hidden');
}

/**
 * Open Details Modal
 */
async function openDetailsModal(acc: PublicAccount) {
  const res = await sendMessage<any>({ type: 'GET_ACCOUNT_DETAIL', payload: { id: acc.id } });
  if (!res.success || !res.data) {
    showToast(res.error || 'Failed to load details');
    return;
  }

  const detail = res.data;
  activeSecretValue = detail.secret;

  detailsIssuer.textContent = detail.issuer || '-';
  detailsAccount.textContent = detail.account || '-';
  detailsParams.textContent = `${detail.digits || 6} Digits • ${detail.period || 30}s Period • ${detail.algorithm || 'SHA1'}`;
  detailsSecret.value = activeSecretValue;
  detailsSecret.type = 'password';

  if (detailsNextCode) {
    detailsNextCode.textContent = acc.nextCode ? formatOTPCode(acc.nextCode) : '-';
  }

  modalDetails.classList.remove('hidden');
}

function closeDetailsModal() {
  modalDetails.classList.add('hidden');
  activeSecretValue = '';
}

/**
 * Open Export Modal
 */
function openExportModal() {
  closeAllMenus();
  if (!modalExport) return;
  modalExport.classList.remove('hidden');
  modalExportError?.classList.add('hidden');
  if (exportPasswordInput) {
    exportPasswordInput.value = '';
    exportPasswordInput.focus();
  }
}

function closeExportModal() {
  if (!modalExport) return;
  modalExport.classList.add('hidden');
  if (exportPasswordInput) {
    exportPasswordInput.value = '';
  }
}

/**
 * Render accounts list with linear progress bar timer & 3-dot kebab menu
 */
function renderAccounts() {
  const query = searchInput.value.toLowerCase().trim();
  const filtered = accounts.filter((acc) => {
    return (
      acc.issuer.toLowerCase().includes(query) ||
      acc.account.toLowerCase().includes(query)
    );
  });

  const sorted = sortAccounts(filtered, currentSortMode);

  accountsContainer.innerHTML = '';

  if (sorted.length === 0) {
    emptyState.classList.remove('hidden');
    return;
  }
  emptyState.classList.add('hidden');

  sorted.forEach((acc) => {
    const card = document.createElement('div');
    card.className = 'account-card';
    card.setAttribute('data-id', acc.id);

    const period = acc.period || 30;
    const remaining = Math.max(0, acc.secondsRemaining);
    const percent = Math.max(0, Math.min(100, (remaining / period) * 100));
    const dashOffset = (69.12 * (1 - remaining / period)).toFixed(2);

    let stateClass = '';
    if (remaining <= 5) {
      stateClass = 'danger';
    } else if (remaining <= 10) {
      stateClass = 'warning';
    }

    const isEmail = acc.account && acc.account.includes('@');
    const brand = getBrandInfo(acc.issuer || acc.account);

    card.innerHTML = `
      <div class="account-main">
        <div class="service-avatar" style="background: ${brand.bg}; color: ${brand.color};">
          ${brand.svg ? brand.svg : brand.label}
        </div>
        <div class="account-details">
          <div class="issuer-name" title="${escapeHtml(acc.issuer || 'Account')}">
            ${escapeHtml(acc.issuer || 'Account')}
          </div>
          <div class="account-label" title="${escapeHtml(acc.account)}">
            ${isEmail ? `
              <svg class="account-label-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13">
                <rect x="2" y="4" width="20" height="16" rx="2"/>
                <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/>
              </svg>
            ` : `
              <svg class="account-label-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13">
                <path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/>
                <circle cx="12" cy="7" r="4"/>
              </svg>
            `}
            <span class="account-email-text">${escapeHtml(acc.account)}</span>
          </div>
        </div>
      </div>
      <div class="code-action-box">
        <div class="code-container" data-timer-id="${acc.id}" title="${remaining}s remaining • Click card to copy code">
          <div class="code-display">${formatOTPCode(acc.code)}</div>
          <div class="radial-timer-box" title="${remaining}s remaining">
            <svg class="radial-ring" viewBox="0 0 28 28">
              <circle class="radial-ring-bg" cx="14" cy="14" r="11" />
              <circle class="radial-ring-fill ${stateClass}" cx="14" cy="14" r="11" style="stroke-dashoffset: ${dashOffset};" />
            </svg>
            <span class="radial-ring-text ${stateClass}">${remaining}</span>
          </div>
          <div class="chip-progress-track">
            <div class="chip-progress-fill ${stateClass}" style="width: ${percent}%;"></div>
          </div>
        </div>
        <div class="account-menu-wrap">
          <button type="button" class="btn-card-menu" data-id="${acc.id}" title="More options" aria-label="More options for ${escapeHtml(acc.issuer || acc.account)}">
            <svg viewBox="0 0 24 24" fill="currentColor" width="16" height="16">
              <circle cx="12" cy="5" r="2.2"/>
              <circle cx="12" cy="12" r="2.2"/>
              <circle cx="12" cy="19" r="2.2"/>
            </svg>
          </button>
          <div class="account-dropdown-menu hidden" data-menu-id="${acc.id}">
            <button type="button" class="dropdown-item" data-action="copy">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="15" height="15">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
              </svg>
              <span>Copy Code</span>
            </button>
            <button type="button" class="dropdown-item" data-action="edit">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="15" height="15">
                <path d="M12 20h9"/>
                <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/>
              </svg>
              <span>Edit Account</span>
            </button>
            <button type="button" class="dropdown-item" data-action="copy-secret">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="15" height="15">
                <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
              </svg>
              <span>Copy Secret Key</span>
            </button>
            <button type="button" class="dropdown-item" data-action="view-details">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="15" height="15">
                <circle cx="12" cy="12" r="10"/>
                <line x1="12" y1="16" x2="12" y2="12"/>
                <line x1="12" y1="8" x2="12.01" y2="8"/>
              </svg>
              <span>View Details</span>
            </button>
            <button type="button" class="dropdown-item" data-action="export-backup">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="15" height="15">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                <polyline points="7 10 12 15 17 10"/>
                <line x1="12" y1="15" x2="12" y2="3"/>
              </svg>
              <span>Export & Backup</span>
            </button>
            <div class="dropdown-divider"></div>
            <button type="button" class="dropdown-item text-danger" data-action="delete">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="15" height="15">
                <polyline points="3 6 5 6 21 6"/>
                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
              </svg>
              <span>Delete Account</span>
            </button>
          </div>
        </div>
      </div>
    `;

    // Click card to copy code (unless clicking inside the 3-dot menu)
    card.addEventListener('click', (e) => {
      const target = e.target as HTMLElement;
      if (target.closest('.account-menu-wrap')) return;

      copyAccountCode(acc, card);
    });

    // 3-dot menu toggle button
    const menuBtn = card.querySelector('.btn-card-menu') as HTMLButtonElement;
    const dropdown = card.querySelector('.account-dropdown-menu') as HTMLDivElement;

    menuBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const isCurrentlyOpen = !dropdown.classList.contains('hidden');
      closeAllMenus();
      if (!isCurrentlyOpen) {
        const rect = menuBtn.getBoundingClientRect();
        if (rect.bottom + 230 > window.innerHeight) {
          dropdown.classList.add('open-up');
        } else {
          dropdown.classList.remove('open-up');
        }
        dropdown.classList.remove('hidden');
        menuBtn.classList.add('active');
        card.classList.add('menu-open');
        activeMenuId = acc.id;
      }
    });

    // Dropdown actions handler
    dropdown.addEventListener('click', async (e) => {
      e.stopPropagation();
      const item = (e.target as HTMLElement).closest('.dropdown-item') as HTMLButtonElement | null;
      if (!item) return;

      const action = item.getAttribute('data-action');
      closeAllMenus();

      if (action === 'copy') {
        copyAccountCode(acc, card);
      } else if (action === 'edit') {
        openEditModal(acc);
      } else if (action === 'copy-secret') {
        await handleCopySecret(acc);
      } else if (action === 'view-details') {
        await openDetailsModal(acc);
      } else if (action === 'export-backup') {
        openExportModal();
      } else if (action === 'delete') {
        await handleDeleteAccount(acc);
      }
    });

    accountsContainer.appendChild(card);
  });
}

function escapeHtml(str: string): string {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

/**
 * In-place update of timer bars without tearing down card elements or menus
 */
function updateTimerBars() {
  accounts.forEach((acc) => {
    const codeContainer = accountsContainer.querySelector(`.code-container[data-timer-id="${acc.id}"]`);
    if (!codeContainer) return;

    const period = acc.period || 30;
    const remaining = Math.max(0, acc.secondsRemaining);
    const percent = Math.max(0, Math.min(100, (remaining / period) * 100));
    const dashOffset = (69.12 * (1 - remaining / period)).toFixed(2);

    let stateClass = '';
    if (remaining <= 5) {
      stateClass = 'danger';
    } else if (remaining <= 10) {
      stateClass = 'warning';
    }

    const fillEl = codeContainer.querySelector('.chip-progress-fill') as HTMLElement | null;
    if (fillEl) {
      fillEl.style.width = `${percent}%`;
      fillEl.className = `chip-progress-fill ${stateClass}`.trim();
    }

    const ringFillEl = codeContainer.querySelector('.radial-ring-fill') as SVGCircleElement | null;
    if (ringFillEl) {
      ringFillEl.style.strokeDashoffset = `${dashOffset}`;
      ringFillEl.setAttribute('class', `radial-ring-fill ${stateClass}`.trim());
    }

    const ringTextEl = codeContainer.querySelector('.radial-ring-text') as HTMLElement | null;
    if (ringTextEl) {
      ringTextEl.textContent = String(remaining);
      ringTextEl.className = `radial-ring-text ${stateClass}`.trim();
    }

    codeContainer.setAttribute('title', `${remaining}s remaining • Click card to copy code`);
  });
}

/**
 * Start 1-second countdown ticker (pauses when hidden to save CPU/RAM)
 */
function startTicker() {
  if (timerInterval) clearInterval(timerInterval);
  timerInterval = setInterval(() => {
    if (document.hidden) return;

    let needsRefresh = false;
    accounts.forEach((acc) => {
      acc.secondsRemaining -= 1;
      if (acc.secondsRemaining <= 0) {
        needsRefresh = true;
      }
    });

    if (needsRefresh) {
      loadAccounts();
    } else {
      updateTimerBars();
    }
  }, 1000);
}

/**
 * Sync status with service worker
 */
async function checkStatus() {
  try {
    const res = await sendMessage<VaultStatus>({ type: 'GET_STATUS' });
    if (!res.success || !res.data) {
      switchView('init');
      return;
    }

    const { isInitialized, isLocked } = res.data;
    if (!isInitialized) {
      switchView('init');
    } else if (isLocked) {
      switchView('lock');
    } else {
      switchView('main');
      await loadAccounts();
      startTicker();
    }
  } catch (err: any) {
    switchView('init');
  }
}

// Event Listeners
formInit.addEventListener('submit', async (e) => {
  e.preventDefault();
  initError.classList.add('hidden');

  const p1 = initPassword.value;
  const p2 = initConfirm.value;

  if (p1 !== p2) {
    initError.textContent = 'Passwords do not match';
    initError.classList.remove('hidden');
    return;
  }
  if (p1.length < 8) {
    initError.textContent = 'Password must be at least 8 characters';
    initError.classList.remove('hidden');
    return;
  }

  const res = await sendMessage({ type: 'INIT_VAULT', payload: { password: p1 } });
  if (res.success) {
    showToast('Vault created successfully');
    switchView('main');
    await loadAccounts();
    startTicker();
  } else {
    initError.textContent = res.error || 'Failed to create vault';
    initError.classList.remove('hidden');
  }
});

formUnlock.addEventListener('submit', async (e) => {
  e.preventDefault();
  unlockError.classList.add('hidden');

  const p = unlockPassword.value;
  const res = await sendMessage({ type: 'UNLOCK_VAULT', payload: { password: p } });
  if (res.success) {
    const statusRes = await sendMessage<VaultStatus>({ type: 'GET_STATUS' }).catch(() => null);
    if (statusRes?.success && statusRes.data?.settings?.biometricEnabled) {
      await chrome.storage.session.set({ biometricToken: p }).catch(() => {});
    } else {
      await chrome.storage.session.remove('biometricToken').catch(() => {});
    }
    switchView('main');
    await loadAccounts();
    startTicker();
  } else {
    unlockError.textContent = res.error || 'Incorrect master password';
    unlockError.classList.remove('hidden');
  }
});

btnBiometricUnlock?.addEventListener('click', async () => {
  try {
    const statusRes = await sendMessage<VaultStatus>({ type: 'GET_STATUS' }).catch(() => null);
    if (!statusRes?.success || !statusRes.data?.settings?.biometricEnabled) {
      btnBiometricUnlock.classList.add('hidden');
      await chrome.storage.session.remove('biometricToken').catch(() => {});
      showToast('Biometric unlock is disabled in settings');
      return;
    }

    const res = await chrome.storage.session.get('biometricToken');
    const token = res?.biometricToken;
    if (!token) {
      btnBiometricUnlock.classList.add('hidden');
      showToast('Enter password to authenticate first');
      return;
    }

    if (window.PublicKeyCredential) {
      try {
        await navigator.credentials.get({
          publicKey: {
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            timeout: 60000,
            userVerification: 'preferred',
          },
        });
      } catch (credErr) {
        console.warn('WebAuthn prompt rejected:', credErr);
        return;
      }
    }

    const unlockRes = await sendMessage({ type: 'UNLOCK_VAULT', payload: { password: token } });
    if (unlockRes.success) {
      switchView('main');
      await loadAccounts();
      startTicker();
      showToast('Unlocked via Biometrics!');
    } else {
      unlockError.textContent = unlockRes.error || 'Failed to unlock';
      unlockError.classList.remove('hidden');
    }
  } catch (err: any) {
    showToast('Biometric unlock cancelled');
  }
});

btnHeaderLock.addEventListener('click', async () => {
  await sendMessage({ type: 'LOCK_VAULT' });
  if (timerInterval) clearInterval(timerInterval);
  accounts = [];
  switchView('lock');
  showToast('Vault locked');
});

btnHeaderSettings.addEventListener('click', async () => {
  const statusRes = await sendMessage<VaultStatus>({ type: 'GET_STATUS' });
  if (!statusRes.success || !statusRes.data || statusRes.data.isLocked || !statusRes.data.isInitialized) {
    showToast('Unlock vault to access settings');
    return;
  }
  if (chrome.runtime.openOptionsPage) {
    chrome.runtime.openOptionsPage();
  } else {
    window.open(chrome.runtime.getURL('src/options/options.html'));
  }
});

searchInput.addEventListener('input', () => {
  if (searchInput.value.trim().length > 0) {
    btnClearSearch?.classList.remove('hidden');
  } else {
    btnClearSearch?.classList.add('hidden');
  }
  closeAllMenus();
  renderAccounts();
});

btnClearSearch?.addEventListener('click', () => {
  searchInput.value = '';
  btnClearSearch.classList.add('hidden');
  searchInput.focus();
  closeAllMenus();
  renderAccounts();
});

// Edit Modal Handling
btnCloseEditModal.addEventListener('click', closeEditModal);
btnCancelEdit.addEventListener('click', closeEditModal);

formEditAccount.addEventListener('submit', async (e) => {
  e.preventDefault();
  modalEditError.classList.add('hidden');

  const id = editId.value;
  const issuer = editIssuer.value.trim();
  const account = editAccount.value.trim();
  const digits = parseInt(editDigits.value, 10);
  const period = parseInt(editPeriod.value, 10);
  const newSecret = editSecret.value.trim();
  const payload: any = {
    id,
    issuer,
    account,
    digits,
    period,
  };
  if (newSecret) {
    payload.secret = newSecret;
  }

  const res = await sendMessage({ type: 'UPDATE_ACCOUNT', payload });
  if (res.success) {
    closeEditModal();
    showToast('Account updated');
    await loadAccounts();
  } else {
    modalEditError.textContent = res.error || 'Failed to update account';
    modalEditError.classList.remove('hidden');
  }
});

// Details Modal Handling
btnCloseDetailsModal.addEventListener('click', closeDetailsModal);
btnDoneDetails.addEventListener('click', closeDetailsModal);

btnToggleSecret.addEventListener('click', () => {
  detailsSecret.type = detailsSecret.type === 'password' ? 'text' : 'password';
});

btnCopySecret.addEventListener('click', () => {
  if (activeSecretValue) {
    navigator.clipboard.writeText(activeSecretValue).then(() => {
      showToast('Secret key copied!');
    });
  }
});

// Sort Button and Dropdown Menu Event Handlers
btnSort?.addEventListener('click', (e) => {
  e.stopPropagation();
  toggleSortMenu();
});

sortDropdownMenu?.addEventListener('click', (e) => {
  e.stopPropagation();
  const option = (e.target as HTMLElement).closest('.sort-option') as HTMLButtonElement | null;
  if (!option) return;
  const mode = option.getAttribute('data-sort') as SortMode | null;
  if (mode) {
    setSortMode(mode);
  }
});

// Global outside-click and escape handlers
document.addEventListener('click', (e) => {
  const target = e.target as HTMLElement;
  if (!target.closest('.account-menu-wrap')) {
    document.querySelectorAll('.account-dropdown-menu').forEach((m) => m.classList.add('hidden'));
    document.querySelectorAll('.btn-card-menu').forEach((b) => b.classList.remove('active'));
    document.querySelectorAll('.account-card').forEach((c) => c.classList.remove('menu-open'));
    activeMenuId = null;
  }
  if (!target.closest('.sort-control-wrap')) {
    closeSortMenu();
  }
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    if (sortDropdownMenu && !sortDropdownMenu.classList.contains('hidden')) {
      closeSortMenu();
      return;
    }
    if (activeMenuId) {
      closeAllMenus();
      return;
    }
    if (modalExport && !modalExport.classList.contains('hidden')) {
      closeExportModal();
      return;
    }
    if (!modalEdit.classList.contains('hidden')) {
      closeEditModal();
      return;
    }
    if (!modalDetails.classList.contains('hidden')) {
      closeDetailsModal();
      return;
    }
    if (!modalAdd.classList.contains('hidden')) {
      closeAddModal();
      return;
    }
  }
});

// Export Modal Handling
btnHeaderExport?.addEventListener('click', openExportModal);
btnCloseExportModal?.addEventListener('click', closeExportModal);

formExportBackup?.addEventListener('submit', async (e) => {
  e.preventDefault();
  if (modalExportError) modalExportError.classList.add('hidden');

  const password = exportPasswordInput?.value || '';
  if (!password) {
    if (modalExportError) {
      modalExportError.textContent = 'Please enter your master password';
      modalExportError.classList.remove('hidden');
    }
    return;
  }

  const res = await sendMessage<string>({
    type: 'EXPORT_VAULT',
    payload: { password },
  });

  if (res.success && res.data) {
    const blob = new Blob([res.data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `buffer-authenticator-backup-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    closeExportModal();
    showToast('Backup downloaded successfully!');
  } else {
    if (modalExportError) {
      modalExportError.textContent = res.error || 'Export failed: Incorrect master password';
      modalExportError.classList.remove('hidden');
    }
  }
});

// Add Modal Handling
function openAddModal() {
  modalAdd.classList.remove('hidden');
  modalError.classList.add('hidden');
  uriInput.value = '';
  uriInput.focus();
}

function closeAddModal() {
  modalAdd.classList.add('hidden');
}

btnAddAccount.addEventListener('click', openAddModal);
btnEmptyAdd.addEventListener('click', openAddModal);
btnCloseModal.addEventListener('click', closeAddModal);

// Modal Tabs
document.querySelectorAll('.tab-btn').forEach((tab) => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach((t) => t.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach((p) => p.classList.add('hidden'));

    tab.classList.add('active');
    const targetId = tab.getAttribute('data-tab');
    if (targetId) {
      document.getElementById(targetId)?.classList.remove('hidden');
    }
  });
});



// QR Code Scanner Handlers
async function processQrImage(imageSource: HTMLImageElement | ImageBitmap | ImageData) {
  let rawQrValue = '';
  if ('BarcodeDetector' in window) {
    try {
      const detector = new (window as any).BarcodeDetector({ formats: ['qr_code'] });
      const detected = await detector.detect(imageSource);
      if (detected && detected.length > 0) {
        rawQrValue = detected[0].rawValue;
      }
    } catch (e: any) {
      console.warn('BarcodeDetector error:', e);
    }
  }

  if (!rawQrValue) {
    if (qrFeedback) {
      qrFeedback.className = 'qr-feedback error';
      qrFeedback.textContent = 'No QR code found in image. Please ensure the QR is visible.';
      qrFeedback.classList.remove('hidden');
    }
    return;
  }

  try {
    if (rawQrValue.startsWith('otpauth://')) {
      const parsed = parseOtpAuthUri(rawQrValue);
      const payload = {
        issuer: parsed.issuer || 'QR Code',
        account: parsed.account || 'Account',
        secret: parsed.secret,
        algorithm: parsed.algorithm,
        digits: parsed.digits,
        period: parsed.period,
        type: parsed.type,
        category: 'General',
      };
      const res = await sendMessage({ type: 'ADD_ACCOUNT', payload });
      if (res.success) {
        closeAddModal();
        showToast('Account added from QR code!');
        await loadAccounts();
        return;
      }
    } else if (rawQrValue.startsWith('otpauth-migration://')) {
      const parsedAccounts = parseGoogleAuthMigration(rawQrValue);
      if (parsedAccounts.length > 0) {
        for (const acc of parsedAccounts) {
          await sendMessage({ type: 'ADD_ACCOUNT', payload: { ...acc, category: 'General' } });
        }
        closeAddModal();
        showToast(`Imported ${parsedAccounts.length} account(s) from QR!`);
        await loadAccounts();
        return;
      }
    } else {
      const payload = {
        issuer: 'QR Import',
        account: 'Account',
        secret: rawQrValue,
        algorithm: 'SHA1' as const,
        digits: 6,
        period: 30,
        type: 'totp' as const,
        category: 'General',
      };
      const res = await sendMessage({ type: 'ADD_ACCOUNT', payload });
      if (res.success) {
        closeAddModal();
        showToast('Account added from QR code!');
        await loadAccounts();
        return;
      }
    }
  } catch (err: any) {
    if (qrFeedback) {
      qrFeedback.className = 'qr-feedback error';
      qrFeedback.textContent = err.message || 'Invalid QR code content';
      qrFeedback.classList.remove('hidden');
    }
  }
}

async function scanActiveTabQr() {
  if (qrFeedback) {
    qrFeedback.className = 'qr-feedback';
    qrFeedback.textContent = 'Scanning tab screenshot...';
    qrFeedback.classList.remove('hidden');
  }

  try {
    const dataUrl = await new Promise<string>((resolve, reject) => {
      chrome.tabs.captureVisibleTab(null as any, { format: 'png' }, (res) => {
        if (chrome.runtime.lastError || !res) {
          reject(chrome.runtime.lastError || new Error('Failed to capture active tab'));
        } else {
          resolve(res);
        }
      });
    });

    const img = new Image();
    img.src = dataUrl;
    await img.decode();
    await processQrImage(img);
  } catch (err: any) {
    if (qrFeedback) {
      qrFeedback.className = 'qr-feedback error';
      qrFeedback.textContent = 'Could not scan tab: ' + (err.message || 'Make sure tab with QR code is open.');
      qrFeedback.classList.remove('hidden');
    }
  }
}

function handleQrFile(file: File) {
  if (!file.type.startsWith('image/')) {
    if (qrFeedback) {
      qrFeedback.className = 'qr-feedback error';
      qrFeedback.textContent = 'Please choose an image file (PNG, JPG, WebP)';
      qrFeedback.classList.remove('hidden');
    }
    return;
  }

  const reader = new FileReader();
  reader.onload = async () => {
    const img = new Image();
    img.src = reader.result as string;
    await img.decode();
    await processQrImage(img);
  };
  reader.readAsDataURL(file);
}

btnScanTabQr?.addEventListener('click', scanActiveTabQr);

btnBrowseQr?.addEventListener('click', () => {
  inputQrFile?.click();
});

dropzoneQr?.addEventListener('click', (e) => {
  if (e.target !== btnBrowseQr) {
    inputQrFile?.click();
  }
});

dropzoneQr?.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropzoneQr.classList.add('dragover');
});

dropzoneQr?.addEventListener('dragleave', () => {
  dropzoneQr.classList.remove('dragover');
});

dropzoneQr?.addEventListener('drop', (e) => {
  e.preventDefault();
  dropzoneQr.classList.remove('dragover');
  if (e.dataTransfer && e.dataTransfer.files.length > 0) {
    handleQrFile(e.dataTransfer.files[0]);
  }
});

inputQrFile?.addEventListener('change', () => {
  if (inputQrFile.files && inputQrFile.files.length > 0) {
    handleQrFile(inputQrFile.files[0]);
  }
});

// Add URI Form
formAddUri.addEventListener('submit', async (e) => {
  e.preventDefault();
  modalError.classList.add('hidden');

  const input = uriInput.value.trim();
  try {
    let payload;
    if (input.startsWith('otpauth://')) {
      const parsed = parseOtpAuthUri(input);
      payload = {
        issuer: parsed.issuer || 'Unknown',
        account: parsed.account || 'Account',
        secret: parsed.secret,
        algorithm: parsed.algorithm,
        digits: parsed.digits,
        period: parsed.period,
        type: parsed.type,
      };
    } else {
      payload = {
        issuer: 'Manual Entry',
        account: 'TOTP Account',
        secret: input,
        algorithm: 'SHA1' as const,
        digits: 6,
        period: 30,
        type: 'totp' as const,
      };
    }

    const res = await sendMessage({ type: 'ADD_ACCOUNT', payload });
    if (res.success) {
      closeAddModal();
      showToast('Account added');
      await loadAccounts();
    } else {
      modalError.textContent = res.error || 'Failed to add account';
      modalError.classList.remove('hidden');
    }
  } catch (err: any) {
    modalError.textContent = err.message || 'Invalid URI or secret key';
    modalError.classList.remove('hidden');
  }
});

// Add Manual Form
formAddManual.addEventListener('submit', async (e) => {
  e.preventDefault();
  modalError.classList.add('hidden');

  const issuer = (document.getElementById('manual-issuer') as HTMLInputElement).value.trim();
  const account = (document.getElementById('manual-account') as HTMLInputElement).value.trim();
  const secret = (document.getElementById('manual-secret') as HTMLInputElement).value.trim();
  const digits = parseInt((document.getElementById('manual-digits') as HTMLSelectElement).value, 10);
  const period = parseInt((document.getElementById('manual-period') as HTMLSelectElement).value, 10);
  const payload = {
    issuer,
    account,
    secret,
    algorithm: 'SHA1' as const,
    digits,
    period,
    type: 'totp' as const,
  };

  const res = await sendMessage({ type: 'ADD_ACCOUNT', payload });
  if (res.success) {
    closeAddModal();
    showToast('Account added');
    await loadAccounts();
  } else {
    modalError.textContent = res.error || 'Failed to add account';
    modalError.classList.remove('hidden');
  }
});

// Password visibility toggles
document.querySelectorAll('.password-toggle-btn').forEach((btn) => {
  btn.addEventListener('click', () => {
    const targetId = btn.getAttribute('data-target');
    if (!targetId) return;
    const input = document.getElementById(targetId) as HTMLInputElement;
    if (input) {
      input.type = input.type === 'password' ? 'text' : 'password';
    }
  });
});

// Memory and timer cleanup on page unload / hide
window.addEventListener('pagehide', () => {
  if (timerInterval) {
    clearInterval(timerInterval);
    timerInterval = null;
  }
  if (toastTimeout) {
    clearTimeout(toastTimeout);
    toastTimeout = null;
  }
  accounts = [];
});

document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    if (timerInterval) {
      clearInterval(timerInterval);
      timerInterval = null;
    }
  } else {
    checkStatus();
  }
});

// Restore saved sort order preference
chrome.storage.local.get(['accountSortOrder'], (result) => {
  if (result?.accountSortOrder === 'desc' || result?.accountSortOrder === 'recent' || result?.accountSortOrder === 'asc') {
    currentSortMode = result.accountSortOrder;
    updateSortButtonUI();
  }
});

// Biometric state synchronization
if (chrome.storage && chrome.storage.session && chrome.storage.session.onChanged) {
  chrome.storage.session.onChanged.addListener((changes) => {
    if (changes.biometricToken && !changes.biometricToken.newValue && btnBiometricUnlock) {
      btnBiometricUnlock.classList.add('hidden');
    }
  });
}

if (chrome.storage && chrome.storage.onChanged) {
  chrome.storage.onChanged.addListener((changes) => {
    if (changes.settings) {
      const newSettings = changes.settings.newValue as VaultSettings | undefined;
      if (newSettings && !newSettings.biometricEnabled) {
        chrome.storage.session.remove('biometricToken').catch(() => {});
        if (btnBiometricUnlock) {
          btnBiometricUnlock.classList.add('hidden');
        }
      }
    }
  });
}

// Bootstrap
checkStatus();
