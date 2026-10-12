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
import type { MessageRequest, MessageResponse, PublicAccount, VaultStatus } from '../types';

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
    initPassword.focus();
  } else if (view === 'lock') {
    viewLock.classList.remove('hidden');
    btnHeaderLock.classList.add('hidden');
    btnHeaderExport?.classList.add('hidden');
    unlockPassword.value = '';
    unlockPassword.focus();

    if (btnBiometricUnlock) {
      chrome.storage.session.get('biometricToken', (res) => {
        if (res && res.biometricToken) {
          btnBiometricUnlock.classList.remove('hidden');
        } else {
          btnBiometricUnlock.classList.add('hidden');
        }
      });
    }
  } else if (view === 'main') {
    viewMain.classList.remove('hidden');
    btnHeaderLock.classList.remove('hidden');
    btnHeaderExport?.classList.remove('hidden');
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
 * Brand Avatar resolver for M3 Expressive design
 */
function getBrandInfo(issuerName: string): { bg: string; color: string; label: string; svg?: string } {
  const norm = issuerName.toLowerCase().trim();
  if (norm.includes('google')) {
    return {
      bg: '#1a2332',
      color: '#4285F4',
      label: 'G',
      svg: `<svg viewBox="0 0 24 24"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"/></svg>`,
    };
  }
  if (norm.includes('github')) {
    return {
      bg: '#24292e',
      color: '#ffffff',
      label: 'GH',
      svg: `<svg viewBox="0 0 24 24" fill="currentColor"><path fill-rule="evenodd" clip-rule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/></svg>`,
    };
  }
  if (norm.includes('microsoft')) {
    return {
      bg: '#182538',
      color: '#00a4ef',
      label: 'MS',
      svg: `<svg viewBox="0 0 24 24"><path fill="#f25022" d="M2 2h9v9H2z"/><path fill="#7fba00" d="M13 2h9v9h-9z"/><path fill="#00a4ef" d="M2 13h9v9H2z"/><path fill="#ffb900" d="M13 13h9v9h-9z"/></svg>`,
    };
  }
  if (norm.includes('facebook') || norm.includes('meta')) {
    return {
      bg: '#0c2e59',
      color: '#1877f2',
      label: 'FB',
      svg: `<svg viewBox="0 0 24 24" fill="#1877f2"><path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z"/></svg>`,
    };
  }
  if (norm.includes('instagram')) {
    return {
      bg: '#3b1828',
      color: '#e1306c',
      label: 'IG',
      svg: `<svg viewBox="0 0 24 24" fill="none" stroke="#e1306c" stroke-width="2"><rect x="2" y="2" width="20" height="20" rx="5" ry="5"/><path d="M16 11.37A4 4 0 1 1 12.63 8 4 4 0 0 1 16 11.37z"/><line x1="17.5" y1="6.5" x2="17.51" y2="6.5"/></svg>`,
    };
  }
  if (norm.includes('snapchat')) {
    return {
      bg: '#33300a',
      color: '#fffc00',
      label: 'SC',
      svg: `<svg viewBox="0 0 24 24" fill="#fffc00"><path d="M12 2.5c-3.5 0-5.5 2.5-5.5 5.5 0 .5.2 1.8.5 2.5-.5.2-1.2.5-1.5 1-.4.6-.2 1.4.3 1.6.4.2 1.2.1 1.7-.1.2 1 .8 2.2 2 3-.5.2-1.2.4-1.7.9-.6.6-.4 1.3 0 1.5 1 .4 3 .1 4.2-.4 1.2.5 3.2.8 4.2.4.4-.2.6-.9 0-1.5-.5-.5-1.2-.7-1.7-.9 1.2-.8 1.8-2 2-3 .5.2 1.3.3 1.7.1.5-.2.7-1 .3-1.6-.3-.5-1-.8-1.5-1 .3-.7.5-2 .5-2.5 0-3-2-5.5-5.5-5.5z"/></svg>`,
    };
  }
  if (norm.includes('twitter') || norm.includes('x')) {
    return {
      bg: '#1b222d',
      color: '#ffffff',
      label: 'X',
      svg: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>`,
    };
  }
  if (norm.includes('tiktok')) {
    return {
      bg: '#1a1d24',
      color: '#25f4ee',
      label: 'TT',
      svg: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M19.589 6.686a4.793 4.793 0 0 1-3.77-4.245V2h-3.445v13.672a2.896 2.896 0 1 1-2.896-2.895c.386 0 .753.076 1.09.213V9.453A6.335 6.335 0 0 0 9.07 9.17 6.34 6.34 0 1 0 15.41 15.51V8.65a8.21 8.21 0 0 0 4.179 1.135V6.686z"/></svg>`,
    };
  }
  if (norm.includes('teamviewer')) {
    return {
      bg: '#0a2540',
      color: '#0e70eb',
      label: 'TV',
      svg: `<svg viewBox="0 0 24 24" fill="none" stroke="#0e70eb" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M8 12h8m-3-4 4 4-4 4"/></svg>`,
    };
  }

  // Deterministic colorful avatar for any service
  let hash = 0;
  for (let i = 0; i < norm.length; i++) {
    hash = norm.charCodeAt(i) + ((hash << 5) - hash);
  }
  const hue = Math.abs(hash % 360);
  const initials = (issuerName.slice(0, 2) || '2F').toUpperCase();
  return {
    bg: `hsl(${hue}, 40%, 18%)`,
    color: `hsl(${hue}, 85%, 75%)`,
    label: initials,
  };
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
    chrome.storage.session.set({ biometricToken: p }).catch(() => {});
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
    const res = await chrome.storage.session.get('biometricToken');
    const token = res?.biometricToken;
    if (!token) {
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

btnHeaderSettings.addEventListener('click', () => {
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

// Bootstrap
checkStatus();
