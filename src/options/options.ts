/**
 * Options Page Controller (M3 Expressive)
 */

import type { MessageRequest, MessageResponse, VaultSettings, VaultStatus } from '../types';

const statusBanner = document.getElementById('status-banner') as HTMLDivElement;
const bannerIcon = document.getElementById('banner-icon') as HTMLSpanElement;
const bannerMessage = document.getElementById('banner-message') as HTMLSpanElement;
const btnCloseBanner = document.getElementById('btn-close-banner') as HTMLButtonElement;

const selectAutoLock = document.getElementById('select-autolock') as HTMLSelectElement;
const checkIdle = document.getElementById('check-idle') as HTMLInputElement;
const selectClipboard = document.getElementById('select-clipboard') as HTMLSelectElement | null;
const checkBiometric = document.getElementById('check-biometric') as HTMLInputElement | null;

const formChangePwd = document.getElementById('form-change-pwd') as HTMLFormElement;
const pwdCurrent = document.getElementById('pwd-current') as HTMLInputElement;
const pwdNew = document.getElementById('pwd-new') as HTMLInputElement;
const pwdConfirm = document.getElementById('pwd-confirm') as HTMLInputElement;

const exportPwd = document.getElementById('export-pwd') as HTMLInputElement;
const btnExport = document.getElementById('btn-export') as HTMLButtonElement;

const fileImport = document.getElementById('file-import') as HTMLInputElement;
const textImport = document.getElementById('text-import') as HTMLTextAreaElement;
const importPwd = document.getElementById('import-pwd') as HTMLInputElement;
const btnImport = document.getElementById('btn-import') as HTMLButtonElement;

const uploadPrompt = document.getElementById('upload-prompt') as HTMLDivElement;
const fileInfoBadge = document.getElementById('file-info-badge') as HTMLDivElement;
const fileNameDisplay = document.getElementById('file-name-display') as HTMLSpanElement;
const fileSizeDisplay = document.getElementById('file-size-display') as HTMLSpanElement;
const btnRemoveFile = document.getElementById('btn-remove-file') as HTMLButtonElement;

// Locked / Unlocked View Elements
const viewOptionsLocked = document.getElementById('view-options-locked') as HTMLDivElement | null;
const viewOptionsUninit = document.getElementById('view-options-uninit') as HTMLDivElement | null;
const optionsMainContent = document.getElementById('options-main-content') as HTMLDivElement | null;
const formOptionsUnlock = document.getElementById('form-options-unlock') as HTMLFormElement | null;
const optionsUnlockPwd = document.getElementById('options-unlock-pwd') as HTMLInputElement | null;
const optionsLockError = document.getElementById('options-lock-error') as HTMLDivElement | null;
const btnOptionsLock = document.getElementById('btn-options-lock') as HTMLButtonElement | null;
const optionsStatusDot = document.getElementById('options-status-dot') as HTMLSpanElement | null;
const optionsStatusText = document.getElementById('options-status-text') as HTMLSpanElement | null;

// Top Nav Tabs
const tabPills = document.querySelectorAll<HTMLButtonElement>('.tab-pill');
const tabPanes = document.querySelectorAll<HTMLElement>('.tab-pane');

tabPills.forEach((pill) => {
  pill.addEventListener('click', () => {
    tabPills.forEach((p) => p.classList.remove('active'));
    tabPanes.forEach((pane) => pane.classList.add('hidden'));

    pill.classList.add('active');
    const targetId = pill.getAttribute('data-tab');
    if (targetId) {
      document.getElementById(targetId)?.classList.remove('hidden');
    }
  });
});

// Backup Mode Toggle (Import vs Export)
const btnModeImport = document.getElementById('btn-mode-import') as HTMLButtonElement;
const btnModeExport = document.getElementById('btn-mode-export') as HTMLButtonElement;
const panelImport = document.getElementById('panel-import') as HTMLDivElement;
const panelExport = document.getElementById('panel-export') as HTMLDivElement;

btnModeImport?.addEventListener('click', () => {
  btnModeImport.classList.add('active');
  btnModeExport?.classList.remove('active');
  panelImport?.classList.remove('hidden');
  panelExport?.classList.add('hidden');
});

btnModeExport?.addEventListener('click', () => {
  btnModeExport.classList.add('active');
  btnModeImport?.classList.remove('active');
  panelExport?.classList.remove('hidden');
  panelImport?.classList.add('hidden');
});

// Import Type Toggle (File Upload vs Scan QR vs Paste Text)
const tabImportFile = document.getElementById('tab-import-file') as HTMLButtonElement;
const tabImportQr = document.getElementById('tab-import-qr') as HTMLButtonElement | null;
const tabImportText = document.getElementById('tab-import-text') as HTMLButtonElement;
const paneImportFile = document.getElementById('pane-import-file') as HTMLDivElement;
const paneImportQr = document.getElementById('pane-import-qr') as HTMLDivElement | null;
const paneImportText = document.getElementById('pane-import-text') as HTMLDivElement;

const fileImportQr = document.getElementById('file-import-qr') as HTMLInputElement | null;
const uploadPromptQr = document.getElementById('upload-prompt-qr') as HTMLDivElement | null;
const qrInfoBadge = document.getElementById('qr-info-badge') as HTMLDivElement | null;
const qrFileNameDisplay = document.getElementById('qr-file-name-display') as HTMLSpanElement | null;
const qrFileSizeDisplay = document.getElementById('qr-file-size-display') as HTMLSpanElement | null;
const btnRemoveQrFile = document.getElementById('btn-remove-qr-file') as HTMLButtonElement | null;

let activeImportMode: 'file' | 'qr' | 'text' = 'file';

tabImportFile?.addEventListener('click', () => {
  activeImportMode = 'file';
  tabImportFile.classList.add('active');
  tabImportQr?.classList.remove('active');
  tabImportText?.classList.remove('active');
  paneImportFile?.classList.remove('hidden');
  paneImportQr?.classList.add('hidden');
  paneImportText?.classList.add('hidden');
});

tabImportQr?.addEventListener('click', () => {
  activeImportMode = 'qr';
  tabImportQr?.classList.add('active');
  tabImportFile?.classList.remove('active');
  tabImportText?.classList.remove('active');
  paneImportQr?.classList.remove('hidden');
  paneImportFile?.classList.add('hidden');
  paneImportText?.classList.add('hidden');
});

tabImportText?.addEventListener('click', () => {
  activeImportMode = 'text';
  tabImportText.classList.add('active');
  tabImportFile?.classList.remove('active');
  tabImportQr?.classList.remove('active');
  paneImportText?.classList.remove('hidden');
  paneImportFile?.classList.add('hidden');
  paneImportQr?.classList.add('hidden');
});

// Dynamic File Selection Feedback
fileImport?.addEventListener('change', () => {
  const file = fileImport.files?.[0];
  if (file) {
    uploadPrompt?.classList.add('hidden');
    fileInfoBadge?.classList.remove('hidden');
    if (fileNameDisplay) fileNameDisplay.textContent = file.name;
    const kb = (file.size / 1024).toFixed(1);
    if (fileSizeDisplay) fileSizeDisplay.textContent = `${kb} KB • Ready to import`;
  } else {
    resetFileSelection();
  }
});

function resetFileSelection() {
  if (fileImport) fileImport.value = '';
  uploadPrompt?.classList.remove('hidden');
  fileInfoBadge?.classList.add('hidden');
}

btnRemoveFile?.addEventListener('click', (e) => {
  e.stopPropagation();
  resetFileSelection();
});

// Dynamic QR File Selection Feedback
fileImportQr?.addEventListener('change', () => {
  const file = fileImportQr.files?.[0];
  if (file) {
    uploadPromptQr?.classList.add('hidden');
    qrInfoBadge?.classList.remove('hidden');
    if (qrFileNameDisplay) qrFileNameDisplay.textContent = file.name;
    const kb = (file.size / 1024).toFixed(1);
    if (qrFileSizeDisplay) qrFileSizeDisplay.textContent = `${kb} KB • Ready to scan & import`;
  } else {
    resetQrFileSelection();
  }
});

function resetQrFileSelection() {
  if (fileImportQr) fileImportQr.value = '';
  uploadPromptQr?.classList.remove('hidden');
  qrInfoBadge?.classList.add('hidden');
}

btnRemoveQrFile?.addEventListener('click', (e) => {
  e.stopPropagation();
  resetQrFileSelection();
});

async function decodeQrFromImageFile(file: File): Promise<string> {
  if (!file.type.startsWith('image/') && !/\.(png|jpe?g|webp|gif|bmp|svg)$/i.test(file.name)) {
    throw new Error('Please select an image file (PNG, JPG, JPEG, WebP)');
  }

  if (!('BarcodeDetector' in window)) {
    throw new Error('QR code scanning requires BarcodeDetector API, which is not available in this browser environment.');
  }

  let imageSource: ImageBitmap | HTMLImageElement;
  if (typeof createImageBitmap === 'function') {
    imageSource = await createImageBitmap(file);
  } else {
    imageSource = await new Promise<HTMLImageElement>((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = async () => {
        const img = new Image();
        img.src = reader.result as string;
        try {
          await img.decode();
          resolve(img);
        } catch {
          reject(new Error('Failed to decode image data'));
        }
      };
      reader.onerror = () => reject(new Error('Failed to read image file'));
      reader.readAsDataURL(file);
    });
  }

  const detector = new (window as any).BarcodeDetector({ formats: ['qr_code'] });
  const detected = await detector.detect(imageSource);
  if (!detected || detected.length === 0) {
    throw new Error('No QR code detected in the uploaded image. Please ensure the QR code is clearly visible.');
  }

  const rawValues = detected.map((d: any) => d.rawValue).filter(Boolean);
  if (rawValues.length === 0) {
    throw new Error('QR code content could not be decoded.');
  }

  return rawValues.join('\n');
}

// Password show/hide toggle
document.querySelectorAll<HTMLButtonElement>('.pwd-toggle').forEach((btn) => {
  btn.addEventListener('click', () => {
    const targetId = btn.getAttribute('data-target');
    if (!targetId) return;
    const input = document.getElementById(targetId) as HTMLInputElement;
    if (!input) return;
    const isPassword = input.type === 'password';
    input.type = isPassword ? 'text' : 'password';
    btn.innerHTML = isPassword
      ? `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`
      : `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
  });
});

let bannerTimeout: number | undefined;

function showBanner(message: string, isError = false) {
  if (bannerMessage) bannerMessage.textContent = message;
  if (bannerIcon) bannerIcon.textContent = isError ? '⚠' : '✓';
  statusBanner.className = `banner ${isError ? 'banner-error' : 'banner-success'}`;
  statusBanner.classList.remove('hidden');

  if (bannerTimeout) window.clearTimeout(bannerTimeout);
  if (!isError) {
    bannerTimeout = window.setTimeout(() => {
      statusBanner.classList.add('hidden');
    }, 4500);
  }
}

btnCloseBanner?.addEventListener('click', () => {
  statusBanner.classList.add('hidden');
  if (bannerTimeout) window.clearTimeout(bannerTimeout);
});

async function sendMessage<T>(msg: MessageRequest): Promise<MessageResponse<T>> {
  return chrome.runtime.sendMessage(msg);
}

function setLockUIState(isLocked: boolean, isInitialized = true) {
  if (!isInitialized) {
    viewOptionsUninit?.classList.remove('hidden');
    viewOptionsLocked?.classList.add('hidden');
    optionsMainContent?.classList.add('hidden');
    btnOptionsLock?.classList.add('hidden');
    optionsStatusDot?.classList.add('locked');
    if (optionsStatusText) optionsStatusText.textContent = 'Vault Not Set Up';
    return;
  }

  viewOptionsUninit?.classList.add('hidden');

  if (isLocked) {
    viewOptionsLocked?.classList.remove('hidden');
    optionsMainContent?.classList.add('hidden');
    btnOptionsLock?.classList.add('hidden');
    optionsStatusDot?.classList.add('locked');
    if (optionsStatusText) optionsStatusText.textContent = 'Vault Locked';
    if (optionsUnlockPwd) {
      optionsUnlockPwd.value = '';
      optionsUnlockPwd.focus();
    }
  } else {
    viewOptionsLocked?.classList.add('hidden');
    optionsMainContent?.classList.remove('hidden');
    btnOptionsLock?.classList.remove('hidden');
    optionsStatusDot?.classList.remove('locked');
    if (optionsStatusText) optionsStatusText.textContent = 'AES-256-GCM Vault';
  }
}

async function loadSettings() {
  const res = await sendMessage<VaultStatus>({ type: 'GET_STATUS' });
  if (res.success && res.data) {
    const { isInitialized, isLocked, settings } = res.data;
    if (!isInitialized) {
      setLockUIState(true, false);
      return;
    }
    if (isLocked) {
      setLockUIState(true, true);
      return;
    }

    setLockUIState(false, true);

    const s = settings;
    if (selectAutoLock) selectAutoLock.value = String(s.autoLockMinutes ?? 5);
    if (checkIdle) checkIdle.checked = Boolean(s.lockOnIdle);
    if (selectClipboard) selectClipboard.value = String(s.clipboardClearSeconds ?? 30);
    if (checkBiometric) checkBiometric.checked = Boolean(s.biometricEnabled);
  } else {
    setLockUIState(true, true);
  }
}

async function saveSettingChange() {
  const payload: Partial<VaultSettings> = {
    autoLockMinutes: parseInt(selectAutoLock.value, 10),
    lockOnIdle: checkIdle.checked,
    clipboardClearSeconds: selectClipboard ? parseInt(selectClipboard.value, 10) : 30,
    biometricEnabled: checkBiometric ? checkBiometric.checked : false,
  };
  if (!payload.biometricEnabled && chrome.storage?.session) {
    await chrome.storage.session.remove('biometricToken').catch(() => {});
  }
  const res = await sendMessage({ type: 'UPDATE_SETTINGS', payload });
  if (res.success) {
    showBanner('Setting saved successfully');
  } else {
    showBanner(res.error || 'Failed to update setting', true);
  }
}

selectAutoLock?.addEventListener('change', saveSettingChange);
checkIdle?.addEventListener('change', saveSettingChange);
selectClipboard?.addEventListener('change', saveSettingChange);
checkBiometric?.addEventListener('change', saveSettingChange);

// Change Password
formChangePwd?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const current = pwdCurrent.value;
  const newP = pwdNew.value;
  const confirmP = pwdConfirm.value;

  if (newP !== confirmP) {
    showBanner('New passwords do not match', true);
    return;
  }
  if (newP.length < 8) {
    showBanner('New password must be at least 8 characters long', true);
    return;
  }

  const res = await sendMessage({
    type: 'CHANGE_PASSWORD',
    payload: { currentPassword: current, newPassword: newP },
  });

  if (res.success) {
    showBanner('Master password updated. Your vault has been re-encrypted.');
    formChangePwd.reset();
  } else {
    showBanner(res.error || 'Failed to update master password', true);
  }
});

// Export Vault
btnExport?.addEventListener('click', async () => {
  const password = exportPwd.value;
  if (!password) {
    showBanner('Please enter your master password to export an encrypted backup', true);
    exportPwd.focus();
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
    exportPwd.value = '';
    showBanner('Backup downloaded successfully');
  } else {
    showBanner(res.error || 'Export failed: Incorrect master password', true);
  }
});

// Import Vault
btnImport?.addEventListener('click', async () => {
  const password = importPwd.value.trim();

  async function processImport(content: string) {
    try {
      const res = await sendMessage<{ importedCount: number }>({
        type: 'IMPORT_VAULT',
        payload: { data: content, password: password || undefined },
      });

      if (res.success && res.data) {
        showBanner(`Successfully imported ${res.data.importedCount} accounts!`);
        resetFileSelection();
        resetQrFileSelection();
        if (textImport) textImport.value = '';
        importPwd.value = '';
      } else {
        showBanner(res.error || 'Import failed. Check password and file format.', true);
      }
    } catch (err: any) {
      showBanner(`Import error: ${err.message}`, true);
    }
  }

  if (activeImportMode === 'text') {
    const textContent = textImport?.value?.trim();
    if (!textContent) {
      showBanner('Please paste backup text or otpauth:// URIs into the box', true);
      textImport?.focus();
      return;
    }
    await processImport(textContent);
  } else if (activeImportMode === 'qr') {
    const files = fileImportQr?.files;
    if (!files || files.length === 0) {
      showBanner('Please select a QR code image to import', true);
      return;
    }

    try {
      showBanner('Scanning QR code image...');
      const qrData = await decodeQrFromImageFile(files[0]);
      await processImport(qrData);
    } catch (err: any) {
      showBanner(err.message || 'Failed to scan QR code image', true);
    }
  } else {
    const files = fileImport.files;
    if (!files || files.length === 0) {
      showBanner('Please select a backup file (.json, .txt, or QR image) to import', true);
      return;
    }

    const file = files[0];

    // If user dropped or selected an image file in the backup file area, decode it as QR
    if (file.type.startsWith('image/') || /\.(png|jpe?g|webp|gif|bmp)$/i.test(file.name)) {
      try {
        showBanner('Scanning QR code from image file...');
        const qrData = await decodeQrFromImageFile(file);
        await processImport(qrData);
      } catch (err: any) {
        showBanner(err.message || 'Failed to scan QR code from image', true);
      }
      return;
    }

    const reader = new FileReader();

    reader.onload = async (e) => {
      const content = e.target?.result as string;
      if (!content) {
        showBanner('Failed to read file contents', true);
        return;
      }
      await processImport(content);
    };

    reader.onerror = () => {
      showBanner('Error reading backup file', true);
    };

    reader.readAsText(file);
  }
});

window.addEventListener('pagehide', () => {
  if (bannerTimeout) {
    window.clearTimeout(bannerTimeout);
    bannerTimeout = undefined;
  }
});

// Options Page Unlock Form Handling
formOptionsUnlock?.addEventListener('submit', async (e) => {
  e.preventDefault();
  if (optionsLockError) optionsLockError.classList.add('hidden');

  const password = optionsUnlockPwd?.value || '';
  if (!password) return;

  const res = await sendMessage({ type: 'UNLOCK_VAULT', payload: { password } });
  if (res.success) {
    if (optionsUnlockPwd) optionsUnlockPwd.value = '';
    await loadSettings();
    showBanner('Vault unlocked successfully');
  } else {
    if (optionsLockError) {
      optionsLockError.textContent = res.error || 'Incorrect master password';
      optionsLockError.classList.remove('hidden');
    }
  }
});

// Options Page Manual Lock Button
btnOptionsLock?.addEventListener('click', async () => {
  await sendMessage({ type: 'LOCK_VAULT' });
  setLockUIState(true, true);
  showBanner('Vault locked');
});

// Sync lock state if vault locks in background (idle/timeout)
if (chrome.storage && chrome.storage.session && chrome.storage.session.onChanged) {
  chrome.storage.session.onChanged.addListener((changes) => {
    if (changes.sessionKey && !changes.sessionKey.newValue) {
      setLockUIState(true, true);
    }
  });
}

loadSettings();
