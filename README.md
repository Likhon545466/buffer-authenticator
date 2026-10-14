# Buffer Authenticator

[![CI Build & Security Audit](https://github.com/Likhon545466/buffer-authenticator/actions/workflows/build.yml/badge.svg)](https://github.com/Likhon545466/buffer-authenticator/actions/workflows/build.yml)
[![Latest Release](https://img.shields.io/github/v/release/Likhon545466/buffer-authenticator?color=blue&label=Release)](https://github.com/Likhon545466/buffer-authenticator/releases/latest)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Manifest V3](https://img.shields.io/badge/Manifest-V3-success.svg)](manifest.json)
[![Security: AES--256--GCM](https://img.shields.io/badge/Vault-AES--256--GCM-green.svg)](docs/security-audit.md)
[![Zero Network Calls](https://img.shields.io/badge/Telemetry-None%20(100%25%20Offline)-brightgreen.svg)](docs/security-audit.md)

**Buffer Authenticator** is a modern, privacy-first, 100% offline two-factor authentication (2FA/TOTP) browser extension built with a bespoke **Material 3 (Material You) + Dark Claymorphism** hybrid design and zero-compromise local cryptographic security.

---

## ✨ Features

- 🔒 **Authenticated Vault Encryption**: All 2FA secrets are encrypted locally with **AES-256-GCM** using keys derived via **PBKDF2-HMAC-SHA256** (310,000 iterations + cryptographically random 16-byte salt).
- 🛡️ **100% Offline & Zero Telemetry**: Zero external network requests, zero tracking scripts, and zero cloud storage. No `<all_urls>` permission requested.
- 🎨 **Material 3 + Dark Claymorphism Hybrid Theme**: Bespoke visual experience using official M3 tonal surface tokens (`#111318`, `#1D2026`, `#14161B`, pastel blue `#A8C7FA`), 3-layer tactile claymorphism depth (outer drop shadow + dual inset lighting shadows), squircle service icons, and tactile micro-animations.
- ⚡ **Contextual Inline Autofill with In-Field Unlock**: Detects 2FA verification inputs on login forms and provides a secure, one-click autofill popover. When locked, users can unlock their vault directly from the in-field popover without opening the toolbar popup, with complete host-page keystroke isolation.
- 🔐 **Guarded Settings & Preferences**: The extension settings and Options page are guarded behind master password authentication to protect backup exports, master password modification, and auto-lock policies.
- ⏱️ **Recessed OTP Code Badge & Timer**: Houses 6-digit codes in softly carved clay wells with an integrated countdown timer bar and soft pastel glow.
- 📷 **Built-in QR Code Scanner**: Add 2FA accounts instantly by scanning QR codes directly from the active tab or dragging & dropping image files.
- 🔄 **Universal Multi-Format Import & Export**:
  - Supports **Aegis Authenticator** (both encrypted AES-GCM/Scrypt and plaintext JSON backups).
  - Supports **Google Authenticator** (`otpauth-migration://` Protobuf exports).
  - Supports **2FAS**, **Bitwarden**, and standard `otpauth://` URI lists.
  - Export password-protected encrypted backups anytime.
- ⏳ **Configurable Auto-Lock**: Automatically locks the vault after customizable periods of inactivity or when the operating system screen locks.

---

## 🚀 Installation Guide

### Option 1: Install from Pre-built Release (Recommended)

1. **Download the Latest Release**:
   - Go to [**GitHub Releases**](https://github.com/Likhon545466/buffer-authenticator/releases/latest) and download [`buffer-authenticator.zip`](https://github.com/Likhon545466/buffer-authenticator/releases/latest/download/buffer-authenticator.zip).
2. **Extract the ZIP Archive**:
   - Unpack `buffer-authenticator.zip` into a permanent directory on your computer (e.g., `~/Documents/buffer-authenticator` or `C:\Users\<user>\Documents\buffer-authenticator`).
   > [!IMPORTANT]
   > Do NOT delete or move this folder after installing, as Chromium browsers load extension files directly from this folder.
3. **Open Extensions Management**:
   - Open your Chromium-based browser (Google Chrome, Brave, Microsoft Edge, Arc, Opera, or Vivaldi) and navigate to the extensions page:
     - **Chrome / Brave / Arc / Vivaldi**: `chrome://extensions/`
     - **Microsoft Edge**: `edge://extensions/`
4. **Enable Developer Mode**:
   - Toggle on the **"Developer mode"** switch (usually located at the top-right corner of the page).
5. **Load the Extension**:
   - Click the **"Load unpacked"** button in the top-left corner.
   - Select the extracted folder (which contains `manifest.json`, `background/`, `icons/`, etc.).
6. **Pin to Toolbar**:
   - Click the puzzle piece icon (Extensions) in your browser toolbar and click the **Pin** icon next to **Buffer Authenticator** for quick access.

---

### Option 2: Build & Install from Source

If you prefer building the extension from source:

#### Prerequisites
- [Node.js](https://nodejs.org/) v20+ or v22+
- `npm`

#### Build Steps
```bash
# 1. Clone the repository
git clone https://github.com/Likhon545466/buffer-authenticator.git
cd buffer-authenticator

# 2. Install dependencies
npm install

# 3. Run automated test suite (50 unit & security checklist tests)
npm test

# 4. Build production bundle (outputs to dist/)
npm run build

# 5. (Optional) Package into shareable zip
npm run package
```

#### Load into Browser:
1. Open `chrome://extensions/` in your browser.
2. Enable **Developer mode** in the top-right corner.
3. Click **Load unpacked** and select the `dist/` directory inside the repository root.

---

## 🧪 Security & Verification

Buffer Authenticator is rigorously verified with automated tests covering cryptographic primitives, key derivation parameters, and security boundaries:

```bash
npm run test:coverage
```

- **RFC 6238 (TOTP) & RFC 4226 (HOTP)**: Verified against official RFC test vectors.
- **RFC 7914 (Scrypt)**: Verified against official RFC 7914 test vectors.
- **WebCrypto AES-GCM**: Verified against authenticated encryption and tamper detection tests.
- **Aegis / Google Auth Migration Parsers**: Verified against encrypted and protobuf migration payloads.
- **Security Checklist Verification**: Automated e2e tests enforce PBKDF2 iterations (>= 250,000), minimum salt length (>= 16 bytes), strict CSP (`no eval()`, `no remote scripts`), and zero telemetry endpoints.

See [docs/security-audit.md](docs/security-audit.md) for full architecture and threat model analysis.

---

## 📜 Permissions Breakdown

| Permission | Justification |
| :--- | :--- |
| `storage` | Stores the AES-256-GCM encrypted vault in local storage and ephemeral session keys in memory while unlocked. |
| `activeTab` | Allows domain detection and scanning QR codes from the active browser tab upon user action. |
| `alarms` | Drives the background idle auto-lock countdown timer. |
| `idle` | Detects screen locking events to immediately wipe in-memory keys and lock the vault. |
| `scripting` | Injects the inline autofill badge into 2FA code input fields when interacting with web forms. |

---

## 📄 License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
