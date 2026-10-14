# Changelog

All notable changes to the **Buffer Authenticator** extension will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] - 2026-10-14

### Added
- **In-Field Popover Direct Vault Unlock**: When encountering a 2FA input field on any website while the vault is locked, the contextual autofill popover now provides an inline unlock form with password visibility toggle, real-time feedback, and keystroke isolation. Users no longer need to switch tabs or open the toolbar popup to unlock their credentials.
- **Material 3 + Dark Claymorphism Hybrid Theme**: Complete aesthetic transformation of the extension popup:
  - Material 3 tonal surface tokens (`--md-sys-color-background: #111318`, `--md-sys-color-surface-container: #1D2026`, `--md-sys-color-surface-well: #14161B`, pastel blue `--md-sys-color-primary: #A8C7FA`).
  - Tactile 3-layer claymorphism depth (outer drop shadow + dual inset lighting shadows) replacing flat 1px borders across cards, pills, and buttons.
  - Raised squircle header badge, circular action buttons, and recessed clay wells for search inputs and 6-digit OTP codes.
  - Soft glowing countdown progress bar and tactile click/copy micro-animations.
- **Settings Menu Vault Lock Protection**:
  - Gated the Settings gear button in the popup header: it is hidden during setup and lock screens, requiring vault unlock to access.
  - Dedicated protection for the Options page (`options.html`): displays a "Vault is Locked" authentication view, preventing unauthorized inspection or modification of security settings, master password, or backups.
  - Added a quick "Lock Vault" button and live status badge in the Options header.
  - Real-time session monitoring that automatically re-locks the Options page if the vault auto-locks in the background.

### Fixed
- **Biometric Quick-Unlock State Synchronization**: Fixed a bug where disabling the biometric quick-unlock toggle in settings would sometimes leave the biometric button visible on the login screen. Disabling biometric unlock now immediately purges the session token, and all unlock views verify both the stored token and the active setting state.
- **Shadow DOM Shortcut Interception**: Fixed an issue where typing passwords in the in-field autofill popover could bubble up and trigger host page keyboard shortcuts (e.g. GitHub `/` search).

---

## [1.0.1] - 2026-10-13

### Added
- **Interactive In-Field Autofill Popover**: Injected shadow-DOM popover docked to detected OTP/2FA fields with live TOTP digits, countdown ticker, and domain matching algorithms.
- **Account Sorting**: Added alphabetical (A–Z, Z–A) and Recently Added sort options with persistent user preferences.

### Changed
- Improved Scrypt key derivation test timeouts for compute-intensive Aegis mobile backup vectors.

---

## [1.0.0] - 2026-10-12

### Initial Release
- **Local-Only AES-256-GCM Vault**: Encrypted offline storage with PBKDF2 (310,000 iterations), WebCrypto, and zero telemetry.
- **Universal Multi-Format Backup & Import**: Aegis (AES-GCM & Scrypt), 2FAS, Bitwarden, Google Authenticator Migration (Protobuf), and standard `otpauth://` URIs.
- **QR Code Import & Screen Scanner**: Direct drag-and-drop QR scanning and active tab screenshot analysis.
- **Automated Locking Policies**: Configurable inactivity timer and system screen lock idle detection.
