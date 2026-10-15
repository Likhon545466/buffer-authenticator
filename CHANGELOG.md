# Changelog

All notable changes to the **Buffer Authenticator** extension will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.2.1] - 2026-10-15

### Fixed
- **Content Script Standalone IIFE Packaging (Critical Root Cause Fix)**:
  - Fixed a bundling regression where Vite split shared brand icon utilities into an external ES module chunk (`assets/brand-icons-*.js`), generating `import ... from ...` inside `dist/content/content.js`. Because Chrome Manifest V3 content scripts execute as classic scripts and do not support ES module `import` syntax, Chrome threw `SyntaxError: Cannot use import statement outside a module` and killed the script before any OTP detection or icon rendering could run.
  - Implemented an automatic standalone IIFE build hook in `vite.config.ts` so `dist/content/content.js` is compiled with zero external `import` statements and 100% self-contained code.
- **Autofill 2FA Icon Detection & Visibility**:
  - Expanded heuristic matching in `isOtpField` to comprehensively recognize placeholder masks (such as GitHub's `XXXXXX`, `XXX-XXX`, `000000`, and `• • • • • •`), Google `pin`/`idvPin`, Microsoft `otc`, Apple/GitHub `passcode`, Discord/Facebook `code`, PayPal `security_code`, Steam `twofactorcode`, numeric 6/8-digit patterns, etc.
  - Added dynamic SPA and multi-step login detection using attribute observing in `MutationObserver`, staggered post-load sweeps, and global `focusin` listeners, ensuring the autofill trigger is attached immediately when a 2FA prompt appears or is focused.
  - Enabled `"all_frames": true` in `manifest.json` for seamless 2FA prompt detection inside login iframes.
  - Fixed segmented 6-box OTP badge docking: positioned neatly beside the last digit box without modifying padding or distorting individual digit input boxes.
  - Upgraded badge button aesthetics to the official squircle gradient (`#004a77` to `#002d4c`) with round-cap shield vector and claymorphic elevation.

---

## [1.2.0] - 2026-10-15

### Added
- **Brand SVG Logos & Offline Vector Catalog**: Bundled crisp, official offline vector brand icons for 35+ top web services (Google, GitHub, Instagram, Snapchat, TeamViewer, Discord, Steam, AWS, Apple, TikTok, WhatsApp, Binance, Coinbase, Cloudflare, Reddit, Twitch, OpenAI, Spotify, PayPal, Bitwarden, Telegram, etc.) with dynamic color fallback for custom services. Both issuer and account fields are intelligently scanned to resolve logos automatically.
- **Right-Click Context Menu ("Add to Buffer Authenticator")**:
  - Right-click any 2FA QR code image on any webpage to scan and import it directly into your vault in one click.
  - Floating dark claymorphic in-page toast feedback confirms success or warns if vault is locked.
- **Smart 6-Box Split Input Autofill**:
  - Automatically identifies 4-to-8 box segmented OTP input clusters (e.g. GitHub, Amazon, Steam, Binance).
  - Distributes digits sequentially across individual boxes with native prototype property setters and `InputEvent` dispatching for 100% compatibility with React, Vue, and Angular forms.

---

## [1.1.1] - 2026-10-15

### Added
- **Settings QR Code Image Scan & Import**: Added a dedicated "Scan QR Code Image" tab under Settings > Vault Migration & Backups (Import Accounts). Users can drag-and-drop or browse screenshot/image files (`.png`, `.jpg`, `.jpeg`, `.webp`), decode QR codes natively via the `BarcodeDetector` API without third-party services, and import `otpauth://` URIs, Google Authenticator batch migration codes, and secret keys directly into their encrypted vault.
- **Auto-Detection for Image Backup Files**: If an image is dropped or uploaded into the general backup file area, the extension automatically detects and parses the embedded QR code.

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
