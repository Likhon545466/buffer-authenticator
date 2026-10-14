import { describe, it, expect, beforeAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';
import { PBKDF2_ITERATIONS, SALT_BYTE_LENGTH, IV_BYTE_LENGTH } from '../../src/crypto/webcrypto';

describe('Security Checklist Verification (Non-Negotiable)', () => {
  const rootDir = path.resolve(__dirname, '../../');
  const distDir = path.resolve(rootDir, 'dist');
  const manifestPath = path.resolve(distDir, 'manifest.json');

  beforeAll(() => {
    if (!fs.existsSync(distDir) || !fs.existsSync(manifestPath)) {
      execSync('npm run build', { cwd: rootDir, stdio: 'pipe' });
    }
  });

  it('Verifies Encryption at Rest & Key Derivation Parameters', () => {
    // PBKDF2 must be >= 250,000 iterations
    expect(PBKDF2_ITERATIONS).toBeGreaterThanOrEqual(250000);
    // Salt must be >= 16 bytes
    expect(SALT_BYTE_LENGTH).toBeGreaterThanOrEqual(16);
    // IV must be 12 bytes for AES-GCM
    expect(IV_BYTE_LENGTH).toBe(12);
  });

  it('Verifies Manifest V3 & Minimal Permissions', () => {
    expect(fs.existsSync(manifestPath)).toBe(true);
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));

    expect(manifest.manifest_version).toBe(3);

    // Permitted permissions
    const allowedPermissions = new Set(['storage', 'activeTab', 'alarms', 'idle', 'scripting', 'contextMenus']);
    manifest.permissions.forEach((perm: string) => {
      expect(allowedPermissions.has(perm)).toBe(true);
    });

    // Explicitly forbidden broad permissions
    expect(manifest.permissions).not.toContain('tabs');
    expect(manifest.permissions).not.toContain('cookies');
    expect(manifest.permissions).not.toContain('webRequest');

    // Strict Content Security Policy
    expect(manifest.content_security_policy).toBeDefined();
    const csp = manifest.content_security_policy.extension_pages;
    expect(csp).toContain("script-src 'self'");
    expect(csp).not.toContain('unsafe-eval');
    expect(csp).not.toContain('unsafe-inline');
    expect(csp).not.toContain('http://');
    expect(csp).not.toContain('https://');
  });

  it('Verifies that all icon files declared exist with non-zero size', () => {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
    expect(manifest.icons).toBeDefined();
    for (const size of Object.keys(manifest.icons)) {
      const iconRelPath = manifest.icons[size];
      const iconAbsPath = path.resolve(distDir, iconRelPath);
      expect(fs.existsSync(iconAbsPath)).toBe(true);
      const stats = fs.statSync(iconAbsPath);
      expect(stats.size).toBeGreaterThan(0);
    }
  });

  it('Verifies No eval() or remotely hosted code in built bundle', () => {
    function scanDir(dir: string) {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          scanDir(fullPath);
        } else if (entry.name.endsWith('.js')) {
          const content = fs.readFileSync(fullPath, 'utf-8');
          // Disallow eval(
          expect(content).not.toMatch(/\beval\s*\(/);
          // Disallow new Function(
          expect(content).not.toMatch(/new\s+Function\s*\(/);
          // Disallow remote http script references
          expect(content).not.toMatch(/https?:\/\/[^\s"']+\.js/);
        }
      }
    }
    scanDir(distDir);
  });

  it('Verifies 100% offline guarantee: Zero telemetry or analytics endpoints', () => {
    function scanForTelemetry(dir: string) {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          scanForTelemetry(fullPath);
        } else if (entry.name.endsWith('.js')) {
          const content = fs.readFileSync(fullPath, 'utf-8');
          expect(content).not.toContain('google-analytics');
          expect(content).not.toContain('segment.io');
          expect(content).not.toContain('sentry.io');
          expect(content).not.toContain('mixpanel');
        }
      }
    }
    scanForTelemetry(distDir);
  });

  it('Verifies i18n messages structure exists in dist', () => {
    const messagesPath = path.resolve(distDir, '_locales/en/messages.json');
    expect(fs.existsSync(messagesPath)).toBe(true);
    const messages = JSON.parse(fs.readFileSync(messagesPath, 'utf-8'));
    expect(messages.extensionName).toBeDefined();
    expect(messages.extensionDescription).toBeDefined();
  });
});
