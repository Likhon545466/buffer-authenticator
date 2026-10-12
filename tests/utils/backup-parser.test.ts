import { describe, it, expect } from 'vitest';
import { parseBackup, parsePlainTextBackup } from '../../src/utils/backup-parser';

describe('Universal Backup Parser', () => {
  it('parses Aegis Authenticator mobile plaintext JSON backup (db.entries)', async () => {
    const aegisJson = JSON.stringify({
      version: 1,
      header: {
        slots: null,
        params: null,
      },
      db: {
        version: 1,
        entries: [
          {
            type: 'totp',
            uuid: 'b3f545a9-f0ee-49cf-8982-f5c71d6f51cb',
            name: 'alice@github.com',
            issuer: 'GitHub',
            group: null,
            note: null,
            favorite: false,
            icon: null,
            info: {
              secret: 'JBSWY3DPEHPK3PXP',
              algo: 'SHA1',
              digits: 6,
              period: 30,
            },
          },
          {
            type: 'totp',
            uuid: 'c8913b52-789a-4c21-b3fa-09e45b89a123',
            name: 'bob@google.com',
            issuer: 'Google',
            info: {
              secret: 'HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ',
              algo: 'SHA256',
              digits: 8,
              period: 60,
            },
          },
        ],
      },
    });

    const results = await parseBackup(aegisJson);
    expect(results.length).toBe(2);

    expect(results[0].issuer).toBe('GitHub');
    expect(results[0].account).toBe('alice@github.com');
    expect(results[0].secret).toBe('JBSWY3DPEHPK3PXP');
    expect(results[0].digits).toBe(6);
    expect(results[0].period).toBe(30);
    expect(results[0].algorithm).toBe('SHA1');

    expect(results[1].issuer).toBe('Google');
    expect(results[1].account).toBe('bob@google.com');
    expect(results[1].secret).toBe('HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ');
    expect(results[1].digits).toBe(8);
    expect(results[1].period).toBe(60);
    expect(results[1].algorithm).toBe('SHA256');
  });

  it('parses Aegis format with "Issuer: Account" inside entry name', async () => {
    const aegisJson = JSON.stringify({
      version: 1,
      db: {
        entries: [
          {
            type: 'totp',
            name: 'Amazon Web Services: admin',
            issuer: '',
            info: {
              secret: 'JBSWY3DPEHPK3PXP',
            },
          },
        ],
      },
    });

    const results = await parseBackup(aegisJson);
    expect(results.length).toBe(1);
    expect(results[0].issuer).toBe('Amazon Web Services');
    expect(results[0].account).toBe('admin');
  });

  it('parses Plain Text (.txt) file with otpauth:// URIs', async () => {
    const txtContent = `
# Exported 2FA tokens
otpauth://totp/GitHub:user%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30
otpauth://totp/Discord:gamer%231234?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=Discord

// Ignored comment line
otpauth://hotp/Acme:admin?secret=JBSWY3DPEHPK3PXP&issuer=Acme&counter=10
`;

    const results = await parseBackup(txtContent);
    expect(results.length).toBe(3);

    expect(results[0].issuer).toBe('GitHub');
    expect(results[0].account).toBe('user@example.com');
    expect(results[0].secret).toBe('JBSWY3DPEHPK3PXP');

    expect(results[1].issuer).toBe('Discord');
    expect(results[1].account).toBe('gamer#1234');

    expect(results[2].type).toBe('hotp');
    expect(results[2].counter).toBe(10);
  });

  it('parses Plain Text (.txt) file with Key-Value lines or CSV', async () => {
    const txtContent = `
GitHub: JBSWY3DPEHPK3PXP
Cloudflare (ops@team.com): HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ
Google, test@gmail.com, JBSWY3DPEHPK3PXP
`;

    const results = parsePlainTextBackup(txtContent);
    expect(results.length).toBe(3);

    expect(results[0].issuer).toBe('GitHub');
    expect(results[0].secret).toBe('JBSWY3DPEHPK3PXP');

    expect(results[1].issuer).toBe('Cloudflare');
    expect(results[1].account).toBe('ops@team.com');
    expect(results[1].secret).toBe('HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ');

    expect(results[2].issuer).toBe('Google');
    expect(results[2].account).toBe('test@gmail.com');
    expect(results[2].secret).toBe('JBSWY3DPEHPK3PXP');
  });

  it('parses 2FAS format JSON', async () => {
    const twoFasJson = JSON.stringify({
      services: [
        {
          name: 'ProtonMail',
          secret: 'JBSWY3DPEHPK3PXP',
          otp: {
            account: 'user@proton.me',
            digits: 6,
            period: 30,
            algorithm: 'SHA1',
          },
        },
      ],
    });

    const results = await parseBackup(twoFasJson);
    expect(results.length).toBe(1);
    expect(results[0].issuer).toBe('ProtonMail');
    expect(results[0].account).toBe('user@proton.me');
  });

  it('parses official Aegis Authenticator mobile encrypted JSON backup', async () => {
    const aegisEncryptedJson = JSON.stringify({
      version: 1,
      header: {
        slots: [
          {
            type: 1,
            uuid: 'a8325752-c1be-458a-9b3e-5e0a8154d9ec',
            key: '491d44550430ba248986b904b8cffd3a6c5755d176ac877bd11b82c934225017',
            key_params: {
              nonce: 'e9705513ba4951fa7a0608d2',
              tag: '931237af257b83c693ddb8f9a7eddaf0',
            },
            n: 32768,
            r: 8,
            p: 1,
            salt: '27ea9ae53fa2f08a8dcd201615a8229422647b3058f9f36b08f9457e62888be1',
            repaired: true,
          },
        ],
        params: {
          nonce: '095fd13dee336fa56b4634ff',
          tag: '5db2470edf2d12f82a89ae7f48ccd50c',
        },
      },
      db: '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',
    });

    const results = await parseBackup(aegisEncryptedJson, 'test');
    expect(results.length).toBeGreaterThan(0);
    // Verify an entry is extracted properly
    expect(results[0].secret).toBeDefined();
    expect(results[0].digits).toBeGreaterThanOrEqual(6);
  }, 30000);

  it('rejects Aegis encrypted backup with incorrect password', async () => {
    const aegisEncryptedJson = JSON.stringify({
      version: 1,
      header: {
        slots: [
          {
            type: 1,
            uuid: 'a8325752-c1be-458a-9b3e-5e0a8154d9ec',
            key: '491d44550430ba248986b904b8cffd3a6c5755d176ac877bd11b82c934225017',
            key_params: {
              nonce: 'e9705513ba4951fa7a0608d2',
              tag: '931237af257b83c693ddb8f9a7eddaf0',
            },
            n: 32768,
            r: 8,
            p: 1,
            salt: '27ea9ae53fa2f08a8dcd201615a8229422647b3058f9f36b08f9457e62888be1',
            repaired: true,
          },
        ],
        params: {
          nonce: '095fd13dee336fa56b4634ff',
          tag: '5db2470edf2d12f82a89ae7f48ccd50c',
        },
      },
      db: 'dummy',
    });

    await expect(parseBackup(aegisEncryptedJson, 'wrong-password')).rejects.toThrow(
      'Incorrect Aegis master password'
    );
  }, 30000);

  it('parses Google Authenticator migration URI (otpauth-migration://)', async () => {
    const migrationUri =
      'otpauth-migration://offline?data=Ci0KCkhlbGxvU2VjcmUSEHRlc3RAZXhhbXBsZS5jb20aB1Rlc3RBcHAgASgBMAI=';

    const results = await parseBackup(migrationUri);
    expect(results.length).toBe(1);
    expect(results[0].issuer).toBe('TestApp');
    expect(results[0].account).toBe('test@example.com');
    expect(results[0].digits).toBe(6);
    expect(results[0].type).toBe('totp');
    expect(results[0].secret).toBeTruthy();
  });

  it('rejects completely invalid text with informative error', async () => {
    await expect(parseBackup('This is not a valid 2FA backup file at all.')).rejects.toThrow(
      'Unrecognized backup format'
    );
  });
});
