import { describe, it, expect } from 'vitest';
import { isOtpField, getSegmentedCluster } from '../../src/content/content';

// Simple mock for HTMLInputElement in node test environment
function createMockInput(attrs: {
  name?: string;
  id?: string;
  type?: string;
  placeholder?: string;
  autocomplete?: string;
  ariaLabel?: string;
  maxLength?: number;
  pattern?: string;
  inputMode?: string;
  disabled?: boolean;
  readOnly?: boolean;
  processed?: string;
  parentInputs?: any[];
}): HTMLInputElement {
  const store = new Map<string, string>();
  if (attrs.processed) {
    store.set('data-buffer-auth-detected', attrs.processed);
  }
  if (attrs.autocomplete) {
    store.set('autocomplete', attrs.autocomplete);
  }
  if (attrs.ariaLabel) {
    store.set('aria-label', attrs.ariaLabel);
  }

  const el = {
    name: attrs.name || '',
    id: attrs.id || '',
    type: attrs.type || 'text',
    placeholder: attrs.placeholder || '',
    maxLength: attrs.maxLength !== undefined ? attrs.maxLength : -1,
    pattern: attrs.pattern || '',
    inputMode: attrs.inputMode || '',
    disabled: Boolean(attrs.disabled),
    readOnly: Boolean(attrs.readOnly),
    title: '',
    hasAttribute: (name: string) => store.has(name),
    getAttribute: (name: string) => store.get(name) || null,
    setAttribute: (name: string, val: string) => store.set(name, val),
    parentElement: attrs.parentInputs
      ? {
          querySelectorAll: (_sel: string) => attrs.parentInputs,
        }
      : null,
  } as unknown as HTMLInputElement;

  return el;
}

describe('2FA / OTP Field Detection Heuristics', () => {
  it('detects standard one-time-code autocomplete attribute', () => {
    const input = createMockInput({ autocomplete: 'one-time-code' });
    expect(isOtpField(input)).toBe(true);
  });

  it('detects common service 2FA input names and IDs', () => {
    // Google: Pin / idvPin / totpPin
    expect(isOtpField(createMockInput({ name: 'Pin', id: 'idvPin', type: 'tel' }))).toBe(true);
    expect(isOtpField(createMockInput({ name: 'totpPin', type: 'tel' }))).toBe(true);

    // Microsoft: otc
    expect(isOtpField(createMockInput({ name: 'otc', id: 'idTxtBx_SAOTCC_OTC' }))).toBe(true);

    // Discord / Dropbox / Facebook / generic: code, securityCode, passcode
    expect(isOtpField(createMockInput({ name: 'code', type: 'text', inputMode: 'numeric' }))).toBe(true);
    expect(isOtpField(createMockInput({ name: 'securityCode', type: 'text' }))).toBe(true);
    expect(isOtpField(createMockInput({ name: 'security_code', type: 'text' }))).toBe(true);
    expect(isOtpField(createMockInput({ name: 'passcode', type: 'text' }))).toBe(true);

    // Steam / GitLab / PayPal
    expect(isOtpField(createMockInput({ name: 'twofactorcode', type: 'text' }))).toBe(true);
    expect(isOtpField(createMockInput({ name: 'user[otp_attempt]', type: 'text' }))).toBe(true);

    // Placeholder-based detection (including GitHub XXXXXX)
    expect(isOtpField(createMockInput({ placeholder: 'XXXXXX', type: 'text' }))).toBe(true);
    expect(isOtpField(createMockInput({ placeholder: '000000', type: 'text' }))).toBe(true);
    expect(isOtpField(createMockInput({ placeholder: 'Enter 6-digit code', type: 'text' }))).toBe(true);
    expect(isOtpField(createMockInput({ placeholder: 'Verification code', type: 'text' }))).toBe(true);
  });

  it('detects 6-digit numeric pattern or length inputs', () => {
    expect(isOtpField(createMockInput({ maxLength: 6, inputMode: 'numeric' }))).toBe(true);
    expect(isOtpField(createMockInput({ maxLength: 8, type: 'tel' }))).toBe(true);
    expect(isOtpField(createMockInput({ pattern: '[0-9]{6}', type: 'text' }))).toBe(true);
  });

  it('rejects regular passwords, usernames, and non-OTP fields', () => {
    // Regular password without OTP context
    expect(isOtpField(createMockInput({ name: 'password', type: 'password' }))).toBe(false);
    expect(isOtpField(createMockInput({ name: 'user_password', type: 'password' }))).toBe(false);

    // Usernames / emails
    expect(isOtpField(createMockInput({ name: 'username', type: 'text' }))).toBe(false);
    expect(isOtpField(createMockInput({ name: 'email', type: 'email' }))).toBe(false);

    // Postal codes / zip codes / CVV
    expect(isOtpField(createMockInput({ name: 'postal_code', type: 'text' }))).toBe(false);
    expect(isOtpField(createMockInput({ name: 'zipCode', type: 'text' }))).toBe(false);
    expect(isOtpField(createMockInput({ name: 'cvv', type: 'text' }))).toBe(false);

    // Already processed fields
    expect(isOtpField(createMockInput({ name: 'code', processed: 'true' }))).toBe(false);
  });

  it('handles segmented multi-box split OTP inputs', () => {
    const boxes: any[] = [];
    for (let i = 0; i < 6; i++) {
      boxes.push(
        createMockInput({
          maxLength: 1,
          type: 'text',
          inputMode: 'numeric',
          parentInputs: boxes,
        })
      );
    }
    // Set parentElement on each box to point to the cluster list
    boxes.forEach((b) => {
      (b as any).parentElement = {
        querySelectorAll: () => boxes,
      };
    });

    // Cluster detection
    expect(getSegmentedCluster(boxes[0])).toHaveLength(6);

    // The trigger should be attached to the LAST box in the cluster
    expect(isOtpField(boxes[0])).toBe(false);
    expect(isOtpField(boxes[5])).toBe(true);
    // Siblings should be marked as cluster-sibling
    expect(boxes[0].getAttribute('data-buffer-auth-detected')).toBe('cluster-sibling');
  });
});
