import { describe, expect, it } from 'vitest';
import {
  decodeMultikey,
  encodeMultikey,
  generateKeyPair,
  Invalid,
  jcs,
  RKEY,
  SCAPE_HANDLE_LABEL,
  signBytes,
  utf8,
  verifyBytes,
} from '../src/index.ts';

const text = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

describe('jcs', () => {
  it('sorts keys and drops whitespace (RFC 8785)', () => {
    expect(text(jcs({ b: [1, { d: true, c: null }], a: 'é ' }))).toBe('{"a":"é ","b":[1,{"c":null,"d":true}]}');
  });

  it('rejects fractional and unsafe numbers', () => {
    expect(() => jcs({ a: 1.5 })).toThrow(Invalid);
    expect(() => jcs([2 ** 53])).toThrow(Invalid);
    expect(() => jcs({ a: -(2 ** 53 - 1) })).not.toThrow();
  });
});

describe('keys', () => {
  it('round-trips Multikeys with the did:key prefix', () => {
    const pair = generateKeyPair();
    expect(pair.multikey.startsWith('z6Mk')).toBe(true);
    expect(decodeMultikey(encodeMultikey(pair.publicKey))).toEqual(pair.publicKey);
  });

  it('signs and verifies, and rejects malformed signatures', () => {
    const pair = generateKeyPair();
    const message = utf8('hello');
    const sig = signBytes(message, pair.secretKey);
    expect(verifyBytes(sig, message, pair.multikey)).toBe(true);
    expect(verifyBytes(sig, utf8('hellO'), pair.multikey)).toBe(false);
    expect(verifyBytes('not base64!', message, pair.multikey)).toBe(false);
    expect(verifyBytes(sig.slice(0, -4), message, pair.multikey)).toBe(false);
  });
});

describe('names', () => {
  it('accepts Scape handle labels of 3–30 characters', () => {
    for (const label of ['ada', 'ada-l', 'a1b', 'x'.repeat(30)]) expect(SCAPE_HANDLE_LABEL.test(label)).toBe(true);
    for (const label of ['a', 'ab', 'x'.repeat(31), '-ada', 'ada-', 'Ada', 'a_b']) {
      expect(SCAPE_HANDLE_LABEL.test(label)).toBe(false);
    }
  });

  it('refuses -- in the third and fourth places, as in xn--', () => {
    expect(SCAPE_HANDLE_LABEL.test('xn--80ak6aa92e')).toBe(false);
    expect(SCAPE_HANDLE_LABEL.test('ab--cd')).toBe(false);
    expect(SCAPE_HANDLE_LABEL.test('abc--d')).toBe(true);
  });

  it('allows only self or a generated TID as an rkey', () => {
    expect(RKEY.test('self')).toBe(true);
    expect(RKEY.test('3l2kq7xxa2c2s')).toBe(true);
    for (const rkey of ['links', 'my-trip', '3l2kq7xxa2c2', '3l2kq7xxa2c218']) expect(RKEY.test(rkey)).toBe(false);
  });
});
