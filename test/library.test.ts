import { describe, expect, it } from 'vitest';
import {
  decodeMultikey,
  encodeMultikey,
  generateKeyPair,
  Invalid,
  jcs,
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
