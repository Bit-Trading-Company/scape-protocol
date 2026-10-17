import { ed25519 } from '@noble/curves/ed25519.js';
import { base58 } from '@scure/base';
import { base64url } from './encoding.ts';
import { check, Invalid } from './errors.ts';

/** Multicodec prefix for an Ed25519 public key. */
const ED25519_PUB = Uint8Array.of(0xed, 0x01);

export interface KeyPair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
  /** The public key as a Multikey (`z6Mk…`). */
  multikey: string;
}

export function encodeMultikey(publicKey: Uint8Array): string {
  const bytes = new Uint8Array(ED25519_PUB.length + publicKey.length);
  bytes.set(ED25519_PUB);
  bytes.set(publicKey, ED25519_PUB.length);
  return `z${base58.encode(bytes)}`;
}

export function decodeMultikey(multikey: unknown): Uint8Array {
  check(typeof multikey === 'string' && multikey.startsWith('z'), 'bad_shape', 'not a Multikey');
  let bytes: Uint8Array;
  try {
    bytes = base58.decode(multikey.slice(1));
  } catch {
    throw new Invalid('bad_shape', 'Multikey is not base58btc');
  }
  check(bytes.length === 34 && bytes[0] === 0xed && bytes[1] === 0x01, 'bad_shape', 'not an Ed25519 Multikey');
  return bytes.slice(2);
}

export function isMultikey(value: unknown): value is string {
  try {
    decodeMultikey(value);
    return true;
  } catch {
    return false;
  }
}

export function keyPairFromSecret(secretKey: Uint8Array): KeyPair {
  const publicKey = ed25519.getPublicKey(secretKey);
  return { secretKey, publicKey, multikey: encodeMultikey(publicKey) };
}

export function generateKeyPair(): KeyPair {
  return keyPairFromSecret(ed25519.utils.randomSecretKey());
}

/** An Ed25519 signature over `message`, base64url without padding. */
export function signBytes(message: Uint8Array, secretKey: Uint8Array): string {
  return base64url.encode(ed25519.sign(message, secretKey));
}

/** Strict RFC 8032 verification, so every implementation accepts the same signatures. */
export function verifyBytes(signature: string, message: Uint8Array, multikey: string): boolean {
  try {
    const sig = base64url.decode(signature);
    if (sig.length !== 64) return false;
    return ed25519.verify(sig, message, decodeMultikey(multikey), { zip215: false });
  } catch {
    return false;
  }
}
