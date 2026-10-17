import { sha256 } from '@noble/hashes/sha2.js';
import { base32nopad, base64urlnopad, hex } from '@scure/base';
import canonicalize from 'canonicalize';
import { check } from './errors.ts';

const encoder = new TextEncoder();

export const utf8 = (text: string): Uint8Array => encoder.encode(text);

export const HASH_REF = /^sha256:[0-9a-f]{64}$/;
export const SHA256_HEX = /^[0-9a-f]{64}$/;
export const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function isTime(value: unknown): value is string {
  return typeof value === 'string' && TIME.test(value) && !Number.isNaN(Date.parse(value));
}

/** Signed JSON holds integers only (spec: Encodings). */
export function assertIntegers(value: unknown, path = ''): void {
  if (typeof value === 'number') {
    check(Number.isSafeInteger(value), 'not_integer', `${path || '/'} is not a safe integer`);
  } else if (Array.isArray(value)) {
    value.forEach((item, i) => assertIntegers(item, `${path}/${i}`));
  } else if (isObject(value)) {
    for (const [key, item] of Object.entries(value)) assertIntegers(item, `${path}/${key}`);
  }
}

/** RFC 8785 canonical bytes. */
export function jcs(value: unknown): Uint8Array {
  assertIntegers(value);
  const text = canonicalize(value);
  check(text !== undefined, 'bad_shape', 'value is not JSON');
  return utf8(text);
}

export function withoutSig<T extends { sig?: unknown }>(object: T): Omit<T, 'sig'> {
  const { sig: _sig, ...rest } = object;
  return rest;
}

export const sha256Hex = (bytes: Uint8Array): string => hex.encode(sha256(bytes));

/** `sha256:<hex>` over the bytes. */
export const hashRef = (bytes: Uint8Array): string => `sha256:${sha256Hex(bytes)}`;

/** The CID of a signed object: the hash of its canonical bytes without `sig`. */
export const cidOf = (object: { sig?: unknown }): string => hashRef(jcs(withoutSig(object)));

/** The hash of an object's full canonical bytes, `sig` included, as used by `prev` links. */
export const fullHash = (object: unknown): string => hashRef(jcs(object));

export const base32lower = (bytes: Uint8Array): string => base32nopad.encode(bytes).toLowerCase();

export const sha256Bytes = sha256;
export { base64urlnopad as base64url, hex };
