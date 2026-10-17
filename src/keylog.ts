import { base32lower, fullHash, HASH_REF, isObject, isTime, jcs, sha256Bytes, withoutSig } from './encoding.ts';
import { check, verdict, type Verdict } from './errors.ts';
import { isMultikey, signBytes, verifyBytes, type KeyPair } from './keys.ts';

export interface Sig {
  /** A Multikey (key log entries) or a signing key's name (everything else). */
  key: string;
  value: string;
}

export interface Restriction {
  types?: string[];
  [unknown: string]: unknown;
}

export interface SigningKey {
  key: string;
  restrict?: Restriction;
}

export interface KeylogEntry {
  v: 0;
  account: string | null;
  seq: number;
  prev: string | null;
  rotationKeys: string[];
  signingKeys: Record<string, SigningKey>;
  revokedKeys: string[];
  handles: string[];
  hosts: string[];
  created: string;
  deactivated?: true;
  sig: Sig;
}

export type UnsignedKeylogEntry = Omit<KeylogEntry, 'sig'>;

/** A verified key log. */
export interface Keylog {
  account: string;
  entries: KeylogEntry[];
  head: KeylogEntry;
  headHash: string;
}

/** What a signing key is being used for. */
export type Purpose = { record: string } | 'checkpoint' | 'proof';

export const ACCOUNT_ID = /^[a-z2-7]{24}$/;
export const KEY_NAME = /^[a-z0-9-]{1,32}$/;
const LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
export const HANDLE = new RegExp(`^(?=.{1,253}$)${LABEL}(?:\\.${LABEL})+$`);
/** A Scape handle's first label (spec: Handles). */
export const SCAPE_HANDLE_LABEL = /^[a-z0-9](?:[a-z0-9-]{1,28}[a-z0-9])$/;

export function isHostUrl(value: unknown): boolean {
  if (typeof value !== 'string') return false;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.username || url.password || url.search || url.hash) return false;
  if (url.protocol === 'https:') return true;
  return url.protocol === 'http:' && (url.hostname === 'localhost' || url.hostname === '127.0.0.1');
}

/** The account ID: 24 base32 characters of the SHA-256 of the signed genesis entry. */
export function accountIdOf(genesis: KeylogEntry): string {
  return base32lower(sha256Bytes(jcs(genesis))).slice(0, 24);
}

export function signKeylogEntry(entry: UnsignedKeylogEntry, rotationKey: KeyPair): KeylogEntry {
  return { ...entry, sig: { key: rotationKey.multikey, value: signBytes(jcs(entry), rotationKey.secretKey) } };
}

function checkSig(value: unknown): asserts value is Sig {
  check(
    isObject(value) && typeof value.key === 'string' && typeof value.value === 'string',
    'bad_shape',
    'sig must be { key, value }',
  );
}

function checkStrings(value: unknown, min: number, max: number, test: (item: unknown) => boolean, name: string): void {
  check(
    Array.isArray(value) && value.length >= min && value.length <= max && value.every(test),
    'bad_shape',
    `${name} must be ${min}–${max} valid entries`,
  );
  check(new Set(value).size === value.length, 'bad_shape', `${name} has duplicates`);
}

function checkEntryShape(entry: unknown): asserts entry is KeylogEntry {
  check(isObject(entry), 'bad_shape', 'entry must be an object');
  check(entry.v === 0, 'bad_version', 'v must be 0');
  check(Number.isSafeInteger(entry.seq) && (entry.seq as number) >= 0, 'bad_shape', 'seq must be an integer ≥ 0');
  check(entry.account === null || typeof entry.account === 'string', 'bad_shape', 'account must be a string or null');
  check(
    entry.prev === null || (typeof entry.prev === 'string' && HASH_REF.test(entry.prev)),
    'bad_shape',
    'prev must be a hash or null',
  );
  checkStrings(entry.rotationKeys, 1, 5, isMultikey, 'rotationKeys');
  check(isObject(entry.signingKeys), 'bad_shape', 'signingKeys must be an object');
  const names = Object.keys(entry.signingKeys);
  check(names.length >= 1 && names.length <= 8, 'bad_shape', 'signingKeys must have 1–8 keys');
  for (const name of names) {
    const signingKey = entry.signingKeys[name];
    check(KEY_NAME.test(name), 'bad_shape', `signing key name "${name}" is invalid`);
    check(isObject(signingKey) && isMultikey(signingKey.key), 'bad_shape', `signing key "${name}" is invalid`);
    check(
      signingKey.restrict === undefined || isObject(signingKey.restrict),
      'bad_shape',
      `restrict of "${name}" must be an object`,
    );
  }
  checkStrings(entry.revokedKeys, 0, 64, isMultikey, 'revokedKeys');
  checkStrings(entry.handles, 0, 4, (h) => typeof h === 'string' && HANDLE.test(h), 'handles');
  checkStrings(entry.hosts, 1, 4, isHostUrl, 'hosts');
  check(isTime(entry.created), 'bad_shape', 'created must be an RFC 3339 UTC time with milliseconds');
  check(
    entry.deactivated === undefined || entry.deactivated === true,
    'bad_shape',
    'deactivated must be true if present',
  );
  checkSig(entry.sig);
}

function verifyKeylogOrThrow(entries: unknown): Keylog {
  check(Array.isArray(entries) && entries.length > 0, 'bad_shape', 'a key log is a non-empty array');
  let account = '';
  let head: KeylogEntry | undefined;
  const verified: KeylogEntry[] = [];
  for (const [i, entry] of entries.entries()) {
    checkEntryShape(entry);
    check(entry.seq === i, 'bad_seq', `entry ${i} has seq ${entry.seq}`);
    const previous = verified[i - 1];
    if (previous === undefined) {
      check(entry.account === null, 'bad_account', 'the genesis entry has account null');
      check(entry.prev === null, 'bad_prev', 'the genesis entry has prev null');
    } else {
      check(entry.account === account, 'bad_account', `entry ${i} names another account`);
      check(entry.prev === fullHash(previous), 'bad_prev', `entry ${i} does not follow entry ${i - 1}`);
      check(previous.deactivated !== true, 'deactivated', `entry ${i} follows a deactivation`);
    }
    const message = jcs(withoutSig(entry));
    const authority = previous ?? entry;
    check(
      authority.rotationKeys.includes(entry.sig.key),
      'unknown_key',
      `entry ${i} is not signed by an authorized rotation key`,
    );
    check(!authority.revokedKeys.includes(entry.sig.key), 'revoked_key', `entry ${i} is signed by a revoked key`);
    check(verifyBytes(entry.sig.value, message, entry.sig.key), 'bad_signature', `entry ${i} has a bad signature`);
    if (previous === undefined) account = accountIdOf(entry);
    verified.push(entry);
    head = entry;
  }
  check(head !== undefined, 'bad_shape', 'a key log is a non-empty array');
  return { account, entries: verified, head, headHash: fullHash(head) };
}

export function verifyKeylog(entries: unknown): Verdict<Keylog> {
  return verdict(() => verifyKeylogOrThrow(entries));
}

/**
 * The Multikey a signature must verify against: the key named `name` in the
 * entry at `keylogSeq`, checked against revocation and its restrictions.
 */
export function signingKeyFor(log: Keylog, keylogSeq: unknown, name: unknown, purpose: Purpose): string {
  check(Number.isSafeInteger(keylogSeq) && (keylogSeq as number) >= 0, 'bad_shape', 'keylogSeq must be an integer ≥ 0');
  const entry = log.entries[keylogSeq as number];
  check(entry !== undefined, 'unknown_key', `the key log has no entry ${String(keylogSeq)}`);
  check(
    typeof name === 'string' && Object.hasOwn(entry.signingKeys, name),
    'unknown_key',
    `entry ${entry.seq} has no signing key "${String(name)}"`,
  );
  const signingKey = entry.signingKeys[name];
  check(signingKey !== undefined, 'unknown_key', `entry ${entry.seq} has no signing key "${name}"`);
  check(!log.head.revokedKeys.includes(signingKey.key), 'revoked_key', `signing key "${name}" has been revoked`);
  const restrict = signingKey.restrict;
  if (restrict !== undefined) {
    const unknown = Object.keys(restrict).filter((field) => field !== 'types');
    check(
      unknown.length === 0,
      'unknown_restriction',
      `signing key "${name}" has unknown restrictions: ${unknown.join(', ')}`,
    );
    check(typeof purpose === 'object', 'key_restricted', `restricted key "${name}" cannot sign a ${String(purpose)}`);
    if (restrict.types !== undefined) {
      check(Array.isArray(restrict.types), 'unknown_restriction', `restrict.types of "${name}" is not a list`);
      check(
        restrict.types.includes(purpose.record),
        'key_restricted',
        `signing key "${name}" may not sign ${purpose.record} records`,
      );
    }
  }
  return signingKey.key;
}
