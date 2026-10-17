import { cidOf, HASH_REF, isObject, isTime, jcs, withoutSig } from './encoding.ts';
import { check, verdict, type Verdict } from './errors.ts';
import { signBytes, verifyBytes } from './keys.ts';
import { signingKeyFor, type Keylog, type Sig } from './keylog.ts';
import { checkManifest } from './scape.ts';
import { bodyProblem } from './schemas.ts';

export interface MemeRecord {
  v: 0;
  account: string;
  type: string;
  rkey: string;
  prev: string | null;
  created: string;
  license?: string;
  body: Record<string, unknown> | null;
  deleted?: true;
  keylogSeq: number;
  sig: Sig;
}

export type UnsignedRecord = Omit<MemeRecord, 'sig'>;

/** A core type: one segment, defined by the protocol's type registry. */
export const CORE_TYPE = /^[a-z][a-z0-9]*$/;
const DOMAIN_LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
/** An extension type: reverse-DNS with at least three segments. */
export const EXTENSION_TYPE = new RegExp(`^(?=.{1,253}$)${DOMAIN_LABEL}(?:\\.${DOMAIN_LABEL}){2,}$`);
export const RKEY = /^[a-z0-9][a-z0-9-]{0,63}$/;
const SPDX_ID = /^[A-Za-z0-9][A-Za-z0-9.+-]{0,127}$/;
export const MAX_BODY_BYTES = 64 * 1024;

export function isRecordType(type: unknown): type is string {
  return typeof type === 'string' && (CORE_TYPE.test(type) || EXTENSION_TYPE.test(type));
}

function isLicense(value: unknown): boolean {
  if (typeof value !== 'string') return false;
  if (SPDX_ID.test(value)) return true;
  try {
    return new URL(value).protocol === 'https:';
  } catch {
    return false;
  }
}

export function signRecord(record: UnsignedRecord, keyName: string, secretKey: Uint8Array): MemeRecord {
  return { ...record, sig: { key: keyName, value: signBytes(jcs(record), secretKey) } };
}

function checkRecordShape(record: unknown): asserts record is MemeRecord {
  check(isObject(record), 'bad_shape', 'a record is an object');
  check(record.v === 0, 'bad_version', 'v must be 0');
  check(typeof record.account === 'string', 'bad_shape', 'account must be a string');
  check(isRecordType(record.type), 'bad_shape', 'type must be a core type or a reverse-DNS extension type');
  check(typeof record.rkey === 'string' && RKEY.test(record.rkey), 'bad_shape', 'rkey is invalid');
  check(
    record.prev === null || (typeof record.prev === 'string' && HASH_REF.test(record.prev)),
    'bad_shape',
    'prev must be a hash or null',
  );
  check(isTime(record.created), 'bad_shape', 'created must be an RFC 3339 UTC time with milliseconds');
  check(
    record.license === undefined || isLicense(record.license),
    'bad_shape',
    'license must be an SPDX ID or an https URL',
  );
  if (record.deleted === undefined) {
    check(isObject(record.body), 'bad_shape', 'body must be an object');
  } else {
    check(record.deleted === true && record.body === null, 'bad_shape', 'a tombstone has deleted: true and body: null');
  }
  check(
    isObject(record.sig) && typeof record.sig.key === 'string' && typeof record.sig.value === 'string',
    'bad_shape',
    'sig must be { key, value }',
  );
}

function verifyRecordOrThrow(record: unknown, keylog: Keylog): { record: MemeRecord; cid: string } {
  checkRecordShape(record);
  check(record.account === keylog.account, 'bad_account', 'record belongs to another account');
  check(jcs(record.body).length <= MAX_BODY_BYTES, 'too_large', 'body is larger than 64 KiB');
  const message = jcs(withoutSig(record));
  const key = signingKeyFor(keylog, record.keylogSeq, record.sig.key, { record: record.type });
  check(verifyBytes(record.sig.value, message, key), 'bad_signature', 'signature does not verify');
  if (record.body !== null) {
    const problem = bodyProblem(record.type, record.body);
    check(problem === null, 'schema', `body ${problem ?? ''}`);
    if (record.type === 'scape') checkManifest(record.body);
  }
  return { record, cid: cidOf(record) };
}

/**
 * Verifies a record against its account's verified key log (spec: Records).
 * Bodies of known core types are checked against their schemas.
 */
export function verifyRecord(record: unknown, keylog: Keylog): Verdict<{ record: MemeRecord; cid: string }> {
  return verdict(() => verifyRecordOrThrow(record, keylog));
}
