import { fullHash, HASH_REF, isObject, isTime, jcs, withoutSig } from './encoding.ts';
import { check, verdict, type Verdict } from './errors.ts';
import { verifyBytes, type KeyPair } from './keys.ts';
import { checkSig, sign, signingKeyFor, type Keylog, type Sig } from './keylog.ts';
import { isRecordType, RKEY } from './record.ts';

export interface LogEntry {
  v: 0;
  seq: number;
  prev: string | null;
  op: 'put' | 'withdraw';
  type: string;
  rkey: string;
  cid?: string;
}

export interface Checkpoint {
  v: 0;
  account: string;
  seq: number;
  head: string;
  created: string;
  sig: Sig;
}

export type UnsignedCheckpoint = Omit<Checkpoint, 'sig'>;

/** Where a reader's view of a log ends: the last seq it has and that entry's hash. */
export interface LogPosition {
  seq: number;
  head: string;
}

export const logEntryHash = (entry: LogEntry): string => fullHash(entry);

/** The next entry after `previous` (or the first entry). */
export function nextLogEntry(
  previous: LogEntry | null,
  change: { op: 'put'; type: string; rkey: string; cid: string } | { op: 'withdraw'; type: string; rkey: string },
): LogEntry {
  return {
    v: 0,
    seq: previous === null ? 1 : previous.seq + 1,
    prev: previous === null ? null : logEntryHash(previous),
    ...change,
  };
}

export function signCheckpoint(checkpoint: UnsignedCheckpoint, signingKey: KeyPair, keylogSeq: number): Checkpoint {
  return sign(checkpoint, signingKey, keylogSeq);
}

function checkEntryShape(entry: unknown): asserts entry is LogEntry {
  check(isObject(entry), 'bad_shape', 'a log entry is an object');
  check(entry.v === 0, 'bad_version', 'v must be 0');
  check(Number.isSafeInteger(entry.seq), 'bad_shape', 'seq must be an integer');
  check(
    entry.prev === null || (typeof entry.prev === 'string' && HASH_REF.test(entry.prev)),
    'bad_shape',
    'prev must be a hash or null',
  );
  check(isRecordType(entry.type), 'bad_shape', 'type is invalid');
  check(typeof entry.rkey === 'string' && RKEY.test(entry.rkey), 'bad_shape', 'rkey is invalid');
  if (entry.op === 'put') {
    check(typeof entry.cid === 'string' && HASH_REF.test(entry.cid), 'bad_shape', 'a put needs a cid');
  } else {
    check(entry.op === 'withdraw', 'bad_shape', 'op must be put or withdraw');
    check(entry.cid === undefined, 'bad_shape', 'a withdraw has no cid');
  }
}

function verifyCheckpointOrThrow(checkpoint: unknown, keylog: Keylog): Checkpoint {
  check(isObject(checkpoint), 'bad_shape', 'a checkpoint is an object');
  check(checkpoint.v === 0, 'bad_version', 'v must be 0');
  check(
    Number.isSafeInteger(checkpoint.seq) && (checkpoint.seq as number) >= 1,
    'bad_shape',
    'seq must be an integer ≥ 1',
  );
  check(typeof checkpoint.head === 'string' && HASH_REF.test(checkpoint.head), 'bad_shape', 'head must be a hash');
  check(isTime(checkpoint.created), 'bad_shape', 'created must be an RFC 3339 UTC time with milliseconds');
  checkSig(checkpoint.sig);
  check(checkpoint.account === keylog.account, 'bad_account', 'checkpoint belongs to another account');
  const signed = checkpoint as unknown as Checkpoint;
  const message = jcs(withoutSig(signed));
  const key = signingKeyFor(keylog, signed.sig, 'checkpoint');
  check(verifyBytes(signed.sig.value, message, key), 'bad_signature', 'signature does not verify');
  return signed;
}

export function verifyCheckpoint(checkpoint: unknown, keylog: Keylog): Verdict<Checkpoint> {
  return verdict(() => verifyCheckpointOrThrow(checkpoint, keylog));
}

/**
 * Checks that `entries` are exactly the log entries after `after` (or from the
 * start) up to a signed checkpoint, so nothing was left out, reordered or altered.
 */
export function verifyLogRange(
  input: { after: LogPosition | null; entries: unknown; checkpoint: unknown },
  keylog: Keylog,
): Verdict<{ entries: LogEntry[]; checkpoint: Checkpoint }> {
  return verdict(() => {
    const { after, entries } = input;
    check(Array.isArray(entries), 'bad_shape', 'entries must be an array');
    check(after !== null || entries.length > 0, 'bad_shape', 'an empty range needs a starting position');
    let seq = after?.seq ?? 0;
    let head = after?.head ?? null;
    for (const entry of entries) {
      checkEntryShape(entry);
      check(entry.seq === seq + 1, 'bad_seq', `expected seq ${seq + 1}, got ${entry.seq}`);
      check(entry.prev === head, 'bad_prev', `entry ${entry.seq} does not follow entry ${seq}`);
      seq = entry.seq;
      head = logEntryHash(entry);
    }
    const checkpoint = verifyCheckpointOrThrow(input.checkpoint, keylog);
    check(
      checkpoint.seq === seq && checkpoint.head === head,
      'bad_head',
      `the range ends at ${seq}, the checkpoint does not match it`,
    );
    return { entries: entries as LogEntry[], checkpoint };
  });
}
