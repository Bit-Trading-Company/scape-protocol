/**
 * Why an object is invalid. Every implementation should report the same reason
 * for the same vector; see vectors/README.md for the order checks run in.
 */
export type Reason =
  | 'bad_shape'
  | 'bad_version'
  | 'not_integer'
  | 'too_large'
  | 'bad_seq'
  | 'bad_prev'
  | 'bad_account'
  | 'deactivated'
  | 'unknown_key'
  | 'revoked_key'
  | 'key_restricted'
  | 'unknown_restriction'
  | 'bad_signature'
  | 'schema'
  | 'bad_head'
  | 'bad_audience'
  | 'bad_nonce'
  | 'expired'
  | 'window_too_long'
  | 'bad_path'
  | 'bad_entry'
  | 'bad_hash'
  | 'bad_size';

export class Invalid extends Error {
  readonly reason: Reason;

  constructor(reason: Reason, message: string) {
    super(message);
    this.name = 'Invalid';
    this.reason = reason;
  }
}

export type Verdict<T> = { valid: true; value: T } | { valid: false; reason: Reason; message: string };

export function check(condition: unknown, reason: Reason, message: string): asserts condition {
  if (!condition) throw new Invalid(reason, message);
}

/** Runs a check that throws `Invalid` and turns the outcome into a verdict. */
export function verdict<T>(fn: () => T): Verdict<T> {
  try {
    return { valid: true, value: fn() };
  } catch (error) {
    if (error instanceof Invalid) return { valid: false, reason: error.reason, message: error.message };
    throw error;
  }
}
