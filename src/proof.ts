import { base64url, isObject, isTime, jcs, withoutSig } from './encoding.ts';
import { check, verdict, type Verdict } from './errors.ts';
import { signBytes, verifyBytes } from './keys.ts';
import { signingKeyFor, type Keylog, type Sig } from './keylog.ts';

export interface Proof {
  v: 0;
  account: string;
  audience: string;
  nonce: string;
  issued: string;
  expires: string;
  keylogSeq: number;
  sig: Sig;
}

export type UnsignedProof = Omit<Proof, 'sig'>;

export const MAX_PROOF_WINDOW_MS = 5 * 60 * 1000;
export const MIN_NONCE_BYTES = 16;

export function signProof(proof: UnsignedProof, keyName: string, secretKey: Uint8Array): Proof {
  return { ...proof, sig: { key: keyName, value: signBytes(jcs(proof), secretKey) } };
}

function nonceBytes(nonce: string): number {
  try {
    return base64url.decode(nonce).length;
  } catch {
    return 0;
  }
}

/**
 * Verifies a sign-in proof (spec: Sign-in proofs). `audience` is the verifier's
 * own origin, `nonce` the one it issued, `now` the current time.
 */
export function verifyProof(
  proof: unknown,
  keylog: Keylog,
  expected: { audience: string; nonce: string; now: string },
): Verdict<Proof> {
  return verdict(() => {
    check(isObject(proof), 'bad_shape', 'a proof is an object');
    check(proof.v === 0, 'bad_version', 'v must be 0');
    check(typeof proof.audience === 'string', 'bad_shape', 'audience must be a string');
    check(
      typeof proof.nonce === 'string' && nonceBytes(proof.nonce) >= MIN_NONCE_BYTES,
      'bad_shape',
      'nonce must be base64url of at least 16 bytes',
    );
    check(
      isTime(proof.issued) && isTime(proof.expires),
      'bad_shape',
      'issued and expires must be RFC 3339 UTC times with milliseconds',
    );
    check(
      isObject(proof.sig) && typeof proof.sig.key === 'string' && typeof proof.sig.value === 'string',
      'bad_shape',
      'sig must be { key, value }',
    );
    const signed = proof as unknown as Proof;
    check(signed.account === keylog.account, 'bad_account', 'proof is for another account');
    check(signed.audience === expected.audience, 'bad_audience', 'proof is for another audience');
    check(signed.nonce === expected.nonce, 'bad_nonce', 'proof carries another nonce');
    const issued = Date.parse(signed.issued);
    const expires = Date.parse(signed.expires);
    const now = Date.parse(expected.now);
    check(expires - issued <= MAX_PROOF_WINDOW_MS, 'window_too_long', 'a proof is valid for at most 5 minutes');
    check(issued <= now && now <= expires, 'expired', 'proof is not valid at this time');
    const message = jcs(withoutSig(signed));
    const key = signingKeyFor(keylog, signed.keylogSeq, signed.sig.key, 'proof');
    check(verifyBytes(signed.sig.value, message, key), 'bad_signature', 'signature does not verify');
    return signed;
  });
}
