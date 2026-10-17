/**
 * Builds every test vector from fixed keys and times, so the output is
 * byte-for-byte reproducible. `pnpm vectors` writes it to vectors/; a test
 * fails if the committed files drift from what this produces.
 */
import {
  accountIdOf,
  base64url,
  cidOf,
  fileRefOf,
  fullHash,
  keyPairFromSecret,
  logEntryHash,
  nextLogEntry,
  sha256Bytes,
  signCheckpoint,
  signKeylogEntry,
  signProof,
  signRecord,
  utf8,
  withoutSig,
  type KeyPair,
  type KeylogEntry,
  type MemeRecord,
  type Reason,
  type ScapeManifest,
  type SigningKey,
  type UnsignedKeylogEntry,
  type UnsignedRecord,
} from '../src/index.ts';

export type Expect = { valid: true; [derived: string]: unknown } | { valid: false; reason: Reason };

export interface Vector {
  description: string;
  context?: Record<string, unknown>;
  input: unknown;
  expect: Expect;
}

const key = (name: string): KeyPair => keyPairFromSecret(sha256Bytes(utf8(`meme-vectors/${name}`)));
const K = {
  rotation: key('rotation'),
  rotation2: key('rotation2'),
  signing: key('signing'),
  signing2: key('signing2'),
  phone: key('phone'),
  stranger: key('stranger'),
};
const at = (minute: number): string => new Date(Date.UTC(2026, 9, 17, 9, minute)).toISOString();
const ZERO_HASH = `sha256:${'0'.repeat(64)}`;
const OTHER_ACCOUNT = 'a'.repeat(24);

// Key logs

function genesis(overrides: Record<string, unknown> = {}, signer = K.rotation): KeylogEntry {
  return signKeylogEntry(
    {
      v: 0,
      account: null,
      seq: 0,
      prev: null,
      rotationKeys: [K.rotation.multikey],
      signingKeys: { main: { key: K.signing.multikey } },
      revokedKeys: [],
      handles: ['ada.host.example'],
      hosts: ['https://host.example'],
      created: at(0),
      ...overrides,
    } as UnsignedKeylogEntry,
    signer,
  );
}

const g = genesis();
const account = accountIdOf(g);

function next(previous: KeylogEntry, changes: Record<string, unknown> = {}, signer = K.rotation): KeylogEntry {
  return signKeylogEntry(
    {
      ...withoutSig(previous),
      account,
      seq: previous.seq + 1,
      prev: fullHash(previous),
      created: at(previous.seq + 1),
      ...changes,
    } as UnsignedKeylogEntry,
    signer,
  );
}

const main: SigningKey = { key: K.signing.multikey };
const phone = (restrict: Record<string, unknown>): SigningKey => ({ key: K.phone.multikey, restrict });

const logs = {
  base: [g],
  rotated: [g, next(g, { signingKeys: { main: { key: K.signing2.multikey } } })],
  revoked: [g, next(g, { signingKeys: { main2: { key: K.signing2.multikey } }, revokedKeys: [K.signing.multikey] })],
  withPhone: [g, next(g, { signingKeys: { main, phone: phone({ types: ['post', 'file'] }) } })],
  unknownRestriction: [g, next(g, { signingKeys: { main, phone: phone({ types: ['post'], expires: at(60) }) } })],
};

/** Removes the signature check from the picture by changing a field after signing. */
const tamper = <T extends object>(signed: T, changes: Record<string, unknown>): T => ({ ...signed, ...changes });

// Records

function record(
  overrides: Partial<UnsignedRecord> & Record<string, unknown> = {},
  signer: { name: string; key: KeyPair } = { name: 'main', key: K.signing },
): MemeRecord {
  const fields = {
    v: 0,
    account,
    type: 'profile',
    rkey: 'self',
    prev: null,
    created: at(10),
    license: 'LicenseRef-scape-1.0',
    body: { displayName: 'Ada' },
    keylogSeq: 0,
    ...overrides,
  };
  // An override of `undefined` removes the field.
  const unsigned = Object.fromEntries(
    Object.entries(fields).filter(([, value]) => value !== undefined),
  ) as UnsignedRecord;
  return signRecord(unsigned, signer.name, signer.key.secretKey);
}

const bytesOf = (text: string) => utf8(text);
const photo = fileRefOf(bytesOf('not really a jpeg'), 'image/jpeg');

const site = {
  'index.html': fileRefOf(bytesOf('<h1>Ada</h1>\n'), 'text/html'),
  'about/index.html': fileRefOf(bytesOf('<h1>About</h1>\n'), 'text/html'),
  'assets/site.css': fileRefOf(bytesOf('h1{font-weight:400}\n'), 'text/css'),
  '404.html': fileRefOf(bytesOf('<h1>Not here</h1>\n'), 'text/html'),
};
const manifest: ScapeManifest = {
  title: "Ada's links",
  entry: 'index.html',
  files: site,
  uses: { functions: ['account.get'] },
  generator: 'meme-vectors',
};
const withFiles = (files: Record<string, unknown>, entry = 'index.html') => ({ ...manifest, entry, files });

const profile = record();
const profileCid = cidOf(profile);

// Repository log

const fileRecord = record({ type: 'file', rkey: '3l2kq7xxa2c2s', body: { blob: photo, name: 'photo.jpg' } });
const e1 = nextLogEntry(null, { op: 'put', type: 'profile', rkey: 'self', cid: profileCid });
const e2 = nextLogEntry(e1, { op: 'put', type: 'file', rkey: '3l2kq7xxa2c2s', cid: cidOf(fileRecord) });
const e3 = nextLogEntry(e2, { op: 'withdraw', type: 'file', rkey: '3l2kq7xxa2c2s' });
const checkpoint = (seq: number, head: string, signer = { name: 'main', key: K.signing }, keylogSeq = 0) =>
  signCheckpoint({ v: 0, account, seq, head, created: at(20 + seq), keylogSeq }, signer.name, signer.key.secretKey);
const cp2 = checkpoint(2, logEntryHash(e2));
const cp3 = checkpoint(3, logEntryHash(e3));

// Sign-in proofs

const nonce = base64url.encode(sha256Bytes(utf8('meme-vectors/nonce')));
const audience = 'https://app.example';
const proofContext = { keylog: logs.base, audience, nonce, now: at(31) };
const proof = (overrides: Record<string, unknown> = {}, signer = { name: 'main', key: K.signing }) =>
  signProof(
    { v: 0, account, audience, nonce, issued: at(30), expires: at(35), keylogSeq: 0, ...overrides } as never,
    signer.name,
    signer.key.secretKey,
  );

// Files

const blob = bytesOf('hello, meme\n');
const blobRef = fileRefOf(blob, 'text/plain');

const valid = (derived: Record<string, unknown> = {}): Expect => ({ valid: true, ...derived });
const invalid = (reason: Reason): Expect => ({ valid: false, reason });
const keylogExpect = (entries: KeylogEntry[]) => valid({ account, headHash: fullHash(entries[entries.length - 1]) });
const genesisExpect = (entry: KeylogEntry) => valid({ account: accountIdOf(entry), headHash: fullHash(entry) });
const recordExpect = (r: MemeRecord) => valid({ cid: cidOf(r) });

export function buildVectors(): Record<string, Vector> {
  const deactivated = next(g, { deactivated: true });
  const vectors: Record<string, Vector> = {
    // Key logs
    'keylog/valid/genesis.json': {
      description: 'A genesis entry alone.',
      input: logs.base,
      expect: keylogExpect(logs.base),
    },
    'keylog/valid/rotated-signing-key.json': {
      description: 'Entry 1 replaces the signing key, signed by the rotation key from entry 0.',
      input: logs.rotated,
      expect: keylogExpect(logs.rotated),
    },
    'keylog/valid/restricted-key.json': {
      description: 'A signing key restricted to some record types.',
      input: logs.withPhone,
      expect: keylogExpect(logs.withPhone),
    },
    'keylog/valid/unknown-restriction.json': {
      description: 'A key with an unknown restriction does not make the key log invalid; the key is unusable.',
      input: logs.unknownRestriction,
      expect: keylogExpect(logs.unknownRestriction),
    },
    'keylog/valid/unknown-field.json': (() => {
      const entry = genesis({ note: 'readers ignore fields they do not know' });
      return {
        description: 'Unknown fields are ignored, but covered by the signature and the account ID.',
        input: [entry],
        expect: genesisExpect(entry),
      };
    })(),
    'keylog/valid/deactivated.json': {
      description: 'An account can be deactivated.',
      input: [g, deactivated],
      expect: keylogExpect([g, deactivated]),
    },
    'keylog/valid/localhost-host.json': (() => {
      const entry = genesis({ hosts: ['http://localhost:8787'] });
      return {
        description: 'Plain http is allowed for localhost, for development.',
        input: [entry],
        expect: genesisExpect(entry),
      };
    })(),
    'keylog/invalid/empty.json': {
      description: 'A key log has at least one entry.',
      input: [],
      expect: invalid('bad_shape'),
    },
    'keylog/invalid/version-1.json': {
      description: 'v0 readers only accept v: 0.',
      input: [genesis({ v: 1 })],
      expect: invalid('bad_version'),
    },
    'keylog/invalid/genesis-names-account.json': {
      description: 'The genesis entry has account: null.',
      input: [genesis({ account: OTHER_ACCOUNT })],
      expect: invalid('bad_account'),
    },
    'keylog/invalid/seq-gap.json': {
      description: 'seq rises by exactly 1.',
      input: [g, next(g, { seq: 2 })],
      expect: invalid('bad_seq'),
    },
    'keylog/invalid/prev-mismatch.json': {
      description: 'prev must be the hash of the previous entry.',
      input: [g, next(g, { prev: ZERO_HASH })],
      expect: invalid('bad_prev'),
    },
    'keylog/invalid/genesis-signed-by-signing-key.json': {
      description: 'Only a rotation key may sign a key log entry.',
      input: [genesis({}, K.signing)],
      expect: invalid('unknown_key'),
    },
    'keylog/invalid/signed-by-its-own-new-key.json': {
      description: 'Entry 1 must be signed by a rotation key from entry 0, not one it introduces.',
      input: [g, next(g, { rotationKeys: [K.rotation2.multikey] }, K.rotation2)],
      expect: invalid('unknown_key'),
    },
    'keylog/invalid/tampered.json': {
      description: 'A field changed after signing.',
      input: [tamper(g, { handles: ['eve.host.example'] })],
      expect: invalid('bad_signature'),
    },
    'keylog/invalid/after-deactivation.json': {
      description: 'Nothing follows a deactivation.',
      input: [g, deactivated, next(deactivated)],
      expect: invalid('deactivated'),
    },
    'keylog/invalid/fractional-number.json': {
      description: 'Signed JSON holds integers only, even in unknown fields.',
      input: [tamper(g, { weight: 0.5 })],
      expect: invalid('not_integer'),
    },
    'keylog/invalid/six-rotation-keys.json': {
      description: 'At most 5 rotation keys.',
      input: [
        genesis({
          rotationKeys: [K.rotation, K.rotation2, K.signing, K.signing2, K.phone, K.stranger].map((k) => k.multikey),
        }),
      ],
      expect: invalid('bad_shape'),
    },
    'keylog/invalid/plain-http-host.json': {
      description: 'Hosts use https, except localhost.',
      input: [genesis({ hosts: ['http://host.example'] })],
      expect: invalid('bad_shape'),
    },

    // Records
    'record/valid/profile.json': {
      description: 'A profile.',
      context: { keylog: logs.base },
      input: profile,
      expect: recordExpect(profile),
    },
    'record/valid/no-license.json': (() => {
      const r = record({ license: undefined });
      return { description: 'license is optional.', context: { keylog: logs.base }, input: r, expect: recordExpect(r) };
    })(),
    'record/valid/revision.json': (() => {
      const r = record({ prev: profileCid, created: at(11), body: { displayName: 'Ada L.' } });
      return {
        description: 'A second revision, chained by prev.',
        context: { keylog: logs.base },
        input: r,
        expect: recordExpect(r),
      };
    })(),
    'record/valid/tombstone.json': (() => {
      const r = record({ prev: profileCid, created: at(12), body: null, deleted: true });
      return { description: 'A signed deletion.', context: { keylog: logs.base }, input: r, expect: recordExpect(r) };
    })(),
    'record/valid/extension-type.json': (() => {
      const r = record({
        type: 'com.example.recipe',
        rkey: '3l2kq7xxa2c2t',
        body: { title: 'Bread', steps: ['mix', 'bake'] },
      });
      return {
        description: 'A reverse-DNS extension type; its body is not checked by the core registry.',
        context: { keylog: logs.base },
        input: r,
        expect: recordExpect(r),
      };
    })(),
    'record/valid/unknown-body-field.json': (() => {
      const r = record({ body: { displayName: 'Ada', 'com.example.badge': 'gold' } });
      return {
        description: 'Readers ignore unknown body fields.',
        context: { keylog: logs.base },
        input: r,
        expect: recordExpect(r),
      };
    })(),
    'record/valid/unknown-envelope-field.json': (() => {
      const r = record({ via: 'a newer client' } as never);
      return {
        description: 'Readers ignore unknown envelope fields.',
        context: { keylog: logs.base },
        input: r,
        expect: recordExpect(r),
      };
    })(),
    'record/valid/rotated-out-key.json': {
      description: 'A key that was rotated out (not revoked) keeps its past signatures valid.',
      context: { keylog: logs.rotated },
      input: profile,
      expect: recordExpect(profile),
    },
    'record/valid/restricted-key-allowed-type.json': (() => {
      const r = record(
        { type: 'file', rkey: '3l2kq7xxa2c2s', body: { blob: photo, name: 'photo.jpg' }, keylogSeq: 1 },
        { name: 'phone', key: K.phone },
      );
      return {
        description: 'A restricted key signing a type it is allowed.',
        context: { keylog: logs.withPhone },
        input: r,
        expect: recordExpect(r),
      };
    })(),
    'record/valid/scape.json': (() => {
      const r = record({ type: 'scape', rkey: 'links', body: manifest as never });
      return {
        description: 'A scape bundle manifest.',
        context: { keylog: logs.base },
        input: r,
        expect: recordExpect(r),
      };
    })(),
    'record/invalid/version-1.json': {
      description: 'v0 readers only accept v: 0.',
      context: { keylog: logs.base },
      input: record({ v: 1 } as never),
      expect: invalid('bad_version'),
    },
    'record/invalid/two-segment-type.json': {
      description: 'A type is one segment (core) or at least three (reverse-DNS).',
      context: { keylog: logs.base },
      input: record({ type: 'scape.post' }),
      expect: invalid('bad_shape'),
    },
    'record/invalid/tombstone-with-body.json': {
      description: 'A tombstone has body: null.',
      context: { keylog: logs.base },
      input: record({ deleted: true }),
      expect: invalid('bad_shape'),
    },
    'record/invalid/wrong-account.json': {
      description: 'The record names another account than the key log.',
      context: { keylog: logs.base },
      input: record({ account: OTHER_ACCOUNT }),
      expect: invalid('bad_account'),
    },
    'record/invalid/fractional-number.json': {
      description: 'Signed JSON holds integers only.',
      context: { keylog: logs.base },
      input: tamper(profile, { body: { displayName: 'Ada', score: 1.5 } }),
      expect: invalid('not_integer'),
    },
    'record/invalid/body-too-large.json': {
      description: 'Bodies are at most 64 KiB.',
      context: { keylog: logs.base },
      input: record({ body: { bio: 'x'.repeat(70_000) } }),
      expect: invalid('too_large'),
    },
    'record/invalid/keylog-seq-beyond-head.json': {
      description: 'keylogSeq must name an existing entry.',
      context: { keylog: logs.base },
      input: record({ keylogSeq: 5 }),
      expect: invalid('unknown_key'),
    },
    'record/invalid/unknown-key-name.json': {
      description: 'sig.key must name a signing key in the entry at keylogSeq.',
      context: { keylog: logs.base },
      input: record({}, { name: 'other', key: K.signing }),
      expect: invalid('unknown_key'),
    },
    'record/invalid/revoked-key.json': {
      description: 'A revoked key invalidates its past signatures too.',
      context: { keylog: logs.revoked },
      input: profile,
      expect: invalid('revoked_key'),
    },
    'record/invalid/restricted-key-other-type.json': {
      description: 'A restricted key may sign only its listed types.',
      context: { keylog: logs.withPhone },
      input: record({ keylogSeq: 1 }, { name: 'phone', key: K.phone }),
      expect: invalid('key_restricted'),
    },
    'record/invalid/unknown-restriction.json': {
      description: 'Restrictions fail closed: a key with an unknown restriction is unusable.',
      context: { keylog: logs.unknownRestriction },
      input: record(
        { type: 'post', rkey: '3l2kq7xxa2c2u', body: { text: 'hi' }, keylogSeq: 1 },
        { name: 'phone', key: K.phone },
      ),
      expect: invalid('unknown_restriction'),
    },
    'record/invalid/tampered.json': {
      description: 'The body changed after signing.',
      context: { keylog: logs.base },
      input: tamper(profile, { body: { displayName: 'Eve' } }),
      expect: invalid('bad_signature'),
    },
    'record/invalid/wrong-signer.json': {
      description: 'Signed by a key that is not the named signing key.',
      context: { keylog: logs.base },
      input: record({}, { name: 'main', key: K.stranger }),
      expect: invalid('bad_signature'),
    },
    'record/invalid/schema.json': {
      description: 'The body breaks its core type schema (displayName is at most 64 characters).',
      context: { keylog: logs.base },
      input: record({ body: { displayName: 'A'.repeat(65) } }),
      expect: invalid('schema'),
    },
    'record/invalid/scape-bad-path.json': {
      description: 'Bundle paths never contain "..".',
      context: { keylog: logs.base },
      input: record({ type: 'scape', rkey: 'links', body: withFiles({ ...site, '../secret.txt': blobRef }) as never }),
      expect: invalid('bad_path'),
    },

    // Repository log
    'log/valid/from-start.json': {
      description: 'The whole log, up to a checkpoint.',
      context: { keylog: logs.base, after: null },
      input: { entries: [e1, e2, e3], checkpoint: cp3 },
      expect: valid(),
    },
    'log/valid/continuing.json': {
      description: 'The entries after a position the reader already holds.',
      context: { keylog: logs.base, after: { seq: 2, head: logEntryHash(e2) } },
      input: { entries: [e3], checkpoint: cp3 },
      expect: valid(),
    },
    'log/valid/up-to-date.json': {
      description: 'Nothing new since the reader’s position.',
      context: { keylog: logs.base, after: { seq: 3, head: logEntryHash(e3) } },
      input: { entries: [], checkpoint: cp3 },
      expect: valid(),
    },
    'log/invalid/missing-entry.json': {
      description: 'An entry was left out.',
      context: { keylog: logs.base, after: null },
      input: { entries: [e1, e3], checkpoint: cp3 },
      expect: invalid('bad_seq'),
    },
    'log/invalid/altered-middle-entry.json': {
      description: 'An earlier entry was altered, so the next one no longer follows it.',
      context: { keylog: logs.base, after: null },
      input: { entries: [e1, { ...e2, rkey: '3l2kq7xxa2c2z' }, e3], checkpoint: cp3 },
      expect: invalid('bad_prev'),
    },
    'log/invalid/altered-last-entry.json': {
      description: 'The last entry was altered, so it no longer matches the checkpoint.',
      context: { keylog: logs.base, after: null },
      input: { entries: [e1, e2, { ...e3, rkey: '3l2kq7xxa2c2z' }], checkpoint: cp3 },
      expect: invalid('bad_head'),
    },
    'log/invalid/stale-checkpoint.json': {
      description: 'The checkpoint is for an earlier point than the entries reach.',
      context: { keylog: logs.base, after: null },
      input: { entries: [e1, e2, e3], checkpoint: cp2 },
      expect: invalid('bad_head'),
    },
    'log/invalid/withdraw-with-cid.json': {
      description: 'A withdraw has no cid.',
      context: { keylog: logs.base, after: { seq: 2, head: logEntryHash(e2) } },
      input: { entries: [{ ...e3, cid: profileCid }], checkpoint: cp3 },
      expect: invalid('bad_shape'),
    },

    // Checkpoints
    'checkpoint/valid/checkpoint.json': {
      description: 'A checkpoint.',
      context: { keylog: logs.base },
      input: cp3,
      expect: valid(),
    },
    'checkpoint/invalid/restricted-signer.json': {
      description: 'Restricted keys cannot sign checkpoints.',
      context: { keylog: logs.withPhone },
      input: checkpoint(3, logEntryHash(e3), { name: 'phone', key: K.phone }, 1),
      expect: invalid('key_restricted'),
    },
    'checkpoint/invalid/wrong-account.json': {
      description: 'The checkpoint names another account.',
      context: { keylog: logs.base },
      input: tamper(cp3, { account: OTHER_ACCOUNT }),
      expect: invalid('bad_account'),
    },
    'checkpoint/invalid/tampered.json': {
      description: 'The head changed after signing.',
      context: { keylog: logs.base },
      input: tamper(cp3, { head: ZERO_HASH }),
      expect: invalid('bad_signature'),
    },

    // Sign-in proofs
    'proof/valid/proof.json': {
      description: 'A sign-in proof.',
      context: proofContext,
      input: proof(),
      expect: valid(),
    },
    'proof/invalid/wrong-audience.json': {
      description: 'Made for another app.',
      context: { ...proofContext, audience: 'https://other.example' },
      input: proof(),
      expect: invalid('bad_audience'),
    },
    'proof/invalid/wrong-nonce.json': {
      description: 'Carries a nonce the app did not issue.',
      context: { ...proofContext, nonce: base64url.encode(sha256Bytes(utf8('meme-vectors/other-nonce'))) },
      input: proof(),
      expect: invalid('bad_nonce'),
    },
    'proof/invalid/expired.json': {
      description: 'Presented after it expired.',
      context: { ...proofContext, now: at(36) },
      input: proof(),
      expect: invalid('expired'),
    },
    'proof/invalid/not-yet-valid.json': {
      description: 'Presented before it was issued.',
      context: { ...proofContext, now: at(29) },
      input: proof(),
      expect: invalid('expired'),
    },
    'proof/invalid/window-too-long.json': {
      description: 'Valid for more than 5 minutes.',
      context: proofContext,
      input: proof({ expires: at(36) }),
      expect: invalid('window_too_long'),
    },
    'proof/invalid/short-nonce.json': {
      description: 'Nonces carry at least 16 bytes.',
      context: { ...proofContext, nonce: base64url.encode(utf8('8 bytes!')) },
      input: proof({ nonce: base64url.encode(utf8('8 bytes!')) }),
      expect: invalid('bad_shape'),
    },
    'proof/invalid/restricted-key.json': {
      description: 'Restricted keys cannot sign proofs.',
      context: { ...proofContext, keylog: logs.withPhone },
      input: proof({ keylogSeq: 1 }, { name: 'phone', key: K.phone }),
      expect: invalid('key_restricted'),
    },
    'proof/invalid/tampered.json': {
      description: 'Changed after signing.',
      context: proofContext,
      input: tamper(proof(), { expires: at(34) }),
      expect: invalid('bad_signature'),
    },

    // Files
    'file/valid/blob.json': {
      description: 'Bytes that match their file ref. bytes is base64url.',
      input: { bytes: base64url.encode(blob), ref: blobRef },
      expect: valid(),
    },
    'file/invalid/wrong-hash.json': {
      description: 'Bytes that do not match sha256.',
      input: {
        bytes: base64url.encode(blob),
        ref: { ...blobRef, sha256: fileRefOf(bytesOf('other'), 'text/plain').sha256 },
      },
      expect: invalid('bad_hash'),
    },
    'file/invalid/wrong-size.json': {
      description: 'Bytes that do not match size.',
      input: { bytes: base64url.encode(blob), ref: { ...blobRef, size: blobRef.size + 1 } },
      expect: invalid('bad_size'),
    },

    // Scape bundles
    'scape/valid/site.json': {
      description: 'A manifest, and which file each request path serves.',
      input: manifest,
      expect: valid({
        serve: [
          { request: '/', path: 'index.html', status: 200 },
          { request: '/index.html', path: 'index.html', status: 200 },
          { request: '/about', path: 'about/index.html', status: 200 },
          { request: '/about/', path: 'about/index.html', status: 200 },
          { request: '/assets/site.css', path: 'assets/site.css', status: 200 },
          { request: '/assets/', path: '404.html', status: 404 },
          { request: '/missing', path: '404.html', status: 404 },
          { request: '/%2e%2e/secret', path: '404.html', status: 404 },
        ],
      }),
    },
    'scape/valid/no-404-page.json': (() => {
      const { '404.html': _, ...files } = site;
      return {
        description: 'Without 404.html, a miss is an empty 404.',
        input: withFiles(files),
        expect: valid({ serve: [{ request: '/missing', path: null, status: 404 }] }),
      };
    })(),
    'scape/invalid/dot-dot.json': {
      description: 'No ".." segments.',
      input: withFiles({ ...site, 'a/../b.html': blobRef }),
      expect: invalid('bad_path'),
    },
    'scape/invalid/leading-slash.json': {
      description: 'Paths are relative.',
      input: withFiles({ ...site, '/b.html': blobRef }),
      expect: invalid('bad_path'),
    },
    'scape/invalid/empty-segment.json': {
      description: 'No empty segments.',
      input: withFiles({ ...site, 'a//b.html': blobRef }),
      expect: invalid('bad_path'),
    },
    'scape/invalid/space.json': {
      description: 'Only [A-Za-z0-9._~-/].',
      input: withFiles({ ...site, 'a b.html': blobRef }),
      expect: invalid('bad_path'),
    },
    'scape/invalid/missing-entry.json': {
      description: 'entry must be one of files.',
      input: withFiles(site, 'home.html'),
      expect: invalid('bad_entry'),
    },
    'scape/invalid/schema.json': {
      description: 'Every file ref has sha256, size and mime.',
      input: withFiles({ ...site, 'b.html': { sha256: blobRef.sha256, mime: 'text/html' } }),
      expect: invalid('schema'),
    },
  };
  return vectors;
}

/** The serialized form written to disk. */
export const serialize = (vector: Vector): string => `${JSON.stringify(vector, null, 2)}\n`;
