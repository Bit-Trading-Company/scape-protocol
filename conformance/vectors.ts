/**
 * Runs test vectors against the reference library. Other TypeScript
 * implementations can copy this runner and swap in their own verifiers.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  base64url,
  resolvePath,
  verifyBlob,
  verifyCheckpoint,
  verifyKeylog,
  verifyLogRange,
  verifyManifest,
  verifyProof,
  verifyRecord,
  type FileRef,
  type Keylog,
  type LogPosition,
  type Verdict,
} from '../src/index.ts';
import type { Vector } from './build-vectors.ts';

export const VECTORS_DIR = fileURLToPath(new URL('../vectors', import.meta.url));

export const KINDS = ['keylog', 'record', 'log', 'checkpoint', 'proof', 'file', 'scape'] as const;
export type Kind = (typeof KINDS)[number];

export interface Outcome {
  pass: boolean;
  detail: string;
}

/** Reads every vector under vectors/, keyed by path relative to it ("record/valid/profile.json"). */
export function readVectors(dir = VECTORS_DIR): Record<string, Vector> {
  const vectors: Record<string, Vector> = {};
  const walk = (path: string): void => {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      const full = join(path, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith('.json')) {
        vectors[relative(dir, full).split(sep).join('/')] = JSON.parse(readFileSync(full, 'utf8')) as Vector;
      }
    }
  };
  walk(dir);
  return vectors;
}

function contextKeylog(vector: Vector): Keylog {
  const result = verifyKeylog(vector.context?.keylog);
  if (!result.valid) throw new Error(`context.keylog is invalid (${result.reason}): ${result.message}`);
  return result.value;
}

function verify(kind: Kind, vector: Vector): Verdict<unknown> {
  const input = vector.input as Record<string, unknown>;
  const context = vector.context ?? {};
  switch (kind) {
    case 'keylog':
      return verifyKeylog(vector.input);
    case 'record':
      return verifyRecord(vector.input, contextKeylog(vector));
    case 'checkpoint':
      return verifyCheckpoint(vector.input, contextKeylog(vector));
    case 'log':
      return verifyLogRange(
        { after: (context.after ?? null) as LogPosition | null, entries: input.entries, checkpoint: input.checkpoint },
        contextKeylog(vector),
      );
    case 'proof':
      return verifyProof(vector.input, contextKeylog(vector), {
        audience: String(context.audience),
        nonce: String(context.nonce),
        now: String(context.now),
      });
    case 'file':
      return verifyBlob(base64url.decode(String(input.bytes)), input.ref as FileRef);
    case 'scape':
      return verifyManifest(vector.input);
  }
}

/** The values a valid vector expects beyond `valid`, computed from a verdict. */
function derived(kind: Kind, vector: Vector, value: unknown): Record<string, unknown> {
  const v = value as Record<string, unknown>;
  switch (kind) {
    case 'keylog':
      return { account: v.account, headHash: v.headHash };
    case 'record':
      return { cid: v.cid };
    case 'scape': {
      const serve = (vector.expect as { serve?: { request: string }[] }).serve;
      if (serve === undefined) return {};
      return {
        serve: serve.map(({ request }) => ({ request, ...resolvePath(value as never, request) })),
      };
    }
    default:
      return {};
  }
}

export function runVector(path: string, vector: Vector): Outcome {
  const kind = path.split('/')[0] as Kind;
  if (!KINDS.includes(kind)) return { pass: false, detail: `unknown kind "${kind}"` };
  const result = verify(kind, vector);
  const expect = vector.expect;
  if (!expect.valid) {
    if (result.valid) return { pass: false, detail: `expected ${expect.reason}, but it verified` };
    if (result.reason !== expect.reason) {
      return { pass: false, detail: `expected ${expect.reason}, got ${result.reason}: ${result.message}` };
    }
    return { pass: true, detail: expect.reason };
  }
  if (!result.valid) return { pass: false, detail: `expected valid, got ${result.reason}: ${result.message}` };
  const { valid: _valid, ...wanted } = expect;
  const got = derived(kind, vector, result.value);
  for (const field of Object.keys(wanted)) {
    if (JSON.stringify(got[field]) !== JSON.stringify(wanted[field])) {
      return {
        pass: false,
        detail: `${field}: expected ${JSON.stringify(wanted[field])}, got ${JSON.stringify(got[field])}`,
      };
    }
  }
  return { pass: true, detail: 'valid' };
}
