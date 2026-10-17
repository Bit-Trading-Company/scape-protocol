import { isObject } from './encoding.ts';
import { check, verdict, type Verdict } from './errors.ts';
import type { FileRef } from './file.ts';
import { bodyProblem } from './schemas.ts';

export interface ScapeManifest {
  title?: string;
  entry: string;
  files: Record<string, FileRef>;
  blocks?: { name: string; version: string; manifest: FileRef }[];
  uses?: { records?: unknown[]; functions?: string[] };
  generator?: string;
}

const PATH_CHARS = /^[A-Za-z0-9._~\-/]+$/;
export const MAX_FILES = 10_000;
export const MAX_BUNDLE_BYTES = 1024 ** 3;

export function isBundlePath(path: string): boolean {
  return (
    path.length <= 256 &&
    PATH_CHARS.test(path) &&
    path.split('/').every((segment) => segment !== '' && segment !== '.' && segment !== '..')
  );
}

/**
 * The rules beyond the `scape` type's JSON Schema: paths, the entry, and size
 * limits. Assumes the body already passed the schema.
 */
export function checkManifest(body: unknown): asserts body is ScapeManifest {
  check(isObject(body) && isObject(body.files) && typeof body.entry === 'string', 'bad_shape', 'not a scape manifest');
  const files = body.files as Record<string, FileRef>;
  const entries = Object.entries(files);
  for (const [path] of entries) check(isBundlePath(path), 'bad_path', `"${path}" is not a valid bundle path`);
  check(Object.hasOwn(files, body.entry), 'bad_entry', `entry "${body.entry}" is not in files`);
  check(entries.length <= MAX_FILES, 'too_large', `more than ${MAX_FILES} files`);
  const total = entries.reduce((sum, [, ref]) => sum + ref.size, 0);
  check(total <= MAX_BUNDLE_BYTES, 'too_large', 'bundle is larger than 1 GiB');
}

/** Checks a manifest on its own: the `scape` type's schema, then the bundle rules. */
export function verifyManifest(body: unknown): Verdict<ScapeManifest> {
  return verdict(() => {
    const problem = bodyProblem('scape', body);
    check(problem === null, 'schema', `manifest ${problem ?? ''}`);
    checkManifest(body);
    return body;
  });
}

export interface Resolved {
  /** The bundle path to serve, or `null` for an empty 404. */
  path: string | null;
  status: 200 | 404;
}

/** Which file a request path serves (spec: Serving a bundle at any address). */
export function resolvePath(manifest: ScapeManifest, requestPath: string): Resolved {
  const has = (path: string) => Object.hasOwn(manifest.files, path);
  const notFound: Resolved = has('404.html') ? { path: '404.html', status: 404 } : { path: null, status: 404 };
  let path: string;
  try {
    path = decodeURIComponent(requestPath);
  } catch {
    return notFound;
  }
  if (!path.startsWith('/')) return notFound;
  if (path === '/') return { path: manifest.entry, status: 200 };
  const relative = path.slice(1);
  const candidates = relative.endsWith('/') ? [`${relative}index.html`] : [relative, `${relative}/index.html`];
  const found = candidates.find((candidate) => isBundlePath(candidate) && has(candidate));
  return found === undefined ? notFound : { path: found, status: 200 };
}
