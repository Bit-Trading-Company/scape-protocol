import { sha256Hex } from './encoding.ts';
import { check, verdict, type Verdict } from './errors.ts';

export interface FileRef {
  sha256: string;
  size: number;
  mime: string;
}

export function fileRefOf(bytes: Uint8Array, mime: string): FileRef {
  return { sha256: sha256Hex(bytes), size: bytes.length, mime };
}

/** Checks that fetched bytes match the file ref that named them. */
export function verifyBlob(bytes: Uint8Array, ref: FileRef): Verdict<FileRef> {
  return verdict(() => {
    check(bytes.length === ref.size, 'bad_size', `expected ${ref.size} bytes, got ${bytes.length}`);
    check(sha256Hex(bytes) === ref.sha256, 'bad_hash', 'bytes do not match sha256');
    return ref;
  });
}
