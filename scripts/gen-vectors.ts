/** Regenerates vectors/ from conformance/build-vectors.ts. */
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { buildVectors, serialize } from '../conformance/build-vectors.ts';
import { KINDS, VECTORS_DIR } from '../conformance/vectors.ts';

for (const kind of KINDS) rmSync(join(VECTORS_DIR, kind), { recursive: true, force: true });
const vectors = buildVectors();
for (const [path, vector] of Object.entries(vectors)) {
  const file = join(VECTORS_DIR, path);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, serialize(vector));
}
console.log(`wrote ${Object.keys(vectors).length} vectors to vectors/`);
