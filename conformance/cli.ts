/**
 * pnpm conformance            runs every vector against the reference library
 * pnpm conformance --host URL checks a live host (arrives with the M0 host)
 */
import { readVectors, runVector } from './vectors.ts';

const args = process.argv.slice(2);
if (args.includes('--host')) {
  console.error('Host checks are not built yet. They arrive with the first host endpoints (M0 vertical slice).');
  process.exit(2);
}

let failed = 0;
const vectors = readVectors();
for (const [path, vector] of Object.entries(vectors).sort(([a], [b]) => a.localeCompare(b))) {
  const outcome = runVector(path, vector);
  if (!outcome.pass) failed++;
  console.log(`${outcome.pass ? 'pass' : 'FAIL'}  ${path}  ${outcome.detail}`);
}
console.log(`\n${Object.keys(vectors).length - failed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
