/**
 * pnpm conformance                                  every vector against the reference library
 * pnpm conformance --host URL --account ID [--handle H]   a live host
 */
import { parseArgs } from 'node:util';
import { checkHost } from './host.ts';
import { readVectors, runVector } from './vectors.ts';

const { values } = parseArgs({
  options: { host: { type: 'string' }, account: { type: 'string' }, handle: { type: 'string' } },
});

if (values.host !== undefined) {
  if (values.account === undefined) {
    console.error('--host needs --account <id> of an account the host serves');
    process.exit(2);
  }
  const results = await checkHost({ base: values.host, account: values.account, handle: values.handle });
  for (const { name, status, detail } of results) console.log(`${status.padEnd(7)} ${name}  ${detail}`);
  const failed = results.filter((r) => r.status === 'fail').length;
  const pending = results.filter((r) => r.status === 'pending').length;
  console.log(`\n${results.length - failed - pending} passed, ${failed} failed, ${pending} pending`);
  process.exit(failed === 0 ? 0 : 1);
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
