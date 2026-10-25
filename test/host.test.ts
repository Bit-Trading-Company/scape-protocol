import { describe, expect, it } from 'vitest';
import { checkHost } from '../conformance/host.ts';
import { readVectors } from '../conformance/vectors.ts';

const vector = readVectors()['keylog/valid/genesis.json'];
const entries = vector?.input as unknown[];
const account = (vector?.expect as unknown as { account: string }).account;

/** A minimal host serving one account, with switches to break it. */
function fakeHost(breaks: { cookie?: boolean; tamper?: boolean; errorShape?: boolean } = {}) {
  const headers = (extra: Record<string, string> = {}) => ({
    'content-type': 'application/json',
    'access-control-allow-origin': '*',
    ...(breaks.cookie ? { 'set-cookie': 'a=b' } : {}),
    ...extra,
  });
  const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: headers() });
  return async (request: Request) => {
    const path = new URL(request.url).pathname;
    if (path === '/.well-known/meme')
      return json({ v: 0, api: 'https://public.example/meme/v0', files: 'https://files.example/' });
    if (path === `/meme/v0/accounts/${account}/keylog`) {
      const served = breaks.tamper ? [{ ...(entries[0] as object), handles: ['eve.host.example'] }] : entries;
      return json({ entries: served });
    }
    if (path === '/meme/v0/handles/ada.host.example') return json({ account });
    return breaks.errorShape
      ? json({ message: 'nope' }, 404)
      : json({ error: { code: 'not_found', message: 'Not found.' } }, 404);
  };
}

const run = (fetch: (r: Request) => Promise<Response>) =>
  checkHost({ base: 'http://host.test', account, handle: 'ada.host.example', fetch });
const status = (results: Awaited<ReturnType<typeof checkHost>>) =>
  Object.fromEntries(results.map((r) => [r.name, r.status]));

describe('checkHost', () => {
  it('passes a conforming host and reports unbuilt endpoints as pending', async () => {
    expect(status(await run(fakeHost()))).toEqual({
      descriptor: 'pass',
      keylog: 'pass',
      errors: 'pass',
      handle: 'pass',
      checkpoint: 'pending',
      log: 'pending',
      records: 'pending',
    });
  });

  it('fails a host that sets cookies, serves a tampered key log, or misshapes errors', async () => {
    expect(status(await run(fakeHost({ cookie: true })))).toMatchObject({ descriptor: 'fail', keylog: 'fail' });
    expect(status(await run(fakeHost({ tamper: true })))).toMatchObject({ keylog: 'fail' });
    expect(status(await run(fakeHost({ errorShape: true })))).toMatchObject({ errors: 'fail' });
  });
});
