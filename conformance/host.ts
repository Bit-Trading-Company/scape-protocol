/**
 * Live host checks (spec: The host interface). Given a host and an account it
 * serves, checks every endpoint the spec defines, the serving rules and the
 * error shapes. Endpoints a host has not built yet are reported as pending,
 * not passed.
 */
import { verifyKeylog } from '../src/index.ts';

export interface HostCheckOptions {
  /** The host's origin, e.g. https://scape.com.de */
  base: string;
  /** An account the host serves. */
  account: string;
  /** One of the account's handles, if any. */
  handle?: string;
  /** Defaults to global fetch; pass an in-process handler to test without a network. */
  fetch?: (request: Request) => Promise<Response>;
}

export type HostCheckStatus = 'pass' | 'fail' | 'pending';

export interface HostCheck {
  name: string;
  status: HostCheckStatus;
  detail: string;
}

const UNKNOWN_ACCOUNT = 'aaaaaaaaaaaaaaaaaaaaaaaa';

export async function checkHost(options: HostCheckOptions): Promise<HostCheck[]> {
  const doFetch = options.fetch ?? ((request: Request) => fetch(request));
  const get = (url: string) => doFetch(new Request(url, { headers: { accept: 'application/json' } }));
  const results: HostCheck[] = [];
  const record = (name: string, status: HostCheckStatus, detail = '') => results.push({ name, status, detail });

  async function json(response: Response): Promise<Record<string, unknown> | null> {
    try {
      return (await response.json()) as Record<string, unknown>;
    } catch {
      return null;
    }
  }

  function publicResponseProblems(response: Response): string[] {
    const problems: string[] = [];
    if (!(response.headers.get('content-type') ?? '').startsWith('application/json'))
      problems.push('not application/json');
    if (response.headers.get('access-control-allow-origin') !== '*') problems.push('not CORS-open');
    if (response.headers.get('set-cookie') !== null) problems.push('sets a cookie');
    return problems;
  }

  // The descriptor
  const descriptorResponse = await get(new URL('/.well-known/meme', options.base).href);
  const descriptor = await json(descriptorResponse);
  const descriptorProblems = publicResponseProblems(descriptorResponse);
  if (descriptorResponse.status !== 200 || descriptor === null) {
    record('descriptor', 'fail', `GET /.well-known/meme returned ${descriptorResponse.status}`);
    return results;
  }
  if (descriptor.v !== 0 || typeof descriptor.api !== 'string' || typeof descriptor.files !== 'string') {
    descriptorProblems.push('must be { v: 0, api, files }');
  }
  record('descriptor', descriptorProblems.length === 0 ? 'pass' : 'fail', descriptorProblems.join('; '));
  const api = String(descriptor.api).replace(/\/$/, '');
  // The descriptor names the host's public API; resolve its path against the origin under test.
  const apiUrl = (path: string) => new URL(`${new URL(api).pathname}${path}`, options.base).href;

  // The key log
  const keylogResponse = await get(apiUrl(`/accounts/${options.account}/keylog`));
  const keylog = await json(keylogResponse);
  const keylogProblems = publicResponseProblems(keylogResponse);
  if (keylogResponse.status !== 200 || keylog === null) {
    keylogProblems.push(`returned ${keylogResponse.status}`);
  } else {
    const verdict = verifyKeylog(keylog.entries);
    if (!verdict.valid) keylogProblems.push(`entries are invalid (${verdict.reason}): ${verdict.message}`);
    else if (verdict.value.account !== options.account) keylogProblems.push('entries belong to another account');
  }
  record('keylog', keylogProblems.length === 0 ? 'pass' : 'fail', keylogProblems.join('; '));

  // Errors
  const missing = await get(apiUrl(`/accounts/${UNKNOWN_ACCOUNT}/keylog`));
  const missingBody = await json(missing);
  const error = missingBody?.error as Record<string, unknown> | undefined;
  const errorOk = missing.status === 404 && error?.code === 'not_found' && typeof error.message === 'string';
  record(
    'errors',
    errorOk ? 'pass' : 'fail',
    errorOk ? '' : `unknown account returned ${missing.status} ${JSON.stringify(missingBody)}`,
  );

  // Handles
  if (options.handle !== undefined) {
    const handleResponse = await get(apiUrl(`/handles/${encodeURIComponent(options.handle)}`));
    const body = await json(handleResponse);
    const ok = handleResponse.status === 200 && body?.account === options.account;
    record('handle', ok ? 'pass' : 'fail', ok ? '' : `returned ${handleResponse.status} ${JSON.stringify(body)}`);
  } else {
    record('handle', 'pending', 'no handle given');
  }

  // Endpoints that arrive later in the host's build. Reported, never counted as passing.
  const later: [string, string][] = [
    ['checkpoint', `/accounts/${options.account}/checkpoint`],
    ['log', `/accounts/${options.account}/log`],
    ['records', `/accounts/${options.account}/records/profile`],
  ];
  for (const [name, path] of later) {
    const response = await get(apiUrl(path));
    if (response.status === 404 || response.status === 501) record(name, 'pending', 'not served yet');
    else record(name, response.ok ? 'pending' : 'fail', `returned ${response.status}; checks not written yet`);
  }

  return results;
}
