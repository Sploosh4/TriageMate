import { acquireQuerySlot } from './queryAdmission';
export type ExactCell = { type: string; value: string };
export type Cell = string | number | boolean | ExactCell | null;
export function cellText(cell: Exclude<Cell, null>): string {
  return typeof cell === 'object' ? cell.value : String(cell);
}
export type QueryResult = {
  columns: string[];
  rows: Cell[][];
  truncated: boolean;
  changed: number;
  editable: boolean;
  databaseBytes?: number;
  requestId: string;
  engine: 'PostgreSQL';
  columnTypes: { name: string; type: string; oid: number }[];
};
export type PageFile = {
  name: string;
  markdown: string;
  revision: string;
  readonly?: boolean;
};
export type Session = {
  token: string;
  engine: string;
  databaseBytes: number | null;
};
let session: Promise<Session> | undefined;
export async function read<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(path, { signal });
  const data = await response.json();
  if (!response.ok)
    throw new Error(data.error || 'TriageMate is unavailable. Check the application container.');
  return data;
}
export function getSession(signal?: AbortSignal): Promise<Session> {
  if (signal?.aborted) return Promise.reject(signal.reason);
  if (!session) {
    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(new Error('Local session request exceeded 20 seconds. Try again.')),
      20_000,
    );
    const pending = read<Session>('/api/session', controller.signal)
      .catch((error) => {
        if (session === pending) session = undefined;
        throw error;
      })
      .finally(() => clearTimeout(timer));
    session = pending;
  }
  if (!signal) return session;
  // Cancelling one waiter must not abort session acquisition for other work.
  const pending = session;
  return new Promise<Session>((resolve, reject) => {
    const abort = () => {
      cleanup();
      reject(signal.reason);
    };
    const cleanup = () => signal.removeEventListener('abort', abort);
    signal.addEventListener('abort', abort, { once: true });
    pending.then(
      (value) => {
        cleanup();
        resolve(value);
      },
      (error) => {
        cleanup();
        reject(error);
      },
    );
    if (signal.aborted) abort();
  });
}
export async function send<T>(path: string, body: unknown, signal?: AbortSignal): Promise<T> {
  const { token } = await getSession(signal);
  const response = await fetch(path, {
    method: 'POST',
    signal,
    headers: { 'Content-Type': 'application/json', 'X-Lab-Token': token },
    body: JSON.stringify(body),
  });
  const result = await response.json();
  if (!response.ok) {
    if (response.status === 403) session = undefined;
    throw new Error(result.error || 'Local request failed.');
  }
  return result;
}

export function executeQuery(
  sql: string,
  endpoint: '/api/query' | '/api/catalogue' = '/api/query',
) {
  const requestId = crypto.randomUUID();
  const controller = new AbortController();
  let finished = false;
  let dispatched = false;
  let release: (() => void) | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  function cancel(message = 'Query cancelled. Your SQL is unchanged.') {
    if (finished || controller.signal.aborted) return;
    controller.abort(new Error(message));
    if (dispatched) void send('/api/query/cancel', { requestId }).catch(() => {});
  }
  const promise = (async () => {
    release = await acquireQuerySlot(controller.signal);
    if (controller.signal.aborted) throw controller.signal.reason;
    const started = performance.now();
    timer = setTimeout(
      () => cancel('Query exceeded 20 seconds. Filter or simplify the SQL and run again.'),
      20_000,
    );
    await getSession(controller.signal);
    if (controller.signal.aborted) throw controller.signal.reason;
    dispatched = true;
    const result = await send<QueryResult>(endpoint, { sql, requestId }, controller.signal);
    if (controller.signal.aborted) throw controller.signal.reason;
    if (performance.now() - started >= 20_000)
      throw new Error('Query exceeded 20 seconds. Filter or simplify the SQL and run again.');
    if (result.requestId !== requestId)
      throw new Error('Query response did not match this request. Run again.');
    return result;
  })()
    .catch((error) => {
      throw controller.signal.aborted ? controller.signal.reason : error;
    })
    .finally(() => {
      finished = true;
      clearTimeout(timer);
      release?.();
    });
  return { promise, cancel };
}
