import { useEffect, useRef, useState } from 'react';
import { useEventCallback } from '../useEventCallback';
import { executeQuery, type QueryResult } from '../labApi';
import { SqlTable } from './SqlTable';
import { CodeEditor } from '../engine/CodeEditor';
export function DatabaseQuery({
  sql,
  onChange,
  refreshToken = 0,
}: {
  sql: string;
  refreshToken?: number;
  onChange: (sql: string) => void;
}) {
  const [result, setResult] = useState<QueryResult | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const request = useRef<ReturnType<typeof executeQuery> | null>(null);
  const generation = useRef(0);
  const executedSql = useRef<string | null>(null);
  const previousRefresh = useRef(refreshToken);
  const refreshPending = useRef(false);
  function invalidate(preserveResult = false) {
    executedSql.current = null;
    refreshPending.current = false;
    generation.current++;
    request.current?.cancel();
    request.current = null;
    setLoading(false);
    if (!preserveResult) setResult(null);
  }
  useEffect(
    () => () => {
      generation.current++;
      request.current?.cancel();
    },
    [],
  );
  const run = useEventCallback((preserveResult: boolean = false) => {
    invalidate(preserveResult);
    const version = generation.current;
    setLoading(true);
    setError('');
    const pending = executeQuery(sql);
    request.current = pending;
    pending.promise
      .then((value) => {
        if (version === generation.current) {
          executedSql.current = sql;
          setResult(value);
        }
      })
      .catch((e) => {
        if (version === generation.current) setError(e.message);
      })
      .finally(() => {
        if (version === generation.current) {
          setLoading(false);
          request.current = null;
        }
      });
  });
  useEffect(() => {
    if (previousRefresh.current !== refreshToken) {
      previousRefresh.current = refreshToken;
      refreshPending.current = true;
    }
    if (refreshPending.current && !loading) {
      refreshPending.current = false;
      if (executedSql.current === sql) run(true);
    }
  }, [refreshToken, loading, sql, run]);
  return (
    <section className="database-query" aria-label="Database query" aria-busy={loading}>
      <div className="database-query-actions">
        {loading ? (
          <button
            onClick={() => {
              invalidate();
              setError('Query cancelled. Your SQL is unchanged.');
            }}
          >
            Cancel query
          </button>
        ) : (
          <button onClick={() => run()}>Run query</button>
        )}
        <button onClick={() => void navigator.clipboard.writeText(sql)}>Copy SQL</button>
      </div>
      <CodeEditor
        label="Database SQL"
        language="sql"
        value={sql}
        onChange={(value) => {
          invalidate();
          setError('');
          onChange(value);
        }}
        onRun={() => run()}
      />
      {loading && !result ? (
        <p role="status">Loading…</p>
      ) : error ? (
        <p role="alert">{error}</p>
      ) : (
        result && <SqlTable result={result} />
      )}
    </section>
  );
}
