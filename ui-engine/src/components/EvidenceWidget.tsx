import { useEffect, useState } from 'react';
import { executeQuery, type QueryResult } from '../labApi';
import { SqlTable } from './SqlTable';
import { Chart } from '../engine/Chart';
import type { ChartConfig } from '../engine/chartTypes';

export function EvidenceWidget({
  sql,
  chart,
  revision,
}: {
  sql: string;
  chart?: ChartConfig;
  revision: number;
}) {
  const [result, setResult] = useState<QueryResult | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(true);
  const [showSql, setShowSql] = useState(false);
  useEffect(() => {
    let current = true;
    const request = executeQuery(sql);
    setBusy(true);
    setError('');
    setResult(null);
    request.promise
      .then((value) => {
        if (current) setResult(value);
      })
      .catch((failure: Error) => {
        if (current) setError(failure.message);
      })
      .finally(() => {
        if (current) setBusy(false);
      });
    return () => {
      current = false;
      request.cancel();
    };
  }, [sql, revision]);
  return (
    <section
      className="evidence-widget"
      aria-label={chart?.title || 'Evidence table'}
      aria-busy={busy}
    >
      {chart && <h3>{chart.title}</h3>}
      <button aria-expanded={showSql} onClick={() => setShowSql(!showSql)}>
        SQL
      </button>
      {showSql && <pre>{sql}</pre>}
      {busy ? (
        <p role="status">Loading…</p>
      ) : error ? (
        <p role="alert">{error}</p>
      ) : (
        result && (chart ? <Chart config={chart} result={result} /> : <SqlTable result={result} />)
      )}
    </section>
  );
}
