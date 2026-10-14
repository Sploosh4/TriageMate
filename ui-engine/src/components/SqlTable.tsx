import { useState } from 'react';
import { cellText, type QueryResult } from '../labApi';
export function SqlTable({ result }: { result: QueryResult }) {
  const [zoom, setZoom] = useState(100);
  if (!result.rows.length) return <p role="status">Query succeeded. No rows returned.</p>;
  return (
    <>
      <div className="table-zoom" role="group" aria-label="Table zoom">
        <button
          aria-label="Zoom table out"
          disabled={zoom === 50}
          onClick={() => setZoom((value) => Math.max(50, value - 10))}
        >
          −
        </button>
        <input
          type="range"
          aria-label="Table zoom percentage"
          min={50}
          max={150}
          step={10}
          value={zoom}
          onChange={(event) => setZoom(Number(event.target.value))}
        />
        <button aria-label="Reset table zoom" title="Reset to 100%" onClick={() => setZoom(100)}>
          {zoom}%
        </button>
        <button
          aria-label="Zoom table in"
          disabled={zoom === 150}
          onClick={() => setZoom((value) => Math.min(150, value + 10))}
        >
          +
        </button>
      </div>
      <div className="table-scroll" role="region" aria-label="SQL results" tabIndex={0}>
        <table className="sql-table" style={{ zoom: zoom / 100 }}>
          <caption className="sr-only">PostgreSQL query results</caption>
          <thead>
            <tr>
              {result.columns.map((c, i) => (
                <th key={i} scope="col">
                  {c}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {result.rows.map((row, i) => (
              <tr key={i}>
                {row.map((cell, j) => (
                  <td key={j}>
                    {cell === null ? (
                      <span className="null-value">Unknown · NULL</span>
                    ) : cell === '' ? (
                      <span className="muted">Empty string</span>
                    ) : (
                      cellText(cell)
                    )}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
