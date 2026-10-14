import { cellText, type QueryResult } from '../labApi';
import type { ChartConfig } from './chartTypes';
function numberLabel(value: number) {
  return value.toLocaleString(undefined, {
    maximumSignificantDigits: 17,
    notation:
      value !== 0 && (Math.abs(value) < 0.001 || Math.abs(value) >= 1e9)
        ? 'scientific'
        : 'standard',
  });
}
function scaledTotalLabel(total: number, scale: number) {
  const value = total * scale;
  if (Number.isFinite(value)) return numberLabel(value);
  const [coefficient, exponent] = scale.toExponential().split('e');
  const combined = total * Number(coefficient);
  const shift = Math.floor(Math.log10(combined));
  return `${numberLabel(combined / 10 ** shift)}e+${Number(exponent) + shift}`;
}
const colors = ['#fa6425', '#09b8a7', '#ffc052', '#7795ac', '#b293ef', '#e684ae'];
export function Chart({ result, config }: { result: QueryResult; config: ChartConfig }) {
  const xi = result.columns.indexOf(config.x),
    yi = result.columns.indexOf(config.y);
  if (xi < 0 || yi < 0)
    return (
      <p role="alert">
        Choose existing columns for X and Y. Available: {result.columns.join(', ')}
      </p>
    );
  if (!result.rows.length) return <p role="status">No rows returned.</p>;
  if (result.rows.some((r) => typeof r[yi] !== 'number' || !Number.isFinite(r[yi])))
    return (
      <p role="alert">
        Y must contain finite numbers. Exact numeric values require an explicit SQL cast to double
        precision for plotting. NULL is unknown, not zero; filter or explicitly transform unknown
        values in SQL.
      </p>
    );
  const values = result.rows.map((r) => Number(r[yi]));
  const labels = result.rows.map((r) => (r[xi] === null ? 'Unknown · NULL' : cellText(r[xi]!)));
  if (config.type === 'doughnut' && (values.some((v) => v < 0) || !values.some((v) => v > 0)))
    return <p role="alert">Doughnut charts require non-negative values with a positive total.</p>;
  const low = values.reduce((a, b) => Math.min(a, b), 0),
    high = values.reduce((a, b) => Math.max(a, b), 0);
  const scale = Math.max(Math.abs(low), Math.abs(high)) || 1;
  const normalized = values.map((value) => value / scale);
  const span = high / scale - low / scale || 1;
  const y = (v: number) => 190 - ((v / scale - low / scale) / span) * 160;
  const x = (i: number) => 55 + (i * 370) / Math.max(1, values.length - 1);
  const total = normalized.reduce((a, b) => a + b, 0);
  let offset = 0;
  return (
    <div className="chart-plot">
      <svg
        viewBox="0 0 460 250"
        role="img"
        aria-label={`${config.title}, ${config.type} chart`}
        preserveAspectRatio="xMidYMid meet"
      >
        <title>{config.title}</title>
        <desc>{labels.map((l, i) => `${l}: ${values[i]}`).join('; ')}</desc>
        {config.type === 'doughnut' ? (
          <>
            {values.map((v, i) => {
              const fraction = normalized[i] / total;
              const start = offset;
              offset += fraction;
              return (
                <circle
                  key={i}
                  cx="230"
                  cy="122"
                  r="78"
                  fill="none"
                  stroke={colors[i % colors.length]}
                  strokeWidth="35"
                  pathLength="100"
                  strokeDasharray={`${fraction * 100} ${100 - fraction * 100}`}
                  strokeDashoffset={-start * 100}
                  transform="rotate(-90 230 122)"
                >
                  <title>
                    {labels[i]}: {v}
                  </title>
                </circle>
              );
            })}
            <text x="230" y="125" textAnchor="middle" fill="currentColor" fontSize="24">
              {scaledTotalLabel(total, scale)}
            </text>
            <text x="230" y="146" textAnchor="middle" fill="currentColor">
              Total
            </text>
          </>
        ) : (
          <>
            <line x1="40" x2="440" y1={y(0)} y2={y(0)} stroke="#72818c" />
            <text x="3" y="30" fill="currentColor" fontSize="11">
              {numberLabel(high)}
            </text>
            <text x="3" y="192" fill="currentColor" fontSize="11">
              {numberLabel(low)}
            </text>
            {config.type === 'line' ? (
              <>
                <polyline
                  fill="none"
                  stroke={colors[1]}
                  strokeWidth="3"
                  points={values.map((v, i) => `${x(i)},${y(v)}`).join(' ')}
                />
                {values.map((v, i) => (
                  <circle key={i} cx={x(i)} cy={y(v)} r="5" fill={colors[0]}>
                    <title>
                      {labels[i]}: {v}
                    </title>
                  </circle>
                ))}
              </>
            ) : (
              values.map((v, i) => {
                const step = 390 / values.length;
                return (
                  <rect
                    key={i}
                    x={45 + i * step}
                    y={Math.min(y(v), y(0))}
                    width={Math.max(1, step - 8)}
                    height={Math.max(1, Math.abs(y(v) - y(0)))}
                    fill={colors[i % colors.length]}
                  >
                    <title>
                      {labels[i]}: {v}
                    </title>
                  </rect>
                );
              })
            )}
            {values.map((v, i) => (
              <text
                key={i}
                x={config.type === 'line' ? x(i) : 45 + ((i + 0.5) * 390) / values.length}
                y="212"
                textAnchor="middle"
                fill="currentColor"
                fontSize="10"
              >
                {labels[i].slice(0, 12)}
                {labels[i].length > 12 ? '…' : ''}
              </text>
            ))}
          </>
        )}
      </svg>
      <div className="chart-legend">
        {labels.map((l, i) => (
          <span key={i}>
            <i style={{ background: colors[i % colors.length] }} />
            {l}: <strong>{numberLabel(values[i])}</strong>
          </span>
        ))}
      </div>
    </div>
  );
}
