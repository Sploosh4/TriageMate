import { lazy, Suspense, useEffect, useState } from 'react';
import { dashboard } from './dashboard';
import { EvidenceWidget } from './components/EvidenceWidget';
import { Classifications } from './components/Classifications';
import { Operations } from './components/Operations';
import { read } from './labApi';
import { useEvidenceRefresh } from './engine/useEvidenceRefresh';
import './sql.css';
import './app.css';

type Notice = {
  id: string;
  source: string;
  input: string;
  scope: string;
  status: string;
  urgency: string;
  message?: string;
  details?: Record<string, unknown>;
  startedAt: string | null;
  resolvedAt: string | null;
  failureCount: number | null;
  failures: { attemptId: string; code: string; finishedAt: string }[];
};
const routes = ['Dashboard', 'Database', 'Notifications', 'Settings'] as const;
type Route = (typeof routes)[number];
const DatabaseScreen = lazy(() => import('./components/DatabaseScreen'));
export function App() {
  const evidenceRevision = useEvidenceRefresh();
  const initial = routes.find((name) => '#' + name.toLowerCase() === location.hash) || 'Dashboard';
  const [route, setRoute] = useState<Route>(initial);
  const [sql, setSql] = useState('SELECT current_user::text AS reader;');
  const [revision, setRevision] = useState(0);
  const [classification, setClassification] = useState(false);
  const [operations, setOperations] = useState(false);
  const [notices, setNotices] = useState<Notice[]>([]);
  const [error, setError] = useState('');
  useEffect(() => {
    const change = () =>
      setRoute(routes.find((name) => '#' + name.toLowerCase() === location.hash) || 'Dashboard');
    window.addEventListener('hashchange', change);
    return () => window.removeEventListener('hashchange', change);
  }, []);
  useEffect(() => {
    if (route !== 'Notifications') return;
    let current = true;
    const refresh = () =>
      void read<{ notifications: Notice[] }>('/api/notifications')
        .then((value) => {
          if (current) {
            setNotices(value.notifications);
            setError('');
          }
        })
        .catch((failure: Error) => {
          if (current) setError(failure.message);
        });
    refresh();
    const timer = window.setInterval(refresh, 30000);
    return () => {
      current = false;
      clearInterval(timer);
    };
  }, [route]);
  return (
    <div className="application">
      <nav aria-label="Main navigation">
        <a className="application-name" href="#dashboard">
          TriageMate
        </a>
        {routes.map((name) => (
          <a
            key={name}
            href={'#' + name.toLowerCase()}
            aria-current={route === name ? 'page' : undefined}
          >
            {name}
          </a>
        ))}
        <button onClick={() => setOperations(true)}>Application</button>
        <button onClick={() => setClassification(true)}>Classifications</button>
      </nav>
      <main>
        <header>
          <h1>{route}</h1>
          {route === 'Dashboard' && (
            <button onClick={() => setRevision(revision + 1)}>Refresh evidence</button>
          )}
        </header>
        {route === 'Dashboard' &&
          dashboard.map((block, index) =>
            block.kind === 'heading' ? (
              <h2 key={index}>{block.text}</h2>
            ) : block.kind === 'text' ? (
              <p key={index}>{block.text}</p>
            ) : (
              <EvidenceWidget
                key={index}
                sql={block.sql!}
                chart={block.chart}
                revision={revision + evidenceRevision}
              />
            ),
          )}
        {route === 'Database' && (
          <Suspense fallback={<p role="status">Loading SQL explorer…</p>}>
            <DatabaseScreen sql={sql} onChange={setSql} />
          </Suspense>
        )}
        {route === 'Notifications' && (
          <>
            {error && <p role="alert">{error}</p>}
            {!error && notices.length === 0 && <p role="status">No collection notifications.</p>}
            {notices.map((notice) => (
              <article className="notification-detail" key={notice.id}>
                <h2>
                  {notice.source} {notice.input}
                </h2>
                <p>
                  {notice.status} · {notice.urgency} · {notice.scope}
                </p>
                {notice.message && <p>{notice.message}</p>}
                {notice.details && (
                  <dl>
                    {Object.entries(notice.details).map(([name, value]) => (
                      <div key={name}>
                        <dt>{name}</dt>
                        <dd>
                          {value === null
                            ? 'Unknown'
                            : typeof value === 'object'
                              ? JSON.stringify(value)
                              : String(value)}
                        </dd>
                      </div>
                    ))}
                  </dl>
                )}
                <dl>
                  <dt>First failure</dt>
                  <dd>{notice.startedAt || 'Unknown'}</dd>
                  <dt>Resolved</dt>
                  <dd>
                    {notice.resolvedAt || (notice.status === 'resolved' ? 'Unknown' : 'Unresolved')}
                  </dd>
                  <dt>Failures</dt>
                  <dd>{notice.failureCount ?? 'Not applicable'}</dd>
                </dl>
                <table>
                  <thead>
                    <tr>
                      <th>Attempt</th>
                      <th>Failure</th>
                      <th>Collected at</th>
                    </tr>
                  </thead>
                  <tbody>
                    {notice.failures.map((failure) => (
                      <tr key={failure.attemptId}>
                        <td>{failure.attemptId}</td>
                        <td>{failure.code}</td>
                        <td>{failure.finishedAt}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </article>
            ))}
          </>
        )}
        {route === 'Settings' && (
          <section>
            <h2>Application controls</h2>
            <button onClick={() => setOperations(true)}>Manage collection</button>
            <h2>Shutdown</h2>
            <p>
              Save or copy any SQL draft before stopping the application. Stop both containers from
              the project directory:
            </p>
            <pre>docker compose stop</pre>
            <p>
              Restart with <code>docker compose up -d</code>. The database volume retains collected
              evidence.
            </p>
          </section>
        )}
      </main>
      <Operations open={operations} onClose={() => setOperations(false)} />
      <Classifications open={classification} onClose={() => setClassification(false)} />
    </div>
  );
}
