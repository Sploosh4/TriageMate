import { useEffect, useState } from 'react';
import { executeQuery } from '../labApi';
import { IconButton } from '../engine/IconButton';
import { catalogueGroups, groupForRelation, type CatalogueGroup } from '../engine/catalogueGroups';
type Relation = {
  schema: string;
  name: string;
  kind: string;
  description: string;
  columns: { name: string; type: string; required: boolean }[];
};
export function DatabaseSidebar({
  onCollapse,
  onQuery,
}: {
  onCollapse: () => void;
  onQuery: () => void;
}) {
  const [openGroups, setOpenGroups] = useState<Set<CatalogueGroup>>(
    () => new Set(['analyst', 'other']),
  );
  const [relations, setRelations] = useState<Relation[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [refresh, setRefresh] = useState(0);
  const [selected, setSelected] = useState('');
  const [expanded, setExpanded] = useState(new Set<string>());
  useEffect(() => {
    let current = true;
    setLoading(true);
    setError('');
    setRelations([]);
    const request = executeQuery('', '/api/catalogue');
    request.promise
      .then((result) => {
        if (!current) return;
        const grouped = new Map<string, Relation>();
        for (const row of result.rows) {
          const [schema, name, kind, description, column, type, required] = row;
          const key = `${schema}.${name}`;
          if (!grouped.has(key))
            grouped.set(key, {
              schema: String(schema),
              name: String(name),
              kind: String(kind),
              description: description ? String(description) : '',
              columns: [],
            });
          grouped.get(key)!.columns.push({
            name: String(column),
            type: String(type),
            required: required === true,
          });
        }
        setRelations([...grouped.values()]);
      })
      .catch((e) => {
        if (current) setError(e.message);
      })
      .finally(() => {
        if (current) setLoading(false);
      });
    return () => {
      current = false;
      request.cancel();
    };
  }, [refresh]);
  return (
    <>
      <div className="sidebar-actions">
        <IconButton
          icon="code"
          aria-label="New database query"
          title="New database query"
          onClick={onQuery}
        />
        <IconButton
          icon="refresh"
          aria-label="Refresh catalogue"
          title="Refresh catalogue"
          onClick={() => setRefresh((v) => v + 1)}
        />
        <IconButton
          icon="sidebar"
          aria-label="Collapse database sidebar"
          title="Collapse database sidebar"
          onClick={onCollapse}
        />
      </div>
      {loading && <p role="status">Loading…</p>}
      {error && (
        <div role="alert" className="sidebar-error">
          {error}
          <button onClick={() => setRefresh((v) => v + 1)}>Retry catalogue</button>
        </div>
      )}
      <nav className="file-tree database-tree" aria-label="Database catalogue">
        {catalogueGroups
          .filter(
            (group) =>
              group.id !== 'other' || relations.some((r) => groupForRelation(r) === 'other'),
          )
          .map((group) => (
            <details
              data-catalogue-group={group.id}
              open={openGroups.has(group.id)}
              onToggle={(event) => {
                const open = event.currentTarget.open;
                setOpenGroups((previous) => {
                  if (previous.has(group.id) === open) return previous;
                  const next = new Set(previous);
                  if (open) next.add(group.id);
                  else next.delete(group.id);
                  return next;
                });
              }}
              key={group.id}
            >
              <summary>
                {group.label} ({relations.filter((r) => groupForRelation(r) === group.id).length})
              </summary>
              <ul>
                {relations
                  .filter((r) => groupForRelation(r) === group.id)
                  .sort((a, b) => `${a.schema}.${a.name}`.localeCompare(`${b.schema}.${b.name}`))
                  .map((r) => {
                    const key = `${r.schema}.${r.name}`;
                    return (
                      <li key={key}>
                        <div className="catalogue-relation">
                          <button
                            className="column-toggle"
                            aria-label={`Columns for ${key}`}
                            aria-expanded={expanded.has(key)}
                            onClick={() =>
                              setExpanded((previous) => {
                                const next = new Set(previous);
                                if (next.has(key)) next.delete(key);
                                else next.add(key);
                                return next;
                              })
                            }
                          >
                            {expanded.has(key) ? '⌄' : '›'}
                          </button>
                          <button
                            className={selected === key ? 'active-file' : ''}
                            aria-pressed={selected === key}
                            title={`${key}\n${r.description}`}
                            onClick={() => setSelected(key)}
                          >
                            {r.name}{' '}
                            <span className="relation-kind">
                              {r.kind === 'v' || r.kind === 'm' ? 'view' : 'table'}
                            </span>
                          </button>
                        </div>
                        {expanded.has(key) && (
                          <ul aria-label={`${key} columns`}>
                            {r.columns.map((c) => (
                              <li
                                className="catalogue-column"
                                key={c.name}
                                title={`${c.name}: ${c.type}${c.required ? ' · not null' : ''}`}
                              >
                                <span>{c.name}</span>
                                <span>{c.type}</span>
                              </li>
                            ))}
                          </ul>
                        )}
                      </li>
                    );
                  })}
              </ul>
            </details>
          ))}
      </nav>
    </>
  );
}
