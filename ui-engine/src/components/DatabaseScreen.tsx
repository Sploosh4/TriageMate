import { DatabaseQuery } from './DatabaseQuery';
import { DatabaseSidebar } from './DatabaseSidebar';
import { useState } from 'react';

export default function DatabaseScreen({
  sql,
  onChange,
}: {
  sql: string;
  onChange: (value: string) => void;
}) {
  const [catalogueOpen, setCatalogueOpen] = useState(true);
  return (
    <div className="database-explorer">
      {catalogueOpen ? (
        <aside aria-label="Database catalogue">
          <DatabaseSidebar
            onCollapse={() => setCatalogueOpen(false)}
            onQuery={() => onChange('SELECT current_user::text AS reader;')}
          />
        </aside>
      ) : (
        <button onClick={() => setCatalogueOpen(true)}>Show catalogue</button>
      )}
      <DatabaseQuery sql={sql} onChange={onChange} />
    </div>
  );
}
