import { useEffect, useState } from 'react';
import { read } from '../labApi';

// One poll for the workspace, coalescing all commits between polls. Failed reads
// retain the previous watermark; they never fabricate an empty database state.
export function useEvidenceRefresh() {
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    let stopped = false,
      busy = false,
      previous: string | undefined;
    async function check() {
      if (stopped || busy || document.hidden) return;
      busy = true;
      try {
        const value = await read<{ revision: string }>('/api/evidence/revision');
        if (stopped || typeof value.revision !== 'string' || !/^[a-f0-9]{64}$/.test(value.revision))
          return;
        if (previous !== undefined && previous !== value.revision)
          setRevision((value) => value + 1);
        previous = value.revision;
      } catch {
        /* Keep the last confirmed results; query errors still use their own UI. */
      } finally {
        busy = false;
      }
    }
    void check();
    const timer = setInterval(() => void check(), 5000);
    const visible = () => void check();
    document.addEventListener('visibilitychange', visible);
    return () => {
      stopped = true;
      clearInterval(timer);
      document.removeEventListener('visibilitychange', visible);
    };
  }, []);
  return revision;
}
