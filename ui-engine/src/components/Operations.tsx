import { useEffect, useRef, useState } from 'react';
import { useEventCallback } from '../useEventCallback';
import { read, send } from '../labApi';

type Mode = 'running' | 'off' | 'maintenance';
type Status = {
  available: boolean;
  state: string;
  desired: Mode | null;
  active: number | null;
  configured_inputs: number | null;
  revision: number | null;
  recovery_required: boolean;
  error?: string;
};
const names: Record<string, string> = {
  running: 'Running',
  off: 'Off',
  maintenance: 'Maintenance',
  draining: 'Draining',
  recovering: 'Recovering',
  unavailable: 'Unavailable',
};

export function Operations({ open, onClose }: { open: boolean; onClose: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const trigger = useRef<HTMLElement | null>(null);
  const generation = useRef(0);
  const loading = useRef(false);
  const [status, setStatus] = useState<Status | null>(null);
  const [mode, setMode] = useState<Mode>('off');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [readError, setReadError] = useState('');
  function accept(value: Status) {
    setStatus((previous) =>
      previous &&
      previous.revision !== null &&
      value.revision !== null &&
      value.revision < previous.revision
        ? previous
        : value,
    );
  }
  const refresh = useEventCallback(async (initial: boolean = false) => {
    if (loading.current) return;
    loading.current = true;
    const current = generation.current;
    try {
      const value = await read<Status>('/api/operations');
      if (current !== generation.current) return;
      accept(value);
      setReadError('');
      if (initial && value.desired) setMode(value.desired);
    } catch (e) {
      if (current === generation.current)
        setReadError(e instanceof Error ? e.message : 'Could not load application state.');
    } finally {
      if (current === generation.current) loading.current = false;
    }
  });
  const invalidateGeneration = useEventCallback(() => {
    generation.current++;
  });
  useEffect(() => {
    generation.current++;
    loading.current = false;
    if (!open) {
      dialog.current?.close();
      trigger.current?.focus();
      return;
    }
    trigger.current = document.activeElement as HTMLElement;
    setStatus(null);
    setError('');
    setReadError('');
    setBusy(false);
    dialog.current?.showModal();
    void refresh(true);
    const timer = window.setInterval(() => void refresh(), 2000);
    return () => {
      window.clearInterval(timer);
      invalidateGeneration();
    };
  }, [open, refresh, invalidateGeneration]);
  async function apply() {
    if (busy) return;
    const current = generation.current;
    setBusy(true);
    setError('');
    try {
      const value = await send<Status>('/api/operations', { mode });
      if (current !== generation.current) return;
      accept(value);
      if (value.desired !== mode)
        throw new Error('The requested mode was not confirmed. Refresh application state.');
    } catch (e) {
      if (current === generation.current)
        setError(e instanceof Error ? e.message : 'The requested mode was not confirmed.');
    } finally {
      if (current === generation.current) {
        setBusy(false);
        void refresh();
      }
    }
  }
  return (
    <dialog
      ref={dialog}
      className="workspace-dialog operations-dialog"
      aria-label="Application controls"
      onCancel={() => onClose()}
    >
      <h2>Application controls</h2>
      <label>
        Current state{' '}
        <output aria-label="Application state">
          {status ? (names[status.state] ?? 'Unavailable') : 'Loading…'}
        </output>
      </label>
      {status?.active !== null && status?.active !== undefined && status.active > 0 && (
        <p>
          {status.active} active {status.active === 1 ? 'run' : 'runs'}
        </p>
      )}
      {status?.configured_inputs === 0 && <p>No collection inputs are configured.</p>}
      <form
        onSubmit={(event) => {
          event.preventDefault();
          void apply();
        }}
      >
        <label>
          Operating mode
          <select
            aria-label="Operating mode"
            value={mode}
            disabled={busy || !status}
            onChange={(event) => setMode(event.target.value as Mode)}
          >
            <option value="running">Running</option>
            <option value="off">Off</option>
            <option value="maintenance">Maintenance</option>
          </select>
        </label>
        {(error || readError || status?.error) && (
          <p role="alert">{error || readError || status?.error}</p>
        )}
        <button type="submit" disabled={busy || !status}>
          {busy ? 'Applying…' : 'Apply mode'}
        </button>
        <button type="button" disabled={busy} onClick={() => void refresh()}>
          Refresh state
        </button>
        <button type="button" onClick={onClose}>
          Close
        </button>
      </form>
    </dialog>
  );
}
