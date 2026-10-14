import { useEffect, useRef, useState } from 'react';
import { useEventCallback } from '../useEventCallback';
import { read, send, type QueryResult } from '../labApi';
type Decision = {
  decisionId: string;
  deviceId: string;
  selectedType: string;
  reason: string;
  expectedPrevious: string | null;
};
type Device = {
  id: string;
  source: string;
  name: string;
  sourceType: string;
  decisionId: string | null;
  selectedType: string;
  reason: string;
};
export function Classifications({ open, onClose }: { open: boolean; onClose: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null),
    trigger = useRef<HTMLElement | null>(null),
    pending = useRef<Decision | null>(null),
    lock = useRef(false);
  const [devices, setDevices] = useState<Device[]>([]),
    [selected, setSelected] = useState(''),
    [type, setType] = useState(''),
    [reason, setReason] = useState(''),
    [error, setError] = useState(''),
    [busy, setBusy] = useState(false),
    [retry, setRetry] = useState(false);
  const current = devices.find((d) => d.id === selected);
  function choose(d?: Device) {
    setSelected(d?.id ?? '');
    setType(d?.selectedType ?? '');
    setReason(d?.reason ?? '');
  }
  const reload = useEventCallback(async () => {
    if (lock.current) return;
    lock.current = true;
    setBusy(true);
    setError('');
    try {
      const result = await read<QueryResult>('/api/classifications');
      const unique = new Map<string, Device>();
      for (const row of result.rows) {
        const id = String(row[0]);
        const sourceType =
          [row[6], row[7], row[8]]
            .filter((v) => v !== null && v !== '')
            .map(String)
            .join(' / ') || 'Unknown';
        const previous = unique.get(id);
        unique.set(id, {
          id,
          source: String(row[1]),
          name: row[3] === null ? String(row[2]) : String(row[3]),
          sourceType:
            previous && previous.sourceType !== sourceType
              ? previous.sourceType + '; ' + sourceType
              : sourceType,
          decisionId: row[9] === null ? null : String(row[9]),
          selectedType: row[10] === null ? '' : String(row[10]),
          reason: row[11] === null ? '' : String(row[11]),
        });
      }
      const next = [...unique.values()];
      setDevices(next);
      pending.current = null;
      setRetry(false);
      choose(next.find((d) => d.id === selected));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not load classifications. Retry loading.');
    } finally {
      lock.current = false;
      setBusy(false);
    }
  });
  useEffect(() => {
    if (open) {
      trigger.current = document.activeElement as HTMLElement;
      dialog.current?.showModal();
      if (!pending.current) void reload();
    } else {
      dialog.current?.close();
      trigger.current?.focus();
    }
  }, [open, reload]);
  async function save() {
    if (lock.current || !current) return;
    const request = pending.current ?? {
      decisionId: crypto.randomUUID(),
      deviceId: current.id,
      selectedType: type,
      reason,
      expectedPrevious: current.decisionId,
    };
    pending.current = request;
    lock.current = true;
    setBusy(true);
    setError('');
    try {
      const result = await send<{ decisionId: string }>('/api/classifications', request);
      if (result.decisionId !== request.decisionId)
        throw new Error('Save acknowledgement did not match. Retry the same decision.');
      pending.current = null;
      setRetry(false);
      lock.current = false;
      await reload();
    } catch (e) {
      setRetry(true);
      setError(
        e instanceof Error
          ? e.message
          : 'Save was not confirmed. Retry the same decision or reload decisions.',
      );
    } finally {
      lock.current = false;
      setBusy(false);
    }
  }
  return (
    <dialog
      ref={dialog}
      className="workspace-dialog classification-dialog"
      aria-label="Microsoft classifications"
      onCancel={(e) => {
        e.preventDefault();
        if (!busy) onClose();
      }}
    >
      <h2>Microsoft classifications</h2>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void save();
        }}
      >
        <label>
          Device
          <select
            value={selected}
            disabled={busy || retry}
            onChange={(e) => choose(devices.find((d) => d.id === e.target.value))}
            required
          >
            <option value="">Choose a device</option>
            {devices.map((d) => (
              <option key={d.id} value={d.id}>
                {d.name} — {d.source}
              </option>
            ))}
          </select>
        </label>
        {!busy && !devices.length && !error && <p>No collected Microsoft devices are available.</p>}
        {current && (
          <table>
            <thead>
              <tr>
                <th>Microsoft classification</th>
                <th>Latest analyst decision</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>{current.sourceType}</td>
                <td>{current.selectedType || 'No decision'}</td>
              </tr>
            </tbody>
          </table>
        )}
        <label>
          Selected type
          <input
            value={type}
            onChange={(e) => setType(e.target.value)}
            disabled={busy || retry || !current}
            maxLength={128}
            required
          />
        </label>
        <label>
          Reason
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            disabled={busy || retry || !current}
            maxLength={4000}
            required
          />
        </label>
        {error && <p role="alert">{error}</p>}
        <button type="submit" disabled={busy || !current || !type.trim() || !reason.trim()}>
          {busy ? 'Working…' : retry ? 'Retry same decision' : 'Save decision'}
        </button>
        <button type="button" disabled={busy} onClick={() => void reload()}>
          Reload decisions
        </button>
        <button type="button" disabled={busy} onClick={onClose}>
          Close
        </button>
      </form>
    </dialog>
  );
}
