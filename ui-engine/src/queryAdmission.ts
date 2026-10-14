// Match the server's three reader slots. Waiting blocks remain cancellable and
// do not spend their SQL execution budget before a request can be dispatched.
let active = 0;
const waiting: Array<() => void> = [];
function drain() {
  while (!document.hidden && active < 3 && waiting.length) waiting.shift()!();
}
document.addEventListener('visibilitychange', drain);
export function acquireQuerySlot(signal: AbortSignal): Promise<() => void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(signal.reason);
      return;
    }
    const stop = () => {
      const index = waiting.indexOf(start);
      if (index >= 0) waiting.splice(index, 1);
      reject(signal.reason);
    };
    const start = () => {
      signal.removeEventListener('abort', stop);
      if (signal.aborted) {
        reject(signal.reason);
        return;
      }
      active++;
      let released = false;
      resolve(() => {
        if (released) return;
        released = true;
        active--;
        drain();
      });
    };
    waiting.push(start);
    signal.addEventListener('abort', stop, { once: true });
    drain();
  });
}
