type ClockBackend = {
  open: () => Promise<number>;
  wait: (clockId: number, sequence: number, delayMs: number) => Promise<boolean>;
};
type Timer = {
  id: number;
  callback: (...args: any[]) => void;
  args: any[];
  deadline: number;
  period: number | null;
  browser: number | null;
  browserGeneration: number;
};

export function installBackgroundTimers(
  host: Pick<Window, 'setTimeout' | 'clearTimeout' | 'setInterval' | 'clearInterval'>,
  visibility: Pick<Document, 'visibilityState' | 'addEventListener' | 'removeEventListener'>,
  backend: ClockBackend,
  now = () => performance.now(),
  reportError = (error: unknown) => { console.error('Android timer callback failed', error); },
) {
  const original = {
    setTimeout: host.setTimeout, clearTimeout: host.clearTimeout,
    setInterval: host.setInterval, clearInterval: host.clearInterval,
  };
  const timers = new Map<number, Timer>();
  let clockId: number | null = null;
  let sequence = 0;
  let alarm: { sequence: number; deadline: number } | null = null;
  let native = false;
  let draining = false;
  let disposed = false;
  const delay = (value: unknown) => Math.max(0, Number(value) | 0);
  const reportFailure = (error: unknown) => {
    console.error('Android background clock unavailable', error);
    clockId = null;
    switchMode();
  };
  function cancelAlarm() {
    if (!alarm || clockId === null) return;
    alarm = null;
    void backend.wait(clockId, ++sequence, 0).catch(reportFailure);
  }
  function fire(timer: Timer) {
    if (!timers.has(timer.id)) return;
    if (timer.period === null) timers.delete(timer.id);
    else timer.deadline = now() + timer.period;
    try { timer.callback.apply(host, timer.args); }
    catch (error) { reportError(error); }
  }
  function armBrowser(timer: Timer) {
    if (timer.browser !== null) return;
    const generation = ++timer.browserGeneration;
    timer.browser = original.setTimeout.call(host, () => {
      if (generation !== timer.browserGeneration) return;
      timer.browser = null;
      if (native || !timers.has(timer.id)) return;
      fire(timer);
      if (!native && timers.has(timer.id)) armBrowser(timer);
    }, Math.max(0, timer.deadline - now()));
  }
  async function deliver() {
    draining = true;
    try {
      const due = [...timers.values()].filter(timer => timer.deadline <= now())
        .sort((a, b) => a.deadline - b.deadline);
      for (const timer of due) {
        await Promise.resolve();
        if (!native || disposed) break;
        fire(timer);
      }
    } finally { draining = false; schedule(); }
  }

  function schedule() {
    if (!native || clockId === null || draining || disposed) return;
    let deadline = Infinity;
    for (const timer of timers.values()) deadline = Math.min(deadline, timer.deadline);
    if (deadline === Infinity) { cancelAlarm(); return; }
    if (alarm?.deadline === deadline) return;
    const current = { sequence: ++sequence, deadline };
    alarm = current;
    void backend.wait(clockId, current.sequence, Math.max(4, Math.ceil(deadline - now())))
      .then(fired => {
        if (alarm !== current || !native || disposed) return;
        alarm = null;
        if (!fired) throw new Error('Android clock lease was cancelled');
        return deliver();
      }).catch(reportFailure);
  }

  function switchMode() {
    if (disposed) return;
    const next = clockId !== null && visibility.visibilityState === 'hidden';
    if (next === native) return;
    cancelAlarm();
    native = next;
    for (const timer of timers.values()) {
      if (timer.browser !== null) original.clearTimeout.call(host, timer.browser);
      timer.browserGeneration++;
      timer.browser = null;
      if (!native) armBrowser(timer);
    }
    if (native) schedule();
  }

  function add(handler: TimerHandler, timeout: number | undefined, args: any[], repeat: boolean): number {
    if (typeof handler !== 'function') {
      let id: number;
      do {
        id = (repeat ? original.setInterval : original.setTimeout).call(host, handler, timeout, ...args);
        if (!timers.has(id)) return id;
        original.clearTimeout.call(host, id);
      } while (true);
    }
    const period = repeat ? Math.max(1, delay(timeout)) : null;
    const timer: Timer = { id: 0, callback: handler as Timer['callback'], args,
      deadline: now() + (period ?? delay(timeout)), period, browser: null, browserGeneration: 0 };
    do {
      armBrowser(timer);
      timer.id = timer.browser!;
      if (!timers.has(timer.id)) break;
      original.clearTimeout.call(host, timer.id);
      timer.browser = null;
    } while (true);
    timers.set(timer.id, timer);
    if (native) {
      original.clearTimeout.call(host, timer.browser!);
      timer.browser = null;
      timer.browserGeneration++;
      schedule();
    }
    return timer.id;
  }
  function clear(id?: number) {
    const timer = timers.get(Number(id));
    if (!timer) { original.clearTimeout.call(host, id); original.clearInterval.call(host, id); return; }
    timers.delete(timer.id);
    if (timer.browser !== null) original.clearTimeout.call(host, timer.browser);
    schedule();
  }
  host.setTimeout = (handler, timeout, ...args) => add(handler, timeout, args, false);
  host.setInterval = (handler, timeout, ...args) => add(handler, timeout, args, true);
  host.clearTimeout = clear;
  host.clearInterval = clear;
  visibility.addEventListener('visibilitychange', switchMode);
  const ready = backend.open().then(id => {
    if (disposed) return;
    clockId = id;
    switchMode();
  }).catch(reportFailure);
  return {
    ready,
    dispose() {
      cancelAlarm();
      disposed = true;
      visibility.removeEventListener('visibilitychange', switchMode);
      for (const timer of timers.values()) if (timer.browser !== null) original.clearTimeout.call(host, timer.browser);
      timers.clear();
      Object.assign(host, original);
    },
  };
}
