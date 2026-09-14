export const MAX_ATTEMPTS = 3;
export const WAIT_MS = 60_000;
export class LoginLockedError extends Error {
  constructor() { super('Too many incorrect passwords. Wait before trying again.'); }
}

// Browser-only deterrent. No passwords or keys are stored here.
export class LoginLimiter {
  constructor(storage, key, now = Date.now, locks = null) {
    this.storage = storage; this.key = key; this.now = now; this.locks = locks;
    this.storageFailed = false;
    this.memory = { failures: 0, until: 0 };
  }
  save(state) {
    this.memory = state;
    try { this.storage.setItem(this.key, JSON.stringify(state)); } catch { this.storageFailed = true; }
  }
  state() {
    let state = this.memory;
    try {
      const saved = this.storageFailed ? null : JSON.parse(this.storage.getItem(this.key));
      if (saved && Number.isInteger(saved.failures) && saved.failures >= 0 && saved.failures <= MAX_ATTEMPTS && Number.isFinite(saved.until) && saved.until >= 0) state = saved;
    } catch { /* Retain memory state. */ }
    if (state.until && state.until <= this.now()) { state = { failures: 0, until: 0 }; this.save(state); }
    this.memory = state;
    return { ...state, seconds: Math.max(0, Math.ceil((state.until - this.now()) / 1000)), remaining: MAX_ATTEMPTS - state.failures };
  }
  async attempt(check) {
    const run = async () => {
      const state = this.state();
      if (state.seconds) throw new LoginLockedError();
      try {
        const value = await check();
        this.save({ failures: 0, until: 0 });
        return value;
      } catch (error) {
        const failures = Math.min(MAX_ATTEMPTS, state.failures + 1);
        this.save({ failures, until: failures === MAX_ATTEMPTS ? this.now() + WAIT_MS : 0 });
        throw error;
      }
    };
    return this.locks ? this.locks.request(this.key, run) : run();
  }
}
