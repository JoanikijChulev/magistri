import { PAGE_SCOPE, unlockJson } from './crypto.js';
import { LoginLimiter } from './login-limit.js';

// Keep native form prompts Macedonian even when the browser UI is English.
document.addEventListener('invalid', event => {
  const field = event.target;
  if (field.validity.valueMissing) field.setCustomValidity(field.type === 'checkbox'
    ? 'Потврди го ова поле за да продолжиш.'
    : field.type === 'radio' ? 'Избери еден одговор.' : 'Пополнѝ го ова поле.');
}, true);
for (const type of ['input', 'change']) document.addEventListener(type, event => {
  if (event.target.form) for (const field of event.target.form.elements) {
    if (typeof field.setCustomValidity === 'function') field.setCustomValidity('');
  }
});

// Force all JavaScript on this page, including the decrypted invitation module,
// to treat reduced motion as disabled while leaving every other media query intact.
const nativeMatchMedia = window.matchMedia.bind(window);
window.matchMedia = query => {
  const result = nativeMatchMedia(query);
  if (String(query).replace(/\s+/g, '') !== '(prefers-reduced-motion:reduce)') return result;
  return new Proxy(result, {
    get(target, property) {
      if (property === 'matches') return false;
      const value = Reflect.get(target, property, target);
      return typeof value === 'function' ? value.bind(target) : value;
    }
  });
};

const form = document.querySelector('#access-form');
const input = document.querySelector('#access-password');
const submit = document.querySelector('#access-submit');
const feedback = document.querySelector('#access-feedback');
const mode = document.body.dataset.access;
const envelope = JSON.parse(document.querySelector('#protected-payload').textContent);
let busy = false;
let opened = false, wasLocked = false;
let loginStorage;
try { loginStorage = window.localStorage; } catch { loginStorage = null; }
const limiter = new LoginLimiter(loginStorage, `doh:login-limit:${new URL('.', location.href).pathname}:${mode}`, Date.now, navigator.locks);
const encryptionSupported = window.isSecureContext && Boolean(crypto.subtle);
function renderLimit() {
  if (opened || !encryptionSupported) return;
  const state = limiter.state();
  submit.disabled = busy || state.seconds > 0;
  input.readOnly = busy || state.seconds > 0;
  document.body.classList.toggle('access-locked', state.seconds > 0);
  if (state.seconds) {
    feedback.textContent = `3 погрешни обиди. Пробај повторно за ${state.seconds} сек.`;
    wasLocked = true;
  } else if (wasLocked && !busy) {
    feedback.textContent = 'Можеш да пробаш повторно. Имаш 3 обиди.';
    wasLocked = false; document.body.classList.remove('access-error'); input.removeAttribute('aria-invalid');
  }
}
const limitTimer = setInterval(renderLimit, 1000);
window.addEventListener('storage', event => { if (event.key === limiter.key || event.key === null) renderLimit(); });
document.addEventListener('visibilitychange', renderLimit);

if (!window.isSecureContext || !crypto.subtle) {
  feedback.textContent = 'Отвори ја поканата преку HTTPS или преку локалниот преглед. Потребен е прелистувач што поддржува безбедно отворање.';
  submit.disabled = true;
}

function updateSignal() {
  const length = Array.from(input.value).length;
  document.body.classList.toggle('access-typing', length > 0);
  document.documentElement.style.setProperty('--typed-angle', `${length * 23}deg`);
  document.documentElement.style.setProperty('--signal', `${Math.min(length / 12, 1) * 100}%`);
  document.querySelectorAll('.signal-bars i').forEach((bar, index) => {
    bar.style.setProperty('--bar', `${length ? 15 + ((length * 13 + index * 17) % 65) : 12 + (index % 3) * 8}%`);
  });
  if (!busy && !limiter.state().seconds && encryptionSupported) { feedback.textContent = ''; document.body.classList.remove('access-error'); input.removeAttribute('aria-invalid'); }
  renderLimit();
}
input.addEventListener('input', updateSignal);
input.addEventListener('focus', () => document.body.classList.add('access-focused'));
input.addEventListener('blur', () => document.body.classList.remove('access-focused'));
input.addEventListener('keyup', event => { document.querySelector('#caps-lock').hidden = !event.getModifierState('CapsLock'); });
document.querySelector('#show-password').addEventListener('click', event => {
  const shown = input.type === 'password'; input.type = shown ? 'text' : 'password';
  event.currentTarget.textContent = shown ? 'Сокриј' : 'Прикажи';
  event.currentTarget.setAttribute('aria-pressed', String(shown));
  input.focus();
});

async function showPage(value, key, kdf) {
  if (!value || typeof value.body !== 'string' || typeof value.module !== 'string') throw new Error('This protected page is incomplete.');
  document.title = value.title;
  document.documentElement.classList.remove('js', 'motion-paused');
  document.documentElement.style.removeProperty('--typed-angle');
  document.documentElement.style.removeProperty('--signal');
  const parsed = new DOMParser().parseFromString(`<body>${value.body}</body>`, 'text/html');
  document.body.className = value.bodyClass || '';
  delete document.body.dataset.access;
  document.body.replaceChildren(...Array.from(parsed.body.childNodes, node => document.importNode(node, true)));
  const blob = URL.createObjectURL(new Blob([value.module], { type: 'text/javascript' }));
  let app;
  try { app = await import(blob); } finally { URL.revokeObjectURL(blob); }
  // The decrypted view must not reappear from the back/forward cache.
  window.addEventListener('pagehide', () => document.body.replaceChildren(), { once: true });
  window.addEventListener('pageshow', event => { if (event.persisted) location.reload(); });
  let mounted = false;
  const mount = () => {
    if (mounted) return;
    app.mountInvitation(value.config || {});
    mounted = true;
    if (!location.hash) window.scrollTo({ top: 0, behavior: 'instant' });
  };
  // Play after every successful login, once the invitation has been decrypted.
  try { await app.showWelcome?.({ onReveal: mount }); } catch { /* An intro failure must not block the invitation. */ }
  mount();
  document.querySelector('h1')?.setAttribute('tabindex', '-1');
  document.querySelector('h1')?.focus({ preventScroll: true });
  if (location.hash) {
    const target = document.getElementById(decodeURIComponent(location.hash.slice(1)));
    target?.scrollIntoView({ behavior: 'instant' });
  } else window.scrollTo({ top: 0, behavior: 'instant' });
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  if (busy || !input.value || !encryptionSupported) return;
  if (limiter.state().seconds) { renderLimit(); return; }
  busy = true; submit.disabled = true; input.readOnly = true;
  document.body.classList.remove('access-error');
  document.body.classList.add('access-checking');
  feedback.textContent = 'Го фаќаме твојот ритам…';
  let password = input.value;
  let unlocked;
  try { unlocked = await limiter.attempt(() => unlockJson(envelope, password, PAGE_SCOPE[mode])); }
  catch {
    document.body.classList.remove('access-checking');
    document.body.classList.add('access-error');
    const state = limiter.state();
    feedback.textContent = `Погрешна лозинка. Преостанати обиди: ${state.remaining}.`;
    input.setAttribute('aria-invalid', 'true');
    busy = false; renderLimit();
    if (!state.seconds) { input.focus(); input.select(); }
    else input.value = '';
    return;
  } finally { password = ''; }
  opened = true; clearInterval(limitTimer);
  input.value = ''; input.type = 'password';
  document.body.classList.remove('access-checking');
  document.body.classList.add('access-approved');
  feedback.textContent = 'На списокот си. Ајде на забава!';
  await new Promise(resolve => setTimeout(resolve, 950));
  try { await showPage(unlocked.value, unlocked.key, unlocked.kdf); }
  catch {
    // Show no decrypted content if mounting the protected application fails.
    document.body.replaceChildren();
    const message = document.createElement('p'); message.className = 'notice';
    message.textContent = 'Страницата не се отвори целосно. Освежи ја и пробај повторно. Зачуваните одговори не се изгубени.';
    const retry = document.createElement('button'); retry.className = 'button button-acid'; retry.textContent = 'Назад кон најавата';retry.addEventListener('click', () => location.reload());
    document.body.append(message, retry);
  }
});
updateSignal();
