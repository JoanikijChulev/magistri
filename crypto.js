// Password-derived encryption with the browser's native Web Crypto API.
// This module contains no passwords, password hashes, or encryption keys.
export const ITERATIONS = 600_000;
export const PAGE_SCOPE = { invitation: 'doh:invitation:v1' };
const encoder = new TextEncoder();

export function base64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 32768) binary += String.fromCharCode(...bytes.subarray(i, i + 32768));
  return btoa(binary);
}

export function unbase64(text, max = 6_000_000) {
  if (typeof text !== 'string' || text.length > max || text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) throw new Error('Invalid encrypted data.');
  return Uint8Array.from(atob(text), char => char.charCodeAt(0));
}

export function createKdf(salt = base64(crypto.getRandomValues(new Uint8Array(16)))) {
  if (unbase64(salt, 32).length !== 16) throw new Error('Invalid encryption salt.');
  return { name: 'PBKDF2', hash: 'SHA-256', iterations: ITERATIONS, salt };
}

function validateKdf(input) {
  if (input?.name !== 'PBKDF2' || input.hash !== 'SHA-256' || input.iterations !== ITERATIONS) throw new Error('Unsupported encryption settings.');
  return createKdf(input.salt);
}

export async function derivePasswordKey(password, input) {
  if (typeof password !== 'string' || !password.length || password.length > 256) throw new Error('Enter your password.');
  const kdf = validateKdf(input);
  const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: unbase64(kdf.salt), iterations: kdf.iterations, hash: kdf.hash }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

function aad(kdf, scope) { return encoder.encode(JSON.stringify({ format: 'doh-encrypted', version: 1, kdf, scope })); }

export function validateEnvelope(input, scope) {
  if (input?.format !== 'doh-encrypted' || input.version !== 1 || input.scope !== scope || input.cipher?.name !== 'AES-GCM') throw new Error('This encrypted file does not belong here.');
  const kdf = validateKdf(input.kdf);
  const iv = unbase64(input.cipher.iv, 24);
  const data = unbase64(input.cipher.data);
  if (iv.length !== 12 || data.length < 16) throw new Error('Incomplete encrypted file.');
  return { kdf, iv, data };
}

export async function sealJson(value, key, input, scope) {
  const kdf = validateKdf(input);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(kdf, scope), tagLength: 128 }, key, encoder.encode(JSON.stringify(value)));
  return { format: 'doh-encrypted', version: 1, scope, kdf, cipher: { name: 'AES-GCM', iv: base64(iv), data: base64(new Uint8Array(data)) } };
}

export async function openJson(input, key, scope) {
  const { kdf, iv, data } = validateEnvelope(input, scope);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad(kdf, scope), tagLength: 128 }, key, data);
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(decrypted));
}

export async function unlockJson(input, password, scope) {
  const { kdf } = validateEnvelope(input, scope);
  const key = await derivePasswordKey(password, kdf);
  const value = await openJson(input, key, scope);
  return { value, key, kdf };
}
