import { setAuthTokenGetter } from '@workspace/api-client-react';

const TOKEN_KEY = 'securix_token';
const SESSION_KEY = 'securix_session';

export type StoredSession = { token: string; username: string; role: string };

export function getSession(): StoredSession | null {
  try {
    const raw = localStorage.getItem(SESSION_KEY);
    return raw ? JSON.parse(raw) as StoredSession : null;
  } catch {
    return null;
  }
}

export function saveSession(session: StoredSession) {
  localStorage.setItem(TOKEN_KEY, session.token);
  localStorage.setItem(SESSION_KEY, JSON.stringify(session));
}

export function clearSession() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(SESSION_KEY);
}

export function hasSession() {
  return Boolean(getSession()?.token);
}

export function configureAuth() {
  setAuthTokenGetter(() => localStorage.getItem(TOKEN_KEY));
}