import type { LocalUser } from "../types";

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "";
let csrfToken = "";
export function serverCsrfToken() { return csrfToken; }

export async function authMode(): Promise<boolean> {
  const response = await fetch(`${API_BASE}/api/auth/mode`, { credentials: "same-origin", cache: "no-store" });
  if (!response.ok) throw new Error("No se pudo comprobar la seguridad del servidor. Recarga la página.");
  const body = await response.json();
  if (typeof body.enabled !== "boolean") throw new Error("Respuesta de seguridad inválida. Recarga la página.");
  return body.enabled;
}

export async function serverSession(username?: string, password?: string): Promise<LocalUser | null> {
  const login = username !== undefined;
  const response = await fetch(`${API_BASE}/api/auth/${login ? "login" : "me"}`, {
    method: login ? "POST" : "GET", credentials: "same-origin", cache: "no-store",
    headers: { "Content-Type": "application/json" },
    ...(login ? { body: JSON.stringify({ username, password }) } : {})
  });
  if (!login && response.status === 401) return null;
  const body = await response.json();
  if (!response.ok) throw new Error(response.status === 429 ? "Demasiados intentos. Espera 15 minutos." : login ? "Usuario o contraseña incorrectos." : "La sesión no está disponible.");
  csrfToken = body.csrfToken;
  return body.user;
}

export async function serverLogout(): Promise<void> {
  const response = await fetch(`${API_BASE}/api/auth/logout`, {
    method: "POST", credentials: "same-origin", headers: { "X-CSRF-Token": csrfToken }
  });
  if (!response.ok && response.status !== 401) throw new Error("No se pudo cerrar la sesión. Intenta nuevamente.");
  csrfToken = "";
}
