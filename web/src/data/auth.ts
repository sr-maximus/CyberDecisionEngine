import type { LanguageMode, LocalUser, UserRole } from "../types";

export const USERS_STORAGE_KEY = "cyberdecision.users";
export const SESSION_STORAGE_KEY = "cyberdecision.session";
export const SESSION_IDLE_TIMEOUT_MS = 30 * 60 * 1000;
export const SESSION_ABSOLUTE_TIMEOUT_MS = 8 * 60 * 60 * 1000;
export const SUPER_ADMIN_SESSION_IDLE_TIMEOUT_MS = 6 * 60 * 60 * 1000;
export const SUPER_ADMIN_SESSION_ABSOLUTE_TIMEOUT_MS = 24 * 60 * 60 * 1000;
export const LOGIN_LOCK_THRESHOLD = 5;
export const LOGIN_LOCKOUT_MS = 15 * 60 * 1000;
export const MFA_CODE_TTL_MS = 10 * 60 * 1000;

export interface StoredSession {
  userId: string;
  issuedAt: number;
  lastActivity: number;
}

export interface SessionPolicy {
  idleTimeoutMs: number;
  absoluteTimeoutMs: number;
}

export type AuthResultStatus = "success" | "mfa_required" | "invalid" | "locked";

export interface AuthResult {
  status: AuthResultStatus;
  users: LocalUser[];
  user?: LocalUser;
  failedAttempts?: number;
  lockedUntil?: number;
}

export interface MfaVerificationResult {
  status: "success" | "invalid" | "expired" | "locked";
  users: LocalUser[];
  user?: LocalUser;
  lockedUntil?: number;
}

export const roleLabels: Record<UserRole, string> = {
  super_admin: "Super admin",
  admin: "Administrador",
  analyst: "Analista",
  executive: "Directivo",
  viewer: "Lector"
};

export const roleLabelsByLanguage: Record<LanguageMode, Record<UserRole, string>> = {
  es: roleLabels,
  en: {
    super_admin: "Super admin",
    admin: "Administrator",
    analyst: "Analyst",
    executive: "Executive",
    viewer: "Viewer"
  }
};

export function loadUsers(): LocalUser[] {
  const saved = typeof window === "undefined" ? null : window.localStorage.getItem(USERS_STORAGE_KEY);
  const users = safeParseUsers(saved).map((user) => normalizeUser(sanitizeUser(user)));
  saveUsers(users);
  return users;
}

export function saveUsers(users: LocalUser[]) {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(USERS_STORAGE_KEY, JSON.stringify(users.map(sanitizeUser)));
}

export function sessionPolicyForUser(user?: LocalUser | null): SessionPolicy {
  if (user?.role === "super_admin") {
    return {
      idleTimeoutMs: SUPER_ADMIN_SESSION_IDLE_TIMEOUT_MS,
      absoluteTimeoutMs: SUPER_ADMIN_SESSION_ABSOLUTE_TIMEOUT_MS,
    };
  }
  return {
    idleTimeoutMs: SESSION_IDLE_TIMEOUT_MS,
    absoluteTimeoutMs: SESSION_ABSOLUTE_TIMEOUT_MS,
  };
}

export function readSession(now = Date.now(), policy: SessionPolicy = sessionPolicyForUser()): StoredSession | null {
  if (typeof window === "undefined") return null;
  const raw = window.localStorage.getItem(SESSION_STORAGE_KEY);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as Partial<StoredSession>;
    if (!parsed.userId || typeof parsed.issuedAt !== "number" || typeof parsed.lastActivity !== "number") {
      clearSession();
      return null;
    }
    const session = parsed as StoredSession;
    if (!isSessionFresh(session, now, policy)) {
      clearSession();
      return null;
    }
    return session;
  } catch {
    clearSession();
    return null;
  }
}

export function writeSession(userId: string, now = Date.now()): StoredSession {
  const session = { userId, issuedAt: now, lastActivity: now };
  if (typeof window !== "undefined") window.localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(session));
  return session;
}

export function touchSession(userId: string, now = Date.now(), policy: SessionPolicy = sessionPolicyForUser()): StoredSession | null {
  const session = readSession(now, policy);
  if (!session || session.userId !== userId) return null;
  const nextSession = { ...session, lastActivity: now };
  if (typeof window !== "undefined") window.localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(nextSession));
  return nextSession;
}

export function clearSession() {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(SESSION_STORAGE_KEY);
}

export function isSessionFresh(session: StoredSession, now = Date.now(), policy: SessionPolicy = sessionPolicyForUser()): boolean {
  if (!session.userId) return false;
  if (now - session.lastActivity > policy.idleTimeoutMs) return false;
  if (now - session.issuedAt > policy.absoluteTimeoutMs) return false;
  return true;
}

export async function authenticateUser(users: LocalUser[], username: string, password: string, now = Date.now()): Promise<AuthResult> {
  const normalized = username.trim().toLowerCase();
  const user = users.find((item) => item.username.toLowerCase() === normalized);
  if (!user) return { status: "invalid", users };
  if (isUserLocked(user, now)) {
    return { status: "locked", users, user, lockedUntil: user.lockedUntil };
  }
  const hash = await hashPassword(password);
  if (user.passwordHash !== hash) {
    const nextUsers = markFailedLogin(users, user.id, now);
    const nextUser = nextUsers.find((item) => item.id === user.id);
    return {
      status: nextUser?.lockedUntil ? "locked" : "invalid",
      users: nextUsers,
      user: nextUser,
      failedAttempts: nextUser?.failedLoginCount,
      lockedUntil: nextUser?.lockedUntil
    };
  }
  const nextUsers = clearLoginRisk(users, user.id);
  const nextUser = nextUsers.find((item) => item.id === user.id) ?? user;
  return { status: nextUser.mfaEnabled ? "mfa_required" : "success", users: nextUsers, user: nextUser };
}

export async function verifyMfaCode(users: LocalUser[], userId: string, code: string, now = Date.now()): Promise<MfaVerificationResult> {
  const user = users.find((item) => item.id === userId);
  if (!user) return { status: "invalid", users };
  if (isUserLocked(user, now)) return { status: "locked", users, user, lockedUntil: user.lockedUntil };
  if (!user.mfaEnabled) return { status: "success", users, user };
  if (!user.mfaCodeHash || !user.mfaCodeExpiresAt || user.mfaCodeExpiresAt < now) {
    return { status: "expired", users, user };
  }
  const hash = await hashPassword(code.trim());
  if (hash !== user.mfaCodeHash) {
    const nextUsers = markFailedLogin(users, user.id, now);
    const nextUser = nextUsers.find((item) => item.id === user.id);
    return {
      status: nextUser?.lockedUntil ? "locked" : "invalid",
      users: nextUsers,
      user: nextUser,
      lockedUntil: nextUser?.lockedUntil
    };
  }
  const nextUsers = clearLoginRisk(
    users.map((item) =>
      item.id === user.id
        ? { ...item, mfaCodeHash: undefined, mfaCodeIssuedAt: undefined, mfaCodeExpiresAt: undefined }
        : item
    ),
    user.id
  );
  return { status: "success", users: nextUsers, user: nextUsers.find((item) => item.id === user.id) };
}

export function createLocalUser(input: Omit<LocalUser, "id" | "createdAt" | "permissions"> & { permissions?: string[] }): LocalUser {
  return {
    ...input,
    id: `local-${Date.now().toString(36)}`,
    permissions: input.permissions ?? defaultPermissions(input.role),
    mfaEnabled: input.mfaEnabled ?? false,
    failedLoginCount: 0,
    mustChangePassword: input.mustChangePassword ?? true,
    passwordUpdatedAt: input.passwordUpdatedAt ?? new Date().toISOString(),
    createdAt: new Date().toISOString()
  };
}

export async function hashPassword(password: string): Promise<string> {
  const bytes = new TextEncoder().encode(password);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export function defaultPermissions(role: UserRole): string[] {
  if (role === "super_admin") return ["platform:superadmin", "license:manage", "company:manage", "users:manage", "settings:write", "analysis:run", "reports:view", "surface:view"];
  if (role === "admin") return ["users:manage", "settings:write", "analysis:run", "reports:view", "surface:view"];
  if (role === "analyst") return ["analysis:run", "reports:view", "surface:view", "sources:view"];
  if (role === "executive") return ["dashboards:view", "reports:view", "surface:view"];
  return ["dashboards:view", "reports:view"];
}

export function isUserLocked(user: LocalUser, now = Date.now()): boolean {
  return typeof user.lockedUntil === "number" && user.lockedUntil > now;
}

export function lockoutMinutes(user: LocalUser, now = Date.now()): number {
  if (!isUserLocked(user, now) || !user.lockedUntil) return 0;
  return Math.max(1, Math.ceil((user.lockedUntil - now) / 60_000));
}

export function generateNumericCode(length = 6): string {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((byte) => String(byte % 10))
    .join("");
}

export function generateTemporaryPassword(length = 16): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#$%*?";
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((byte) => alphabet[byte % alphabet.length])
    .join("");
}

export async function attachTemporaryMfaCode(user: LocalUser, now = Date.now()): Promise<{ user: LocalUser; code: string }> {
  const code = generateNumericCode();
  return {
    code,
    user: {
      ...user,
      mfaEnabled: true,
      mfaCodeHash: await hashPassword(code),
      mfaCodeIssuedAt: new Date(now).toISOString(),
      mfaCodeExpiresAt: now + MFA_CODE_TTL_MS
    }
  };
}

export function unlockUser(user: LocalUser): LocalUser {
  return { ...user, failedLoginCount: 0, lockedUntil: undefined };
}

function markFailedLogin(users: LocalUser[], userId: string, now: number): LocalUser[] {
  return users.map((user) => {
    if (user.id !== userId) return user;
    const failedLoginCount = (user.failedLoginCount ?? 0) + 1;
    return {
      ...user,
      failedLoginCount,
      lockedUntil: failedLoginCount >= LOGIN_LOCK_THRESHOLD ? now + LOGIN_LOCKOUT_MS : user.lockedUntil
    };
  });
}

function clearLoginRisk(users: LocalUser[], userId: string): LocalUser[] {
  return users.map((user) =>
    user.id === userId ? { ...user, failedLoginCount: 0, lockedUntil: undefined } : user
  );
}

function normalizeUser(user: LocalUser): LocalUser {
  return {
    ...user,
    permissions: user.permissions?.length ? user.permissions : defaultPermissions(user.role),
    mfaEnabled: Boolean(user.mfaEnabled),
    failedLoginCount: user.failedLoginCount ?? 0,
    createdAt: user.createdAt ?? new Date().toISOString()
  };
}

function safeParseUsers(payload: string | null): LocalUser[] {
  if (!payload) return [];
  try {
    const parsed = JSON.parse(payload);
    return Array.isArray(parsed) ? parsed.filter(isLocalUser) : [];
  } catch {
    return [];
  }
}

function isLocalUser(value: unknown): value is LocalUser {
  if (!value || typeof value !== "object") return false;
  const user = value as Partial<LocalUser>;
  return Boolean(user.username && user.passwordHash && user.fullName && user.role);
}

function sanitizeUser(user: LocalUser): LocalUser {
  const { password: _password, ...safeUser } = user;
  return safeUser;
}
