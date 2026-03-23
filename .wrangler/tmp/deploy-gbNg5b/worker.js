var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// worker.js
function base64url(buffer) {
  let str = typeof buffer === "string" ? buffer : String.fromCharCode(...new Uint8Array(buffer));
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
__name(base64url, "base64url");
async function hmacSha256(secret, data) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return signature;
}
__name(hmacSha256, "hmacSha256");
async function createToken(secret, expiresSeconds = 1800, claims = {}) {
  const header = base64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = base64url(JSON.stringify({
    exp: Math.floor(Date.now() / 1e3) + expiresSeconds,
    ...claims
  }));
  const message = `${header}.${payload}`;
  const sig = await hmacSha256(secret, message);
  const token = `${message}.${base64url(sig)}`;
  return token;
}
__name(createToken, "createToken");
async function verifyToken(secret, token) {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [header, payload, signature] = parts;
  const message = `${header}.${payload}`;
  const expectedSig = base64url(await hmacSha256(secret, message));
  if (signature !== expectedSig) return null;
  const data = JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/")));
  if (!(data.exp && Date.now() / 1e3 < data.exp)) {
    return null;
  }
  return data;
}
__name(verifyToken, "verifyToken");
function sanitizeFileName(fileName) {
  return (fileName || "upload").toLowerCase().replace(/[^a-z0-9._-]/g, "-").replace(/-+/g, "-").replace(/^-|-$/g, "").slice(0, 80) || "upload";
}
__name(sanitizeFileName, "sanitizeFileName");
var PORTFOLIO_DATA_KEY = "portfolio:data:v1";
var FILE_KEY_PREFIX = "file:";
var AUTH_CODE_KEY = "auth:code:v1";
var ACCESS_USERS_KEY = "access:users:v1";
var DELETE_PASSWORD_HASH_KEY = "delete:password:hash:v1";
var LOGIN_ACTIVITY_KEY = "login:activity:v1";
var PASSWORD_HASH_ITERATIONS = 21e4;
var ROLE_LEVEL = {
  viewer: 1,
  editor: 2,
  admin: 3
};
function normalizeRole(role) {
  const value = String(role || "").toLowerCase();
  return ROLE_LEVEL[value] ? value : "viewer";
}
__name(normalizeRole, "normalizeRole");
function hasRole(actualRole, requiredRole) {
  return (ROLE_LEVEL[normalizeRole(actualRole)] || 0) >= (ROLE_LEVEL[normalizeRole(requiredRole)] || Number.MAX_SAFE_INTEGER);
}
__name(hasRole, "hasRole");
function normalizeAccessUsers(users, fallbackCode) {
  if (!Array.isArray(users)) {
    return [{ id: "admin", name: "Admin", code: fallbackCode, role: "admin" }];
  }
  const normalized = users.map((user, index) => {
    const code = String(user?.code || "").trim();
    if (!/^\d{4}$/.test(code)) {
      return null;
    }
    return {
      id: String(user?.id || `user-${index + 1}`),
      name: String(user?.name || `User ${index + 1}`),
      code,
      role: normalizeRole(user?.role)
    };
  }).filter(Boolean);
  if (!normalized.some((user) => user.role === "admin")) {
    normalized.unshift({ id: "admin", name: "Admin", code: fallbackCode, role: "admin" });
  }
  return normalized.length > 0 ? normalized : [{ id: "admin", name: "Admin", code: fallbackCode, role: "admin" }];
}
__name(normalizeAccessUsers, "normalizeAccessUsers");
function sanitizeAccessUsersForAdmin(users) {
  return (Array.isArray(users) ? users : []).map((user) => ({
    id: user.id,
    name: user.name,
    code: user.code,
    role: normalizeRole(user.role)
  }));
}
__name(sanitizeAccessUsersForAdmin, "sanitizeAccessUsersForAdmin");
function generateUserId() {
  return `user-${crypto.randomUUID()}`;
}
__name(generateUserId, "generateUserId");
async function hashText(value) {
  const data = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
__name(hashText, "hashText");
function randomHex(byteLength) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
__name(randomHex, "randomHex");
function timingSafeEqualHex(a, b) {
  const left = String(a || "");
  const right = String(b || "");
  const maxLength = Math.max(left.length, right.length);
  let diff = left.length ^ right.length;
  for (let index = 0; index < maxLength; index += 1) {
    const leftCode = index < left.length ? left.charCodeAt(index) : 0;
    const rightCode = index < right.length ? right.charCodeAt(index) : 0;
    diff |= leftCode ^ rightCode;
  }
  return diff === 0;
}
__name(timingSafeEqualHex, "timingSafeEqualHex");
async function derivePasswordHash(password, saltHex, pepper, iterations = PASSWORD_HASH_ITERATIONS) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(`${String(password)}${pepper || ""}`),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: Uint8Array.from(saltHex.match(/.{1,2}/g).map((value) => parseInt(value, 16))),
      iterations,
      hash: "SHA-256"
    },
    keyMaterial,
    256
  );
  return Array.from(new Uint8Array(bits)).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
__name(derivePasswordHash, "derivePasswordHash");
async function hashPasswordSecure(password, pepper) {
  const saltHex = randomHex(16);
  const hashHex = await derivePasswordHash(password, saltHex, pepper, PASSWORD_HASH_ITERATIONS);
  return `pbkdf2$${PASSWORD_HASH_ITERATIONS}$${saltHex}$${hashHex}`;
}
__name(hashPasswordSecure, "hashPasswordSecure");
async function verifyPasswordSecure(password, storedHash, pepper) {
  if (!storedHash) {
    return false;
  }
  if (storedHash.startsWith("pbkdf2$")) {
    const parts = storedHash.split("$");
    if (parts.length !== 4) {
      return false;
    }
    const iterations = Number(parts[1]);
    const saltHex = parts[2];
    const expectedHash = parts[3];
    if (!Number.isFinite(iterations) || !saltHex || !expectedHash) {
      return false;
    }
    const derived = await derivePasswordHash(password, saltHex, pepper, iterations);
    return timingSafeEqualHex(derived, expectedHash);
  }
  if (/^[a-f0-9]{64}$/i.test(storedHash)) {
    const legacy = await hashText(String(password));
    return timingSafeEqualHex(legacy, storedHash);
  }
  return false;
}
__name(verifyPasswordSecure, "verifyPasswordSecure");
async function getAccessUsers(env) {
  const fallbackCode = env.AUTH_CODE || "1234";
  let sourceUsers = null;
  if (env.PORTFOLIO_KV) {
    const raw = await env.PORTFOLIO_KV.get(ACCESS_USERS_KEY);
    if (raw) {
      try {
        sourceUsers = JSON.parse(raw);
      } catch {
        sourceUsers = null;
      }
    }
  }
  if (!sourceUsers && env.ACCESS_USERS_JSON) {
    try {
      sourceUsers = JSON.parse(env.ACCESS_USERS_JSON);
    } catch {
      sourceUsers = null;
    }
  }
  return normalizeAccessUsers(sourceUsers, fallbackCode);
}
__name(getAccessUsers, "getAccessUsers");
async function setAccessUsers(env, users) {
  if (!env.PORTFOLIO_KV) {
    throw new Error("KV binding missing");
  }
  const normalized = normalizeAccessUsers(users, env.AUTH_CODE || "1234");
  await env.PORTFOLIO_KV.put(ACCESS_USERS_KEY, JSON.stringify(normalized));
  const adminUser = normalized.find((user) => user.role === "admin");
  if (adminUser?.code) {
    await env.PORTFOLIO_KV.put(AUTH_CODE_KEY, adminUser.code);
  }
  return normalized;
}
__name(setAccessUsers, "setAccessUsers");
async function getDeletePasswordHash(env) {
  if (!env.PORTFOLIO_KV) {
    return "";
  }
  return await env.PORTFOLIO_KV.get(DELETE_PASSWORD_HASH_KEY) || "";
}
__name(getDeletePasswordHash, "getDeletePasswordHash");
async function setDeletePasswordHash(env, password) {
  if (!env.PORTFOLIO_KV) {
    throw new Error("KV binding missing");
  }
  const hashed = await hashPasswordSecure(String(password), env.DELETE_PASSWORD_PEPPER || "");
  await env.PORTFOLIO_KV.put(DELETE_PASSWORD_HASH_KEY, hashed);
}
__name(setDeletePasswordHash, "setDeletePasswordHash");
async function appendLoginActivity(env, request, user) {
  if (!env.PORTFOLIO_KV) {
    return;
  }
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const userAgent = request.headers.get("User-Agent") || "unknown";
  const location = request.cf?.country || "unknown";
  const entry = {
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    ip,
    location,
    userAgent,
    userId: user?.id || "unknown",
    userName: user?.name || "Unknown user",
    userCode: user?.code || "unknown",
    role: normalizeRole(user?.role)
  };
  const raw = await env.PORTFOLIO_KV.get(LOGIN_ACTIVITY_KEY);
  let activity = [];
  if (raw) {
    try {
      const parsed = JSON.parse(raw);
      activity = Array.isArray(parsed) ? parsed : [];
    } catch {
      activity = [];
    }
  }
  activity.unshift(entry);
  await env.PORTFOLIO_KV.put(LOGIN_ACTIVITY_KEY, JSON.stringify(activity.slice(0, 20)));
}
__name(appendLoginActivity, "appendLoginActivity");
function getSessionTokenFromCookieHeader(cookieHeader) {
  const cookie = cookieHeader || "";
  return cookie.split(";").map((c) => c.trim()).find((c) => c.startsWith("session="))?.split("=")[1];
}
__name(getSessionTokenFromCookieHeader, "getSessionTokenFromCookieHeader");
async function getSessionFromRequest(request, env) {
  const token = getSessionTokenFromCookieHeader(request.headers.get("Cookie") || "");
  return verifyToken(env.SESSION_SECRET || "default-session-secret", token);
}
__name(getSessionFromRequest, "getSessionFromRequest");
function unauthorizedResponse() {
  return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: { "Content-Type": "application/json" } });
}
__name(unauthorizedResponse, "unauthorizedResponse");
function forbiddenResponse() {
  return new Response(JSON.stringify({ error: "Forbidden" }), { status: 403, headers: { "Content-Type": "application/json" } });
}
__name(forbiddenResponse, "forbiddenResponse");
function collectFileKeys(value, keys = /* @__PURE__ */ new Set()) {
  if (Array.isArray(value)) {
    for (const item of value) {
      collectFileKeys(item, keys);
    }
    return keys;
  }
  if (value && typeof value === "object") {
    for (const nested of Object.values(value)) {
      collectFileKeys(nested, keys);
    }
    return keys;
  }
  if (typeof value === "string" && value.includes("/api/files/")) {
    const prefixIndex = value.indexOf("/api/files/");
    const encoded = value.slice(prefixIndex + "/api/files/".length);
    const decoded = decodeURIComponent(encoded.split("?")[0]);
    if (decoded.startsWith(FILE_KEY_PREFIX)) {
      keys.add(decoded);
    }
  }
  return keys;
}
__name(collectFileKeys, "collectFileKeys");
async function loadPortfolioData(env) {
  if (!env.PORTFOLIO_KV) {
    return { folders: [] };
  }
  const raw = await env.PORTFOLIO_KV.get(PORTFOLIO_DATA_KEY);
  if (!raw) {
    return { folders: [] };
  }
  try {
    const parsed = JSON.parse(raw);
    return { folders: Array.isArray(parsed?.folders) ? parsed.folders : [] };
  } catch {
    return { folders: [] };
  }
}
__name(loadPortfolioData, "loadPortfolioData");
async function savePortfolioData(env, folders) {
  if (!env.PORTFOLIO_KV) {
    throw new Error("KV binding missing");
  }
  const payload = JSON.stringify({ folders: Array.isArray(folders) ? folders : [] });
  await env.PORTFOLIO_KV.put(PORTFOLIO_DATA_KEY, payload);
}
__name(savePortfolioData, "savePortfolioData");
async function saveFile(env, fileKey, buffer, meta) {
  if (env.PORTFOLIO_R2) {
    await env.PORTFOLIO_R2.put(fileKey, buffer, { httpMetadata: { contentType: meta.contentType } });
    await env.PORTFOLIO_R2.put(`${fileKey}:meta`, JSON.stringify(meta));
  } else if (env.PORTFOLIO_KV) {
    await env.PORTFOLIO_KV.put(fileKey, buffer);
    await env.PORTFOLIO_KV.put(`${fileKey}:meta`, JSON.stringify(meta));
  } else {
    throw new Error("No storage configured");
  }
}
__name(saveFile, "saveFile");
async function getFile(env, fileKey) {
  if (env.PORTFOLIO_R2) {
    try {
      const obj = await env.PORTFOLIO_R2.get(fileKey);
      if (!obj) return null;
      return { buffer: await obj.arrayBuffer(), meta: null };
    } catch {
      return null;
    }
  } else if (env.PORTFOLIO_KV) {
    const data = await env.PORTFOLIO_KV.get(fileKey, "arrayBuffer");
    return data ? { buffer: data, meta: null } : null;
  }
  return null;
}
__name(getFile, "getFile");
async function getFileMeta(env, fileKey) {
  if (env.PORTFOLIO_R2) {
    try {
      const obj = await env.PORTFOLIO_R2.get(`${fileKey}:meta`);
      if (!obj) return {};
      return JSON.parse(await obj.text());
    } catch {
      return {};
    }
  } else if (env.PORTFOLIO_KV) {
    const metaRaw = await env.PORTFOLIO_KV.get(`${fileKey}:meta`);
    return metaRaw ? JSON.parse(metaRaw) : {};
  }
  return {};
}
__name(getFileMeta, "getFileMeta");
async function deleteFileFromR2(env, fileKey) {
  if (!env.PORTFOLIO_R2) {
    return false;
  }
  await env.PORTFOLIO_R2.delete(fileKey);
  await env.PORTFOLIO_R2.delete(`${fileKey}:meta`);
  return true;
}
__name(deleteFileFromR2, "deleteFileFromR2");
var CSS = `:root{--bg:#f3f6fb;--card:#ffffff;--accent:#3b82f6;--muted:#6b7280;--danger:#ef4444}*{box-sizing:border-box}body{font-family:Inter,system-ui,Segoe UI,Roboto,Arial,sans-serif;margin:0;background:linear-gradient(180deg,var(--bg),#eaf2ff);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}.container{width:100%;max-width:420px}.card{background:var(--card);padding:28px;border-radius:12px;box-shadow:0 6px 24px rgba(16,24,40,0.08);}h1{margin:0 0 6px;font-size:1.5rem}.lead{margin:0 0 18px;color:var(--muted);font-size:0.95rem}.login-form{display:flex;flex-direction:column;gap:10px}label{font-size:0.85rem;color:var(--muted)}input[type="email"],input[type="password"]{padding:12px 14px;border:1px solid #e6edf8;border-radius:8px;font-size:1rem}.options{display:flex;justify-content:space-between;align-items:center;margin-top:4px}.checkbox{font-size:0.9rem;color:var(--muted)}.forgot{font-size:0.9rem;color:var(--accent);text-decoration:none}.message{min-height:20px;font-size:0.9rem;color:var(--danger);margin-top:6px}.btn{margin-top:8px;padding:12px;border-radius:10px;border:0;background:var(--accent);color:#fff;font-weight:600;cursor:pointer}.signup{margin-top:14px;text-align:center;color:var(--muted);font-size:0.9rem}.signup a{color:var(--accent);text-decoration:none}@media (max-width:420px){.card{padding:20px}}`;
var LOGIN_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login</title><style>${CSS}</style></head><body><main class="container"><section class="card" aria-labelledby="login-heading"><h1 id="login-heading">Access Code</h1><p class="lead">Enter your 4-digit code to continue</p><form id="login-form" class="login-form" novalidate><label for="code">4-Digit Code</label><input id="code" name="code" type="password" inputmode="numeric" pattern="[0-9]{4}" maxlength="4" required autocomplete="off" placeholder="\u2022\u2022\u2022\u2022"><div id="message" role="status" class="message" aria-live="polite"></div><button type="submit" class="btn">Unlock</button></form></section></main><script>${`document.addEventListener('DOMContentLoaded', ()=>{const form = document.getElementById('login-form');const code = document.getElementById('code');const message = document.getElementById('message');function showMessage(text, isError=true){message.textContent = text;message.style.color = isError ? getComputedStyle(document.documentElement).getPropertyValue('--danger') : '#0f5132';}function validate(){const inputCode = code.value.trim();if (!inputCode) { showMessage('Please enter the 4-digit code.'); code.focus(); return false; }if (!/^\\d{4}$/.test(inputCode)) { showMessage('Code must be exactly 4 digits.'); code.focus(); return false; }return true;}form.addEventListener('submit', async (ev)=>{ev.preventDefault();message.textContent = '';if (!validate()) return;const btn = form.querySelector('.btn');btn.disabled = true;btn.textContent = 'Verifying...';try {const response = await fetch('/api/login', {method: 'POST',headers: { 'Content-Type': 'application/json' },body: JSON.stringify({ code: code.value.trim() })});const result = await response.json();if (result.ok) {window.location.href = '/pages/main.html';} else {showMessage(result.error || 'Login failed.');code.value = '';code.focus();}} catch (error) {showMessage('Network error, try again.');console.error(error);} finally {btn.disabled = false;btn.textContent = 'Unlock';}});});`}<\/script></body></html>`;
var worker_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    if (path === "/api/version" && request.method === "GET") {
      return new Response(JSON.stringify({
        hash: env.GIT_HASH || "unknown",
        message: env.GIT_MESSAGE || "production",
        timestamp: env.GIT_TIMESTAMP || (/* @__PURE__ */ new Date()).toISOString()
      }), { status: 200, headers: { "Content-Type": "application/json" } });
    }
    if (path === "/api/login" && request.method === "POST") {
      const body = await request.json().catch(() => null);
      const code = body?.code?.toString().trim();
      if (!/^\d{4}$/.test(code)) {
        return new Response(JSON.stringify({ ok: false, error: "Code must be 4 digits" }), { status: 400, headers: { "Content-Type": "application/json" } });
      }
      const users = await getAccessUsers(env);
      const matchedUser = users.find((user) => user.code === code);
      if (!matchedUser) {
        return new Response(JSON.stringify({ ok: false, error: "Invalid code" }), { status: 401, headers: { "Content-Type": "application/json" } });
      }
      await appendLoginActivity(env, request, matchedUser);
      const token = await createToken(env.SESSION_SECRET || "default-session-secret", 1800, {
        uid: matchedUser.id,
        name: matchedUser.name,
        role: normalizeRole(matchedUser.role)
      });
      const headers = new Headers({ "Content-Type": "application/json" });
      headers.append("Set-Cookie", `session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=1800`);
      return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
    }
    if (path === "/api/logout" && request.method === "POST") {
      const headers = new Headers({ "Content-Type": "application/json" });
      headers.append("Set-Cookie", "session=deleted; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0");
      return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
    }
    if (path === "/api/me" && request.method === "GET") {
      const session = await getSessionFromRequest(request, env);
      if (!session) {
        return unauthorizedResponse();
      }
      return new Response(JSON.stringify({
        ok: true,
        user: {
          id: session.uid,
          name: session.name,
          role: normalizeRole(session.role)
        }
      }), { status: 200, headers: { "Content-Type": "application/json" } });
    }
    if (path === "/api/access-users" && request.method === "GET") {
      const session = await getSessionFromRequest(request, env);
      if (!session) {
        return unauthorizedResponse();
      }
      if (!hasRole(session.role, "admin")) {
        return forbiddenResponse();
      }
      const users = await getAccessUsers(env);
      return new Response(JSON.stringify({ ok: true, users: sanitizeAccessUsersForAdmin(users) }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }
    if (path === "/api/access-users" && request.method === "POST") {
      const session = await getSessionFromRequest(request, env);
      if (!session) {
        return unauthorizedResponse();
      }
      if (!hasRole(session.role, "admin")) {
        return forbiddenResponse();
      }
      try {
        const body = await request.json().catch(() => null);
        const normalizedName = String(body?.name || "").trim();
        const normalizedCode = String(body?.code || "").trim();
        const normalizedRole = normalizeRole(body?.role);
        if (!normalizedName) {
          return new Response(JSON.stringify({ error: "Name is required" }), { status: 400, headers: { "Content-Type": "application/json" } });
        }
        if (!/^\d{4}$/.test(normalizedCode)) {
          return new Response(JSON.stringify({ error: "Code must be exactly 4 digits" }), { status: 400, headers: { "Content-Type": "application/json" } });
        }
        const users = await getAccessUsers(env);
        if (users.some((user) => user.code === normalizedCode)) {
          return new Response(JSON.stringify({ error: "Code is already in use" }), { status: 409, headers: { "Content-Type": "application/json" } });
        }
        users.push({
          id: generateUserId(),
          name: normalizedName,
          code: normalizedCode,
          role: normalizedRole
        });
        const saved = await setAccessUsers(env, users);
        return new Response(JSON.stringify({ ok: true, users: sanitizeAccessUsersForAdmin(saved) }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      } catch {
        return new Response(JSON.stringify({ error: "Failed to create user" }), { status: 500, headers: { "Content-Type": "application/json" } });
      }
    }
    if (path.startsWith("/api/access-users/") && request.method === "PUT") {
      const session = await getSessionFromRequest(request, env);
      if (!session) {
        return unauthorizedResponse();
      }
      if (!hasRole(session.role, "admin")) {
        return forbiddenResponse();
      }
      try {
        const targetId = decodeURIComponent(path.replace("/api/access-users/", "") || "");
        const body = await request.json().catch(() => null);
        const users = await getAccessUsers(env);
        const user = users.find((entry) => entry.id === targetId);
        if (!user) {
          return new Response(JSON.stringify({ error: "User not found" }), { status: 404, headers: { "Content-Type": "application/json" } });
        }
        if (body?.name !== void 0) {
          const normalizedName = String(body.name).trim();
          if (!normalizedName) {
            return new Response(JSON.stringify({ error: "Name is required" }), { status: 400, headers: { "Content-Type": "application/json" } });
          }
          user.name = normalizedName;
        }
        if (body?.code !== void 0) {
          const normalizedCode = String(body.code).trim();
          if (!/^\d{4}$/.test(normalizedCode)) {
            return new Response(JSON.stringify({ error: "Code must be exactly 4 digits" }), { status: 400, headers: { "Content-Type": "application/json" } });
          }
          if (users.some((entry) => entry.id !== targetId && entry.code === normalizedCode)) {
            return new Response(JSON.stringify({ error: "Code is already in use" }), { status: 409, headers: { "Content-Type": "application/json" } });
          }
          user.code = normalizedCode;
        }
        if (body?.role !== void 0) {
          const normalizedRole = normalizeRole(body.role);
          if (user.role === "admin" && normalizedRole !== "admin") {
            const adminCount = users.filter((entry) => entry.role === "admin").length;
            if (adminCount <= 1) {
              return new Response(JSON.stringify({ error: "At least one admin is required" }), { status: 400, headers: { "Content-Type": "application/json" } });
            }
          }
          user.role = normalizedRole;
        }
        const saved = await setAccessUsers(env, users);
        return new Response(JSON.stringify({ ok: true, users: sanitizeAccessUsersForAdmin(saved) }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      } catch {
        return new Response(JSON.stringify({ error: "Failed to update user" }), { status: 500, headers: { "Content-Type": "application/json" } });
      }
    }
    if (path.startsWith("/api/access-users/") && request.method === "DELETE") {
      const session = await getSessionFromRequest(request, env);
      if (!session) {
        return unauthorizedResponse();
      }
      if (!hasRole(session.role, "admin")) {
        return forbiddenResponse();
      }
      try {
        const targetId = decodeURIComponent(path.replace("/api/access-users/", "") || "");
        const users = await getAccessUsers(env);
        const targetIndex = users.findIndex((entry) => entry.id === targetId);
        if (targetIndex === -1) {
          return new Response(JSON.stringify({ error: "User not found" }), { status: 404, headers: { "Content-Type": "application/json" } });
        }
        if (session.uid === targetId) {
          return new Response(JSON.stringify({ error: "You cannot delete your own account" }), { status: 400, headers: { "Content-Type": "application/json" } });
        }
        const targetUser = users[targetIndex];
        if (targetUser.role === "admin") {
          const adminCount = users.filter((entry) => entry.role === "admin").length;
          if (adminCount <= 1) {
            return new Response(JSON.stringify({ error: "At least one admin is required" }), { status: 400, headers: { "Content-Type": "application/json" } });
          }
        }
        users.splice(targetIndex, 1);
        const saved = await setAccessUsers(env, users);
        return new Response(JSON.stringify({ ok: true, users: sanitizeAccessUsersForAdmin(saved) }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      } catch {
        return new Response(JSON.stringify({ error: "Failed to delete user" }), { status: 500, headers: { "Content-Type": "application/json" } });
      }
    }
    if (path === "/api/change-code" && request.method === "POST") {
      const session = await getSessionFromRequest(request, env);
      if (!session) {
        return unauthorizedResponse();
      }
      try {
        const body = await request.json().catch(() => null);
        const { currentCode, newCode, confirmCode } = body || {};
        if (!currentCode || !newCode || !confirmCode) {
          return new Response(JSON.stringify({ error: "All fields are required" }), { status: 400, headers: { "Content-Type": "application/json" } });
        }
        if (!/^\d{4}$/.test(currentCode) || !/^\d{4}$/.test(newCode)) {
          return new Response(JSON.stringify({ error: "Codes must be exactly 4 digits" }), { status: 400, headers: { "Content-Type": "application/json" } });
        }
        if (newCode !== confirmCode) {
          return new Response(JSON.stringify({ error: "New codes do not match" }), { status: 400, headers: { "Content-Type": "application/json" } });
        }
        const users = await getAccessUsers(env);
        const currentUser = users.find((user) => user.id === session.uid);
        if (!currentUser) {
          return new Response(JSON.stringify({ error: "User not found" }), { status: 401, headers: { "Content-Type": "application/json" } });
        }
        if (currentCode !== currentUser.code) {
          return new Response(JSON.stringify({ error: "Current code is incorrect" }), { status: 401, headers: { "Content-Type": "application/json" } });
        }
        currentUser.code = newCode;
        await setAccessUsers(env, users);
        return new Response(JSON.stringify({ ok: true, message: "Access code updated successfully" }), { status: 200, headers: { "Content-Type": "application/json" } });
      } catch (error) {
        return new Response(JSON.stringify({ error: "Failed to process request" }), { status: 500, headers: { "Content-Type": "application/json" } });
      }
    }
    if (path === "/api/login-activity" && request.method === "GET") {
      const session = await getSessionFromRequest(request, env);
      if (!session) {
        return unauthorizedResponse();
      }
      if (!hasRole(session.role, "admin")) {
        return new Response(JSON.stringify({ error: "Forbidden" }), { status: 403, headers: { "Content-Type": "application/json" } });
      }
      if (!env.PORTFOLIO_KV) {
        return new Response(JSON.stringify({ ok: true, activity: [] }), { status: 200, headers: { "Content-Type": "application/json" } });
      }
      const raw = await env.PORTFOLIO_KV.get(LOGIN_ACTIVITY_KEY);
      if (!raw) {
        return new Response(JSON.stringify({ ok: true, activity: [] }), { status: 200, headers: { "Content-Type": "application/json" } });
      }
      try {
        const activity = JSON.parse(raw);
        return new Response(JSON.stringify({ ok: true, activity: Array.isArray(activity) ? activity : [] }), { status: 200, headers: { "Content-Type": "application/json" } });
      } catch {
        return new Response(JSON.stringify({ ok: true, activity: [] }), { status: 200, headers: { "Content-Type": "application/json" } });
      }
    }
    if (path === "/api/delete-password" && request.method === "POST") {
      const session = await getSessionFromRequest(request, env);
      if (!session) {
        return unauthorizedResponse();
      }
      if (!hasRole(session.role, "admin")) {
        return forbiddenResponse();
      }
      try {
        const body = await request.json().catch(() => null);
        const { currentPassword, newPassword, confirmPassword } = body || {};
        if (!newPassword || !confirmPassword) {
          return new Response(JSON.stringify({ error: "New password and confirmation are required" }), { status: 400, headers: { "Content-Type": "application/json" } });
        }
        if (newPassword !== confirmPassword) {
          return new Response(JSON.stringify({ error: "New passwords do not match" }), { status: 400, headers: { "Content-Type": "application/json" } });
        }
        if (String(newPassword).trim().length < 4) {
          return new Response(JSON.stringify({ error: "Delete password must be at least 4 characters" }), { status: 400, headers: { "Content-Type": "application/json" } });
        }
        const existingHash = await getDeletePasswordHash(env);
        if (existingHash) {
          if (!currentPassword) {
            return new Response(JSON.stringify({ error: "Current delete password is required" }), { status: 400, headers: { "Content-Type": "application/json" } });
          }
          const validCurrent = await verifyPasswordSecure(String(currentPassword), existingHash, env.DELETE_PASSWORD_PEPPER || "");
          if (!validCurrent) {
            return new Response(JSON.stringify({ error: "Current delete password is incorrect" }), { status: 401, headers: { "Content-Type": "application/json" } });
          }
        }
        await setDeletePasswordHash(env, String(newPassword));
        return new Response(JSON.stringify({ ok: true, message: "Delete password updated successfully" }), { status: 200, headers: { "Content-Type": "application/json" } });
      } catch {
        return new Response(JSON.stringify({ error: "Failed to process request" }), { status: 500, headers: { "Content-Type": "application/json" } });
      }
    }
    if (path === "/api/data-all" && request.method === "DELETE") {
      const session = await getSessionFromRequest(request, env);
      if (!session) {
        return unauthorizedResponse();
      }
      if (!hasRole(session.role, "admin")) {
        return forbiddenResponse();
      }
      try {
        const body = await request.json().catch(() => null);
        const password = body?.password;
        const existingHash = await getDeletePasswordHash(env);
        if (!existingHash) {
          return new Response(JSON.stringify({ error: "Delete password is not set yet" }), { status: 400, headers: { "Content-Type": "application/json" } });
        }
        if (!password) {
          return new Response(JSON.stringify({ error: "Delete password is required" }), { status: 400, headers: { "Content-Type": "application/json" } });
        }
        const validDeletePassword = await verifyPasswordSecure(String(password), existingHash, env.DELETE_PASSWORD_PEPPER || "");
        if (!validDeletePassword) {
          return new Response(JSON.stringify({ error: "Invalid delete password" }), { status: 401, headers: { "Content-Type": "application/json" } });
        }
        if (!String(existingHash).startsWith("pbkdf2$")) {
          await setDeletePasswordHash(env, String(password));
        }
        const data = await loadPortfolioData(env);
        const keys = [...collectFileKeys(data?.folders || [])];
        if (env.PORTFOLIO_R2) {
          await Promise.all(keys.flatMap((key) => [
            env.PORTFOLIO_R2.delete(key),
            env.PORTFOLIO_R2.delete(`${key}:meta`)
          ]));
        }
        if (env.PORTFOLIO_KV) {
          await Promise.all(keys.flatMap((key) => [
            env.PORTFOLIO_KV.delete(key),
            env.PORTFOLIO_KV.delete(`${key}:meta`)
          ]));
        }
        await savePortfolioData(env, []);
        return new Response(JSON.stringify({ ok: true, deletedFiles: keys.length }), { status: 200, headers: { "Content-Type": "application/json" } });
      } catch {
        return new Response(JSON.stringify({ error: "Failed to process request" }), { status: 500, headers: { "Content-Type": "application/json" } });
      }
    }
    if (path === "/api/session") {
      const session = await getSessionFromRequest(request, env);
      return new Response(JSON.stringify({ authenticated: !!session }), { status: 200, headers: { "Content-Type": "application/json" } });
    }
    if (path === "/api/data" && request.method === "GET") {
      const session = await getSessionFromRequest(request, env);
      if (!session) {
        return unauthorizedResponse();
      }
      try {
        const data = await loadPortfolioData(env);
        return new Response(JSON.stringify(data), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      } catch (error) {
        return new Response(JSON.stringify({ error: "Failed to load data" }), {
          status: 500,
          headers: { "Content-Type": "application/json" }
        });
      }
    }
    if (path === "/api/data" && request.method === "POST") {
      const session = await getSessionFromRequest(request, env);
      if (!session) {
        return unauthorizedResponse();
      }
      if (!hasRole(session.role, "editor")) {
        return forbiddenResponse();
      }
      try {
        const body = await request.json().catch(() => ({}));
        const folders = Array.isArray(body?.folders) ? body.folders : [];
        await savePortfolioData(env, folders);
        return new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      } catch (error) {
        return new Response(JSON.stringify({ error: "Failed to save data" }), {
          status: 500,
          headers: { "Content-Type": "application/json" }
        });
      }
    }
    if (path === "/api/upload" && request.method === "POST") {
      const session = await getSessionFromRequest(request, env);
      if (!session) {
        return unauthorizedResponse();
      }
      if (!hasRole(session.role, "editor")) {
        return forbiddenResponse();
      }
      try {
        if (!env.PORTFOLIO_KV && !env.PORTFOLIO_R2) {
          return new Response(JSON.stringify({ error: "Storage not configured" }), {
            status: 500,
            headers: { "Content-Type": "application/json" }
          });
        }
        const formData = await request.formData();
        const file = formData.get("file");
        if (!file || typeof file === "string") {
          return new Response(JSON.stringify({ error: "No file provided" }), {
            status: 400,
            headers: { "Content-Type": "application/json" }
          });
        }
        const buffer = await file.arrayBuffer();
        const mimeType = file.type || "application/octet-stream";
        const safeName = sanitizeFileName(file.name);
        const fileKey = `${FILE_KEY_PREFIX}${crypto.randomUUID()}-${safeName}`;
        await saveFile(env, fileKey, buffer, {
          contentType: mimeType,
          fileName: file.name || "upload"
        });
        return new Response(JSON.stringify({
          ok: true,
          url: `/api/files/${encodeURIComponent(fileKey)}`,
          name: file.name || "upload"
        }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      } catch (error) {
        return new Response(JSON.stringify({ error: "Upload failed" }), {
          status: 500,
          headers: { "Content-Type": "application/json" }
        });
      }
    }
    if (path.startsWith("/api/files/") && request.method === "GET") {
      const session = await getSessionFromRequest(request, env);
      if (!session) {
        return unauthorizedResponse();
      }
      if (!env.PORTFOLIO_KV && !env.PORTFOLIO_R2) {
        return new Response("Storage not configured", { status: 500 });
      }
      const encodedKey = path.replace("/api/files/", "");
      const fileKey = decodeURIComponent(encodedKey);
      const file = await getFile(env, fileKey);
      if (!file) {
        return new Response("File not found", { status: 404 });
      }
      const meta = await getFileMeta(env, fileKey);
      const headers = new Headers({
        "Content-Type": meta.contentType || "application/octet-stream",
        "Cache-Control": "private, max-age=3600"
      });
      if (meta.fileName) {
        headers.set("Content-Disposition", `inline; filename="${meta.fileName.replace(/"/g, "")}"`);
      }
      return new Response(file.buffer, { status: 200, headers });
    }
    if (path.startsWith("/api/files/") && request.method === "DELETE") {
      const session = await getSessionFromRequest(request, env);
      if (!session) {
        return unauthorizedResponse();
      }
      if (!hasRole(session.role, "editor")) {
        return forbiddenResponse();
      }
      const encodedKey = path.replace("/api/files/", "");
      const fileKey = decodeURIComponent(encodedKey);
      try {
        const deletedFromR2 = await deleteFileFromR2(env, fileKey);
        return new Response(JSON.stringify({ ok: true, deletedFromR2 }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      } catch (error) {
        return new Response(JSON.stringify({ error: "Failed to delete file from R2" }), {
          status: 500,
          headers: { "Content-Type": "application/json" }
        });
      }
    }
    if (path === "/api/files/batch-delete" && request.method === "POST") {
      const session = await getSessionFromRequest(request, env);
      if (!session) {
        return unauthorizedResponse();
      }
      if (!hasRole(session.role, "editor")) {
        return forbiddenResponse();
      }
      const body = await request.json().catch(() => ({}));
      const fileKeys = Array.isArray(body?.fileKeys) ? body.fileKeys.filter((k) => typeof k === "string" && k.startsWith(FILE_KEY_PREFIX)) : [];
      if (fileKeys.length === 0) {
        return new Response(JSON.stringify({ ok: true, deleted: 0, deletedFromR2: false }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      try {
        if (!env.PORTFOLIO_R2) {
          return new Response(JSON.stringify({ ok: true, deleted: 0, deletedFromR2: false }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        const uniqueKeys = [...new Set(fileKeys)];
        await Promise.all(uniqueKeys.map(async (key) => {
          await env.PORTFOLIO_R2.delete(key);
          await env.PORTFOLIO_R2.delete(`${key}:meta`);
        }));
        return new Response(JSON.stringify({ ok: true, deleted: uniqueKeys.length, deletedFromR2: true }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      } catch (error) {
        return new Response(JSON.stringify({ error: "Failed to batch delete files from R2" }), {
          status: 500,
          headers: { "Content-Type": "application/json" }
        });
      }
    }
    if (path === "/pages/main.html") {
      const session = await getSessionFromRequest(request, env);
      if (!session) {
        return Response.redirect(`${new URL(request.url).origin}/`, 302);
      }
      return fetch("https://raw.githubusercontent.com/" + (env.GITHUB_REPO || "your/repo") + "/main/pages/main.html").then((r) => r.ok ? r.text() : null).then((html) => {
        if (html) {
          return new Response(html, { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } });
        } else {
          return new Response("main.html not found", { status: 404 });
        }
      });
    }
    if (path === "/pages/settings.html") {
      const session = await getSessionFromRequest(request, env);
      if (!session) {
        return Response.redirect(`${new URL(request.url).origin}/`, 302);
      }
      return fetch("https://raw.githubusercontent.com/" + (env.GITHUB_REPO || "your/repo") + "/main/pages/settings.html").then((r) => r.ok ? r.text() : null).then((html) => {
        if (html) {
          return new Response(html, { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } });
        } else {
          return new Response("settings.html not found", { status: 404 });
        }
      });
    }
    if (path === "/" || path === "/index.html") {
      return fetch("https://raw.githubusercontent.com/" + (env.GITHUB_REPO || "your/repo") + "/main/index.html").then((r) => r.ok ? r.text() : null).then((html) => {
        if (html) {
          return new Response(html, { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } });
        } else {
          return new Response("index.html not found", { status: 404 });
        }
      });
    }
    if (path === "/styles.css") {
      return fetch("https://raw.githubusercontent.com/" + (env.GITHUB_REPO || "your/repo") + "/main/styles.css").then((r) => r.ok ? r.text() : null).then((css) => {
        if (css) {
          return new Response(css, { status: 200, headers: { "Content-Type": "text/css; charset=utf-8" } });
        } else {
          return new Response("styles.css not found", { status: 404 });
        }
      });
    }
    if (path === "/script.js") {
      return fetch("https://raw.githubusercontent.com/" + (env.GITHUB_REPO || "your/repo") + "/main/script.js").then((r) => r.ok ? r.text() : null).then((js) => {
        if (js) {
          return new Response(js, { status: 200, headers: { "Content-Type": "application/javascript; charset=utf-8" } });
        } else {
          return new Response("script.js not found", { status: 404 });
        }
      });
    }
    return new Response("Not Found", { status: 404 });
  }
};
export {
  worker_default as default
};
//# sourceMappingURL=worker.js.map
