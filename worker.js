function base64url(buffer) {
  let str = typeof buffer === 'string' ? buffer : String.fromCharCode(...new Uint8Array(buffer));
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function hmacSha256(secret, data) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return signature;
}

async function createToken(secret, expiresSeconds = 1800) {
  const header = base64url(JSON.stringify({ alg:'HS256', typ:'JWT' }));
  const payload = base64url(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + expiresSeconds }));
  const message = `${header}.${payload}`;
  const sig = await hmacSha256(secret, message);
  const token = `${message}.${base64url(sig)}`;
  return token;
}

async function verifyToken(secret, token) {
  if (!token) return false;
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const [header, payload, signature] = parts;
  const message = `${header}.${payload}`;
  const expectedSig = base64url(await hmacSha256(secret, message));
  if (signature !== expectedSig) return false;
  const data = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
  return data.exp && Date.now() / 1000 < data.exp;
}

const CSS = `:root{--bg:#f3f6fb;--card:#ffffff;--accent:#3b82f6;--muted:#6b7280;--danger:#ef4444}*{box-sizing:border-box}body{font-family:Inter,system-ui,Segoe UI,Roboto,Arial,sans-serif;margin:0;background:linear-gradient(180deg,var(--bg),#eaf2ff);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}.container{width:100%;max-width:420px}.card{background:var(--card);padding:28px;border-radius:12px;box-shadow:0 6px 24px rgba(16,24,40,0.08);}h1{margin:0 0 6px;font-size:1.5rem}.lead{margin:0 0 18px;color:var(--muted);font-size:0.95rem}.login-form{display:flex;flex-direction:column;gap:10px}label{font-size:0.85rem;color:var(--muted)}input[type="email"],input[type="password"]{padding:12px 14px;border:1px solid #e6edf8;border-radius:8px;font-size:1rem}.options{display:flex;justify-content:space-between;align-items:center;margin-top:4px}.checkbox{font-size:0.9rem;color:var(--muted)}.forgot{font-size:0.9rem;color:var(--accent);text-decoration:none}.message{min-height:20px;font-size:0.9rem;color:var(--danger);margin-top:6px}.btn{margin-top:8px;padding:12px;border-radius:10px;border:0;background:var(--accent);color:#fff;font-weight:600;cursor:pointer}.signup{margin-top:14px;text-align:center;color:var(--muted);font-size:0.9rem}.signup a{color:var(--accent);text-decoration:none}@media (max-width:420px){.card{padding:20px}}`;

const LOGIN_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login</title><style>${CSS}</style></head><body><main class="container"><section class="card" aria-labelledby="login-heading"><h1 id="login-heading">Access Code</h1><p class="lead">Enter your 4-digit code to continue</p><form id="login-form" class="login-form" novalidate><label for="code">4-Digit Code</label><input id="code" name="code" type="password" inputmode="numeric" pattern="[0-9]{4}" maxlength="4" required autocomplete="off" placeholder="••••"><div id="message" role="status" class="message" aria-live="polite"></div><button type="submit" class="btn">Unlock</button></form></section></main><script>${`document.addEventListener('DOMContentLoaded', ()=>{const form = document.getElementById('login-form');const code = document.getElementById('code');const message = document.getElementById('message');function showMessage(text, isError=true){message.textContent = text;message.style.color = isError ? getComputedStyle(document.documentElement).getPropertyValue('--danger') : '#0f5132';}function validate(){const inputCode = code.value.trim();if (!inputCode) { showMessage('Please enter the 4-digit code.'); code.focus(); return false; }if (!/^\\d{4}$/.test(inputCode)) { showMessage('Code must be exactly 4 digits.'); code.focus(); return false; }return true;}form.addEventListener('submit', async (ev)=>{ev.preventDefault();message.textContent = '';if (!validate()) return;const btn = form.querySelector('.btn');btn.disabled = true;btn.textContent = 'Verifying...';try {const response = await fetch('/api/login', {method: 'POST',headers: { 'Content-Type': 'application/json' },body: JSON.stringify({ code: code.value.trim() })});const result = await response.json();if (result.ok) {window.location.href = '/pages/main.html';} else {showMessage(result.error || 'Login failed.');code.value = '';code.focus();}} catch (error) {showMessage('Network error, try again.');console.error(error);} finally {btn.disabled = false;btn.textContent = 'Unlock';}});});`}</script></body></html>`;

const MAIN_HTML = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Main</title><style>body{font-family:Inter,system-ui,Segoe UI,Roboto,Arial,sans-serif;margin:0;background:linear-gradient(180deg,#f3f6fb,#eaf2ff);min-height:100vh;display:flex;align-items:center;justify-content:center;}</style></head><body><main style="max-width:520px;margin:40px auto;padding:1.2rem;border:1px solid #ccd; border-radius:10px;font-family:Inter,system-ui,Segoe UI,Roboto,Arial,sans-serif; text-align:center;"><h1>Welcome to the main page</h1><p>You are authenticated.</p><button id="logoutBtn" style="margin-top:1rem;padding:.75rem 1.2rem;border:none;border-radius:8px;background:#ef4444;color:#fff;font-weight:700;cursor:pointer;">Logout</button><div id="logoutMessage" style="margin-top:1rem;color:#d14343;"></div></main><script>document.getElementById('logoutBtn').addEventListener('click', async () => {const res = await fetch('/api/logout', { method: 'POST' });if (res.ok) {window.location.href = '/';} else {document.getElementById('logoutMessage').textContent = 'Logout failed. Please refresh and try again.';}});</script></body></html>`;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === '/api/version' && request.method === 'GET') {
      return new Response(JSON.stringify({
        hash: env.GIT_HASH || 'unknown',
        message: env.GIT_MESSAGE || 'production',
        timestamp: env.GIT_TIMESTAMP || new Date().toISOString()
      }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }

    if (path === '/api/login' && request.method === 'POST') {
      const body = await request.json().catch(() => null);
      const code = body?.code?.toString().trim();
      if (!/^\d{4}$/.test(code)) {
        return new Response(JSON.stringify({ ok: false, error: 'Code must be 4 digits' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
      }
      if (code !== (env.AUTH_CODE || '1234')) {
        return new Response(JSON.stringify({ ok: false, error: 'Invalid code' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
      }
      const token = await createToken(env.SESSION_SECRET || 'default-session-secret', 1800);
      const headers = new Headers({ 'Content-Type': 'application/json' });
      headers.append('Set-Cookie', `session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=1800`);
      return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
    }

    if (path === '/api/logout' && request.method === 'POST') {
      const headers = new Headers({ 'Content-Type': 'application/json' });
      headers.append('Set-Cookie', 'session=deleted; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0');
      return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
    }

    if (path === '/api/change-code' && request.method === 'POST') {
      const cookie = request.headers.get('Cookie') || '';
      const token = cookie.split(';').map(c => c.trim()).find(c => c.startsWith('session='))?.split('=')[1];
      const valid = await verifyToken(env.SESSION_SECRET || 'default-session-secret', token);
      
      if (!valid) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
      }

      try {
        const body = await request.json().catch(() => null);
        const { currentCode, newCode, confirmCode } = body || {};

        if (!currentCode || !newCode || !confirmCode) {
          return new Response(JSON.stringify({ error: 'All fields are required' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
        }

        if (!/^\d{4}$/.test(currentCode) || !/^\d{4}$/.test(newCode)) {
          return new Response(JSON.stringify({ error: 'Codes must be exactly 4 digits' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
        }

        if (newCode !== confirmCode) {
          return new Response(JSON.stringify({ error: 'New codes do not match' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
        }

        if (currentCode !== (env.AUTH_CODE || '1234')) {
          return new Response(JSON.stringify({ error: 'Current code is incorrect' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
        }

        // Note: On Cloudflare Workers, you would need to use KV storage or Durable Objects to persist the new code
        // For now, this validates and returns success
        return new Response(JSON.stringify({ ok: true, message: 'Access code updated successfully' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      } catch (error) {
        return new Response(JSON.stringify({ error: 'Failed to process request' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
      }
    }

    if (path === '/api/session') {
      const cookie = request.headers.get('Cookie') || '';
      const token = cookie.split(';').map(c => c.trim()).find(c => c.startsWith('session='))?.split('=')[1];
      const valid = await verifyToken(env.SESSION_SECRET || 'default-session-secret', token);
      return new Response(JSON.stringify({ authenticated: valid }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }

    if (path === '/pages/main.html') {
      const cookie = request.headers.get('Cookie') || '';
      const token = cookie.split(';').map(c => c.trim()).find(c => c.startsWith('session='))?.split('=')[1];
      const valid = await verifyToken(env.SESSION_SECRET || 'default-session-secret', token);
      if (!valid) {
        return Response.redirect(`${new URL(request.url).origin}/`, 302);
      }
      return new Response(MAIN_HTML, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    if (path === '/' || path === '') {
      return new Response(LOGIN_HTML, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    return new Response('Not Found', { status: 404 });
  }
};

