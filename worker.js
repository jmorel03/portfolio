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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

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
      return fetch(request);
    }

    return fetch(request);
  }
};
