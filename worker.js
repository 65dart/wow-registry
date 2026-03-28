// =============================================================
//  Warhammer Old World Registry — Cloudflare Worker
//  File: worker.js
//
//  Deploy steps:
//   1. npm install -g wrangler
//   2. wrangler login
//   3. wrangler d1 create wow-registry
//   4. Add the D1 binding to wrangler.toml (see bottom of file)
//   5. wrangler d1 execute wow-registry --file=schema.sql --remote
//   6. wrangler deploy
//
//  wrangler.toml should contain:
//  -------------------------------------------------------
//  name = "wow-registry-api"
//  main = "worker.js"
//  compatibility_date = "2024-01-01"
//
//  [[d1_databases]]
//  binding      = "DB"
//  database_name = "wow-registry"
//  database_id  = "<your-database-id-from-step-3>"
//  -------------------------------------------------------
//
//  Set your Pages site URL in the ALLOWED_ORIGIN secret:
//    wrangler secret put ALLOWED_ORIGIN
//    > https://your-site.pages.dev
// =============================================================

// ── Tiny bcrypt-compatible password hashing using SubtleCrypto ──
// Workers don't have bcrypt, so we use PBKDF2 (secure, built-in)
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key  = await deriveKey(password, salt);
  const saltHex = [...salt].map(b => b.toString(16).padStart(2,'0')).join('');
  const keyHex  = [...new Uint8Array(key)].map(b => b.toString(16).padStart(2,'0')).join('');
  return `pbkdf2:${saltHex}:${keyHex}`;
}

async function verifyPassword(password, stored) {
  const [, saltHex, keyHex] = stored.split(':');
  const salt = new Uint8Array(saltHex.match(/../g).map(h => parseInt(h, 16)));
  const key  = await deriveKey(password, salt);
  const newHex = [...new Uint8Array(key)].map(b => b.toString(16).padStart(2,'0')).join('');
  return newHex === keyHex;
}

async function deriveKey(password, salt) {
  const enc      = new TextEncoder();
  const keyMat   = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  return crypto.subtle.deriveBits({ name:'PBKDF2', salt, iterations:100000, hash:'SHA-256' }, keyMat, 256);
}

function randomToken(bytes = 32) {
  return [...crypto.getRandomValues(new Uint8Array(bytes))]
    .map(b => b.toString(16).padStart(2,'0')).join('');
}

function sessionExpiry(days = 30) {
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d.toISOString();
}

// ── CORS helpers ──
function corsHeaders(origin, env) {
  const allowed = env.ALLOWED_ORIGIN || '*';
  return {
    'Access-Control-Allow-Origin':  allowed === '*' ? '*' : (origin === allowed ? origin : ''),
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Credentials': 'true',
  };
}

function json(data, status = 200, origin = '', env = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin, env) }
  });
}

function err(msg, status = 400, origin = '', env = {}) {
  return json({ error: msg }, status, origin, env);
}

// ── Auth middleware — reads Bearer token from Authorization header ──
async function authenticate(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return null;

  const row = await env.DB.prepare(
    `SELECT s.user_id, s.expires_at, u.username, u.email
     FROM sessions s JOIN users u ON s.user_id = u.id
     WHERE s.token = ?`
  ).bind(token).first();

  if (!row) return null;
  if (new Date(row.expires_at) < new Date()) {
    await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
    return null;
  }
  return row;
}

// ── Main fetch handler ──
export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const url    = new URL(request.url);
    const path   = url.pathname;
    const method = request.method;

    // Preflight
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin, env) });
    }

    // ── POST /api/signup ──
    if (path === '/api/signup' && method === 'POST') {
      const { username, email, password } = await request.json().catch(() => ({}));

      if (!username || !email || !password)
        return err('Username, email and password are required.', 400, origin, env);
      if (username.length < 3 || username.length > 30)
        return err('Username must be 3–30 characters.', 400, origin, env);
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
        return err('Invalid email address.', 400, origin, env);
      if (password.length < 8)
        return err('Password must be at least 8 characters.', 400, origin, env);

      const existing = await env.DB.prepare(
        'SELECT id FROM users WHERE username = ? OR email = ?'
      ).bind(username, email).first();
      if (existing) return err('Username or email already in use.', 409, origin, env);

      const hash = await hashPassword(password);
      const result = await env.DB.prepare(
        'INSERT INTO users (username, email, password) VALUES (?, ?, ?)'
      ).bind(username, email.toLowerCase(), hash).run();

      const userId = result.meta.last_row_id;
      const token  = randomToken();
      const expiry = sessionExpiry(30);
      await env.DB.prepare(
        'INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)'
      ).bind(token, userId, expiry).run();

      return json({ token, username, email: email.toLowerCase(), userId }, 201, origin, env);
    }

    // ── POST /api/login ──
    if (path === '/api/login' && method === 'POST') {
      const { email, password } = await request.json().catch(() => ({}));

      if (!email || !password)
        return err('Email and password are required.', 400, origin, env);

      const user = await env.DB.prepare(
        'SELECT id, username, email, password FROM users WHERE email = ?'
      ).bind(email.toLowerCase()).first();

      if (!user || !(await verifyPassword(password, user.password)))
        return err('Invalid email or password.', 401, origin, env);

      const token  = randomToken();
      const expiry = sessionExpiry(30);
      await env.DB.prepare(
        'INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)'
      ).bind(token, user.id, expiry).run();

      return json({ token, username: user.username, email: user.email, userId: user.id }, 200, origin, env);
    }

    // ── POST /api/logout ──
    if (path === '/api/logout' && method === 'POST') {
      const auth = request.headers.get('Authorization') || '';
      const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
      if (token) await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
      return json({ ok: true }, 200, origin, env);
    }

    // ── All routes below require authentication ──
    const user = await authenticate(request, env);
    if (!user) return err('Unauthorised. Please log in.', 401, origin, env);

    // ── GET /api/armies — load all armies for this user ──
    if (path === '/api/armies' && method === 'GET') {
      const rows = await env.DB.prepare(
        'SELECT id, data, created_at, updated_at FROM armies WHERE user_id = ? ORDER BY created_at DESC'
      ).bind(user.user_id).all();

      const armies = (rows.results || []).map(r => ({
        ...JSON.parse(r.data),
        _dbId: r.id,
        _createdAt: r.created_at,
      }));

      return json({ armies }, 200, origin, env);
    }

    // ── POST /api/armies — save a new army ──
    if (path === '/api/armies' && method === 'POST') {
      const army = await request.json().catch(() => null);
      if (!army) return err('Invalid army data.', 400, origin, env);

      const result = await env.DB.prepare(
        'INSERT INTO armies (user_id, data) VALUES (?, ?)'
      ).bind(user.user_id, JSON.stringify(army)).run();

      return json({ ok: true, dbId: result.meta.last_row_id }, 201, origin, env);
    }

    // ── PUT /api/armies/:id — update an existing army ──
    const putMatch = path.match(/^\/api\/armies\/(\d+)$/);
    if (putMatch && method === 'PUT') {
      const dbId = parseInt(putMatch[1]);
      const army = await request.json().catch(() => null);
      if (!army) return err('Invalid army data.', 400, origin, env);

      // Ensure it belongs to this user
      const existing = await env.DB.prepare(
        'SELECT id FROM armies WHERE id = ? AND user_id = ?'
      ).bind(dbId, user.user_id).first();
      if (!existing) return err('Army not found.', 404, origin, env);

      await env.DB.prepare(
        "UPDATE armies SET data = ?, updated_at = datetime('now') WHERE id = ?"
      ).bind(JSON.stringify(army), dbId).run();

      return json({ ok: true }, 200, origin, env);
    }

    // ── DELETE /api/armies/:id — delete an army ──
    const delMatch = path.match(/^\/api\/armies\/(\d+)$/);
    if (delMatch && method === 'DELETE') {
      const dbId = parseInt(delMatch[1]);

      const existing = await env.DB.prepare(
        'SELECT id FROM armies WHERE id = ? AND user_id = ?'
      ).bind(dbId, user.user_id).first();
      if (!existing) return err('Army not found.', 404, origin, env);

      await env.DB.prepare('DELETE FROM armies WHERE id = ?').bind(dbId).run();
      return json({ ok: true }, 200, origin, env);
    }

    // ── GET /api/me — current user info ──
    if (path === '/api/me' && method === 'GET') {
      return json({ username: user.username, email: user.email, userId: user.user_id }, 200, origin, env);
    }

    return err('Not found.', 404, origin, env);
  }
};
