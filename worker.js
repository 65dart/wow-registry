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

// ── createArmyRecords — saves both players' battle to the main armies table ──
async function createArmyRecords(env, evt, pairing, result) {
  try {
    const today = new Date().toISOString().split('T')[0];

    // Fetch participant data for both players using participant row id
    const p1 = await env.DB.prepare(
      'SELECT * FROM event_participants WHERE id = ?'
    ).bind(pairing.player1_id).first();
    const p2 = pairing.player2_id ? await env.DB.prepare(
      'SELECT * FROM event_participants WHERE id = ?'
    ).bind(pairing.player2_id).first() : null;

    // Determine results for each player
    const p1result = result === 'player1' ? 'Win' : result === 'player2' ? 'Loss' : 'Draw';
    const p2result = result === 'player2' ? 'Win' : result === 'player1' ? 'Loss' : 'Draw';

    // Helper to build opponent display string (faction if known, else name)
    const oppDisplay = (p) => p ? (p.faction || p.username || '') : '';

    // Create army record for p1 if they are a registered user
    if (p1 && p1.user_id) {
      const p1units = (() => { try { return JSON.parse(p1.units||'[]'); } catch(e){ return []; } })();
      const army1 = {
        player:    p1.username,
        name:      p1.army_name || `${p1.username}'s Army`,
        faction:   p1.faction   || '',
        points:    evt.points_limit || 0,
        oppPoints: evt.points_limit || 0,
        result:    p1result,
        opponent:  oppDisplay(p2),
        event:     evt.name,
        notes:     `Round ${pairing.round} — ${evt.name}${p2 ? ` vs ${p2.username}` : ''}`,
        units:     p1units,
        oppUnits:  [],
        date:      today,
        likes:     0,
      };
      await env.DB.prepare(
        'INSERT INTO armies (user_id, data) VALUES (?, ?)'
      ).bind(p1.user_id, JSON.stringify(army1)).run();
    }

    // Create army record for p2 if they are a registered user
    if (p2 && p2.user_id) {
      const p2units = (() => { try { return JSON.parse(p2.units||'[]'); } catch(e){ return []; } })();
      const army2 = {
        player:    p2.username,
        name:      p2.army_name || `${p2.username}'s Army`,
        faction:   p2.faction   || '',
        points:    evt.points_limit || 0,
        oppPoints: evt.points_limit || 0,
        result:    p2result,
        opponent:  oppDisplay(p1),
        event:     evt.name,
        notes:     `Round ${pairing.round} — ${evt.name}${p1 ? ` vs ${p1.username}` : ''}`,
        units:     p2units,
        oppUnits:  [],
        date:      today,
        likes:     0,
      };
      await env.DB.prepare(
        'INSERT INTO armies (user_id, data) VALUES (?, ?)'
      ).bind(p2.user_id, JSON.stringify(army2)).run();
    }
  } catch(e) {
    console.error('createArmyRecords error:', e);
  }
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

    // ── POST /api/visit — record a unique visitor ──
    if (path === '/api/visit' && method === 'POST') {
      const { visitor_id } = await request.json().catch(() => ({}));
      if (!visitor_id) return json({ ok: false }, 400, origin, env);
      try {
        await env.DB.prepare(
          'INSERT OR IGNORE INTO visitors (visitor_id) VALUES (?)'
        ).bind(visitor_id).run();
      } catch(e) {}
      const row = await env.DB.prepare('SELECT COUNT(*) as c FROM visitors').first();
      return json({ ok: true, count: row.c }, 200, origin, env);
    }

    // ── GET /api/visit — get visitor count ──
    if (path === '/api/visit' && method === 'GET') {
      const row = await env.DB.prepare('SELECT COUNT(*) as c FROM visitors').first();
      return json({ count: row.c }, 200, origin, env);
    }

    // ── POST /api/signup ──
    if (path === '/api/signup' && method === 'POST') {
      const { username, email, password } = await request.json().catch(() => ({}));

      if (!username || !email || !password)
        return err('Username, email and password are required.', 400, origin, env);
      if (username.length < 3 || username.length > 30)
        return err('Username must be 3–30 characters.', 400, origin, env);

      // Reserved usernames — cannot be registered by new users
      const RESERVED = ['admin','administrator','mod','moderator'];
      if (RESERVED.includes(username.toLowerCase()))
        return err('That username is reserved and cannot be registered.', 400, origin, env);
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

    // ── GET /api/armies/all — all users' armies for community view ──
    if (path === '/api/armies/all' && method === 'GET') {
      const rows = await env.DB.prepare(
        `SELECT a.id, a.data, a.created_at, u.username
         FROM armies a
         JOIN users u ON a.user_id = u.id
         ORDER BY a.created_at DESC`
      ).all();

      const armies = (rows.results || []).map(r => ({
        ...JSON.parse(r.data),
        _dbId: r.id,
        _createdAt: r.created_at,
        _owner: r.username,
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

    // ── POST /api/armies/:id/like — toggle like on any army ──
    const likeMatch = path.match(/^\/api\/armies\/(\d+)\/like$/);
    if (likeMatch && method === 'POST') {
      const dbId = parseInt(likeMatch[1]);
      const { likes } = await request.json().catch(() => ({}));
      if (likes === undefined) return err('likes value required.', 400, origin, env);

      const existing = await env.DB.prepare('SELECT id, data FROM armies WHERE id = ?').bind(dbId).first();
      if (!existing) return err('Army not found.', 404, origin, env);

      const data = JSON.parse(existing.data || '{}');
      data.likes = Math.max(0, parseInt(likes) || 0);
      await env.DB.prepare("UPDATE armies SET data = ?, updated_at = datetime('now') WHERE id = ?")
        .bind(JSON.stringify(data), dbId).run();

      return json({ ok: true, likes: data.likes }, 200, origin, env);
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
      const PRIVILEGED = ['admin','administrator','mod','moderator'];
      const isPrivileged = PRIVILEGED.includes((user.username||'').toLowerCase());

      // Privileged users can delete any army; others only their own
      const existing = isPrivileged
        ? await env.DB.prepare('SELECT id FROM armies WHERE id = ?').bind(dbId).first()
        : await env.DB.prepare('SELECT id FROM armies WHERE id = ? AND user_id = ?').bind(dbId, user.user_id).first();

      if (!existing) return err('Army not found.', 404, origin, env);

      await env.DB.prepare('DELETE FROM armies WHERE id = ?').bind(dbId).run();
      return json({ ok: true }, 200, origin, env);
    }

    // ── GET /api/me — current user info ──
    if (path === '/api/me' && method === 'GET') {
      return json({ username: user.username, email: user.email, userId: user.user_id }, 200, origin, env);
    }

    // ── POST /api/change-password ──
    if (path === '/api/change-password' && method === 'POST') {
      const { current_password, new_password } = await request.json().catch(() => ({}));
      if (!current_password || !new_password)
        return err('Current and new password are required.', 400, origin, env);
      if (new_password.length < 8)
        return err('New password must be at least 8 characters.', 400, origin, env);

      // Fetch the user's current hashed password
      const userData = await env.DB.prepare(
        'SELECT id, password FROM users WHERE id = ?'
      ).bind(user.user_id).first();
      if (!userData) return err('User not found.', 404, origin, env);

      // Verify current password
      if (!(await verifyPassword(current_password, userData.password)))
        return err('Current password is incorrect.', 401, origin, env);

      // Hash and save new password
      const newHash = await hashPassword(new_password);
      await env.DB.prepare('UPDATE users SET password = ? WHERE id = ?')
        .bind(newHash, user.user_id).run();

      return json({ ok: true }, 200, origin, env);
    }

    // ── GET /api/admin/stats — admin statistics (privileged only) ──
    if (path === '/api/admin/stats' && method === 'GET') {
      const PRIVILEGED = ['admin','administrator','mod','moderator'];
      if (!PRIVILEGED.includes((user.username||'').toLowerCase()))
        return err('Forbidden.', 403, origin, env);

      const totalUsers   = await env.DB.prepare('SELECT COUNT(*) as c FROM users').first();
      const totalArmies  = await env.DB.prepare('SELECT COUNT(*) as c FROM armies').first();
      const totalEvents  = await env.DB.prepare('SELECT COUNT(*) as c FROM events').first();
      const activeEvents = await env.DB.prepare("SELECT COUNT(*) as c FROM events WHERE status='active'").first();
      const newToday     = await env.DB.prepare("SELECT COUNT(*) as c FROM users WHERE created_at >= date('now')").first();
      const newThisWeek  = await env.DB.prepare("SELECT COUNT(*) as c FROM users WHERE created_at >= date('now','-7 days')").first();

      return json({
        total_users:    totalUsers.c,
        total_armies:   totalArmies.c,
        total_events:   totalEvents.c,
        active_events:  activeEvents.c,
        new_today:      newToday.c,
        new_this_week:  newThisWeek.c,
      }, 200, origin, env);
    }

    // ══════════════════════════════════════════
    //  EVENTS
    // ══════════════════════════════════════════

    // ── GET /api/events — list all events ──
    if (path === '/api/events' && method === 'GET') {
      const rows = await env.DB.prepare(
        `SELECT e.*, u.username as organiser_name,
          (SELECT COUNT(*) FROM event_participants p WHERE p.event_id = e.id) as participant_count
         FROM events e JOIN users u ON e.organiser_id = u.id
         ORDER BY e.created_at DESC`
      ).all();
      return json({ events: rows.results || [] }, 200, origin, env);
    }

    // ── POST /api/events — create event ──
    if (path === '/api/events' && method === 'POST') {
      const { name, description, pairing_system, total_rounds, points_limit, max_participants } = await request.json().catch(() => ({}));
      if (!name) return err('Event name is required.', 400, origin, env);
      const rounds  = Math.max(1, Math.min(10, parseInt(total_rounds)||3));
      const pts     = Math.max(0, parseInt(points_limit)||0);
      const maxP    = Math.max(0, parseInt(max_participants)||0);
      const result  = await env.DB.prepare(
        `INSERT INTO events (organiser_id, name, description, pairing_system, total_rounds, points_limit, max_participants)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).bind(user.user_id, name, description||'', pairing_system||'swiss', rounds, pts, maxP).run();
      return json({ ok: true, eventId: result.meta.last_row_id }, 201, origin, env);
    }

    // ── GET /api/events/:id — full event detail ──
    const evtMatch = path.match(/^\/api\/events\/(\d+)$/);
    if (evtMatch && method === 'GET') {
      const eid = parseInt(evtMatch[1]);
      const event = await env.DB.prepare(
        `SELECT e.*, u.username as organiser_name FROM events e
         JOIN users u ON e.organiser_id = u.id WHERE e.id = ?`
      ).bind(eid).first();
      if (!event) return err('Event not found.', 404, origin, env);

      const participants = await env.DB.prepare(
        `SELECT * FROM event_participants WHERE event_id = ? ORDER BY points DESC, wins DESC, battle_points DESC`
      ).bind(eid).all();

      const pairings = await env.DB.prepare(
        `SELECT * FROM event_pairings WHERE event_id = ? ORDER BY round, id`
      ).bind(eid).all();

      return json({ event, participants: participants.results||[], pairings: pairings.results||[] }, 200, origin, env);
    }

    // ── PUT /api/events/:id — update event (organiser or admin) ──
    const evtUpdateMatch = path.match(/^\/api\/events\/(\d+)\/update$/);
    if (evtUpdateMatch && method === 'PUT') {
      const eid = parseInt(evtUpdateMatch[1]);
      const evt = await env.DB.prepare('SELECT * FROM events WHERE id = ?').bind(eid).first();
      if (!evt) return err('Event not found.', 404, origin, env);
      const PRIVILEGED = ['admin','administrator','mod','moderator'];
      const isPrivileged = PRIVILEGED.includes((user.username||'').toLowerCase());
      if (evt.organiser_id !== user.user_id && !isPrivileged)
        return err('Only the organiser or an admin can update this event.', 403, origin, env);
      const { status } = await request.json().catch(() => ({}));
      if (status) await env.DB.prepare('UPDATE events SET status = ? WHERE id = ?').bind(status, eid).run();
      return json({ ok: true }, 200, origin, env);
    }

    // ── DELETE /api/events/:id/remove-participant/:pid — remove a participant ──
    const removeParticipantMatch = path.match(/^\/api\/events\/(\d+)\/remove-participant\/(\d+)$/);
    if (removeParticipantMatch && method === 'DELETE') {
      const eid = parseInt(removeParticipantMatch[1]);
      const pid = parseInt(removeParticipantMatch[2]);
      const evt = await env.DB.prepare('SELECT * FROM events WHERE id = ?').bind(eid).first();
      if (!evt) return err('Event not found.', 404, origin, env);
      const PRIVILEGED = ['admin','administrator','mod','moderator'];
      const isPrivileged = PRIVILEGED.includes((user.username||'').toLowerCase());
      if (evt.organiser_id !== user.user_id && !isPrivileged)
        return err('Only the organiser or an admin can remove participants.', 403, origin, env);
      const participant = await env.DB.prepare(
        'SELECT * FROM event_participants WHERE id = ? AND event_id = ?'
      ).bind(pid, eid).first();
      if (!participant) return err('Participant not found.', 404, origin, env);
      await env.DB.prepare('DELETE FROM event_participants WHERE id = ?').bind(pid).run();
      return json({ ok: true }, 200, origin, env);
    }

    // ── POST /api/events/:id/add-participant — organiser/admin manually adds a user or guest ──
    const addParticipantMatch = path.match(/^\/api\/events\/(\d+)\/add-participant$/);
    if (addParticipantMatch && method === 'POST') {
      const eid = parseInt(addParticipantMatch[1]);
      const evt = await env.DB.prepare('SELECT * FROM events WHERE id = ?').bind(eid).first();
      if (!evt) return err('Event not found.', 404, origin, env);

      // Only organiser or admin can manually add
      const PRIVILEGED = ['admin','administrator','mod','moderator'];
      const isPrivileged = PRIVILEGED.includes((user.username||'').toLowerCase());
      if (evt.organiser_id !== user.user_id && !isPrivileged)
        return err('Only the organiser or an admin can add participants.', 403, origin, env);

      const { username, guest_name, army_name, faction, is_guest, units } = await request.json().catch(() => ({}));

      // Check participant limit
      if (evt.max_participants > 0) {
        const count = await env.DB.prepare(
          'SELECT COUNT(*) as c FROM event_participants WHERE event_id = ?'
        ).bind(eid).first();
        if (count.c >= evt.max_participants)
          return err(`This event is full (${evt.max_participants} players maximum).`, 400, origin, env);
      }

      if (is_guest) {
        // Guest — no user account required, user_id is NULL
        if (!guest_name) return err('Guest name is required.', 400, origin, env);
        const displayName = `${guest_name} (Guest)`;
        try {
          await env.DB.prepare(
            `INSERT INTO event_participants (event_id, user_id, username, faction, army_name, units)
             VALUES (?, NULL, ?, ?, ?, ?)`
          ).bind(eid, displayName, faction||'', army_name||'', JSON.stringify(units||[])).run();
        } catch(e) {
          return err(`Could not add guest. A guest with that name may already exist.`, 409, origin, env);
        }
        return json({ ok: true }, 201, origin, env);
      } else {
        // Registered user — look up by username
        if (!username) return err('Username is required.', 400, origin, env);
        const targetUser = await env.DB.prepare(
          'SELECT id, username FROM users WHERE username = ? COLLATE NOCASE'
        ).bind(username).first();
        if (!targetUser) return err(`No user found with username "${username}".`, 404, origin, env);

        try {
          await env.DB.prepare(
            `INSERT INTO event_participants (event_id, user_id, username, faction, army_name, units)
             VALUES (?, ?, ?, ?, ?, ?)`
          ).bind(eid, targetUser.id, targetUser.username, faction||'', army_name||'', '[]').run();
        } catch(e) {
          return err(`${targetUser.username} is already in this event.`, 409, origin, env);
        }
        return json({ ok: true }, 201, origin, env);
      }
    }

    // ── POST /api/events/:id/join — join event ──
    const joinMatch = path.match(/^\/api\/events\/(\d+)\/join$/);
    if (joinMatch && method === 'POST') {
      const eid = parseInt(joinMatch[1]);
      const evt = await env.DB.prepare('SELECT * FROM events WHERE id = ?').bind(eid).first();
      if (!evt) return err('Event not found.', 404, origin, env);
      if (evt.status !== 'open') return err('This event is no longer accepting registrations.', 400, origin, env);

      // Enforce participant limit if set
      if (evt.max_participants > 0) {
        const count = await env.DB.prepare(
          'SELECT COUNT(*) as c FROM event_participants WHERE event_id = ?'
        ).bind(eid).first();
        if (count.c >= evt.max_participants)
          return err(`This event is full (${evt.max_participants} players maximum).`, 400, origin, env);
      }
      const { faction, army_name, units } = await request.json().catch(() => ({}));
      try {
        await env.DB.prepare(
          `INSERT INTO event_participants (event_id, user_id, username, faction, army_name, units)
           VALUES (?, ?, ?, ?, ?, ?)`
        ).bind(eid, user.user_id, user.username, faction||'', army_name||'', JSON.stringify(units||[])).run();
      } catch(e) {
        return err('You have already joined this event.', 409, origin, env);
      }
      return json({ ok: true }, 201, origin, env);
    }

    // ── POST /api/events/:id/leave — leave event ──
    const leaveMatch = path.match(/^\/api\/events\/(\d+)\/leave$/);
    if (leaveMatch && method === 'POST') {
      const eid = parseInt(leaveMatch[1]);
      await env.DB.prepare(
        'DELETE FROM event_participants WHERE event_id = ? AND user_id = ?'
      ).bind(eid, user.user_id).run();
      return json({ ok: true }, 200, origin, env);
    }

    // ── POST /api/events/:id/round — generate next round pairings (organiser) ──
    const roundMatch = path.match(/^\/api\/events\/(\d+)\/round$/);
    if (roundMatch && method === 'POST') {
      const eid = parseInt(roundMatch[1]);
      const evt = await env.DB.prepare('SELECT * FROM events WHERE id = ?').bind(eid).first();
      if (!evt) return err('Event not found.', 404, origin, env);
      const PRIVILEGED_RND = ['admin','administrator','mod','moderator'];
      const isPrivilegedRnd = PRIVILEGED_RND.includes((user.username||'').toLowerCase());
      if (evt.organiser_id !== user.user_id && !isPrivilegedRnd)
        return err('Only the organiser can generate pairings.', 403, origin, env);

      // Check all results from previous round are approved
      if (evt.current_round > 0) {
        const pending = await env.DB.prepare(
          `SELECT COUNT(*) as c FROM event_pairings
           WHERE event_id = ? AND round = ? AND approved = 0 AND player2_id IS NOT NULL`
        ).bind(eid, evt.current_round).first();
        if (pending.c > 0) return err('All results from the current round must be approved first.', 400, origin, env);
      }

      if (evt.current_round >= evt.total_rounds) return err('All rounds have been played.', 400, origin, env);

      const nextRound = evt.current_round + 1;
      const { pairings: manualPairings, pairing_system } = await request.json().catch(() => ({}));
      const system = pairing_system || evt.pairing_system;

      // Get participants sorted by points desc
      const participants = await env.DB.prepare(
        `SELECT * FROM event_participants WHERE event_id = ? ORDER BY points DESC, wins DESC, battle_points DESC`
      ).bind(eid).all();
      const parts = participants.results || [];
      if (parts.length < 2) return err('Need at least 2 participants.', 400, origin, env);

      let pairs = [];

      if (manualPairings && manualPairings.length) {
        // Organiser provided manual pairings
        pairs = manualPairings;
      } else if (system === 'swiss' || system === 'elimination') {
        // Swiss: pair by similar points, avoid rematches
        // Use participant row .id (not .user_id) as the unique key — supports NULL guest user_ids
        const played = new Set();
        if (nextRound > 1) {
          const prev = await env.DB.prepare(
            `SELECT player1_id, player2_id FROM event_pairings WHERE event_id = ?`
          ).bind(eid).all();
          (prev.results||[]).forEach(p => {
            if (p.player1_id && p.player2_id)
              played.add(`${Math.min(p.player1_id,p.player2_id)}_${Math.max(p.player1_id,p.player2_id)}`);
          });
        }
        const pool = [...parts];
        const used = new Set();
        for (let i = 0; i < pool.length; i++) {
          if (used.has(pool[i].id)) continue;
          let opponent = null;
          for (let j = i+1; j < pool.length; j++) {
            if (used.has(pool[j].id)) continue;
            const key = `${Math.min(pool[i].id,pool[j].id)}_${Math.max(pool[i].id,pool[j].id)}`;
            if (!played.has(key)) { opponent = pool[j]; break; }
          }
          if (!opponent) {
            for (let j = i+1; j < pool.length; j++) {
              if (!used.has(pool[j].id)) { opponent = pool[j]; break; }
            }
          }
          if (opponent) {
            pairs.push({ p1: pool[i], p2: opponent });
            used.add(pool[i].id); used.add(opponent.id);
          } else {
            // bye
            pairs.push({ p1: pool[i], p2: null });
            used.add(pool[i].id);
          }
        }
      } else if (system === 'round_robin') {
        for (let i = 0; i < parts.length - 1; i += 2) {
          pairs.push({ p1: parts[i], p2: parts[i+1] || null });
        }
        if (parts.length % 2 !== 0) pairs.push({ p1: parts[parts.length-1], p2: null });
      } else {
        pairs = parts.map((p,i) => ({ p1: p, p2: parts[i+1]||null }));
      }

      // Insert pairings — use participant row id as player references, not user_id
      for (const pair of pairs) {
        await env.DB.prepare(
          `INSERT INTO event_pairings (event_id, round, player1_id, player2_id, player1_name, player2_name)
           VALUES (?, ?, ?, ?, ?, ?)`
        ).bind(eid, nextRound, pair.p1.id, pair.p2?.id||null, pair.p1.username, pair.p2?.username||'BYE').run();
        // Auto-approve byes
        if (!pair.p2) {
          await env.DB.prepare(
            `UPDATE event_pairings SET result='player1', approved=1 WHERE event_id=? AND round=? AND player1_id=? AND player2_id IS NULL`
          ).bind(eid, nextRound, pair.p1.id).run();
          await env.DB.prepare(
            `UPDATE event_participants SET wins=wins+1, points=points+3 WHERE id=?`
          ).bind(pair.p1.id).run();
        }
      }

      await env.DB.prepare(`UPDATE events SET current_round=?, status='active' WHERE id=?`).bind(nextRound, eid).run();
      return json({ ok: true, round: nextRound }, 200, origin, env);
    }

    // ── POST /api/events/:id/result — player submits their result ──
    const resultMatch = path.match(/^\/api\/events\/(\d+)\/result$/);
    if (resultMatch && method === 'POST') {
      const eid = parseInt(resultMatch[1]);
      const { pairing_id, result: res, battle_points } = await request.json().catch(() => ({}));
      if (!pairing_id || !res) return err('pairing_id and result required.', 400, origin, env);

      const pairing = await env.DB.prepare('SELECT * FROM event_pairings WHERE id = ? AND event_id = ?').bind(pairing_id, eid).first();
      if (!pairing) return err('Pairing not found.', 404, origin, env);
      if (pairing.approved) return err('Result already approved.', 400, origin, env);

      // Look up current user's participant row id
      const myPart = await env.DB.prepare(
        'SELECT id FROM event_participants WHERE event_id = ? AND user_id = ?'
      ).bind(eid, user.user_id).first();

      // Store submission — player1_id/player2_id now reference participant row id
      if (myPart && pairing.player1_id === myPart.id) {
        await env.DB.prepare('UPDATE event_pairings SET player1_submitted=?, player1_points=? WHERE id=?').bind(res, battle_points||null, pairing_id).run();
      } else if (myPart && pairing.player2_id === myPart.id) {
        await env.DB.prepare('UPDATE event_pairings SET player2_submitted=?, player2_points=? WHERE id=?').bind(res, battle_points||null, pairing_id).run();
      } else {
        return err('You are not a participant in this pairing.', 403, origin, env);
      }

      // Re-fetch pairing to check if both submissions now agree
      const updated = await env.DB.prepare('SELECT * FROM event_pairings WHERE id = ?').bind(pairing_id).first();
      const autoApproved = updated.player1_submitted && updated.player2_submitted &&
                           updated.player1_submitted === updated.player2_submitted;

      if (autoApproved) {
        const agreedResult = updated.player1_submitted;
        await env.DB.prepare('UPDATE event_pairings SET result=?, approved=1 WHERE id=?').bind(agreedResult, pairing_id).run();

        // Update standings
        const evt = await env.DB.prepare('SELECT * FROM events WHERE id = ?').bind(eid).first();
        if (agreedResult === 'player1') {
          await env.DB.prepare(`UPDATE event_participants SET wins=wins+1, points=points+3, battle_points=battle_points+? WHERE id=?`).bind(updated.player1_points||0, pairing.player1_id).run();
          await env.DB.prepare(`UPDATE event_participants SET losses=losses+1, battle_points=battle_points+? WHERE id=?`).bind(updated.player2_points||0, pairing.player2_id).run();
        } else if (agreedResult === 'player2') {
          await env.DB.prepare(`UPDATE event_participants SET losses=losses+1, battle_points=battle_points+? WHERE id=?`).bind(updated.player1_points||0, pairing.player1_id).run();
          await env.DB.prepare(`UPDATE event_participants SET wins=wins+1, points=points+3, battle_points=battle_points+? WHERE id=?`).bind(updated.player2_points||0, pairing.player2_id).run();
        } else {
          await env.DB.prepare(`UPDATE event_participants SET draws=draws+1, points=points+1, battle_points=battle_points+? WHERE id=?`).bind(updated.player1_points||0, pairing.player1_id).run();
          await env.DB.prepare(`UPDATE event_participants SET draws=draws+1, points=points+1, battle_points=battle_points+? WHERE id=?`).bind(updated.player2_points||0, pairing.player2_id).run();
        }

        // Save army records to main armies table
        await createArmyRecords(env, evt, pairing, agreedResult);

        // Check if all pairings in round are approved — if last round, complete event
        const pending = await env.DB.prepare(
          `SELECT COUNT(*) as c FROM event_pairings WHERE event_id=? AND round=? AND approved=0 AND player2_id IS NOT NULL`
        ).bind(eid, evt.current_round).first();
        if (pending.c === 0 && evt.current_round >= evt.total_rounds) {
          await env.DB.prepare(`UPDATE events SET status='complete' WHERE id=?`).bind(eid).run();
        }

        return json({ ok: true, autoApproved: true }, 200, origin, env);
      }

      return json({ ok: true, autoApproved: false }, 200, origin, env);
    }

    // ── PUT /api/events/:id/result/:pid — organiser approves/sets result ──
    const approveMatch = path.match(/^\/api\/events\/(\d+)\/result\/(\d+)$/);
    if (approveMatch && method === 'PUT') {
      const eid = parseInt(approveMatch[1]);
      const pid = parseInt(approveMatch[2]);
      const evt = await env.DB.prepare('SELECT * FROM events WHERE id = ?').bind(eid).first();
      if (!evt) return err('Event not found.', 404, origin, env);
      const PRIVILEGED_APR = ['admin','administrator','mod','moderator'];
      const isPrivilegedApr = PRIVILEGED_APR.includes((user.username||'').toLowerCase());
      if (evt.organiser_id !== user.user_id && !isPrivilegedApr)
        return err('Only the organiser can approve results.', 403, origin, env);

      const { result: res, player1_points, player2_points } = await request.json().catch(() => ({}));
      if (!['player1','player2','draw'].includes(res)) return err('Invalid result.', 400, origin, env);

      const pairing = await env.DB.prepare('SELECT * FROM event_pairings WHERE id = ? AND event_id = ?').bind(pid, eid).first();
      if (!pairing) return err('Pairing not found.', 404, origin, env);
      if (pairing.approved) return err('Result already approved.', 400, origin, env);

      await env.DB.prepare('UPDATE event_pairings SET result=?, approved=1, player1_points=?, player2_points=? WHERE id=?')
        .bind(res, player1_points||pairing.player1_points||null, player2_points||pairing.player2_points||null, pid).run();

      // Update standings — player1_id/player2_id reference participant row id
      const p1pts = player1_points || pairing.player1_points || 0;
      const p2pts = player2_points || pairing.player2_points || 0;
      if (res === 'player1') {
        await env.DB.prepare(`UPDATE event_participants SET wins=wins+1, points=points+3, battle_points=battle_points+? WHERE id=?`).bind(p1pts, pairing.player1_id).run();
        await env.DB.prepare(`UPDATE event_participants SET losses=losses+1, battle_points=battle_points+? WHERE id=?`).bind(p2pts, pairing.player2_id).run();
      } else if (res === 'player2') {
        await env.DB.prepare(`UPDATE event_participants SET losses=losses+1, battle_points=battle_points+? WHERE id=?`).bind(p1pts, pairing.player1_id).run();
        await env.DB.prepare(`UPDATE event_participants SET wins=wins+1, points=points+3, battle_points=battle_points+? WHERE id=?`).bind(p2pts, pairing.player2_id).run();
      } else {
        await env.DB.prepare(`UPDATE event_participants SET draws=draws+1, points=points+1, battle_points=battle_points+? WHERE id=?`).bind(p1pts, pairing.player1_id).run();
        await env.DB.prepare(`UPDATE event_participants SET draws=draws+1, points=points+1, battle_points=battle_points+? WHERE id=?`).bind(p2pts, pairing.player2_id).run();
      }

      // Save army records to main armies table
      await createArmyRecords(env, evt, pairing, res);

      // Check if all pairings in round are approved — if so and last round, complete event
      const pending = await env.DB.prepare(
        `SELECT COUNT(*) as c FROM event_pairings WHERE event_id=? AND round=? AND approved=0 AND player2_id IS NOT NULL`
      ).bind(eid, evt.current_round).first();
      if (pending.c === 0 && evt.current_round >= evt.total_rounds) {
        await env.DB.prepare(`UPDATE events SET status='complete' WHERE id=?`).bind(eid).run();
      }

      return json({ ok: true }, 200, origin, env);
    }

    // ── DELETE /api/events/:id — delete event (organiser or admin) ──
    const evtDelMatch = path.match(/^\/api\/events\/(\d+)\/delete$/);
    if (evtDelMatch && method === 'DELETE') {
      const eid = parseInt(evtDelMatch[1]);
      const evt = await env.DB.prepare('SELECT * FROM events WHERE id = ?').bind(eid).first();
      if (!evt) return err('Event not found.', 404, origin, env);
      const PRIVILEGED = ['admin','administrator','mod','moderator'];
      const isPrivileged = PRIVILEGED.includes((user.username||'').toLowerCase());
      if (evt.organiser_id !== user.user_id && !isPrivileged)
        return err('Only the organiser or an admin can delete this event.', 403, origin, env);
      await env.DB.prepare('DELETE FROM events WHERE id = ?').bind(eid).run();
      return json({ ok: true }, 200, origin, env);
    }

    return err('Not found.', 404, origin, env);
  }
};
