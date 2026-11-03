/**
 * 3D План · сервер сповіщень для @fishka_3d_bot (Cloudflare Worker).
 *
 * Mini App надсилає сюди розклад подій користувача (POST /sync), а cron
 * щохвилини розсилає ті, час яких настав, звичайними повідомленнями бота.
 * Telegram показує їх як плашку сповіщення, навіть коли застосунок згорнутий.
 *
 * Потрібно в налаштуваннях Worker:
 *   - D1 binding з назвою DB
 *   - секрет BOT_TOKEN (токен бота від @BotFather)
 *   - Cron trigger: "* * * * *" (щохвилини)
 */

const MAX_EVENTS = 300;              // подій на користувача за раз
const LATE_LIMIT_MS = 15 * 60000;    // пропущені довше за 15 хв не надсилаємо
const KEEP_MS = 2 * 86400000;        // старі записи чистимо через 2 доби
const INITDATA_MAX_AGE_S = 7 * 86400;

export default {
  async fetch(request, env) {
    const cors = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    };
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    const url = new URL(request.url);
    if (request.method === 'GET') {
      const ready = !!(env.BOT_TOKEN && env.DB);
      return new Response(ready ? '3D План: сервер сповіщень працює' : '3D План: потрібні DB і BOT_TOKEN', {
        status: ready ? 200 : 500, headers: { ...cors, 'Content-Type': 'text/plain; charset=utf-8' }
      });
    }
    if (request.method !== 'POST' || url.pathname !== '/sync') return json({ ok: false, error: 'not_found' }, 404, cors);
    if (!env.BOT_TOKEN || !env.DB) return json({ ok: false, error: 'server_not_configured' }, 500, cors);

    let body;
    try { body = JSON.parse(await request.text()); } catch { return json({ ok: false, error: 'bad_json' }, 400, cors); }
    const user = await verifyInitData(String(body.initData || ''), env.BOT_TOKEN);
    if (!user || !user.id) return json({ ok: false, error: 'unauthorized' }, 401, cors);

    const now = Date.now();
    const events = (Array.isArray(body.events) ? body.events : [])
      .filter(e => e && typeof e.id === 'string' && typeof e.text === 'string' && Number.isFinite(e.at)
        && e.at > now - 60000 && e.at < now + 3 * 86400000)
      .slice(0, MAX_EVENTS)
      .map(e => ({ id: e.id.slice(0, 120), at: Math.round(e.at), text: e.text.slice(0, 500) }));

    await ensureSchema(env.DB);
    // The new list replaces everything not yet sent; ids already sent stay sent (no repeats).
    const stmts = [env.DB.prepare('DELETE FROM events WHERE uid = ?1 AND sent = 0').bind(user.id)];
    for (const e of events) {
      stmts.push(env.DB.prepare('INSERT OR IGNORE INTO events (uid, id, at, text, sent) VALUES (?1, ?2, ?3, ?4, 0)')
        .bind(user.id, e.id, e.at, e.text));
    }
    await env.DB.batch(stmts);
    return json({ ok: true, scheduled: events.length }, 200, cors);
  },

  async scheduled(controller, env, ctx) {
    ctx.waitUntil(sendDue(env));
  }
};

export async function sendDue(env, now = Date.now()) {
  if (!env.BOT_TOKEN || !env.DB) return 0;
  await ensureSchema(env.DB);
  const { results } = await env.DB
    .prepare('SELECT uid, id, text FROM events WHERE sent = 0 AND at <= ?1 AND at > ?2 ORDER BY at LIMIT 100')
    .bind(now + 20000, now - LATE_LIMIT_MS)
    .all();
  let sent = 0;
  for (const r of results || []) {
    // Claim the row first, so two overlapping runs never send the same message twice.
    const claim = await env.DB.prepare('UPDATE events SET sent = 1 WHERE uid = ?1 AND id = ?2 AND sent = 0').bind(r.uid, r.id).run();
    if (!claim.meta || claim.meta.changes !== 1) continue;
    if (await tgSend(env.BOT_TOKEN, r.uid, r.text)) sent++;
  }
  await env.DB.prepare('DELETE FROM events WHERE at < ?1').bind(now - KEEP_MS).run();
  return sent;
}

let schemaReady = false;
async function ensureSchema(db) {
  if (schemaReady) return;
  await db.prepare(`CREATE TABLE IF NOT EXISTS events (
    uid INTEGER NOT NULL, id TEXT NOT NULL, at INTEGER NOT NULL, text TEXT NOT NULL,
    sent INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (uid, id))`).run();
  await db.prepare('CREATE INDEX IF NOT EXISTS events_due ON events (sent, at)').run();
  schemaReady = true;
}

async function tgSend(token, chatId, text) {
  try {
    const r = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text })
    });
    return r.ok;
  } catch {
    return false;
  }
}

/* Telegram Mini App initData check: https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app */
export async function verifyInitData(initData, botToken) {
  if (!initData) return null;
  const params = new URLSearchParams(initData);
  const hash = params.get('hash');
  if (!hash) return null;
  params.delete('hash');
  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${k}=${v}`)
    .join('\n');
  const enc = new TextEncoder();
  const secret = await hmac(enc.encode('WebAppData'), enc.encode(botToken));
  const calc = toHex(await hmac(secret, enc.encode(dataCheckString)));
  if (!timingSafeEqual(calc, hash)) return null;
  const authDate = Number(params.get('auth_date'));
  if (!Number.isFinite(authDate) || Date.now() / 1000 - authDate > INITDATA_MAX_AGE_S) return null;
  try { return JSON.parse(params.get('user') || 'null'); } catch { return null; }
}

async function hmac(keyBytes, msgBytes) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, msgBytes));
}
const toHex = bytes => [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
const json = (obj, status, headers) => new Response(JSON.stringify(obj), {
  status, headers: { ...headers, 'Content-Type': 'application/json; charset=utf-8' }
});
