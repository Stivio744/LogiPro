// Outils communs aux fonctions serveur du site LogiPro (aucune dépendance npm).
const crypto = require('node:crypto');

const R_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const R_TOK = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
const P = 'lpw:'; // préfixe des clés : la base peut être partagée avec un autre projet
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || 'chilanceratiarson@gmail.com').trim().toLowerCase();

// ---------- Redis (Upstash REST) ----------
async function redis(...cmd) {
  if (!R_URL || !R_TOK) throw Object.assign(new Error('Base de données non configurée'), { code: 'NODB' });
  const r = await fetch(R_URL, { method: 'POST', headers: { Authorization: 'Bearer ' + R_TOK }, body: JSON.stringify(cmd) });
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j.result;
}
async function pipe(cmds) {
  if (!cmds.length) return [];
  if (!R_URL || !R_TOK) throw Object.assign(new Error('Base de données non configurée'), { code: 'NODB' });
  const r = await fetch(R_URL.replace(/\/$/, '') + '/pipeline', { method: 'POST', headers: { Authorization: 'Bearer ' + R_TOK }, body: JSON.stringify(cmds) });
  const j = await r.json();
  return j.map(x => x.result);
}

// ---------- HTTP ----------
function send(res, code, data) {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Robots-Tag', 'noindex');
  res.end(data === undefined ? '' : JSON.stringify(data));
}
async function body(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') { try { return JSON.parse(req.body); } catch { return {}; } }
  const chunks = [];
  for await (const c of req) chunks.push(c);
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); } catch { return {}; }
}
function cookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function setCookie(res, name, value, maxAge) {
  const c = `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
  const prev = res.getHeader('Set-Cookie');
  res.setHeader('Set-Cookie', prev ? [].concat(prev, c) : c);
}
function ip(req) { return String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '').split(',')[0].trim(); }
function geo(req) {
  let city = req.headers['x-vercel-ip-city'] || '';
  try { city = decodeURIComponent(city); } catch {}
  return { c: req.headers['x-vercel-ip-country'] || '', ci: city };
}
function ua(req) {
  const s = String(req.headers['user-agent'] || '');
  const dv = /iPad|Tablet/i.test(s) ? 'Tablette' : /Mobi|Android|iPhone/i.test(s) ? 'Téléphone' : 'Ordinateur';
  const os = /Windows/i.test(s) ? 'Windows' : /iPhone|iPad|iOS/i.test(s) ? 'iOS' : /Android/i.test(s) ? 'Android' : /Mac OS/i.test(s) ? 'macOS' : /Linux/i.test(s) ? 'Linux' : 'Autre';
  const b = /Edg\//.test(s) ? 'Edge' : /OPR\/|Opera/.test(s) ? 'Opera' : /SamsungBrowser/.test(s) ? 'Samsung' : /Firefox\//.test(s) ? 'Firefox' : /Chrome\//.test(s) ? 'Chrome' : /Safari\//.test(s) ? 'Safari' : 'Autre';
  return { raw: s, dv, os, b, bot: /bot|crawl|spider|slurp|preview|headless|lighthouse|monitor|curl|wget|python|vercel/i.test(s) };
}
const hash = (s, n = 16) => crypto.createHash('sha256').update(s).digest('hex').slice(0, n);
const today = () => new Date().toISOString().slice(0, 10);
const clip = (v, n) => String(v ?? '').trim().slice(0, n);

// ---------- Mot de passe & session ----------
function verifyPassword(password, stored) {
  // format : pbkdf2$<itérations>$<sel base64>$<empreinte base64>
  const [kind, iter, salt, h] = String(stored || '').split('$');
  if (kind !== 'pbkdf2' || !iter || !salt || !h) return false;
  const want = Buffer.from(h, 'base64');
  const got = crypto.pbkdf2Sync(String(password), Buffer.from(salt, 'base64'), +iter, want.length, 'sha256');
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}
function makePassword(password) {
  const salt = crypto.randomBytes(16);
  const h = crypto.pbkdf2Sync(String(password), salt, 210000, 32, 'sha256');
  return `pbkdf2$210000$${salt.toString('base64')}$${h.toString('base64')}`;
}
const secret = () => crypto.createHash('sha256').update('lpw-admin|' + R_TOK + '|' + (process.env.ADMIN_PASS_HASH || '')).digest();
function signSession(deviceId, days = 30) {
  const p = Buffer.from(JSON.stringify({ d: deviceId, e: Date.now() + days * 864e5 })).toString('base64url');
  return p + '.' + crypto.createHmac('sha256', secret()).update(p).digest('base64url');
}
async function session(req) {
  const t = cookies(req).lp_adm;
  if (!t || !R_TOK) return null;
  const [p, s] = t.split('.');
  const want = crypto.createHmac('sha256', secret()).update(p || '').digest('base64url');
  if (!s || s.length !== want.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(want))) return null;
  let data;
  try { data = JSON.parse(Buffer.from(p, 'base64url').toString()); } catch { return null; }
  if (!data.d || data.e < Date.now()) return null;
  const dev = await redis('HGET', P + 'adm:dev', data.d);
  return dev ? { deviceId: data.d, device: JSON.parse(dev) } : null; // appareil retiré = session refusée
}

// ---------- E-mail (Brevo, facultatif) ----------
const mailReady = () => !!process.env.BREVO_API_KEY;
async function sendMail({ to, toName, subject, text, replyTo }) {
  if (!mailReady()) throw Object.assign(new Error('Envoi d’e-mails non configuré'), { code: 'NOMAIL' });
  const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const html = `<div style="font-family:Arial,sans-serif;font-size:15px;line-height:1.6;color:#0f1b33">${esc(text).replace(/\n/g, '<br>')}</div>`;
  const r = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: { 'api-key': process.env.BREVO_API_KEY, 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({
      sender: { email: process.env.BREVO_SENDER || ADMIN_EMAIL, name: process.env.BREVO_SENDER_NAME || 'LogiPro' },
      to: [{ email: to, name: toName || to }],
      replyTo: { email: replyTo || ADMIN_EMAIL },
      subject, textContent: text, htmlContent: html
    })
  });
  if (!r.ok) throw new Error('Brevo : ' + (await r.text()).slice(0, 200));
  return true;
}

module.exports = { P, ADMIN_EMAIL, redis, pipe, send, body, cookies, setCookie, ip, geo, ua, hash, today, clip, verifyPassword, makePassword, signSession, session, mailReady, sendMail, dbReady: () => !!(R_URL && R_TOK) };
