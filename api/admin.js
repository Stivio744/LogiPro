// Interface admin : connexion limitée aux appareils enregistrés, visites, demandes, réponses par e-mail.
const crypto = require('node:crypto');
const L = require('./_lib');

const STATUTS = ['nouvelle', 'en cours', 'répondue', 'démo planifiée', 'client', 'archivée'];
const maxDevices = async () => +(await L.redis('GET', L.P + 'adm:max')) || 2;

async function login(req, res) {
  const b = await L.body(req);
  const fk = L.P + 'adm:fail:' + L.hash(L.ip(req));
  if (+(await L.redis('GET', fk)) >= 5) return L.send(res, 429, { error: 'Trop d’essais. Réessayez dans 15 minutes.' });
  const stored = (await L.redis('GET', L.P + 'adm:pass')) || process.env.ADMIN_PASS_HASH;
  if (!stored) return L.send(res, 503, { error: 'Mot de passe administrateur non configuré sur le serveur (ADMIN_PASS_HASH).' });
  const okUser = String(b.email || '').trim().toLowerCase() === L.ADMIN_EMAIL;
  if (!okUser || !L.verifyPassword(b.password || '', stored)) {
    await L.pipe([['INCR', fk], ['EXPIRE', fk, 900]]);
    return L.send(res, 401, { error: 'E-mail ou mot de passe incorrect.' });
  }
  await L.redis('DEL', fk);

  const u = L.ua(req), g = L.geo(req);
  let id = L.cookies(req).lp_dev;
  let dev = id && await L.redis('HGET', L.P + 'adm:dev', id);
  if (!dev) {
    const n = await L.redis('HLEN', L.P + 'adm:dev');
    const max = await maxDevices();
    if (n >= max) return L.send(res, 403, { error: `Appareil non autorisé : ${n} appareil(s) déjà enregistré(s) sur ${max}. Retirez-en un depuis un appareil autorisé (Paramètres).` });
    id = crypto.randomBytes(16).toString('hex');
    dev = { name: L.clip(b.deviceName, 40) || `${u.dv} · ${u.os}`, dv: u.dv, os: u.os, b: u.b, created: Date.now() };
  } else dev = JSON.parse(dev);
  dev.last = Date.now(); dev.c = g.c; dev.ci = g.ci;
  await L.redis('HSET', L.P + 'adm:dev', id, JSON.stringify(dev));
  L.setCookie(res, 'lp_dev', id, 10 * 365 * 86400);
  L.setCookie(res, 'lp_adm', L.signSession(id), 30 * 86400);
  L.send(res, 200, { ok: true });
}

async function stats(req, res) {
  const days = Math.min(90, Math.max(1, +req.query.days || 30));
  const list = [];
  for (let i = days - 1; i >= 0; i--) list.push(new Date(Date.now() - i * 864e5).toISOString().slice(0, 10));
  const [views, logRaw, total, ids] = await L.pipe([
    ['HMGET', L.P + 'v:days', ...list],
    ['LRANGE', L.P + 'v:log', 0, 4999],
    ['GET', L.P + 'v:total'],
    ['LRANGE', L.P + 'd:ids', 0, -1]
  ]);
  const uniq = await L.pipe(list.map(d => ['PFCOUNT', L.P + 'v:u:' + d]));
  const uniqAll = await L.redis('PFCOUNT', ...list.map(d => L.P + 'v:u:' + d));
  const since = Date.now() - days * 864e5;
  const log = (logRaw || []).map(x => JSON.parse(x)).filter(e => e.t >= since);
  const top = (k, f = e => e[k]) => Object.entries(log.reduce((a, e) => { const v = f(e) || '—'; a[v] = (a[v] || 0) + 1; return a; }, {})).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const recs = await demandes(ids || []);
  L.send(res, 200, {
    days: list.map((d, i) => ({ d, v: +(views[i] || 0), u: +(uniq[i] || 0) })),
    total: +(total || 0), uniques: uniqAll || 0, views: log.length,
    pays: top('c'), villes: top('ci', e => e.ci ? `${e.ci} (${e.c})` : ''), pages: top('p'), sources: top('r', e => e.r || 'Accès direct'),
    appareils: top('dv'), navigateurs: top('b'),
    demandes: { total: recs.length, nouvelles: recs.filter(r => r.statut === 'nouvelle').length, periode: recs.filter(r => r.t >= since).length }
  });
}

async function demandes(ids) {
  if (!ids.length) return [];
  const raw = await L.redis('MGET', ...ids.map(i => L.P + 'd:' + i));
  return raw.filter(Boolean).map(x => JSON.parse(x));
}
async function getDemande(id) {
  const raw = await L.redis('GET', L.P + 'd:' + id);
  if (!raw) throw Object.assign(new Error('Demande introuvable'), { status: 404 });
  return JSON.parse(raw);
}
const saveDemande = d => L.redis('SET', L.P + 'd:' + d.id, JSON.stringify(d));

async function update(req, res) {
  const b = await L.body(req);
  const d = await getDemande(b.id);
  if (b.statut !== undefined) {
    if (!STATUTS.includes(b.statut)) return L.send(res, 400, { error: 'Statut inconnu' });
    if (b.statut !== d.statut) d.hist.push({ t: Date.now(), a: `Statut : ${d.statut} → ${b.statut}` });
    d.statut = b.statut;
  }
  if (b.note !== undefined) { d.note = L.clip(b.note, 5000); }
  if (b.replied) d.hist.push({ t: Date.now(), a: 'Réponse envoyée depuis Gmail', s: L.clip(b.subject, 200), m: L.clip(b.message, 5000) });
  await saveDemande(d);
  L.send(res, 200, d);
}

async function reply(req, res) {
  const b = await L.body(req);
  const d = await getDemande(b.id);
  const subject = L.clip(b.subject, 200), message = L.clip(b.message, 10000);
  if (!subject || !message) return L.send(res, 400, { error: 'Objet et message obligatoires' });
  await L.sendMail({ to: d.email, toName: d.nom, subject, text: message });
  d.hist.push({ t: Date.now(), a: 'Réponse envoyée depuis LogiPro', s: subject, m: message });
  if (['nouvelle', 'en cours'].includes(d.statut)) { d.hist.push({ t: Date.now(), a: `Statut : ${d.statut} → répondue` }); d.statut = 'répondue'; }
  await saveDemande(d);
  L.send(res, 200, d);
}

async function remove(req, res) {
  const { id } = await L.body(req);
  await L.pipe([['DEL', L.P + 'd:' + id], ['LREM', L.P + 'd:ids', 0, id]]);
  L.send(res, 200, { ok: true });
}

async function devices(req, res, s) {
  const all = await L.redis('HGETALL', L.P + 'adm:dev') || [];
  const list = [];
  for (let i = 0; i < all.length; i += 2) list.push({ id: all[i], ...JSON.parse(all[i + 1]), current: all[i] === s.deviceId });
  L.send(res, 200, { list: list.sort((a, b) => a.created - b.created), max: await maxDevices() });
}

async function settings(req, res, s) {
  const b = await L.body(req);
  if (b.revoke) await L.redis('HDEL', L.P + 'adm:dev', b.revoke);
  if (b.rename && b.name) {
    const raw = await L.redis('HGET', L.P + 'adm:dev', b.rename);
    if (raw) await L.redis('HSET', L.P + 'adm:dev', b.rename, JSON.stringify({ ...JSON.parse(raw), name: L.clip(b.name, 40) }));
  }
  if (b.max) await L.redis('SET', L.P + 'adm:max', Math.min(5, Math.max(1, +b.max)));
  if (b.newPassword) {
    const stored = (await L.redis('GET', L.P + 'adm:pass')) || process.env.ADMIN_PASS_HASH;
    if (!L.verifyPassword(b.currentPassword || '', stored)) return L.send(res, 401, { error: 'Mot de passe actuel incorrect' });
    if (String(b.newPassword).length < 10) return L.send(res, 400, { error: 'Au moins 10 caractères' });
    await L.redis('SET', L.P + 'adm:pass', L.makePassword(b.newPassword));
  }
  return devices(req, res, s);
}

module.exports = async (req, res) => {
  const a = req.query.a;
  try {
    if (!L.dbReady()) return L.send(res, 503, { error: 'Base de données non configurée (intégration Upstash Redis à ajouter sur Vercel).', setup: true });
    if (a === 'login' && req.method === 'POST') return await login(req, res);
    const s = await L.session(req);
    if (a === 'me') return L.send(res, 200, s ? { ok: true, email: L.ADMIN_EMAIL, device: s.device, mail: L.mailReady() } : { ok: false });
    if (!s) return L.send(res, 401, { error: 'Session expirée, reconnectez-vous.' });
    if (a === 'logout') { L.setCookie(res, 'lp_adm', '', 0); return L.send(res, 200, { ok: true }); }
    if (a === 'stats') return await stats(req, res);
    if (a === 'visits') {
      const raw = await L.redis('LRANGE', L.P + 'v:log', 0, Math.min(1000, +req.query.n || 200) - 1);
      return L.send(res, 200, raw.map(x => JSON.parse(x)));
    }
    if (a === 'demandes') return L.send(res, 200, await demandes(await L.redis('LRANGE', L.P + 'd:ids', 0, -1)));
    if (req.method !== 'POST') return L.send(res, 405, { error: 'POST attendu' });
    if (a === 'update') return await update(req, res);
    if (a === 'reply') return await reply(req, res);
    if (a === 'delete') return await remove(req, res);
    if (a === 'devices') return await devices(req, res, s);
    if (a === 'settings') return await settings(req, res, s);
    L.send(res, 404, { error: 'Action inconnue' });
  } catch (err) {
    L.send(res, err.status || (err.code === 'NOMAIL' ? 400 : 500), { error: err.message });
  }
};
