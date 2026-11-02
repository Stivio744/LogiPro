// Interface admin : connexion limitée aux appareils enregistrés, visites, demandes, réponses par e-mail.
const crypto = require('node:crypto');
const L = require('./_lib');

const STATUTS = ['nouvelle', 'en cours', 'répondue', 'démo planifiée', 'client', 'archivée'];
const maxDevices = async () => +(await L.redis('GET', L.P + 'adm:max')) || 2;

async function login(req, res) {
  const b = await L.body(req);
  const fk = L.P + 'adm:fail:' + L.hash(L.ip(req));
  if (+(await L.redis('GET', fk)) >= 5) return L.send(res, 429, { error: 'Trop d’essais. Réessayez dans 15 minutes.' });
  const stored = await L.adminPass();
  if (!stored) return L.send(res, 409, { error: 'Aucun mot de passe n’est encore créé.', firstSetup: true });
  const okUser = String(b.email || '').trim().toLowerCase() === L.ADMIN_EMAIL;
  if (!okUser || !L.verifyPassword(b.password || '', stored)) {
    await L.pipe([['INCR', fk], ['EXPIRE', fk, 900]]);
    return L.send(res, 401, { error: 'E-mail ou mot de passe incorrect.' });
  }
  await L.redis('DEL', fk);
  await openSession(req, res, b);
}

// Première configuration : possible une seule fois, tant qu'aucun mot de passe n'existe.
async function setup(req, res) {
  const b = await L.body(req);
  const fk = L.P + 'adm:fail:' + L.hash(L.ip(req));
  if (+(await L.redis('GET', fk)) >= 5) return L.send(res, 429, { error: 'Trop d’essais. Réessayez dans 15 minutes.' });
  if (await L.adminPass()) return L.send(res, 403, { error: 'Le mot de passe est déjà créé : connectez-vous.' });
  if (String(b.email || '').trim().toLowerCase() !== L.ADMIN_EMAIL) {
    await L.pipe([['INCR', fk], ['EXPIRE', fk, 900]]);
    return L.send(res, 401, { error: 'Cette adresse e-mail n’est pas celle de l’administrateur.' });
  }
  const pw = String(b.password || '');
  if (pw.length < 10) return L.send(res, 400, { error: 'Au moins 10 caractères' });
  if (pw !== String(b.confirm || '')) return L.send(res, 400, { error: 'Les deux mots de passe ne sont pas identiques' });
  if (await L.redis('SET', L.P + 'adm:pass', L.makePassword(pw), 'NX') !== 'OK') return L.send(res, 403, { error: 'Le mot de passe est déjà créé : connectez-vous.' });
  await openSession(req, res, b);
}

async function openSession(req, res, b) {
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
  await forgetProspect('d:' + id);
  L.send(res, 200, { ok: true });
}

// ---------- Prospects ----------
// Fiche d'un prospect : sa demande de démo, ou le contact pour qui un lien de suivi a été créé
async function prospectCards(pks) {
  if (!pks.length) return [];
  const raw = await L.redis('MGET', ...pks.map(pk => L.P + (pk[0] === 'd' ? 'd:' : 'p:l:') + pk.slice(2)));
  return pks.map((pk, i) => {
    if (!raw[i]) return null;
    const r = JSON.parse(raw[i]);
    return pk[0] === 'd'
      ? { id: pk, src: 'demande', nom: r.nom, societe: r.societe, email: r.email, tel: r.tel, t: r.t, statut: r.statut }
      : { id: pk, src: 'lien', nom: r.nom, societe: r.societe, email: r.email, tel: r.tel, t: r.t, note: r.note, tok: r.tok, m: r.m };
  });
}
// Historique fusionné de tous les navigateurs rattachés au prospect, du plus récent au plus ancien
async function prospectHistory(pk) {
  const keys = await L.redis('SMEMBERS', L.P + 'pk:' + pk) || [];
  const lists = await L.pipe(keys.map(k => ['LRANGE', L.P + 'vh:' + k, 0, 299]));
  return lists.flat().filter(Boolean).map(x => JSON.parse(x)).sort((a, b) => b.t - a.t);
}
function summarize(h) {
  const pages = h.filter(e => e.e === 'p');
  const mods = {};
  h.filter(e => e.e === 'm').forEach(e => { mods[e.m] = (mods[e.m] || 0) + 1; });
  // une « visite » = des pages vues à moins de 30 min d'intervalle
  let visites = 0, prev = Infinity;
  pages.forEach(e => { if (prev - e.t > 30 * 6e4) visites++; prev = e.t; });
  return { visites, pages: pages.length, last: h[0]?.t || null, first: h[h.length - 1]?.t || null, modules: Object.entries(mods).sort((a, b) => b[1] - a[1]) };
}
async function prospects(req, res) {
  const pks = await L.redis('LRANGE', L.P + 'p:ids', 0, 499) || [];
  const cards = (await prospectCards(pks)).filter(Boolean);
  const out = [];
  for (const c of cards) out.push({ ...c, ...summarize(await prospectHistory(c.id)) });
  out.sort((a, b) => (b.last || b.t) - (a.last || a.t));
  L.send(res, 200, out);
}
async function prospect(req, res) {
  const pk = String(req.query.id || '');
  const [card] = await prospectCards([pk]);
  if (!card) return L.send(res, 404, { error: 'Prospect introuvable' });
  const h = await prospectHistory(pk);
  L.send(res, 200, { ...card, ...summarize(h), hist: h.slice(0, 200) });
}
async function plink(req, res) {
  const b = await L.body(req);
  const nom = L.clip(b.nom, 100);
  if (!nom) return L.send(res, 400, { error: 'Nom obligatoire' });
  const tok = crypto.randomBytes(6).toString('base64url').toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 8).padEnd(8, '0');
  const m = /^[a-z]{3,12}$/.test(b.m || '') ? b.m : '';
  const rec = { tok, nom, societe: L.clip(b.societe, 120), email: L.clip(b.email, 160).toLowerCase(), tel: L.clip(b.tel, 40), note: L.clip(b.note, 1000), m, t: Date.now() };
  await L.pipe([['SET', L.P + 'p:l:' + tok, JSON.stringify(rec)], ['LPUSH', L.P + 'p:ids', 'l:' + tok]]);
  L.send(res, 200, rec);
}
async function forgetProspect(pk) {
  const keys = await L.redis('SMEMBERS', L.P + 'pk:' + pk) || [];
  await L.pipe([['DEL', L.P + 'pk:' + pk], ['LREM', L.P + 'p:ids', 0, pk], ...keys.map(k => ['DEL', L.P + 'vk:' + k])]);
}
async function pdel(req, res) {
  const { id } = await L.body(req);
  if (!/^l:[a-z0-9]{6,16}$/.test(id || '')) return L.send(res, 400, { error: 'Seuls les liens de suivi se suppriment ici' });
  await forgetProspect(id);
  await L.redis('DEL', L.P + 'p:l:' + id.slice(2));
  L.send(res, 200, { ok: true });
}
// Nom du prospect pour chaque visite de la liste « Visiteurs », quand il est connu
async function nameVisits(list) {
  const ks = [...new Set(list.map(e => e.k).filter(Boolean))];
  if (!ks.length) return list;
  const pks = await L.redis('MGET', ...ks.map(k => L.P + 'vk:' + k));
  const cards = await prospectCards([...new Set(pks.filter(Boolean))]);
  const byPk = Object.fromEntries(cards.filter(Boolean).map(c => [c.id, c]));
  const byK = Object.fromEntries(ks.map((k, i) => [k, byPk[pks[i]]]));
  return list.map(e => { const c = e.k && byK[e.k]; return c ? { ...e, who: { id: c.id, nom: c.nom, societe: c.societe } } : e; });
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
    const stored = await L.adminPass();
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
    if (a === 'setup' && req.method === 'POST') return await setup(req, res);
    const s = await L.session(req);
    if (a === 'me') return L.send(res, 200, s ? { ok: true, email: L.ADMIN_EMAIL, device: s.device, mail: L.mailReady() } : { ok: false, firstSetup: !(await L.adminPass()) });
    if (!s) return L.send(res, 401, { error: 'Session expirée, reconnectez-vous.' });
    if (a === 'logout') { L.setCookie(res, 'lp_adm', '', 0); return L.send(res, 200, { ok: true }); }
    if (a === 'stats') return await stats(req, res);
    if (a === 'visits') {
      const raw = await L.redis('LRANGE', L.P + 'v:log', 0, Math.min(1000, +req.query.n || 200) - 1);
      return L.send(res, 200, await nameVisits(raw.map(x => JSON.parse(x))));
    }
    if (a === 'prospects') return await prospects(req, res);
    if (a === 'prospect') return await prospect(req, res);
    if (a === 'demandes') return L.send(res, 200, await demandes(await L.redis('LRANGE', L.P + 'd:ids', 0, -1)));
    if (req.method !== 'POST') return L.send(res, 405, { error: 'POST attendu' });
    if (a === 'update') return await update(req, res);
    if (a === 'reply') return await reply(req, res);
    if (a === 'delete') return await remove(req, res);
    if (a === 'plink') return await plink(req, res);
    if (a === 'pdel') return await pdel(req, res);
    if (a === 'devices') return await devices(req, res, s);
    if (a === 'settings') return await settings(req, res, s);
    L.send(res, 404, { error: 'Action inconnue' });
  } catch (err) {
    L.send(res, err.status || (err.code === 'NOMAIL' ? 400 : 500), { error: err.message });
  }
};
