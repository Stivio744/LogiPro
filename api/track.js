// Mesure d'audience : une visite = page, source, pays/ville, appareil. Aucune adresse IP conservée.
// Chaque navigateur porte un identifiant aléatoire (k) : son historique n'est relié à une personne
// que si elle s'identifie elle-même (demande de démo) ou ouvre un lien de suivi qu'on lui a envoyé.
const L = require('./_lib');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return L.send(res, 405, { error: 'POST attendu' });
  try {
    const u = L.ua(req);
    if (u.bot || !L.dbReady() || await L.session(req)) return L.send(res, 204); // robots et administrateur ignorés
    const b = await L.body(req);
    const k = L.vkey(b.k);
    const g = L.geo(req);

    // Lien de suivi ouvert : ce navigateur est désormais rattaché au prospect
    if (k && /^[a-z0-9]{6,16}$/.test(b.l || '') && await L.redis('EXISTS', L.P + 'p:l:' + b.l)) await L.linkVisitor(k, 'l:' + b.l);

    // Module consulté sur la page : seulement dans l'historique du visiteur
    if (b.e === 'm') {
      if (k && /^[a-z]{3,12}$/.test(b.m || '')) await L.pipe(L.historyCmds(k, { t: Date.now(), e: 'm', m: b.m }));
      return L.send(res, 204);
    }

    let ref = '';
    try { ref = b.r ? new URL(b.r).hostname.replace(/^www\./, '') : ''; } catch {}
    if (ref === String(req.headers.host || '').replace(/^www\./, '')) ref = '';
    const day = L.today();
    const vid = L.hash(L.ip(req) + '|' + u.raw + '|' + day); // identifiant du visiteur pour la journée, irréversible
    const e = { t: Date.now(), p: L.clip(b.p || '/', 120), r: L.clip(ref, 80), c: g.c, ci: L.clip(g.ci, 60), dv: u.dv, os: u.os, b: u.b, v: vid, k: k || undefined };
    await L.pipe([
      ['LPUSH', L.P + 'v:log', JSON.stringify(e)],
      ['LTRIM', L.P + 'v:log', 0, 4999],
      ['HINCRBY', L.P + 'v:days', day, 1],
      ['PFADD', L.P + 'v:u:' + day, vid],
      ['EXPIRE', L.P + 'v:u:' + day, 400 * 86400],
      ['INCR', L.P + 'v:total'],
      ...(k ? L.historyCmds(k, { t: e.t, e: 'p', p: e.p, r: e.r, c: e.c, ci: e.ci, dv: e.dv, os: e.os }) : [])
    ]);
    L.send(res, 204);
  } catch (err) {
    L.send(res, 500, { error: err.message });
  }
};
