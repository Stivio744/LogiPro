// Mesure d'audience : une visite = page, source, pays/ville, appareil. Aucune adresse IP n'est conservée.
const L = require('./_lib');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return L.send(res, 405, { error: 'POST attendu' });
  try {
    const u = L.ua(req);
    if (u.bot || !L.dbReady() || await L.session(req)) return L.send(res, 204); // robots et administrateur ignorés
    const b = await L.body(req);
    let ref = '';
    try { ref = b.r ? new URL(b.r).hostname.replace(/^www\./, '') : ''; } catch {}
    if (ref === String(req.headers.host || '').replace(/^www\./, '')) ref = '';
    const day = L.today();
    const vid = L.hash(L.ip(req) + '|' + u.raw + '|' + day); // identifiant du visiteur pour la journée, irréversible
    const g = L.geo(req);
    const e = { t: Date.now(), p: L.clip(b.p || '/', 120), r: L.clip(ref, 80), c: g.c, ci: L.clip(g.ci, 60), dv: u.dv, os: u.os, b: u.b, v: vid };
    await L.pipe([
      ['LPUSH', L.P + 'v:log', JSON.stringify(e)],
      ['LTRIM', L.P + 'v:log', 0, 4999],
      ['HINCRBY', L.P + 'v:days', day, 1],
      ['PFADD', L.P + 'v:u:' + day, vid],
      ['EXPIRE', L.P + 'v:u:' + day, 400 * 86400],
      ['INCR', L.P + 'v:total']
    ]);
    L.send(res, 204);
  } catch (err) {
    L.send(res, 500, { error: err.message });
  }
};
