// Réception d'une demande de démo : enregistrée pour l'interface admin, avec avis par e-mail si Brevo est branché.
const L = require('./_lib');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return L.send(res, 405, { error: 'POST attendu' });
  try {
    const b = await L.body(req);
    if (b._honey) return L.send(res, 200, { ok: true }); // robot
    const d = {
      nom: L.clip(b.nom, 100), societe: L.clip(b.societe, 120), email: L.clip(b.email, 160).toLowerCase(),
      tel: L.clip(b.tel, 40), modules: (Array.isArray(b.modules) ? b.modules : []).map(m => L.clip(m, 40)).slice(0, 7),
      message: L.clip(b.message, 3000)
    };
    if (!d.nom || !d.societe || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(d.email)) return L.send(res, 400, { error: 'Nom, société et e-mail valides obligatoires' });

    const rl = L.P + 'dm:rl:' + L.hash(L.ip(req));
    const [n] = await L.pipe([['INCR', rl], ['EXPIRE', rl, 3600]]);
    if (n > 5) return L.send(res, 429, { error: 'Trop de demandes, réessayez plus tard' });

    const u = L.ua(req), g = L.geo(req);
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
    const rec = { id, t: Date.now(), ...d, statut: 'nouvelle', note: '', c: g.c, ci: g.ci, dv: u.dv, os: u.os, hist: [{ t: Date.now(), a: 'Demande reçue' }] };
    await L.pipe([['SET', L.P + 'd:' + id, JSON.stringify(rec)], ['LPUSH', L.P + 'd:ids', id]]);

    if (L.mailReady()) {
      const txt = `Nouvelle demande de démo LogiPro\n\nNom : ${d.nom}\nSociété : ${d.societe}\nE-mail : ${d.email}\nTéléphone : ${d.tel || '-'}\nModules : ${d.modules.join(', ') || 'Tous'}\n\n${d.message || ''}\n\nTraitez-la dans votre interface admin : https://${req.headers.host}/admin`;
      await L.sendMail({ to: L.ADMIN_EMAIL, subject: 'Nouvelle demande de démo — ' + d.societe, text: txt, replyTo: d.email }).catch(() => {});
    }
    L.send(res, 200, { ok: true, id });
  } catch (err) {
    L.send(res, err.code === 'NODB' ? 503 : 500, { error: err.message });
  }
};
