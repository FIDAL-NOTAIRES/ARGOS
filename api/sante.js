/* ARGOS · /api/sante — page de santé interrogée par ARGOSAdmin (voyant vert / rouge, version en ligne).
   Vérifie que la base est lisible avec le rôle argos_lecteur et que la clé de lecture du site correspond
   bien à un client. Ne renvoie aucune donnée sensible.
   Réponse 200 : { ok: true, client: "AFTL", actif: true, version: "0.70.0" } — 503 si la base ou la clé ne répond pas. */
const { neon } = require("@neondatabase/serverless");
const VERSION = require("../package.json").version;

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  try {
    if (!process.env.ARGOS_DATABASE_URL || !process.env.ARGOS_CLE_LECTURE) throw new Error("variables absentes");
    const sql = neon(process.env.ARGOS_DATABASE_URL);
    const r = await sql`SELECT nom, actif FROM argos_client WHERE cle_lecture = ${process.env.ARGOS_CLE_LECTURE}`;
    if (!r.length) throw new Error("clé de lecture inconnue");
    res.statusCode = 200;
    res.end(JSON.stringify({ ok: true, client: r[0].nom, actif: r[0].actif, version: VERSION }));
  } catch (e) {
    res.statusCode = 503;
    res.end(JSON.stringify({ ok: false, erreur: e.message, version: VERSION }));
  }
};
