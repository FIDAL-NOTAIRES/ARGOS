/* ARGOS · /api/argos — pont LECTURE SEULE vers les données déposées par ARGOSAdmin (lot 2).
   Le site client ne touche jamais à l'écriture : rôle Neon argos_lecteur (SELECT), clé Scaleway de lecture.
   Variables Vercel du site client :
     ARGOS_DATABASE_URL   chaîne Neon du rôle argos_lecteur (mot de passe posé au bloc 2 du SQL)
     ARGOS_CLE_LECTURE    clé de lecture du client, copiée depuis la fiche client d'ARGOSAdmin
     SCW_LECTURE_CLE / SCW_LECTURE_SECRET   clé d'API Scaleway du compte PRINCIPAL, politique lecture seule
     SCW_REGION           facultatif, défaut fr-par
   Appels :
     GET /api/argos?action=sites            → { client, sites:[{ id, nom, adresse, commune, code_postal, references_, fiche, pieces:[…] }] }
     GET /api/argos?action=piece&id=123     → redirection (302) vers une adresse de lecture signée valable 5 minutes
   Lot 3 : ces appels seront protégés par la session de l'utilisateur client (aujourd'hui, ils ne le sont pas plus que le site lui-même). */
const { neon } = require("@neondatabase/serverless");
const crypto = require("crypto");

const RUBRIQUES = { 1: "Désignation et plans", 2: "Titre", 3: "Exploitation", 4: "Fiscalité", 5: "Diagnostics", 6: "Organisation de l'immeuble / de la zone" };

// ---- signature AWS v4 (lecture seule), identique à celle d'ARGOSAdmin ----
function hex(b) { return Buffer.from(b).toString("hex"); }
function hmac(cle, msg) { return crypto.createHmac("sha256", cle).update(msg, "utf8").digest(); }
function sha256hex(msg) { return crypto.createHash("sha256").update(msg, "utf8").digest("hex"); }
function encoderCle(cle) {
  return cle.split("/").map((seg) => encodeURIComponent(seg).replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase())).join("/");
}
function adresseLecture(bucket, cle, expire) {
  const acces = process.env.SCW_LECTURE_CLE, secret = process.env.SCW_LECTURE_SECRET, region = process.env.SCW_REGION || "fr-par";
  if (!acces || !secret) throw new Error("Clé Scaleway de lecture absente.");
  const hote = `${bucket}.s3.${region}.scw.cloud`;
  const iso = new Date().toISOString().replace(/[:-]|\.\d{3}/g, ""), jour = iso.slice(0, 8);
  const portee = `${jour}/${region}/s3/aws4_request`;
  const uri = "/" + encoderCle(cle);
  const params = { "X-Amz-Algorithm": "AWS4-HMAC-SHA256", "X-Amz-Credential": `${acces}/${portee}`, "X-Amz-Date": iso, "X-Amz-Expires": String(expire), "X-Amz-SignedHeaders": "host" };
  const requete = Object.keys(params).sort().map((k) => `${encodeURIComponent(k)}=${encodeURIComponent(params[k])}`).join("&");
  const canonique = ["GET", uri, requete, `host:${hote}\n`, "host", "UNSIGNED-PAYLOAD"].join("\n");
  const aSigner = ["AWS4-HMAC-SHA256", iso, portee, sha256hex(canonique)].join("\n");
  const kSign = hmac(hmac(hmac(hmac("AWS4" + secret, jour), region), "s3"), "aws4_request");
  return `https://${hote}${uri}?${requete}&X-Amz-Signature=${hex(hmac(kSign, aSigner))}`;
}

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  const url = new URL(req.url, "http://x");
  const action = url.searchParams.get("action") || "sites";
  try {
    if (!process.env.ARGOS_DATABASE_URL || !process.env.ARGOS_CLE_LECTURE) throw new Error("Variables ARGOS_* absentes.");
    const sql = neon(process.env.ARGOS_DATABASE_URL);
    const c = await sql`SELECT id, nom, actif FROM argos_client WHERE cle_lecture = ${process.env.ARGOS_CLE_LECTURE}`;
    if (!c.length) throw new Error("Clé de lecture inconnue.");
    const client = c[0];
    if (!client.actif) { res.statusCode = 403; return res.end(JSON.stringify({ erreur: "Accès suspendu par le cabinet." })); }

    if (action === "sites") {
      const sites = await sql`
        SELECT id, nom, adresse, commune, code_postal, references_, fiche, maj_le
        FROM argos_site WHERE client_id = ${client.id} ORDER BY commune, nom, id`;
      const pieces = await sql`
        SELECT p.id, p.site_id, p.rubrique, p.nom_fichier, p.taille, p.depose_le
        FROM argos_piece p JOIN argos_site s ON s.id = p.site_id
        WHERE s.client_id = ${client.id} ORDER BY p.rubrique, p.depose_le DESC`;
      const parSite = {};
      for (const p of pieces) (parSite[p.site_id] = parSite[p.site_id] || []).push({ id: p.id, rubrique: p.rubrique, libelle: RUBRIQUES[p.rubrique], nom: p.nom_fichier, taille: p.taille, depose_le: p.depose_le });
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      return res.end(JSON.stringify({ client: client.nom, rubriques: RUBRIQUES, sites: sites.map((s) => Object.assign({}, s, { pieces: parSite[s.id] || [] })) }));
    }

    if (action === "piece") {
      const id = parseInt(url.searchParams.get("id"), 10);
      const r = await sql`
        SELECT p.cle_objet, p.bucket_principal, p.nom_fichier
        FROM argos_piece p JOIN argos_site s ON s.id = p.site_id
        WHERE p.id = ${id} AND s.client_id = ${client.id} AND p.copie_principale = TRUE`;
      if (!r.length) { res.statusCode = 404; return res.end("Pièce introuvable."); }
      res.statusCode = 302;
      res.setHeader("Location", adresseLecture(r[0].bucket_principal, r[0].cle_objet, 300));
      return res.end();
    }

    res.statusCode = 400;
    res.end(JSON.stringify({ erreur: "Action inconnue." }));
  } catch (e) {
    console.error("[argos pont]", e);
    res.statusCode = 500;
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.end(JSON.stringify({ erreur: e.message }));
  }
};
