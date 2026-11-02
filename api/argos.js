/* ARGOS · /api/argos — LOT 3 (31/10/2026) : comptes utilisateurs, activation, sessions, appareils, pièces.
   Fonction serveur UNIQUE à actions (limite Vercel Hobby). Le site client ne modifie jamais les pièces :
   il lit la base avec le rôle Neon argos_lecteur (lecture des pièces, écriture limitée aux sessions,
   appareils, secrets des comptes et journal) et sert chaque pièce par une adresse Scaleway signée 5 minutes,
   UNIQUEMENT après vérification de la session.

   Variables Vercel du site client (une par déploiement, posées par ARGOSAdmin à la création du client) :
     ARGOS_DATABASE_URL     chaîne Neon du rôle argos_lecteur
     ARGOS_CLE_LECTURE      clé de lecture du client (fiche client d'ARGOSAdmin)
     ARGOS_SECRET           secret de signature des cookies (généré par ARGOSAdmin)
     SCW_LECTURE_CLE / SCW_LECTURE_SECRET   clé Scaleway du compte principal, politique LECTURE SEULE
     SCW_REGION             facultatif, défaut fr-par
     BREVO_CLE / BREVO_EXPEDITEUR / ADMIN_COURRIEL   facultatifs : envoi des courriels (sinon : événement en base)

   Appels :
     GET  /api/argos?action=etat                 → qui est connecté, appareil connu ou non, nom du client
     POST /api/argos { action: "connexion", courriel, mdp }         → ouvre une session (ordinateur)
     POST /api/argos { action: "connexion_code", code }             → ouvre une session (téléphone connu)
     POST /api/argos { action: "activation_lire", jeton }           → vérifie un lien d'activation
     POST /api/argos { action: "activation", jeton, mdp, code, conditions }   → active le compte
     POST /api/argos { action: "reinit_code", jeton, mdp, code }    → nouveau code secret (lien de JFD)
     POST /api/argos { action: "reinit_mdp", jeton, mdp }           → nouveau mot de passe (lien de JFD)
     POST /api/argos { action: "appairage_creer" }                  → jeton 10 min pour le code QR (session requise)
     POST /api/argos { action: "appairage", jeton, code }           → enregistre le téléphone qui a scanné
     POST /api/argos { action: "deconnexion" }
     GET  /api/argos?action=sites                → sites et pièces autorisés (session requise)
     GET  /api/argos?action=piece&id=123         → la pièce elle-même, servie en flux par le portail (session requise, droits vérifiés, plafonds)
     GET  /api/argos?action=equipe               → journal de l'équipe (responsable seulement)
     POST /api/argos { action: "couper", utilisateur_id }           → le responsable coupe un accès (fusible)
*/
const { neon } = require("@neondatabase/serverless");
const crypto = require("crypto");
const { Readable } = require("stream");

const RUBRIQUES = { 1: "Désignation et plans", 2: "Titre", 3: "Exploitation", 4: "Fiscalité", 5: "Diagnostics", 6: "Organisation de l'immeuble / de la zone", 7: "Servitudes" };
const DUREE_SESSION_MS = 10 * 60 * 60 * 1000;      // 10 heures
const DUREE_APPAREIL_J = 400;                        // cookie d'appareil : 400 jours
const DUREE_APPAIRAGE_MS = 10 * 60 * 1000;           // code QR : 10 minutes
const SUSPENSION_MS = 48 * 60 * 60 * 1000;           // 5 échecs → 48 heures
// LOT 4 (02/11/2026) — pause automatique pour volume inhabituel ; rétablissement par le responsable depuis le portail
const MESSAGE_CADASTRE = "Les références cadastrales de ce site ne sont plus à jour, probablement à la suite d'une division ou d'un remaniement cadastral. Merci de vous rapprocher de FIDAL Notaires pour obtenir une fiche de synthèse actualisée.";
const MESSAGE_PAUSE = "Votre accès est mis en pause pour un volume de consultations inhabituel. Votre responsable peut le rétablir depuis le portail.";
const COOKIE_SESSION = "argos_session", COOKIE_APPAREIL = "argos_appareil";
const CODES_BANALS = /^(\d)\1{5}$|^012345$|^123456$|^234567$|^345678$|^456789$|^987654$|^876543$|^765432$|^654321$|^543210$|^112233$|^121212$|^123123$|^000000$|^111111$/;

// ---------- utilitaires ----------
function sha256(t) { return crypto.createHash("sha256").update(String(t), "utf8").digest("hex"); }
function hacher(secret) {
  const sel = crypto.randomBytes(16).toString("base64url");
  return sel + "$" + crypto.scryptSync(String(secret), sel, 32).toString("base64url");
}
function verifierHachage(secret, stocke) {
  if (!stocke || !stocke.includes("$")) return false;
  const [sel, emp] = stocke.split("$");
  const calc = crypto.scryptSync(String(secret), sel, 32).toString("base64url");
  return calc.length === emp.length && crypto.timingSafeEqual(Buffer.from(calc), Buffer.from(emp));
}
function texte(v, max = 300) { return String(v == null ? "" : v).trim().slice(0, max); }
function entier(v, d) { const n = parseInt(v, 10); return Number.isFinite(n) ? n : d; }
function lireCorps(req) {
  if (req.body && typeof req.body === "object") return req.body;
  if (typeof req.body === "string" && req.body) { try { return JSON.parse(req.body); } catch { return {}; } }
  return {};
}
function lireCookies(req) {
  const c = {}; String(req.headers.cookie || "").split(";").forEach((p) => { const i = p.indexOf("="); if (i > 0) c[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); });
  return c;
}
function poserCookie(res, nom, valeur, maxAgeS) {
  const l = res.getHeader("Set-Cookie") || [];
  const liste = Array.isArray(l) ? l : [l];
  liste.push(`${nom}=${encodeURIComponent(valeur)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAgeS}`);
  res.setHeader("Set-Cookie", liste);
}
function effacerCookie(res, nom) { poserCookie(res, nom, "", 0); }
function ip(req) { return texte((req.headers["x-forwarded-for"] || "").split(",")[0] || req.socket?.remoteAddress || "", 60); }
function libelleAppareil(ua) {
  ua = String(ua || "");
  const nav = /Edg\//.test(ua) ? "Edge" : /OPR\//.test(ua) ? "Opera" : /Chrome\//.test(ua) ? "Chrome" : /Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : "Navigateur";
  const sys = /iPhone/.test(ua) ? "iPhone" : /iPad/.test(ua) ? "iPad" : /Android/.test(ua) ? "Android" : /Windows/.test(ua) ? "Windows" : /Mac OS/.test(ua) ? "Mac" : /Linux/.test(ua) ? "Linux" : "appareil";
  return `${nav} sur ${sys}`;
}
function estTelephone(ua) { return /iPhone|iPad|Android|Mobile/i.test(String(ua || "")); }
function origine(req) { return `https://${req.headers["x-forwarded-host"] || req.headers.host}`; }

// ---------- signature Scaleway (lecture seule) ----------
// Relais d'un objet du stockage vers le navigateur (flux continu, plages partielles, nom maîtrisé)
async function relayer(req, res, bucket, cle, nomFichier) {
  const amont = await fetch(adresseLecture(bucket, cle, 60), { headers: req.headers.range ? { Range: req.headers.range } : {} });
  if (!amont.ok && amont.status !== 206) {
    console.error("[argos] lecture stockage", amont.status, await amont.text().catch(() => ""));
    res.statusCode = 502; res.setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.end("La pièce est momentanément indisponible. Réessayez dans quelques minutes.");
  }
  const nom = nomPropre(nomFichier);
  res.statusCode = amont.status;
  res.setHeader("Content-Type", amont.headers.get("content-type") || "application/octet-stream");
  for (const h of ["content-length", "content-range", "accept-ranges", "etag", "last-modified"]) { const v = amont.headers.get(h); if (v) res.setHeader(h, v); }
  res.setHeader("Content-Disposition", `inline; filename="${nom.replace(/[^\x20-\x7E]/g, "_").replace(/"/g, "")}"; filename*=UTF-8''${encodeURIComponent(nom)}`);
  res.setHeader("Cache-Control", "private, no-store");
  if (!amont.body) return res.end();
  await new Promise((ok, ko) => { const flux = Readable.fromWeb(amont.body); flux.on("error", ko); res.on("close", ok); res.on("error", ko); flux.pipe(res).on("finish", ok); });
}
// Références cadastrales saisies librement dans ARGOSAdmin (« Section AB n° 123, 124 », « AL 4 », « ZD 12 et 13 ») → liste de parcelles
function parcellesDepuisTexte(texteRefs) {
  const mots = String(texteRefs || "").toUpperCase().replace(/N[°º]/g, " ").replace(/[,;/()]/g, " ").split(/\s+/).filter(Boolean);
  const bruit = new Set(["SECTION", "SECTIONS", "PARCELLE", "PARCELLES", "ET", "DE", "DU", "DES", "LA", "LE", "LES", "A", "AU", "LIEUDIT", "LIEU-DIT", "CADASTRE", "CADASTREE", "CADASTREES"]);
  const out = [], vues = new Set(); let section = null, m;
  for (const mot of mots) {
    if (bruit.has(mot)) continue;
    if ((m = mot.match(/^([0-9]?[A-Z]{1,2})(\d{1,4})$/))) { section = m[1]; }
    else if (/^[0-9]?[A-Z]{1,2}$/.test(mot)) { section = mot; continue; }
    else if ((m = mot.match(/^(\d{1,4})$/)) && section) { m = [mot, section, m[1]]; }
    else continue;
    const cle = `${m[1]} ${String(parseInt(m[2], 10))}`;
    if (!vues.has(cle)) { vues.add(cle); out.push({ section: m[1], numero: String(parseInt(m[2], 10)) }); }
  }
  return out;
}
function normaliser(t) { return String(t || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toUpperCase().replace(/[^A-Z0-9]+/g, " ").trim(); }
async function codeInsee(codePostal, commune) {
  const cp = String(codePostal || "").replace(/\D/g, "");
  const quete = cp.length === 5 ? `codePostal=${cp}` : (commune ? `nom=${encodeURIComponent(commune)}` : "");
  if (!quete) return null;
  const r = await fetch(`https://geo.api.gouv.fr/communes?${quete}&fields=code,nom&limit=20`);
  if (!r.ok) throw new Error(`geo.api.gouv ${r.status}`);
  const liste = await r.json();
  if (!Array.isArray(liste) || !liste.length) return null;
  if (liste.length === 1) return liste[0].code;
  const voulu = normaliser(commune);
  const exact = liste.find((c) => normaliser(c.nom) === voulu) || liste.find((c) => voulu && normaliser(c.nom).includes(voulu));
  return exact ? exact.code : null;
}
// true : la parcelle existe ; false : réponse valide sans parcelle ; exception : cadastre injoignable
async function parcelleExiste(insee, section, numero) {
  const sec = section.padStart(2, "0"), num = String(numero).padStart(4, "0");
  const r = await fetch(`https://apicarto.ign.fr/api/cadastre/parcelle?code_insee=${insee}&section=${sec}&numero=${num}`);
  if (!r.ok) throw new Error(`apicarto ${r.status}`);
  const g = await r.json();
  return !!(g.features && g.features.length);
}
function nomPropre(n) { return texte(n, 150).replace(/[\\/:*?"<>|\x00-\x1F]/g, "_").replace(/\s+/g, " ").trim() || "piece.pdf"; }
function hex(b) { return Buffer.from(b).toString("hex"); }
function hmac(cle, msg) { return crypto.createHmac("sha256", cle).update(msg, "utf8").digest(); }
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
  const aSigner = ["AWS4-HMAC-SHA256", iso, portee, sha256(canonique)].join("\n");
  const kSign = hmac(hmac(hmac(hmac("AWS4" + secret, jour), region), "s3"), "aws4_request");
  return `https://${hote}${uri}?${requete}&X-Amz-Signature=${hex(hmac(kSign, aSigner))}`;
}

// ---------- courriels (Brevo si configuré, sinon événement en base lu par ARGOSAdmin) ----------
async function courriel(sql, clientId, destinataires, objet, corps) {
  const cle = process.env.BREVO_CLE, exp = process.env.BREVO_EXPEDITEUR;
  const liste = (destinataires || []).filter(Boolean);
  if (cle && exp && liste.length) {
    try {
      const r = await fetch("https://api.brevo.com/v3/smtp/email", {
        method: "POST", headers: { "api-key": cle, "Content-Type": "application/json" },
        body: JSON.stringify({ sender: { email: exp, name: "FIDAL Notaires" }, to: liste.map((e) => ({ email: e })), subject: objet, textContent: corps }),
      });
      if (r.ok) return true;
    } catch (e) { console.error("[brevo]", e.message); }
  }
  await sql`INSERT INTO argos_evenement (client_id, nature, detail) VALUES (${clientId}, 'courriel_non_envoye', ${objet + " → " + liste.join(", ") + "\n" + corps})`;
  return false;
}

// ---------- journal ----------
async function journal(sql, clientId, utilisateurId, appareilId, resultat, req, detail, courrielSaisi) {
  await sql`INSERT INTO argos_connexion (client_id, utilisateur_id, appareil_id, resultat, courriel, adresse_ip, detail)
            VALUES (${clientId}, ${utilisateurId}, ${appareilId}, ${resultat}, ${courrielSaisi || null}, ${ip(req)}, ${detail || null})`;
}

// ---------- appareil courant (cookie) ----------
async function appareilCourant(sql, req, utilisateurId) {
  const marque = lireCookies(req)[COOKIE_APPAREIL];
  if (!marque) return null;
  const r = utilisateurId
    ? await sql`SELECT id, type, libelle, utilisateur_id FROM argos_appareil WHERE marque_hachage = ${sha256(marque)} AND utilisateur_id = ${utilisateurId}`
    : await sql`SELECT id, type, libelle, utilisateur_id FROM argos_appareil WHERE marque_hachage = ${sha256(marque)}`;
  return r[0] || null;
}
async function enregistrerAppareil(sql, res, req, utilisateurId, type) {
  const marque = crypto.randomBytes(24).toString("base64url");
  const ins = await sql`INSERT INTO argos_appareil (utilisateur_id, libelle, type, marque_hachage)
                        VALUES (${utilisateurId}, ${libelleAppareil(req.headers["user-agent"])}, ${type}, ${sha256(marque)}) RETURNING id`;
  poserCookie(res, COOKIE_APPAREIL, marque, DUREE_APPAREIL_J * 86400);
  return ins[0].id;
}

// ---------- session ----------
async function ouvrirSession(sql, res, utilisateurId, appareilId) {
  const jeton = crypto.randomBytes(32).toString("base64url");
  const expire = new Date(Date.now() + DUREE_SESSION_MS);
  await sql`INSERT INTO argos_session (utilisateur_id, appareil_id, jeton_hachage, expire_le) VALUES (${utilisateurId}, ${appareilId}, ${sha256(jeton)}, ${expire})`;
  await sql`UPDATE argos_utilisateur SET derniere_connexion = NOW(), echecs_mdp = 0, echecs_code = 0 WHERE id = ${utilisateurId}`;
  if (appareilId) await sql`UPDATE argos_appareil SET vu_le = NOW() WHERE id = ${appareilId}`;
  poserCookie(res, COOKIE_SESSION, jeton, Math.floor(DUREE_SESSION_MS / 1000));
}
async function sessionCourante(sql, req, client) {
  const jeton = lireCookies(req)[COOKIE_SESSION];
  if (!jeton) return null;
  const r = await sql`
    SELECT u.id, u.courriel, u.nom, u.prenom, u.role, u.active, u.bloque_jusqua, u.coupe_par_responsable, u.suspendu_le, u.pause_volume, s.appareil_id
    FROM argos_session s JOIN argos_utilisateur u ON u.id = s.utilisateur_id
    WHERE s.jeton_hachage = ${sha256(jeton)} AND s.revoque_le IS NULL AND s.expire_le > NOW() AND u.client_id = ${client.id}`;
  const u = r[0];
  if (!u) return null;
  if (!u.active || u.coupe_par_responsable || u.suspendu_le || u.pause_volume || (u.bloque_jusqua && new Date(u.bloque_jusqua) > new Date())) return null;
  return u;
}
async function utilisateurUtilisable(u) {
  if (!u) return "Identifiants incorrects.";
  if (u.coupe_par_responsable) return "Votre accès a été coupé par votre responsable. Rapprochez-vous de FIDAL Notaires.";
  if (u.suspendu_le) return "Votre accès est suspendu. Rapprochez-vous de FIDAL Notaires.";
  if (u.pause_volume) return MESSAGE_PAUSE;
  if (u.bloque_jusqua && new Date(u.bloque_jusqua) > new Date()) return "Accès suspendu quarante-huit heures après plusieurs tentatives infructueuses. Votre responsable et FIDAL Notaires en sont informés.";
  if (!u.mdp_hachage) return "Compte non encore activé : utilisez le lien d'activation reçu.";
  return null;
}
async function lireJeton(sql, client, jeton, objet) {
  const r = await sql`SELECT * FROM argos_utilisateur WHERE client_id = ${client.id} AND activation_hachage = ${sha256(texte(jeton, 200))}`;
  const u = r[0];
  if (!u || u.activation_objet !== objet) throw new Error("Lien inconnu ou déjà utilisé.");
  if (!u.activation_expire || new Date(u.activation_expire) < new Date()) throw new Error("Ce lien a expiré (quarante-huit heures). Demandez-en un nouveau à FIDAL Notaires.");
  return u;
}
function controlerMdp(mdp) { if (texte(mdp, 200).length < 12) throw new Error("Le mot de passe doit comporter au moins douze caractères."); }
function controlerCode(code) {
  code = texte(code, 10);
  if (!/^\d{6}$/.test(code)) throw new Error("Le code secret comporte six chiffres.");
  if (CODES_BANALS.test(code)) throw new Error("Ce code est trop banal (suite ou répétition) : choisissez-en un autre.");
  return code;
}

// ---------- actions ----------
const actions = {
  async etat(sql, p, req, res, client) {
    const u = await sessionCourante(sql, req, client);
    const app = await appareilCourant(sql, req, u ? u.id : null);
    return {
      client: client.nom,
      utilisateur: u ? { id: u.id, courriel: u.courriel, nom: u.nom, prenom: u.prenom, role: u.role } : null,
      appareil: app ? { type: app.type, libelle: app.libelle } : null,
      telephone: estTelephone(req.headers["user-agent"]),
    };
  },

  async activation_lire(sql, p, req, res, client) {
    const u = await lireJeton(sql, client, p.jeton, "activation");
    return { courriel: u.courriel, nom: u.nom, prenom: u.prenom, client: client.nom };
  },

  async activation(sql, p, req, res, client) {
    const u = await lireJeton(sql, client, p.jeton, "activation");
    controlerMdp(p.mdp);
    const code = controlerCode(p.code);
    if (!p.conditions) throw new Error("Les conditions d'utilisation doivent être acceptées.");
    await sql`UPDATE argos_utilisateur SET mdp_hachage = ${hacher(p.mdp)}, code_hachage = ${hacher(code)}, activation_hachage = NULL, activation_expire = NULL,
              active_le = NOW(), conditions_le = NOW(), active = TRUE, echecs_mdp = 0, echecs_code = 0, maj_le = NOW() WHERE id = ${u.id}`;
    // premier appareil : de confiance d'office, sans courriel
    const appareilId = await enregistrerAppareil(sql, res, req, u.id, estTelephone(req.headers["user-agent"]) ? "telephone" : "ordinateur");
    await ouvrirSession(sql, res, u.id, appareilId);
    await journal(sql, client.id, u.id, appareilId, "activation", req, "Compte activé, conditions acceptées");
    return { ok: true, prenom: u.prenom, nom: u.nom };
  },

  async reinit_code(sql, p, req, res, client) {
    const u = await lireJeton(sql, client, p.jeton, "code");
    if (!verifierHachage(p.mdp, u.mdp_hachage)) throw new Error("Mot de passe incorrect.");
    const code = controlerCode(p.code);
    await sql`UPDATE argos_utilisateur SET code_hachage = ${hacher(code)}, activation_hachage = NULL, activation_expire = NULL, echecs_code = 0, maj_le = NOW() WHERE id = ${u.id}`;
    await journal(sql, client.id, u.id, null, "reinitialisation", req, "Nouveau code secret");
    return { ok: true };
  },

  async reinit_mdp(sql, p, req, res, client) {
    const u = await lireJeton(sql, client, p.jeton, "mdp");
    controlerMdp(p.mdp);
    await sql`UPDATE argos_utilisateur SET mdp_hachage = ${hacher(p.mdp)}, activation_hachage = NULL, activation_expire = NULL, echecs_mdp = 0, bloque_jusqua = NULL, maj_le = NOW() WHERE id = ${u.id}`;
    await sql`UPDATE argos_session SET revoque_le = NOW() WHERE utilisateur_id = ${u.id} AND revoque_le IS NULL`;
    await journal(sql, client.id, u.id, null, "reinitialisation", req, "Nouveau mot de passe");
    return { ok: true };
  },

  async connexion(sql, p, req, res, client) {
    const courrielSaisi = texte(p.courriel, 200).toLowerCase();
    const r = await sql`SELECT * FROM argos_utilisateur WHERE client_id = ${client.id} AND LOWER(courriel) = ${courrielSaisi}`;
    const u = r[0];
    const empeche = await utilisateurUtilisable(u);
    if (empeche) { await new Promise((f) => setTimeout(f, 600)); await journal(sql, client.id, u ? u.id : null, null, u ? "bloque" : "echec", req, empeche, courrielSaisi); throw new Error(empeche); }
    if (!verifierHachage(p.mdp, u.mdp_hachage)) {
      const n = (u.echecs_mdp || 0) + 1;
      if (n >= 5) {
        await sql`UPDATE argos_utilisateur SET echecs_mdp = 0, bloque_jusqua = ${new Date(Date.now() + SUSPENSION_MS)}, maj_le = NOW() WHERE id = ${u.id}`;
        await sql`UPDATE argos_session SET revoque_le = NOW() WHERE utilisateur_id = ${u.id} AND revoque_le IS NULL`;
        await journal(sql, client.id, u.id, null, "suspension", req, "Cinq échecs de mot de passe : suspension 48 h");
        const resp = await sql`SELECT courriel FROM argos_utilisateur WHERE client_id = ${client.id} AND role = 'responsable' AND active = TRUE AND id <> ${u.id}`;
        await courriel(sql, client.id, [process.env.ADMIN_COURRIEL, ...resp.map((x) => x.courriel)],
          `[ARGOS · ANORMAL] Accès suspendu 48 h — ${client.nom}`,
          `Cinq tentatives de mot de passe ont échoué pour ${u.prenom} ${u.nom} (${u.courriel}). L'accès est suspendu quarante-huit heures. FIDAL Notaires peut le rétablir plus tôt.`);
        throw new Error("Accès suspendu quarante-huit heures, votre responsable et FIDAL Notaires en sont informés.");
      }
      await sql`UPDATE argos_utilisateur SET echecs_mdp = ${n}, maj_le = NOW() WHERE id = ${u.id}`;
      await journal(sql, client.id, u.id, null, "echec", req, `Mot de passe incorrect (${n}/5)`, courrielSaisi);
      await new Promise((f) => setTimeout(f, 600));
      throw new Error("Identifiants incorrects.");
    }
    // appareil : connu ou nouveau (nouveau = un seul courriel d'information à JFD, pas de blocage)
    let app = await appareilCourant(sql, req, u.id);
    let appareilId;
    if (app) { appareilId = app.id; }
    else {
      appareilId = await enregistrerAppareil(sql, res, req, u.id, estTelephone(req.headers["user-agent"]) ? "telephone" : "ordinateur");
      await journal(sql, client.id, u.id, appareilId, "nouvel_appareil", req, libelleAppareil(req.headers["user-agent"]) + " — authentification réussie");
      await courriel(sql, client.id, [process.env.ADMIN_COURRIEL], `[ARGOS] Nouvel appareil, authentification réussie — ${client.nom}`,
        `${u.prenom} ${u.nom} (${u.courriel}) s'est connecté depuis un nouvel appareil : ${libelleAppareil(req.headers["user-agent"])}.`);
    }
    await ouvrirSession(sql, res, u.id, appareilId);
    await journal(sql, client.id, u.id, appareilId, "ok", req, null, courrielSaisi);
    return { ok: true, utilisateur: { id: u.id, prenom: u.prenom, nom: u.nom, role: u.role }, nouvel_appareil: !app };
  },

  async connexion_code(sql, p, req, res, client) {
    const app = await appareilCourant(sql, req, null);
    if (!app) throw new Error("Appareil inconnu : connectez-vous avec votre courriel et votre mot de passe.");
    const r = await sql`SELECT * FROM argos_utilisateur WHERE id = ${app.utilisateur_id} AND client_id = ${client.id}`;
    const u = r[0];
    const empeche = await utilisateurUtilisable(u);
    if (empeche) { await journal(sql, client.id, u ? u.id : null, app.id, "bloque", req, empeche); throw new Error(empeche); }
    if (!verifierHachage(texte(p.code, 10), u.code_hachage)) {
      const n = (u.echecs_code || 0) + 1;
      await sql`UPDATE argos_utilisateur SET echecs_code = ${n}, maj_le = NOW() WHERE id = ${u.id}`;
      await journal(sql, client.id, u.id, app.id, "code_echec", req, `Code secret incorrect (${n}/3)`);
      await new Promise((f) => setTimeout(f, 500));
      if (n >= 3) { const e = new Error("Trois codes incorrects : connectez-vous avec votre mot de passe."); e.mdp = true; throw e; }
      throw new Error("Code incorrect.");
    }
    await ouvrirSession(sql, res, u.id, app.id);
    await journal(sql, client.id, u.id, app.id, "ok", req, "Code secret");
    return { ok: true, utilisateur: { id: u.id, prenom: u.prenom, nom: u.nom, role: u.role } };
  },

  async enregistrer_telephone(sql, p, req, res, client) {
    const u = await sessionCourante(sql, req, client);
    if (!u) throw new Error("Session expirée.");
    const existant = await appareilCourant(sql, req, u.id);
    if (existant) { await sql`UPDATE argos_appareil SET type = 'telephone', vu_le = NOW() WHERE id = ${existant.id}`; return { ok: true }; }
    await enregistrerAppareil(sql, res, req, u.id, "telephone");
    return { ok: true };
  },

  async appairage_creer(sql, p, req, res, client) {
    const u = await sessionCourante(sql, req, client);
    if (!u) throw new Error("Session expirée.");
    const jeton = crypto.randomBytes(24).toString("base64url");
    await sql`DELETE FROM argos_appairage WHERE utilisateur_id = ${u.id} OR expire_le < NOW()`;
    await sql`INSERT INTO argos_appairage (jeton_hachage, utilisateur_id, expire_le) VALUES (${sha256(jeton)}, ${u.id}, ${new Date(Date.now() + DUREE_APPAIRAGE_MS)})`;
    return { url: `${origine(req)}/#appareil/${jeton}`, expire_dans: DUREE_APPAIRAGE_MS };
  },

  async appairage(sql, p, req, res, client) {
    const r = await sql`SELECT a.utilisateur_id FROM argos_appairage a JOIN argos_utilisateur u ON u.id = a.utilisateur_id
                        WHERE a.jeton_hachage = ${sha256(texte(p.jeton, 200))} AND a.expire_le > NOW() AND a.utilise_le IS NULL AND u.client_id = ${client.id}`;
    if (!r.length) throw new Error("Code QR expiré ou déjà utilisé : affichez-en un nouveau sur l'ordinateur.");
    const ru = await sql`SELECT * FROM argos_utilisateur WHERE id = ${r[0].utilisateur_id}`;
    const u = ru[0];
    if (!verifierHachage(texte(p.code, 10), u.code_hachage)) { await new Promise((f) => setTimeout(f, 500)); throw new Error("Code secret incorrect."); }
    await sql`UPDATE argos_appairage SET utilise_le = NOW() WHERE jeton_hachage = ${sha256(texte(p.jeton, 200))}`;
    const appareilId = await enregistrerAppareil(sql, res, req, u.id, "telephone");
    await ouvrirSession(sql, res, u.id, appareilId);
    await journal(sql, client.id, u.id, appareilId, "ok", req, "Téléphone ajouté par code QR");
    return { ok: true, utilisateur: { id: u.id, prenom: u.prenom, nom: u.nom, role: u.role } };
  },

  async deconnexion(sql, p, req, res, client) {
    const jeton = lireCookies(req)[COOKIE_SESSION];
    if (jeton) await sql`UPDATE argos_session SET revoque_le = NOW() WHERE jeton_hachage = ${sha256(jeton)} AND revoque_le IS NULL`;
    effacerCookie(res, COOKIE_SESSION);
    return { ok: true };
  },

  async sites(sql, p, req, res, client) {
    const u = await sessionCourante(sql, req, client);
    if (!u) { res.statusCode = 401; return { erreur: "Session expirée." }; }
    const sites = await sql`
      SELECT s.id, s.nom, s.adresse, s.commune, s.code_postal, s.lat, s.lng, s.references_, s.fiche, s.maj_le, s.cadastre_alerte_le, s.organisation_visible,
             (SELECT p.id FROM argos_piece p WHERE p.site_id = s.id AND p.est_plan = TRUE AND p.copie_principale = TRUE ORDER BY p.depose_le DESC LIMIT 1) AS plan_piece_id
      FROM argos_site s WHERE s.client_id = ${client.id}
        AND (${u.role} = 'responsable' OR NOT EXISTS (SELECT 1 FROM argos_site_exclu e WHERE e.site_id = s.id AND e.utilisateur_id = ${u.id}))
      ORDER BY s.commune, s.nom, s.id`;
    const ids = sites.map((s) => s.id);
    const pieces = ids.length ? await sql`
      SELECT p.id, p.site_id, p.rubrique, COALESCE(NULLIF(p.intitule, ''), p.nom_fichier) AS nom_fichier, p.taille, p.depose_le
      FROM argos_piece p WHERE p.site_id = ANY(${ids}) AND p.copie_principale = TRUE ORDER BY p.rubrique, p.depose_le DESC` : [];
    const parSite = {};
    for (const x of pieces) (parSite[x.site_id] = parSite[x.site_id] || []).push({ id: x.id, rubrique: x.rubrique, libelle: RUBRIQUES[x.rubrique], nom: x.nom_fichier, taille: x.taille, depose_le: x.depose_le });
    return { client: client.nom, rubriques: RUBRIQUES, utilisateur: { id: u.id, prenom: u.prenom, nom: u.nom, role: u.role },
      sites: sites.map((s) => Object.assign({}, s, { pieces: parSite[s.id] || [] })) };
  },

  async piece(sql, p, req, res, client, url) {
    const u = await sessionCourante(sql, req, client);
    if (!u) { res.statusCode = 401; res.setHeader("Content-Type", "text/plain; charset=utf-8"); return res.end("Session expirée : reconnectez-vous au portail."); }
    const id = entier(url.searchParams.get("id"), 0);
    const r = await sql`
      SELECT p.cle_objet, p.bucket_principal, p.nom_fichier, s.id AS site_id
      FROM argos_piece p JOIN argos_site s ON s.id = p.site_id
      WHERE p.id = ${id} AND s.client_id = ${client.id} AND p.copie_principale = TRUE
        AND (${u.role} = 'responsable' OR NOT EXISTS (SELECT 1 FROM argos_site_exclu e WHERE e.site_id = s.id AND e.utilisateur_id = ${u.id}))`;
    if (!r.length) { res.statusCode = 404; return res.end("Pièce introuvable."); }
    // LOT 4 — seuils de téléchargement (réglables par client dans ARGOSAdmin) :
    //   palier 1 : seuil_heure_alerte pièces/heure  → « inhabituel » : événement + courriel à l'étude ET au responsable, sans blocage
    //   palier 2 : seuil_heure_pause pièces/heure, ou seuil_jour pièces sur 24 h glissantes → PAUSE automatique (sessions fermées),
    //              présentée comme une pause technique ; rétablissement par le responsable depuis le portail
    const seuils = await sql`SELECT seuil_heure_alerte, seuil_heure_pause, seuil_jour FROM argos_client WHERE id = ${client.id}`;
    const sAlerte = seuils[0].seuil_heure_alerte || 20, sPause = seuils[0].seuil_heure_pause || 50, sJour = seuils[0].seuil_jour || 100;
    const compte = await sql`SELECT COUNT(*) FILTER (WHERE horodatage > NOW() - INTERVAL '1 hour')::int AS heure,
                                    COUNT(*) FILTER (WHERE horodatage > NOW() - INTERVAL '24 hours')::int AS jour
                             FROM argos_telechargement WHERE utilisateur_id = ${u.id}`;
    const heure = compte[0].heure + 1, jour = compte[0].jour + 1; // en comptant la pièce demandée
    if (heure >= sPause || jour >= sJour) {
      await sql`UPDATE argos_utilisateur SET pause_volume = NOW(), maj_le = NOW() WHERE id = ${u.id}`;
      await sql`UPDATE argos_session SET revoque_le = NOW() WHERE utilisateur_id = ${u.id} AND revoque_le IS NULL`;
      const motif = heure >= sPause ? `${heure} pièces en une heure (seuil ${sPause})` : `${jour} pièces en vingt-quatre heures (seuil ${sJour})`;
      await journal(sql, client.id, u.id, null, "pause_volume", req, `Pause automatique : ${motif}`);
      await sql`INSERT INTO argos_evenement (client_id, nature, detail) VALUES (${client.id}, 'pause_volume', ${`${u.prenom} ${u.nom} (${u.courriel}) : accès mis en pause automatiquement — ${motif}. Le responsable peut rétablir depuis le portail.`})`;
      const resp = await sql`SELECT courriel FROM argos_utilisateur WHERE client_id = ${client.id} AND role = 'responsable' AND active = TRUE AND suspendu_le IS NULL AND coupe_par_responsable IS NULL AND id <> ${u.id}`;
      await courriel(sql, client.id, [process.env.ADMIN_COURRIEL, ...resp.map((x) => x.courriel)],
        `[ARGOS · ANORMAL] Accès mis en pause pour volume inhabituel — ${client.nom}`,
        `L'accès de ${u.prenom} ${u.nom} (${u.courriel}) au portail du patrimoine foncier de ${client.nom} a été mis en pause automatiquement : ${motif}.\n\nLe responsable du portail peut rétablir cet accès depuis l'écran « Mon équipe ». FIDAL Notaires peut aussi le faire.\n\nFIDAL Notaires`);
      res.statusCode = 429; res.setHeader("Content-Type", "text/plain; charset=utf-8");
      return res.end(MESSAGE_PAUSE);
    }
    if (heure >= sAlerte) {
      const deja = await sql`SELECT alerte_volume_le FROM argos_utilisateur WHERE id = ${u.id}`;
      if (!deja[0].alerte_volume_le || new Date(deja[0].alerte_volume_le) < new Date(Date.now() - 60 * 60 * 1000)) {
        await sql`UPDATE argos_utilisateur SET alerte_volume_le = NOW() WHERE id = ${u.id}`;
        await sql`INSERT INTO argos_evenement (client_id, nature, detail) VALUES (${client.id}, 'volume_inhabituel', ${`${u.prenom} ${u.nom} (${u.courriel}) : ${heure} pièces ouvertes en une heure (seuil ${sAlerte}). Pas de blocage.`})`;
        const resp = await sql`SELECT courriel FROM argos_utilisateur WHERE client_id = ${client.id} AND role = 'responsable' AND active = TRUE AND suspendu_le IS NULL AND coupe_par_responsable IS NULL AND id <> ${u.id}`;
        await courriel(sql, client.id, [process.env.ADMIN_COURRIEL, ...resp.map((x) => x.courriel)],
          `[ARGOS] Volume de consultations inhabituel — ${client.nom}`,
          `${u.prenom} ${u.nom} (${u.courriel}) a ouvert ${heure} pièces en une heure sur le portail du patrimoine foncier de ${client.nom}. L'accès reste ouvert ; cette information vous est donnée à titre de vigilance.\n\nFIDAL Notaires`);
      }
    }
    await sql`INSERT INTO argos_telechargement (utilisateur_id, piece_id) VALUES (${u.id}, ${id})`;
    // LOT 4 — critère de proportion : plus de la moitié des pièces du client ouvertes par cette personne en sept jours → alerte simple, sans blocage (une fois par semaine)
    try {
      const prop = await sql`SELECT (SELECT COUNT(*)::int FROM argos_piece p JOIN argos_site s ON s.id = p.site_id WHERE s.client_id = ${client.id}) AS total,
                                    (SELECT COUNT(DISTINCT t.piece_id)::int FROM argos_telechargement t WHERE t.utilisateur_id = ${u.id} AND t.horodatage > NOW() - INTERVAL '7 days') AS ouvertes,
                                    (SELECT alerte_proportion_le FROM argos_utilisateur WHERE id = ${u.id}) AS deja`;
      const { total, ouvertes, deja } = prop[0];
      if (total >= 4 && ouvertes * 2 > total && (!deja || new Date(deja) < new Date(Date.now() - 7 * 24 * 60 * 60 * 1000))) {
        await sql`UPDATE argos_utilisateur SET alerte_proportion_le = NOW() WHERE id = ${u.id}`;
        await sql`INSERT INTO argos_evenement (client_id, nature, detail) VALUES (${client.id}, 'proportion_inhabituelle', ${`${u.prenom} ${u.nom} (${u.courriel}) a ouvert ${ouvertes} des ${total} pièces du client en sept jours. Pas de blocage.`})`;
        const resp = await sql`SELECT courriel FROM argos_utilisateur WHERE client_id = ${client.id} AND role = 'responsable' AND active = TRUE AND suspendu_le IS NULL AND coupe_par_responsable IS NULL AND id <> ${u.id}`;
        await courriel(sql, client.id, [process.env.ADMIN_COURRIEL, ...resp.map((x) => x.courriel)],
          `[ARGOS] Proportion de consultations inhabituelle — ${client.nom}`,
          `${u.prenom} ${u.nom} (${u.courriel}) a ouvert ${ouvertes} des ${total} pièces du portail du patrimoine foncier de ${client.nom} en sept jours. L'accès reste ouvert ; cette information vous est donnée à titre de vigilance.\n\nFIDAL Notaires`);
      }
    } catch (e) { console.warn("[argos] proportion", e.message); }
    // 02/11 : le portail SERT la pièce lui-même (flux continu) au lieu de renvoyer vers le stockage ;
    // le client ne voit jamais l'adresse ni le nom du prestataire de stockage, et le nom de fichier est maîtrisé ici.
    return relayer(req, res, r[0].bucket_principal, r[0].cle_objet, r[0].nom_fichier);
  },

  // PLAN DU SITE (image produite dans PAINT par l'étude, déposée dans ARGOSAdmin) : servi pour la fiche de synthèse,
  // sans compter dans les seuils de téléchargement ni dans le journal (ce n'est pas une consultation de pièce)
  async plan(sql, p, req, res, client, url) {
    const u = await sessionCourante(sql, req, client);
    if (!u) { res.statusCode = 401; res.setHeader("Content-Type", "text/plain; charset=utf-8"); return res.end("Session expirée : reconnectez-vous au portail."); }
    const siteId = entier(url.searchParams.get("site_id"), 0);
    const r = await sql`
      SELECT p.cle_objet, p.bucket_principal, p.nom_fichier
      FROM argos_piece p JOIN argos_site s ON s.id = p.site_id
      WHERE s.id = ${siteId} AND s.client_id = ${client.id} AND p.est_plan = TRUE AND p.copie_principale = TRUE
        AND (${u.role} = 'responsable' OR NOT EXISTS (SELECT 1 FROM argos_site_exclu e WHERE e.site_id = s.id AND e.utilisateur_id = ${u.id}))
      ORDER BY p.depose_le DESC LIMIT 1`;
    if (!r.length) { res.statusCode = 404; return res.end("Aucun plan déposé pour ce site."); }
    return relayer(req, res, r[0].bucket_principal, r[0].cle_objet, r[0].nom_fichier);
  },

  // CONTRÔLE CADASTRAL À LA DEMANDE DE FICHE (02/11/2026) : chaque parcelle du site doit exister encore au cadastre (API Carto IGN).
  // Une parcelle disparue ou renumérotée → la fiche ENTIÈRE est bloquée, message au client, alerte à l'étude dans ARGOSAdmin.
  // Références absentes ou illisibles, ou cadastre injoignable : on ne bloque pas (rien ne prouve un changement), on le note seulement.
  async controle_cadastre(sql, p, req, res, client) {
    const u = await sessionCourante(sql, req, client);
    if (!u) { res.statusCode = 401; return { erreur: "Session expirée." }; }
    const siteId = entier(p.site_id, 0);
    const r = await sql`SELECT s.id, s.nom, s.commune, s.code_postal, s.references_, s.insee, s.cadastre_alerte_le, s.cadastre_alerte_detail
                        FROM argos_site s WHERE s.id = ${siteId} AND s.client_id = ${client.id}
                          AND (${u.role} = 'responsable' OR NOT EXISTS (SELECT 1 FROM argos_site_exclu e WHERE e.site_id = s.id AND e.utilisateur_id = ${u.id}))`;
    if (!r.length) { res.statusCode = 404; return { erreur: "Site introuvable." }; }
    const s = r[0];
    const parcelles = parcellesDepuisTexte((s.references_ || {}).cadastre);
    if (!parcelles.length) return { controle: "sans_reference", bloque: false };
    let insee = s.insee;
    try {
      if (!insee) {
        insee = await codeInsee(s.code_postal, s.commune);
        if (insee) await sql`UPDATE argos_site SET insee = ${insee} WHERE id = ${s.id}`;
      }
      if (!insee) return { controle: "commune_inconnue", bloque: false };
      const manquantes = [];
      for (const pc of parcelles) {
        const existe = await parcelleExiste(insee, pc.section, pc.numero);
        if (existe === false) manquantes.push(`${pc.section} ${pc.numero}`);
      }
      if (!manquantes.length) {
        await sql`UPDATE argos_site SET cadastre_controle_le = NOW(), cadastre_alerte_le = NULL, cadastre_alerte_detail = NULL WHERE id = ${s.id}`;
        return { controle: "ok", bloque: false, parcelles: parcelles.length };
      }
      const detail = `Parcelle${manquantes.length > 1 ? "s" : ""} ${manquantes.join(", ")} introuvable${manquantes.length > 1 ? "s" : ""} au cadastre de ${s.commune || insee} (contrôle à la demande de fiche par ${u.prenom} ${u.nom}).`;
      const dejaAlerte = s.cadastre_alerte_le && new Date(s.cadastre_alerte_le) > new Date(Date.now() - 24 * 60 * 60 * 1000);
      await sql`UPDATE argos_site SET cadastre_controle_le = NOW(), cadastre_alerte_le = COALESCE(cadastre_alerte_le, NOW()), cadastre_alerte_detail = ${detail} WHERE id = ${s.id}`;
      if (!dejaAlerte) {
        await sql`INSERT INTO argos_evenement (client_id, nature, detail) VALUES (${client.id}, 'cadastre_evolue', ${`Site « ${s.nom} » : ${detail} Fiche de synthèse bloquée côté client jusqu'à reprise du site dans ARGOSAdmin.`})`;
        await courriel(sql, client.id, [process.env.ADMIN_COURRIEL], `[ARGOS] Références cadastrales à reprendre — ${client.nom}, ${s.nom}`,
          `Bonjour,\n\n${detail}\n\nLa fiche de synthèse de ce site est bloquée côté client (message : références cadastrales plus à jour, se rapprocher de FIDAL Notaires) jusqu'à la mise à jour des références dans ARGOSAdmin.\n\nFIDAL Notaires — ARGOS`);
      }
      return { controle: "evolue", bloque: true, message: MESSAGE_CADASTRE };
    } catch (e) {
      console.warn("[argos] contrôle cadastral indisponible", e.message);
      return { controle: "indisponible", bloque: false };
    }
  },

  async equipe(sql, p, req, res, client) {
    const u = await sessionCourante(sql, req, client);
    if (!u) { res.statusCode = 401; return { erreur: "Session expirée." }; }
    if (u.role !== "responsable") { res.statusCode = 403; return { erreur: "Réservé au responsable." }; }
    const membres = await sql`SELECT id, prenom, nom, courriel, role, active, active_le, derniere_connexion, coupe_par_responsable, suspendu_le, bloque_jusqua, pause_volume
                              FROM argos_utilisateur WHERE client_id = ${client.id} ORDER BY nom, prenom`;
    const connexions = await sql`
      SELECT cx.horodatage, cx.resultat, cx.detail, u.prenom, u.nom, a.libelle AS appareil
      FROM argos_connexion cx LEFT JOIN argos_utilisateur u ON u.id = cx.utilisateur_id LEFT JOIN argos_appareil a ON a.id = cx.appareil_id
      WHERE cx.client_id = ${client.id} ORDER BY cx.horodatage DESC LIMIT 200`;
    const telechargements = await sql`
      SELECT t.horodatage, u.prenom, u.nom, COALESCE(NULLIF(p.intitule, ''), p.nom_fichier) AS nom_fichier, s.nom AS site, s.commune
      FROM argos_telechargement t JOIN argos_utilisateur u ON u.id = t.utilisateur_id JOIN argos_piece p ON p.id = t.piece_id JOIN argos_site s ON s.id = p.site_id
      WHERE u.client_id = ${client.id} ORDER BY t.horodatage DESC LIMIT 200`;
    return { membres, connexions, telechargements };
  },

  // LOT 4 — le responsable lève une PAUSE automatique pour volume (et seulement cela : une coupure ou une suspension reste à FIDAL Notaires)
  async retablir_pause(sql, p, req, res, client) {
    const u = await sessionCourante(sql, req, client);
    if (!u) throw new Error("Session expirée.");
    if (u.role !== "responsable") throw new Error("Réservé au responsable.");
    const cible = entier(p.utilisateur_id, 0);
    const r = await sql`UPDATE argos_utilisateur SET pause_volume = NULL, alerte_volume_le = NULL, maj_le = NOW()
                        WHERE id = ${cible} AND client_id = ${client.id} AND pause_volume IS NOT NULL RETURNING prenom, nom, courriel`;
    if (!r.length) throw new Error("Cette personne n'est pas en pause.");
    await journal(sql, client.id, cible, null, "pause_levee", req, `Pause levée par ${u.prenom} ${u.nom}`);
    await sql`INSERT INTO argos_evenement (client_id, nature, detail) VALUES (${client.id}, 'pause_levee', ${`${u.prenom} ${u.nom} a rétabli l'accès de ${r[0].prenom} ${r[0].nom} (${r[0].courriel}) après une pause automatique.`})`;
    return { ok: true };
  },

  async couper(sql, p, req, res, client) {
    const u = await sessionCourante(sql, req, client);
    if (!u) throw new Error("Session expirée.");
    if (u.role !== "responsable") throw new Error("Réservé au responsable.");
    const cible = entier(p.utilisateur_id, 0);
    if (cible === u.id) throw new Error("Vous ne pouvez pas couper votre propre accès.");
    const r = await sql`UPDATE argos_utilisateur SET coupe_par_responsable = NOW(), maj_le = NOW() WHERE id = ${cible} AND client_id = ${client.id} RETURNING prenom, nom, courriel`;
    if (!r.length) throw new Error("Personne introuvable.");
    await sql`UPDATE argos_session SET revoque_le = NOW() WHERE utilisateur_id = ${cible} AND revoque_le IS NULL`;
    await journal(sql, client.id, cible, null, "coupure_responsable", req, `Coupé par ${u.prenom} ${u.nom}`);
    await sql`INSERT INTO argos_evenement (client_id, nature, detail) VALUES (${client.id}, 'coupure_responsable', ${`${u.prenom} ${u.nom} a coupé l'accès de ${r[0].prenom} ${r[0].nom} (${r[0].courriel}). Rétablissement réservé à FIDAL Notaires.`})`;
    await courriel(sql, client.id, [process.env.ADMIN_COURRIEL], `[ARGOS · ANORMAL] Accès coupé par le responsable — ${client.nom}`,
      `${u.prenom} ${u.nom} a coupé l'accès de ${r[0].prenom} ${r[0].nom} (${r[0].courriel}). Seul FIDAL Notaires peut le rétablir, depuis ARGOSAdmin.`);
    return { ok: true };
  },
};

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  const url = new URL(req.url, "http://x");
  const corps = req.method === "POST" ? lireCorps(req) : {};
  const action = texte(corps.action || url.searchParams.get("action") || "etat", 40);
  try {
    if (!process.env.ARGOS_DATABASE_URL || !process.env.ARGOS_CLE_LECTURE) throw new Error("Variables ARGOS_* absentes.");
    const sql = neon(process.env.ARGOS_DATABASE_URL);
    const c = await sql`SELECT id, nom, actif FROM argos_client WHERE cle_lecture = ${process.env.ARGOS_CLE_LECTURE}`;
    if (!c.length) throw new Error("Clé de lecture inconnue.");
    const client = c[0];
    if (!client.actif && !["etat", "deconnexion"].includes(action)) {
      res.statusCode = 403; res.setHeader("Content-Type", "application/json; charset=utf-8");
      return res.end(JSON.stringify({ erreur: "Accès suspendu par FIDAL Notaires." }));
    }
    const fn = actions[action];
    if (!fn) { res.statusCode = 400; res.setHeader("Content-Type", "application/json; charset=utf-8"); return res.end(JSON.stringify({ erreur: "Action inconnue." })); }
    const resultat = await fn(sql, corps, req, res, client, url);
    if (res.writableEnded) return;
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    return res.end(JSON.stringify(Object.assign({ suspendu: !client.actif }, resultat)));
  } catch (e) {
    console.error("[argos]", action, e);
    if (res.writableEnded) return;
    res.statusCode = e.statusCode || (e.message && /Session expirée/.test(e.message) ? 401 : 400);
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.end(JSON.stringify({ erreur: e.message || "Erreur serveur", mdp: !!e.mdp }));
  }
};
