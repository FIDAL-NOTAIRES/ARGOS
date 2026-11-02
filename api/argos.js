/* ARGOSAdmin · /api/ronde — RONDE DE NUIT (LOT 4, 02/11/2026).
   Appelée chaque nuit par la tâche planifiée Vercel (vercel.json → "crons", 3 h UTC, une fois par jour : limite du forfait Hobby).
   Vercel ajoute l'en-tête Authorization: Bearer <CRON_SECRET> si la variable CRON_SECRET existe sur le projet ; on l'exige alors.
   Sans CRON_SECRET, la ronde reste accessible mais ne fait que des lectures et des vérifications : aucun risque de modification. */
const { neon } = require("@neondatabase/serverless");
const { ronde } = require("./admin.js");

module.exports = async (req, res) => {
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  const secret = process.env.CRON_SECRET;
  if (secret && String(req.headers["authorization"] || "") !== `Bearer ${secret}`) {
    res.statusCode = 401;
    return res.end(JSON.stringify({ erreur: "Ronde réservée à la tâche planifiée." }));
  }
  try {
    const sql = neon(process.env.DATABASE_URL);
    const r = await ronde(sql, { manuel: false });
    return res.end(JSON.stringify(r));
  } catch (e) {
    console.error("[ronde]", e);
    res.statusCode = 500;
    return res.end(JSON.stringify({ erreur: e.message }));
  }
};
