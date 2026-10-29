/* ARGOS · /api/ilc — Indice des loyers commerciaux (ILC), lu à la source : Insee, base BDM, série 001532540
   (« Indice des loyers commerciaux (ILC) - Base 100 au 1er trimestre 2008 »), service web public SDMX, sans clé.
   Le serveur lit l'Insee (pas le navigateur, que l'Insee n'autorise pas à interroger directement) et rend une réponse simple :
   { serie, publie, observations: [{ periode: "2026-Q2", valeur: 137.16 }, …] }  (observations de la plus ancienne à la plus récente)
   « publie » = date de dernière mise à jour de la série à l'Insee ; l'ILC n'étant jamais révisé, c'est la date de parution du dernier indice.
   Réponse gardée en cache 12 heures. */
const SOURCE = 'https://bdm.insee.fr/series/sdmx/data/SERIES_BDM/001532540?startPeriod=2008';

module.exports = async (req, res) => {
  try {
    const r = await fetch(SOURCE, { headers: { Accept: 'application/xml' } });
    if (!r.ok) throw new Error('Insee ' + r.status);
    const xml = await r.text();
    const serie = /<Series\b[^>]*>/.exec(xml);
    if (!serie) throw new Error('réponse Insee illisible');
    const maj = /LAST_UPDATE="([0-9-]+)"/.exec(serie[0]);
    const observations = [];
    const re = /<Obs\b[^>]*\bTIME_PERIOD="([0-9]{4}-Q[1-4])"[^>]*\bOBS_VALUE="([0-9.]+)"[^>]*>/g;
    let m;
    while ((m = re.exec(xml))) observations.push({ periode: m[1], valeur: Number(m[2]) });
    /* l'ordre des attributs peut varier : seconde lecture si la première n'a rien donné */
    if (!observations.length) {
      const re2 = /<Obs\b([^>]*)>/g;
      while ((m = re2.exec(xml))) {
        const p = /TIME_PERIOD="([^"]+)"/.exec(m[1]), v = /OBS_VALUE="([0-9.]+)"/.exec(m[1]);
        if (p && v) observations.push({ periode: p[1], valeur: Number(v[1]) });
      }
    }
    if (!observations.length) throw new Error('aucune valeur dans la réponse Insee');
    observations.sort((a, b) => a.periode.localeCompare(b.periode));
    res.setHeader('Cache-Control', 's-maxage=43200, stale-while-revalidate=86400');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.status(200).send(JSON.stringify({ serie: '001532540', source: 'Insee', publie: maj ? maj[1] : null, observations }));
  } catch (e) {
    res.setHeader('Cache-Control', 'no-store');
    res.status(502).json({ erreur: String(e.message || e) });
  }
};
