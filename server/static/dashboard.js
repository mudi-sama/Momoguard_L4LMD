const LEVEL_LABEL = { faible: "Faible", moyen: "Moyen", eleve: "Élevé" }; // Libellés français des niveaux de risque
const stats = { total: 0, faible: 0, moyen: 0, eleve: 0 }; // Compteurs globaux par niveau pour le tableau de bord

function escapeHtml(s) { // Échappe les caractères HTML pour éviter les injections XSS
  return String(s) // Convertit toute valeur en chaîne
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;") // Échappe &, < et >
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;"); // Échappe les guillemets simples et doubles
}

function formatTime(iso) { // Formate une date ISO en affichage local français
  return new Date(iso).toLocaleString("fr-FR", { hour12: false }); // Heure 24h, locale fr-FR
}

function renderStats() { // Met à jour les compteurs et barres de progression dans l'interface
  document.getElementById("stat-total").textContent = stats.total; // Affiche le total d'alertes
  document.getElementById("stat-faible").textContent = stats.faible; // Compteur niveau faible
  document.getElementById("stat-moyen").textContent = stats.moyen; // Compteur niveau moyen
  document.getElementById("stat-eleve").textContent = stats.eleve; // Compteur niveau élevé
  const t = stats.total || 1; // Dénominateur pour les pourcentages (évite division par zéro)
  [["faible", stats.faible], ["moyen", stats.moyen], ["eleve", stats.eleve]].forEach(([lvl, n]) => { // Par niveau de risque
    const bar = document.getElementById("bar-" + lvl); // Barre de progression du niveau
    const cnt = document.getElementById("barc-" + lvl); // Texte numérique à côté de la barre
    if (bar) bar.style.width = Math.round((n / t) * 100) + "%"; // Largeur proportionnelle au total
    if (cnt) cnt.textContent = n; // Met à jour le nombre affiché
  });
}

// --- Graphique en anneau : répartition par type d'arnaque ------------------
const CAT_PALETTE = [ // Palette bleue-première, alignée sur l'identité MoMoGuard
  "#2f39e6", "#5560ff", "#4ea8ff", "#38bdf8", "#6b7bff", "#8b5cf6",
  "#0ea5b7", "#22c1a6", "#f6b73c", "#ff8a5c", "#ec5a86", "#a3b3ff", "#94a3b8",
];
const categories = {}; // Compteurs cumulés par type d'arnaque

function renderDonut() { // Redessine l'anneau SVG et sa légende à partir de `categories`
  const svg = document.getElementById("donut"); // Élément SVG du donut
  const legend = document.getElementById("donut-legend"); // Conteneur de la légende
  const emptyEl = document.getElementById("donut-empty"); // Message « aucune arnaque »
  if (!svg) return; // Page sans graphique : rien à faire
  const entries = Object.entries(categories) // Paires [libellé, nombre]
    .filter(([, n]) => n > 0) // Ignore les catégories vides
    .sort((a, b) => b[1] - a[1]); // Trie du plus fréquent au plus rare
  const total = entries.reduce((s, [, n]) => s + n, 0); // Total des menaces catégorisées
  if (total === 0) { // Aucune arnaque détectée pour l'instant
    svg.innerHTML = ""; svg.style.display = "none"; // Cache l'anneau
    legend.innerHTML = ""; // Vide la légende
    if (emptyEl) emptyEl.style.display = ""; // Affiche le message d'état vide
    return;
  }
  if (emptyEl) emptyEl.style.display = "none"; // Masque le message d'état vide
  svg.style.display = ""; // Affiche l'anneau
  // Piste de fond (cercle complet gris) puis un segment coloré par catégorie.
  let markup = '<circle cx="21" cy="21" r="15.91549430918954" fill="none" stroke="var(--surface-2)" stroke-width="4"></circle>';
  let cumulative = 0; // Pourcentage cumulé pour positionner chaque segment
  entries.forEach(([label, n], i) => { // Un arc par catégorie
    const pct = (n / total) * 100; // Part relative en pourcentage (circonférence = 100)
    const color = CAT_PALETTE[i % CAT_PALETTE.length]; // Couleur du segment
    const offset = ((25 - cumulative) % 100 + 100) % 100; // Décalage : démarre en haut (12 h)
    markup += `<circle cx="21" cy="21" r="15.91549430918954" fill="none" stroke="${color}" stroke-width="4" stroke-dasharray="${pct} ${100 - pct}" stroke-dashoffset="${offset}"><title>${escapeHtml(label)} : ${n}</title></circle>`;
    cumulative += pct; // Avance le curseur pour le prochain segment
  });
  markup += `<text x="21" y="21.5" class="donut-total">${total}</text>`; // Total au centre
  markup += '<text x="21" y="26" class="donut-caption">alertes</text>'; // Légende centrale
  svg.innerHTML = markup; // Injecte le SVG assemblé
  legend.innerHTML = entries.map(([label, n], i) => { // Construit la légende
    const color = CAT_PALETTE[i % CAT_PALETTE.length]; // Même couleur que le segment
    const p = Math.round((n / total) * 100); // Pourcentage arrondi
    return `<div class="legend-item"><span class="legend-dot" style="background:${color}"></span><span class="legend-label">${escapeHtml(label)}</span><span class="legend-val">${n} · ${p}%</span></div>`;
  }).join(""); // Assemble les lignes de légende
}

function bumpCategory(cat) { // Incrémente une catégorie puis rafraîchit le donut
  if (!cat) return; // Rapport sans catégorie (RAS) : ignoré
  categories[cat] = (categories[cat] || 0) + 1; // +1 sur la catégorie concernée
  renderDonut(); // Redessine l'anneau
}

function buildReport(r) { // Construit un élément DOM pour une alerte individuelle
  const li = document.createElement("li"); // Conteneur liste pour le rapport
  li.className = "report " + r.level; // Classe CSS selon le niveau (couleur)
  li.dataset.level = r.level; // Attribut data pour filtrage par niveau
  li.dataset.platform = (r.platform || "").toLowerCase(); // Plateforme en minuscules pour filtre
  li.dataset.agent = (r.agent_id || "").toLowerCase(); // ID agent en minuscules pour filtre
  li.dataset.text = ((r.content || "") + " " + (r.reasons || []).join(" ")).toLowerCase(); // Texte searchable
  const reasons = (r.reasons || []).map((x) => `<li>${escapeHtml(x)}</li>`).join(""); // Liste HTML des raisons du score
  // Assemble le markup HTML du bloc alerte (template)
  li.innerHTML = `
    <div class="report-top">
      <div class="report-meta">
        <span class="tag">${escapeHtml(r.platform)}</span>
        <span class="tag">${escapeHtml(r.event_type)}</span>
        <span>${escapeHtml(r.agent_id)}</span>
        <span>${formatTime(r.created_at)}</span>
      </div>
      <span class="badge ${r.level}">${LEVEL_LABEL[r.level] || r.level} · ${r.score}</span>
    </div>
    <div class="report-content">${escapeHtml(r.content)}</div>
    <ul class="reasons">${reasons}</ul>
    ${r.conseil ? `<div class="report-conseil"><strong>Conseil :</strong> ${escapeHtml(r.conseil)}</div>` : ""}
  `;
  return li; // Retourne le nœud prêt à insérer dans le fil
}

function matchesFilters(node) { // Vérifie si un rapport passe les filtres actifs du dashboard
  const level = document.getElementById("filter-level").value; // Filtre par niveau de risque
  const platform = document.getElementById("filter-platform").value.toLowerCase(); // Filtre par plateforme
  const agent = document.getElementById("filter-agent").value.trim().toLowerCase(); // Filtre par ID agent (partiel)
  const search = document.getElementById("filter-search").value.trim().toLowerCase(); // Recherche textuelle libre
  if (level && node.dataset.level !== level) return false; // Niveau ne correspond pas
  if (platform && node.dataset.platform !== platform) return false; // Plateforme ne correspond pas
  if (agent && !node.dataset.agent.includes(agent)) return false; // Agent ne contient pas la sous-chaîne
  if (search && !node.dataset.text.includes(search)) return false; // Texte ne contient pas la recherche
  return true; // Tous les filtres actifs sont satisfaits
}

function applyFilters() { // Applique les filtres à tous les rapports visibles du fil
  document.querySelectorAll("#feed .report").forEach((node) => { // Parcourt chaque alerte affichée
    node.style.display = matchesFilters(node) ? "" : "none"; // Affiche ou masque selon les filtres
  });
}

function addReport(r, prepend) { // Ajoute un rapport au fil d'actualité
  const feed = document.getElementById("feed"); // Conteneur principal des alertes
  const empty = document.getElementById("empty-state"); // Message « aucune alerte » si présent
  if (empty) empty.remove(); // Supprime l'état vide dès la première alerte
  const node = buildReport(r); // Construit l'élément DOM du rapport
  if (prepend) feed.prepend(node); // Insère en tête (temps réel)
  else feed.appendChild(node); // Insère en fin (chargement initial)
  node.style.display = matchesFilters(node) ? "" : "none"; // Respecte les filtres courants
}

function bumpStats(level) { // Incrémente les compteurs après une nouvelle alerte
  stats.total += 1; // Total global +1
  if (stats[level] !== undefined) stats[level] += 1; // Compteur du niveau concerné +1
  renderStats(); // Rafraîchit l'affichage des statistiques
}

["filter-level", "filter-platform", "filter-agent", "filter-search"].forEach((id) => { // Écouteurs sur les filtres
  const el = document.getElementById(id); // Élément de formulaire filtre
  if (el) el.addEventListener("input", applyFilters); // Réapplique les filtres à chaque saisie
});

// --- Chargement initial ----------------------------------------------------
fetch("/api/reports") // Récupère les rapports existants et les stats au démarrage
  .then((res) => res.json()) // Parse la réponse JSON
  .then((data) => { // Traite les données reçues
    if (data.stats) { Object.assign(stats, data.stats); renderStats(); } // Fusionne les stats serveur et affiche
    if (data.categories) { Object.assign(categories, data.categories); } // Charge la répartition par type d'arnaque
    renderDonut(); // Dessine l'anneau (ou l'état vide) au démarrage
    (data.reports || []).forEach((r) => addReport(r, false)); // Ajoute chaque rapport historique
  })
  .catch((e) => console.error("Erreur de chargement initial :", e)); // Log en cas d'échec réseau

// --- Temps réel ------------------------------------------------------------
const socket = io(); // Connexion WebSocket Socket.IO au serveur
const statusEl = document.getElementById("conn-status"); // Indicateur visuel de connexion
const labelEl = document.getElementById("conn-label"); // Libellé texte en ligne / hors ligne

socket.on("connect", () => { // Événement : connexion établie
  statusEl.classList.add("online"); statusEl.classList.remove("offline"); // Style « en ligne »
  labelEl.textContent = "en ligne"; // Texte indicateur
});
socket.on("disconnect", () => { // Événement : connexion perdue
  statusEl.classList.add("offline"); statusEl.classList.remove("online"); // Style « hors ligne »
  labelEl.textContent = "hors ligne"; // Texte indicateur
});
socket.on("new_report", (r) => { addReport(r, true); bumpStats(r.level); bumpCategory(r.categorie); }); // Nouvelle alerte : prepend + stats + donut

// --- Bouton de démonstration (soutenance) ---
const demoBtn = document.getElementById("btn-demo"); // Bouton pour déclencher une alerte démo
if (demoBtn) { // Présent uniquement sur certaines pages
  demoBtn.addEventListener("click", () => { // Clic sur le bouton démo
    const token = (document.querySelector('meta[name="csrf-token"]') || {}).content || ""; // Jeton CSRF Flask
    demoBtn.disabled = true; // Désactive le bouton pendant la requête
    fetch("/demo", { method: "POST", headers: { "X-CSRFToken": token } }) // POST vers l'endpoint démo
      .then((r) => r.json()) // Attend la réponse JSON (alerte créée côté serveur)
      .catch((e) => console.error("Démo :", e)) // Log erreur éventuelle
      .finally(() => { demoBtn.disabled = false; }); // Réactive le bouton dans tous les cas
  });
}
