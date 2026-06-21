const LEVEL_LABEL = { faible: "Faible", moyen: "Moyen", eleve: "Élevé" };
const stats = { total: 0, faible: 0, moyen: 0, eleve: 0 };

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function formatTime(iso) {
  return new Date(iso).toLocaleString("fr-FR", { hour12: false });
}

function renderStats() {
  document.getElementById("stat-total").textContent = stats.total;
  document.getElementById("stat-faible").textContent = stats.faible;
  document.getElementById("stat-moyen").textContent = stats.moyen;
  document.getElementById("stat-eleve").textContent = stats.eleve;
}

function buildReport(r) {
  const li = document.createElement("li");
  li.className = "report " + r.level;
  li.dataset.level = r.level;
  li.dataset.platform = (r.platform || "").toLowerCase();
  li.dataset.agent = (r.agent_id || "").toLowerCase();
  li.dataset.text = ((r.content || "") + " " + (r.reasons || []).join(" ")).toLowerCase();
  const reasons = (r.reasons || []).map((x) => `<li>${escapeHtml(x)}</li>`).join("");
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
  `;
  return li;
}

function matchesFilters(node) {
  const level = document.getElementById("filter-level").value;
  const platform = document.getElementById("filter-platform").value.toLowerCase();
  const agent = document.getElementById("filter-agent").value.trim().toLowerCase();
  const search = document.getElementById("filter-search").value.trim().toLowerCase();
  if (level && node.dataset.level !== level) return false;
  if (platform && node.dataset.platform !== platform) return false;
  if (agent && !node.dataset.agent.includes(agent)) return false;
  if (search && !node.dataset.text.includes(search)) return false;
  return true;
}

function applyFilters() {
  document.querySelectorAll("#feed .report").forEach((node) => {
    node.style.display = matchesFilters(node) ? "" : "none";
  });
}

function addReport(r, prepend) {
  const feed = document.getElementById("feed");
  const empty = document.getElementById("empty-state");
  if (empty) empty.remove();
  const node = buildReport(r);
  if (prepend) feed.prepend(node);
  else feed.appendChild(node);
  node.style.display = matchesFilters(node) ? "" : "none";
}

function bumpStats(level) {
  stats.total += 1;
  if (stats[level] !== undefined) stats[level] += 1;
  renderStats();
}

["filter-level", "filter-platform", "filter-agent", "filter-search"].forEach((id) => {
  const el = document.getElementById(id);
  if (el) el.addEventListener("input", applyFilters);
});

// --- Thème : géré dans le gabarit (base.html), partagé par toutes les pages ---

// --- Chargement initial ----------------------------------------------------
fetch("/api/reports")
  .then((res) => res.json())
  .then((data) => {
    if (data.stats) { Object.assign(stats, data.stats); renderStats(); }
    (data.reports || []).forEach((r) => addReport(r, false));
  })
  .catch((e) => console.error("Erreur de chargement initial :", e));

// --- Temps réel ------------------------------------------------------------
const socket = io();
const statusEl = document.getElementById("conn-status");
const labelEl = document.getElementById("conn-label");

socket.on("connect", () => {
  statusEl.classList.add("online"); statusEl.classList.remove("offline");
  labelEl.textContent = "en ligne";
});
socket.on("disconnect", () => {
  statusEl.classList.add("offline"); statusEl.classList.remove("online");
  labelEl.textContent = "hors ligne";
});
socket.on("new_report", (r) => { addReport(r, true); bumpStats(r.level); });
