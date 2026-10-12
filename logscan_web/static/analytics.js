const number = new Intl.NumberFormat();

function formatBytes(value) {
  if (!value) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const unit = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
  return `${(value / (1024 ** unit)).toFixed(unit ? 1 : 0)} ${units[unit]}`;
}

function formatDuration(seconds) {
  if (seconds == null) return "Not available";
  const days = Math.floor(seconds / 86400);
  const hours = Math.round((seconds % 86400) / 3600);
  return days ? `${days}d ${hours}h` : `${hours}h`;
}

function renderMetrics(selector, items) {
  const target = document.querySelector(selector);
  items.forEach(([label, value]) => {
    const item = document.createElement("div");
    const heading = document.createElement("span"); heading.textContent = label;
    const total = document.createElement("strong"); total.textContent = value;
    item.append(heading, total); target.append(item);
  });
}

function renderSummary(totals) {
  renderMetrics("#analytics-summary", [
    ["Kometa logs uploaded", number.format(totals.tools?.kometa || 0)],
    ["ImageMaid logs uploaded", number.format(totals.tools?.imagemaid || 0)],
    ["Log lines processed", number.format(totals.lines_processed)],
    ["Data processed", formatBytes(totals.bytes_processed)],
    ["Missing people images identified", number.format(totals.people_submitted)],
    ["Missing people images resolved", number.format(totals.people_addressed)],
    ["ImageMaid files removed", number.format(totals.imagemaid_files_removed || 0)],
    ["ImageMaid space recovered", formatBytes(totals.imagemaid_bytes_recovered || 0)],
    ["Batch uploads", number.format(totals.batches)],
    ["Duplicates reused", number.format(totals.duplicates_reused || 0)],
    ["Average time to resolve", formatDuration(totals.average_address_seconds)],
    ["Rejected uploads", number.format(Object.values(totals.rejections).reduce((sum, value) => sum + value, 0))],
  ]);
  const seconds = totals.imagemaid_runtime_seconds || 0;
  renderMetrics("#analytics-imagemaid-summary", [
    ["Files removed", number.format(totals.imagemaid_files_removed || 0)],
    ["Space recovered", formatBytes(totals.imagemaid_bytes_recovered || 0)],
    ["Completed runs", number.format(totals.imagemaid_completed_runs || 0)],
    ["Cleanup reports", number.format(totals.imagemaid_cleanup_reports || 0)],
    ["Total runtime", `${number.format(Math.floor(seconds / 3600))}h ${Math.floor(seconds % 3600 / 60)}m ${seconds % 60}s`],
  ]);
  for (const tool of ["kometa", "imagemaid"]) {
    document.querySelector(`#analytics-${tool}-total`).textContent = `${number.format(totals.tools?.[tool] || 0)} logs`;
  }
}

function renderBars(selector, values, empty = "No activity yet") {
  const target = document.querySelector(selector);
  const entries = Object.entries(values || {}).sort((left, right) => right[1] - left[1]);
  if (!entries.length) { target.textContent = empty; target.classList.add("empty-metrics"); return; }
  const maximum = entries[0][1];
  entries.slice(0, 12).forEach(([label, value]) => {
    const row = document.createElement("div"); row.className = "metric-bar";
    const name = document.createElement("span"); name.textContent = label.replaceAll("_", " ");
    if (selector === "#analytics-tools" && ["kometa", "imagemaid"].includes(label)) {
      const icon = document.createElement("img"); icon.src = `/static/${label}.png`; icon.alt = ""; icon.className = "tool-icon";
      name.textContent = label === "imagemaid" ? "ImageMaid" : "Kometa"; name.prepend(icon);
    }
    const count = document.createElement("strong"); count.textContent = number.format(value);
    const track = document.createElement("i");
    const fill = document.createElement("b"); fill.style.width = `${Math.max(3, value / maximum * 100)}%`;
    track.append(fill); row.append(name, count, track); target.append(row);
  });
}

function renderDays(days) {
  const target = document.querySelector("#analytics-days");
  const entries = Object.entries(days).sort(([left], [right]) => right.localeCompare(left)).slice(0, 30);
  if (!entries.length) {
    const row = document.createElement("tr"); const cell = document.createElement("td");
    cell.colSpan = 6; cell.textContent = "No activity yet"; row.append(cell); target.append(row); return;
  }
  entries.forEach(([date, values]) => {
    const row = document.createElement("tr");
    [date, number.format(values.successful_logs), number.format(values.lines_processed), formatBytes(values.bytes_processed), number.format(values.people_submitted), number.format(values.people_addressed)].forEach((value) => {
      const cell = document.createElement("td"); cell.textContent = value; row.append(cell);
    });
    target.append(row);
  });
}

function renderCleanupDays(days) {
  const target = document.querySelector("#analytics-imagemaid-days");
  const entries = Object.entries(days).filter(([, values]) => values.tools?.imagemaid).sort(([left], [right]) => right.localeCompare(left)).slice(0, 30);
  if (!entries.length) {
    const row = document.createElement("tr"); const cell = document.createElement("td");
    cell.colSpan = 5; cell.textContent = "No ImageMaid activity yet"; row.append(cell); target.append(row); return;
  }
  entries.forEach(([date, values]) => {
    const row = document.createElement("tr");
    [date, number.format(values.tools.imagemaid), number.format(values.imagemaid_completed_runs || 0), number.format(values.imagemaid_files_removed || 0), formatBytes(values.imagemaid_bytes_recovered || 0)].forEach((value) => {
      const cell = document.createElement("td"); cell.textContent = value; row.append(cell);
    });
    target.append(row);
  });
}

fetch("/api/analytics").then((response) => {
  if (!response.ok) throw new Error("Analytics could not be loaded.");
  return response.json();
}).then(({ started_at: startedAt, totals, days }) => {
  renderSummary(totals); renderDays(days); renderCleanupDays(days);
  document.querySelector("#analytics-since").textContent = `Tracking since ${new Date(startedAt).toLocaleDateString()}`;
  renderBars("#analytics-sources", totals.sources);
  renderBars("#analytics-tools", totals.tools);
  renderBars("#analytics-imagemaid-versions", totals.imagemaid_versions);
  renderBars("#analytics-imagemaid-modes", totals.imagemaid_modes);
  renderBars("#analytics-imagemaid-platforms", totals.imagemaid_platforms);
  renderBars("#analytics-imagemaid-branches", totals.imagemaid_branches);
  renderBars("#analytics-versions", totals.kometa_versions);
  renderBars("#analytics-kometa-branches", totals.kometa_branches);
  renderBars("#analytics-kometa-platforms", totals.kometa_platforms);
  renderBars("#analytics-installation-methods", totals.installation_methods);
  renderBars("#analytics-launchers", totals.launchers);
  renderBars("#analytics-quickstart-versions", totals.quickstart_versions);
  renderBars("#analytics-quickstart-branches", totals.quickstart_branches);
  renderBars("#analytics-quickstart-platforms", totals.quickstart_platforms);
  renderBars("#analytics-plex-versions", totals.plex_versions);
  renderBars("#analytics-plex-platforms", totals.plex_platforms);
  renderBars("#analytics-plex-channels", totals.plex_update_channels);
  renderBars("#analytics-plex-library-types", totals.plex_library_types);
  renderBars("#analytics-plex-agents", totals.plex_agents);
  renderBars("#analytics-plex-scanners", totals.plex_scanners);
  renderBars("#analytics-severity", totals.recommendations_by_severity);
  renderBars("#analytics-rejections", totals.rejections);
  renderBars("#analytics-recommendations", totals.recommendations_by_id);
}).catch((error) => { document.querySelector("#analytics-summary").textContent = error.message; });
