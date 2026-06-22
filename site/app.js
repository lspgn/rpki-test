const payloadLabels = {
  routeOrigins: "ROA / VRP",
  routerKeys: "BGPsec Keys",
  aspas: "ASPA",
};

const MAX_ROWS = 500;

let manifest = null;
let currentSummary = null;
let currentView = "validators";
let resourcePayload = "routeOrigins";
let resourceReport = null;
let fileTree = null;
let fileValidator = null;
const resourceCache = new Map();
const fileCache = new Map();

const formatter = new Intl.NumberFormat();
const byteFormatter = new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 });

async function fetchJson(path) {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`${path}: ${response.status}`);
  }
  return response.json();
}

function formatBytes(value) {
  if (typeof value !== "number" || Number.isNaN(value)) {
    return "unknown";
  }
  const units = ["B", "KB", "MB", "GB"];
  let size = value;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${byteFormatter.format(size)} ${units[unit]}`;
}

function formatDuration(seconds) {
  if (typeof seconds !== "number") {
    return "unknown";
  }
  if (seconds < 60) {
    return `${byteFormatter.format(seconds)}s`;
  }
  return `${byteFormatter.format(seconds / 60)}m`;
}

function formatPercent(value) {
  return typeof value === "number" ? `${byteFormatter.format(value)}%` : "unknown";
}

function metric(label, value) {
  const template = document.querySelector("#metric-template");
  const node = template.content.firstElementChild.cloneNode(true);
  node.querySelector(".metric-label").textContent = label;
  node.querySelector(".metric-value").textContent = value;
  return node;
}

function setSubtitle(summary) {
  const generated = summary.generatedAt ? new Date(summary.generatedAt).toLocaleString() : "unknown time";
  document.querySelector("#subtitle").textContent = `${summary.id} generated ${generated}`;
}

function renderMetrics(summary) {
  const grid = document.querySelector("#summary-grid");
  const successful = summary.entries.filter((entry) => entry.success).length;
  const disk = summary.entries.reduce((sum, entry) => sum + (entry.metrics?.bytesOnDisk || 0), 0);
  const exchanged = summary.entries.reduce((sum, entry) => sum + (entry.metrics?.bytesExchanged || 0), 0);
  const resources = Object.values(summary.reports || {}).reduce((sum, report) => sum + (report.totalObjects || 0), 0);
  grid.replaceChildren(
    metric("Validators", formatter.format(summary.entries.length)),
    metric("Successful", `${successful}/${summary.entries.length}`),
    metric("Resources", formatter.format(resources)),
    metric("Disk / Network", `${formatBytes(disk)} / ${formatBytes(exchanged)}`),
  );
}

function linkList(paths) {
  const downloads = document.createElement("div");
  downloads.className = "downloads";
  for (const [label, path] of Object.entries(paths || {})) {
    if (!path) {
      continue;
    }
    const values = Array.isArray(path) ? path : [path];
    values.forEach((item, index) => {
      if (!item) {
        return;
      }
      const link = document.createElement("a");
      link.href = item;
      link.textContent = values.length > 1 ? `${label} ${index + 1}` : label;
      downloads.append(link);
    });
  }
  return downloads;
}

function renderValidators(summary) {
  const tbody = document.querySelector("#validators");
  const fragment = document.createDocumentFragment();
  for (const entry of summary.entries) {
    const row = document.createElement("tr");
    const status = document.createElement("span");
    status.className = `status ${entry.success ? "ok" : "fail"}`;
    status.textContent = entry.success ? "ok" : `failed ${entry.exitCode ?? ""}`.trim();
    const metrics = entry.metrics || {};
    row.innerHTML = `
      <td>${entry.label}</td>
      <td>${entry.version}</td>
      <td></td>
      <td>${formatDuration(metrics.durationSeconds)}</td>
      <td>${formatBytes(metrics.bytesExchanged)}</td>
      <td>${formatBytes(metrics.bytesOnDisk)}</td>
      <td>${formatBytes(metrics.memoryPeakBytes)} / ${formatBytes(metrics.memoryMeanBytes)}</td>
      <td>${formatPercent(metrics.cpuPeakPercent)} / ${formatPercent(metrics.cpuMeanPercent)}</td>
      <td></td>
    `;
    row.children[2].replaceChildren(status);
    row.children[8].replaceChildren(linkList(entry.paths));
    fragment.append(row);
  }
  tbody.replaceChildren(fragment);
}

function setView(view) {
  currentView = view;
  document.querySelectorAll("[data-view]").forEach((button) => {
    button.classList.toggle("is-active", button.dataset.view === view);
  });
  document.querySelectorAll(".view").forEach((section) => {
    section.classList.toggle("is-active", section.id === `${view}-view`);
  });
  if (view === "resources") {
    loadResourceReport().catch(showError);
  }
  if (view === "files") {
    loadFileTree().catch(showError);
  }
}

function resourceText(row) {
  const files = (row.sourceFiles || []).map((file) => `${file.path || ""} ${file.sha256 || ""}`).join(" ");
  return `${row.label || ""} ${row.key || ""} ${(row.seenBy || []).join(" ")} ${(row.missingFrom || []).join(" ")} ${files}`.toLowerCase();
}

function sortResources(rows, sort) {
  const sorted = [...rows];
  sorted.sort((left, right) => {
    if (sort === "object") {
      return (left.label || left.key).localeCompare(right.label || right.key);
    }
    if (sort === "seen") {
      return (right.seenBy?.length || 0) - (left.seenBy?.length || 0);
    }
    if (sort === "missing") {
      return (right.missingFrom?.length || 0) - (left.missingFrom?.length || 0);
    }
    return Number(right.divergent) - Number(left.divergent) || (left.label || left.key).localeCompare(right.label || right.key);
  });
  return sorted;
}

function renderResources() {
  const tbody = document.querySelector("#resources");
  if (!resourceReport) {
    tbody.replaceChildren(emptyRow(4, "Load a resource report to inspect objects."));
    document.querySelector("#resource-count").textContent = "";
    return;
  }
  const query = document.querySelector("#resource-search").value.trim().toLowerCase();
  const sort = document.querySelector("#resource-sort").value;
  let rows = resourceReport.rows || [];
  if (query) {
    rows = rows.filter((row) => resourceText(row).includes(query));
  }
  rows = sortResources(rows, sort);
  const shown = rows.slice(0, MAX_ROWS);
  const excluded = (resourceReport.excludedValidators || [])
    .map((validator) => `${validator.label || validator.id}: ${validator.reason}`)
    .join("; ");
  document.querySelector("#resource-count").textContent =
    `${formatter.format(rows.length)} matching from ${formatter.format(resourceReport.totalObjects)} ${payloadLabels[resourcePayload]} objects`
    + (excluded ? `; excluded: ${excluded}` : "");
  const fragment = document.createDocumentFragment();
  for (const item of shown) {
    const row = document.createElement("tr");
    if (item.divergent) {
      row.className = "is-divergent";
    }
    const files = item.sourceFiles?.length
      ? item.sourceFiles.map((file) => `${file.path || "unknown"} ${file.sha256 || ""}`).join("\n")
      : "not available";
    row.innerHTML = `
      <td>${item.label || item.key}</td>
      <td>${item.seenBy?.length ? item.seenBy.join(", ") : "none"}</td>
      <td class="${item.missingFrom?.length ? "" : "muted"}">${item.missingFrom?.length ? item.missingFrom.join(", ") : "none"}</td>
      <td class="mono">${files}</td>
    `;
    fragment.append(row);
  }
  if (rows.length > shown.length) {
    fragment.append(emptyRow(4, `Showing first ${formatter.format(MAX_ROWS)} matching rows. Refine search to narrow the table.`));
  }
  tbody.replaceChildren(fragment);
}

async function loadResourceReport() {
  if (!currentSummary) {
    return;
  }
  const reportPath = currentSummary.reports?.[resourcePayload]?.path;
  if (!reportPath) {
    resourceReport = null;
    renderResources();
    return;
  }
  if (!resourceCache.has(reportPath)) {
    document.querySelector("#resources").replaceChildren(emptyRow(4, `Loading ${payloadLabels[resourcePayload]} resources...`));
    resourceCache.set(reportPath, await fetchJson(reportPath));
  }
  resourceReport = resourceCache.get(reportPath);
  renderResources();
}

function flattenFileTree(tree) {
  const rows = [];
  for (const entry of tree.entries || []) {
    for (const file of entry.files || []) {
      rows.push({
        root: entry.root,
        path: file.path,
        size: file.size,
        sha256: file.sha256,
      });
    }
  }
  return rows;
}

function fileText(row) {
  return `${row.root || ""} ${row.path || ""} ${row.sha256 || ""}`.toLowerCase();
}

function sortFiles(rows, sort) {
  const sorted = [...rows];
  sorted.sort((left, right) => {
    if (sort === "size-desc") {
      return (right.size || 0) - (left.size || 0);
    }
    if (sort === "sha") {
      return (left.sha256 || "").localeCompare(right.sha256 || "");
    }
    return `${left.root}/${left.path}`.localeCompare(`${right.root}/${right.path}`);
  });
  return sorted;
}

function renderFiles() {
  const tbody = document.querySelector("#files");
  if (!fileTree) {
    tbody.replaceChildren(emptyRow(4, "Select a validator with a cache tree."));
    document.querySelector("#file-count").textContent = "";
    return;
  }
  const query = document.querySelector("#file-search").value.trim().toLowerCase();
  const sort = document.querySelector("#file-sort").value;
  let rows = fileTree.rows;
  if (query) {
    rows = rows.filter((row) => fileText(row).includes(query));
  }
  rows = sortFiles(rows, sort);
  const shown = rows.slice(0, MAX_ROWS);
  document.querySelector("#file-count").textContent =
    `${formatter.format(rows.length)} matching from ${formatter.format(fileTree.files)} files`;
  const fragment = document.createDocumentFragment();
  for (const file of shown) {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${file.root}</td>
      <td class="mono">${file.path}</td>
      <td>${formatBytes(file.size)}</td>
      <td class="mono">${file.sha256}</td>
    `;
    fragment.append(row);
  }
  if (rows.length > shown.length) {
    fragment.append(emptyRow(4, `Showing first ${formatter.format(MAX_ROWS)} matching rows. Refine search to narrow the table.`));
  }
  tbody.replaceChildren(fragment);
}

async function loadFileTree() {
  if (!currentSummary || !fileValidator) {
    renderFiles();
    return;
  }
  const entry = currentSummary.entries.find((item) => item.id === fileValidator);
  const path = entry?.paths?.cacheTree;
  if (!path) {
    fileTree = null;
    renderFiles();
    return;
  }
  if (!fileCache.has(path)) {
    document.querySelector("#files").replaceChildren(emptyRow(4, `Loading ${entry.label} file tree...`));
    const tree = await fetchJson(path);
    fileCache.set(path, { ...tree, rows: flattenFileTree(tree) });
  }
  fileTree = fileCache.get(path);
  renderFiles();
}

function emptyRow(colspan, text) {
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = colspan;
  cell.className = "muted";
  cell.textContent = text;
  row.append(cell);
  return row;
}

function populateFileValidators(summary) {
  const select = document.querySelector("#file-validator");
  select.replaceChildren();
  for (const entry of summary.entries) {
    const option = document.createElement("option");
    option.value = entry.id;
    option.textContent = entry.cacheTree ? entry.label : `${entry.label} (no tree)`;
    option.disabled = !entry.cacheTree;
    select.append(option);
  }
  const first = summary.entries.find((entry) => entry.cacheTree);
  fileValidator = first?.id || null;
  if (fileValidator) {
    select.value = fileValidator;
  }
}

function render(summary) {
  currentSummary = summary;
  setSubtitle(summary);
  renderMetrics(summary);
  renderValidators(summary);
  populateFileValidators(summary);
  renderResources();
  renderFiles();
}

async function loadRun(runId) {
  const summary = await fetchJson(`data/runs/${runId}/summary.json`);
  resourceReport = null;
  fileTree = null;
  render(summary);
  if (currentView === "resources") {
    await loadResourceReport();
  }
  if (currentView === "files") {
    await loadFileTree();
  }
}

function setupControls() {
  document.querySelectorAll("[data-view]").forEach((button) => {
    button.addEventListener("click", () => setView(button.dataset.view));
  });
  document.querySelector("#resource-payload").addEventListener("change", (event) => {
    resourcePayload = event.target.value;
    resourceReport = null;
    loadResourceReport().catch(showError);
  });
  document.querySelector("#resource-search").addEventListener("input", renderResources);
  document.querySelector("#resource-sort").addEventListener("change", renderResources);
  document.querySelector("#file-validator").addEventListener("change", (event) => {
    fileValidator = event.target.value;
    fileTree = null;
    loadFileTree().catch(showError);
  });
  document.querySelector("#file-search").addEventListener("input", renderFiles);
  document.querySelector("#file-sort").addEventListener("change", renderFiles);
}

function setupRuns() {
  const select = document.querySelector("#run-select");
  select.replaceChildren();
  for (const run of manifest.runs || []) {
    const option = document.createElement("option");
    option.value = run.id;
    option.textContent = `${run.id} ${run.success ? "" : "(failed)"}`;
    select.append(option);
  }
  select.value = manifest.latestRun;
  select.addEventListener("change", () => loadRun(select.value).catch(showError));
}

function showError(error) {
  document.querySelector("#subtitle").textContent = `Unable to load dashboard data: ${error.message}`;
}

async function main() {
  setupControls();
  manifest = await fetchJson("data/manifest.json");
  setupRuns();
  await loadRun(manifest.latestRun);
}

main().catch(showError);
