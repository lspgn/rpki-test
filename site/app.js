const payloadLabels = {
  routeOrigins: "ROA / VRP",
  routerKeys: "BGPsec Keys",
  aspas: "ASPA",
};

let manifest = null;
let currentSummary = null;
let currentReport = null;
let currentPayload = "routeOrigins";

const formatter = new Intl.NumberFormat();

async function fetchJson(path) {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`${path}: ${response.status}`);
  }
  return response.json();
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
  grid.replaceChildren();
  const successful = summary.entries.filter((entry) => entry.success).length;
  const totalForPayload = summary.entries.reduce((sum, entry) => sum + (entry.counts[currentPayload] || 0), 0);
  const unsupported = summary.entries.filter((entry) => (entry.unsupported || []).includes(currentPayload)).length;
  grid.append(
    metric("Validators", formatter.format(summary.entries.length)),
    metric("Successful", `${successful}/${summary.entries.length}`),
    metric(payloadLabels[currentPayload], formatter.format(totalForPayload)),
    metric("Unsupported", formatter.format(unsupported)),
  );
}

function renderEntries(summary) {
  const tbody = document.querySelector("#entries");
  tbody.replaceChildren();
  for (const entry of summary.entries) {
    const row = document.createElement("tr");
    const unsupported = (entry.unsupported || []).includes(currentPayload);
    const status = document.createElement("span");
    status.className = `status ${entry.success ? "ok" : "fail"}`;
    status.textContent = entry.success ? "ok" : `failed ${entry.exitCode ?? ""}`.trim();

    const downloads = document.createElement("div");
    downloads.className = "downloads";
    for (const [label, path] of Object.entries(entry.paths || {})) {
      if (!path) {
        continue;
      }
      const paths = Array.isArray(path) ? path : [path];
      paths.forEach((item, index) => {
        if (!item) {
          return;
        }
        const link = document.createElement("a");
        link.href = item;
        link.textContent = paths.length > 1 ? `${label} ${index + 1}` : label;
        downloads.append(link);
      });
    }

    row.innerHTML = `
      <td>${entry.label}</td>
      <td>${entry.version}</td>
      <td></td>
      <td>${unsupported ? '<span class="muted">unsupported</span>' : formatter.format(entry.counts[currentPayload] || 0)}</td>
      <td>${(entry.unsupported || []).length ? entry.unsupported.join(", ") : '<span class="muted">none</span>'}</td>
      <td></td>
    `;
    row.children[2].replaceChildren(status);
    row.children[5].replaceChildren(downloads);
    tbody.append(row);
  }
}

function renderDiffs(summary) {
  const diffs = document.querySelector("#diffs");
  diffs.replaceChildren();
  if (!summary.comparisons.length) {
    const empty = document.createElement("p");
    empty.className = "muted";
    empty.textContent = "No comparisons are available for this run.";
    diffs.append(empty);
    return;
  }

  for (const comparison of summary.comparisons) {
    const payload = comparison.payloads[currentPayload];
    const block = document.createElement("article");
    block.className = "diff";
    block.innerHTML = `
      <strong>${comparison.left} vs ${comparison.right}</strong>
      <span class="diff-counts">only left: ${formatter.format(payload.onlyLeft)} · only right: ${formatter.format(payload.onlyRight)}</span>
    `;
    diffs.append(block);
  }
}

function renderPresence(report) {
  const tbody = document.querySelector("#presence");
  tbody.replaceChildren();
  if (!report || !report.rows.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 3;
    cell.className = "muted";
    cell.textContent = "No objects are available for this payload.";
    row.append(cell);
    tbody.append(row);
    return;
  }

  const fragment = document.createDocumentFragment();
  for (const item of report.rows) {
    const row = document.createElement("tr");
    if (item.divergent) {
      row.className = "is-divergent";
    }
    const object = document.createElement("td");
    object.textContent = item.label || item.key;
    const seen = document.createElement("td");
    seen.textContent = item.seenBy.length ? item.seenBy.join(", ") : "none";
    const missing = document.createElement("td");
    missing.className = item.missingFrom.length ? "" : "muted";
    missing.textContent = item.missingFrom.length ? item.missingFrom.join(", ") : "none";
    row.append(object, seen, missing);
    fragment.append(row);
  }
  tbody.append(fragment);
}

function render(summary) {
  currentSummary = summary;
  setSubtitle(summary);
  renderMetrics(summary);
  renderEntries(summary);
  renderDiffs(summary);
  renderPresence(currentReport);
}

async function loadRun(runId) {
  const summary = await fetchJson(`data/runs/${runId}/summary.json`);
  currentSummary = summary;
  currentReport = null;
  render(summary);
  await loadReport();
}

async function loadReport() {
  if (!currentSummary) {
    return;
  }
  const reportPath = currentSummary.reports?.[currentPayload]?.path;
  currentReport = reportPath ? await fetchJson(reportPath) : null;
  render(currentSummary);
}

function setupTabs() {
  for (const button of document.querySelectorAll(".tab")) {
    button.addEventListener("click", () => {
      currentPayload = button.dataset.payload;
      document.querySelectorAll(".tab").forEach((tab) => tab.classList.toggle("is-active", tab === button));
      if (currentSummary) {
        loadReport().catch((error) => {
          document.querySelector("#subtitle").textContent = `Unable to load object report: ${error.message}`;
        });
      }
    });
  }
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
  select.addEventListener("change", () => loadRun(select.value));
}

async function main() {
  setupTabs();
  manifest = await fetchJson("data/manifest.json");
  setupRuns();
  await loadRun(manifest.latestRun);
}

main().catch((error) => {
  document.querySelector("#subtitle").textContent = `Unable to load dashboard data: ${error.message}`;
});
