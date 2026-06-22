const payloadLabels = {
  routeOrigins: "ROA / VRP",
  routerKeys: "BGPsec Keys",
  aspas: "ASPA",
};

let manifest = null;
let currentSummary = null;
let currentPayload = "routeOrigins";

const formatter = new Intl.NumberFormat();

async function fetchJson(path) {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`${path}: ${response.status}`);
  }
  return response.json();
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) {
    return "n/a";
  }
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let value = bytes;
  let unit = units[0];
  for (let index = 1; index < units.length && value >= 1024; index += 1) {
    value /= 1024;
    unit = units[index];
  }
  return `${value >= 10 || unit === "B" ? value.toFixed(0) : value.toFixed(1)} ${unit}`;
}

function formatCores(cores) {
  if (!Number.isFinite(cores)) {
    return "n/a";
  }
  return `${cores.toFixed(2)} cores`;
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
  const peakCpu = Math.max(...summary.entries.map((entry) => entry.resourceUsage?.peakProcessorCores).filter(Number.isFinite), 0);
  const peakMemory = Math.max(...summary.entries.map((entry) => entry.resourceUsage?.peakMemoryBytes).filter(Number.isFinite), 0);
  grid.append(
    metric("Validators", formatter.format(summary.entries.length)),
    metric("Successful", `${successful}/${summary.entries.length}`),
    metric(payloadLabels[currentPayload], formatter.format(totalForPayload)),
    metric("Unsupported", formatter.format(unsupported)),
    metric("Peak CPU", formatCores(peakCpu)),
    metric("Peak RAM", formatBytes(peakMemory)),
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
      const paths = Array.isArray(path) ? path : [path];
      paths.forEach((item, index) => {
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
      <td>${formatCores(entry.resourceUsage?.peakProcessorCores)}</td>
      <td>${formatBytes(entry.resourceUsage?.peakMemoryBytes)}</td>
      <td>${unsupported ? '<span class="muted">unsupported</span>' : formatter.format(entry.counts[currentPayload] || 0)}</td>
      <td>${(entry.unsupported || []).length ? entry.unsupported.join(", ") : '<span class="muted">none</span>'}</td>
      <td></td>
    `;
    row.children[2].replaceChildren(status);
    row.children[7].replaceChildren(downloads);
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

function render(summary) {
  currentSummary = summary;
  setSubtitle(summary);
  renderMetrics(summary);
  renderEntries(summary);
  renderDiffs(summary);
}

async function loadRun(runId) {
  const summary = await fetchJson(`data/runs/${runId}/summary.json`);
  render(summary);
}

function setupTabs() {
  for (const button of document.querySelectorAll(".tab")) {
    button.addEventListener("click", () => {
      currentPayload = button.dataset.payload;
      document.querySelectorAll(".tab").forEach((tab) => tab.classList.toggle("is-active", tab === button));
      if (currentSummary) {
        render(currentSummary);
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
