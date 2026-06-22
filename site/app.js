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
let resourceRows = [];
let resourcePage = 0;
let fileTree = null;
let fileRows = [];
let filePage = 0;
let fileValidator = null;
let timelineValidator = null;
let timelineData = null;
let timeRefreshTimer = null;
const resourceCache = new Map();
const resourceChunkCache = new Map();
const fileCache = new Map();
const fileChunkCache = new Map();
const timelineCache = new Map();

const formatter = new Intl.NumberFormat();
const byteFormatter = new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 });
const relativeTimeFormatter = new Intl.RelativeTimeFormat(undefined, { numeric: "always" });

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

function parseTimestamp(value) {
  if (!value) {
    return null;
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function formatRelativeTime(value, now = new Date()) {
  const date = parseTimestamp(value);
  if (!date) {
    return "unknown time";
  }
  const diffSeconds = Math.round((date.getTime() - now.getTime()) / 1000);
  const absSeconds = Math.abs(diffSeconds);
  if (absSeconds < 5) {
    return "just now";
  }
  if (absSeconds < 60) {
    return relativeTimeFormatter.format(diffSeconds, "second");
  }
  if (absSeconds < 3600) {
    return relativeTimeFormatter.format(Math.round(diffSeconds / 60), "minute");
  }
  if (absSeconds < 86400) {
    return relativeTimeFormatter.format(Math.round(diffSeconds / 3600), "hour");
  }
  return relativeTimeFormatter.format(Math.round(diffSeconds / 86400), "day");
}

function formatPercent(value) {
  return typeof value === "number" ? `${byteFormatter.format(value)}%` : "unknown";
}

function formatRate(value) {
  return typeof value === "number" ? `${formatBytes(value)}/s` : "unknown";
}

function formatOffset(seconds) {
  if (typeof seconds !== "number") {
    return "unknown";
  }
  const minutes = Math.floor(seconds / 60);
  const remaining = Math.floor(seconds % 60);
  return `${minutes}:${String(remaining).padStart(2, "0")}`;
}

function timelineBucketLabel(offset, bucketSeconds) {
  const index = Math.floor((offset || 0) / (bucketSeconds || 10));
  return `${formatOffset(index * (bucketSeconds || 10))}-${formatOffset((index + 1) * (bucketSeconds || 10))}`;
}

function metric(label, value) {
  const template = document.querySelector("#metric-template");
  const node = template.content.firstElementChild.cloneNode(true);
  node.querySelector(".metric-label").textContent = label;
  node.querySelector(".metric-value").textContent = value;
  return node;
}

function setSubtitle(summary) {
  const generated = parseTimestamp(summary.generatedAt);
  const relative = formatRelativeTime(summary.generatedAt);
  const exact = generated ? generated.toLocaleString() : "unknown time";
  document.querySelector("#subtitle").textContent = `${summary.id} generated ${relative} (${exact})`;
}

function updateRunOptionLabels() {
  const select = document.querySelector("#run-select");
  const now = new Date();
  for (const option of select.options) {
    const relative = option.dataset.generatedAt ? ` - ${formatRelativeTime(option.dataset.generatedAt, now)}` : "";
    const failed = option.dataset.success === "false" ? " (failed)" : "";
    option.textContent = `${option.value}${relative}${failed}`;
  }
}

function refreshTimes() {
  if (currentSummary) {
    setSubtitle(currentSummary);
  }
  if (manifest) {
    updateRunOptionLabels();
  }
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
  const visible = {
    config: paths?.config,
    stdout: paths?.stdout,
    stderr: paths?.stderr,
    logs: paths?.logs,
    support: paths?.support,
    status: paths?.status,
  };
  for (const [label, path] of Object.entries(visible)) {
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

function selectedTimelineSeries() {
  return [...document.querySelectorAll("[data-timeline-series]")]
    .filter((input) => input.checked)
    .map((input) => input.dataset.timelineSeries);
}

function timelineSeriesConfig() {
  return {
    cpu: {
      label: "CPU",
      color: "#146c5c",
      value: (bucket) => bucket.cpuPercent,
      format: formatPercent,
    },
    memory: {
      label: "Memory",
      color: "#6f5fb8",
      value: (bucket) => bucket.memoryBytes,
      format: formatBytes,
    },
    network: {
      label: "Network",
      color: "#b65c27",
      value: (bucket) => {
        const docker = (bucket.networkRxBps || 0) + (bucket.networkTxBps || 0);
        const packet = ((bucket.flowRxBytes || 0) + (bucket.flowTxBytes || 0)) / (timelineData?.bucketSeconds || 10);
        return docker || packet || null;
      },
      format: formatRate,
    },
    disk: {
      label: "Disk",
      color: "#587187",
      value: (bucket) => bucket.diskBytes,
      format: formatBytes,
    },
    pids: {
      label: "Processes",
      color: "#7b6a20",
      value: (bucket) => bucket.pids,
      format: (value) => (typeof value === "number" ? formatter.format(value) : "unknown"),
    },
  };
}

function svgElement(name, attrs = {}) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", name);
  for (const [key, value] of Object.entries(attrs)) {
    node.setAttribute(key, value);
  }
  return node;
}

function linePath(points) {
  return points.map((point, index) => `${index ? "L" : "M"}${point[0].toFixed(1)},${point[1].toFixed(1)}`).join(" ");
}

function renderTimelineChart(timeline) {
  const svg = document.querySelector("#timeline-chart");
  svg.replaceChildren();
  const buckets = timeline?.buckets || [];
  if (!buckets.length) {
    svg.setAttribute("viewBox", "0 0 900 120");
    svg.append(svgElement("text", { x: 24, y: 64, class: "timeline-empty" }));
    svg.lastElementChild.textContent = "No timeline samples";
    return;
  }

  const configs = timelineSeriesConfig();
  const enabled = selectedTimelineSeries().filter((key) => configs[key]);
  const lanes = enabled.length ? enabled : ["cpu"];
  const width = 980;
  const left = 112;
  const right = 24;
  const top = 24;
  const laneHeight = 66;
  const height = top + laneHeight * lanes.length + 32;
  const plotWidth = width - left - right;
  const duration = Math.max(
    timeline.durationSeconds || 0,
    ...buckets.map((bucket) => bucket.endOffsetSeconds || 0),
    timeline.bucketSeconds || 10,
  );
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.style.minHeight = `${height}px`;

  const markerGroup = svgElement("g", { class: "timeline-markers" });
  for (const event of (timeline.events || []).slice(0, 300)) {
    const x = left + ((event.offsetSeconds || 0) / duration) * plotWidth;
    markerGroup.append(svgElement("line", { x1: x, x2: x, y1: top - 6, y2: height - 24, class: `event-marker ${event.stream}` }));
  }
  svg.append(markerGroup);

  lanes.forEach((key, laneIndex) => {
    const config = configs[key];
    const yTop = top + laneIndex * laneHeight;
    const yBottom = yTop + laneHeight - 22;
    const values = buckets.map((bucket) => config.value(bucket)).filter((value) => typeof value === "number" && !Number.isNaN(value));
    const maxValue = Math.max(...values, 0);
    const lane = svgElement("g", { class: "timeline-lane" });
    lane.append(svgElement("line", { x1: left, x2: width - right, y1: yBottom, y2: yBottom, class: "axis" }));
    const title = svgElement("text", { x: 18, y: yTop + 18, class: "lane-label" });
    title.textContent = config.label;
    lane.append(title);
    const max = svgElement("text", { x: 18, y: yTop + 38, class: "lane-max" });
    max.textContent = maxValue ? config.format(maxValue) : "no samples";
    lane.append(max);
    const points = buckets
      .map((bucket) => {
        const value = config.value(bucket);
        if (typeof value !== "number" || Number.isNaN(value)) {
          return null;
        }
        const x = left + (((bucket.startOffsetSeconds || 0) + (timeline.bucketSeconds || 10) / 2) / duration) * plotWidth;
        const y = yBottom - (maxValue ? value / maxValue : 0) * (laneHeight - 30);
        return [x, y];
      })
      .filter(Boolean);
    if (points.length === 1) {
      lane.append(svgElement("circle", { cx: points[0][0], cy: points[0][1], r: 3, fill: config.color }));
    } else if (points.length > 1) {
      lane.append(svgElement("path", { d: linePath(points), fill: "none", stroke: config.color, "stroke-width": 2.5 }));
    }
    svg.append(lane);
  });

  const startLabel = svgElement("text", { x: left, y: height - 8, class: "axis-label" });
  startLabel.textContent = "0:00";
  const endLabel = svgElement("text", { x: width - right - 48, y: height - 8, class: "axis-label" });
  endLabel.textContent = formatOffset(duration);
  svg.append(startLabel, endLabel);
}

function renderTimelineTables(timeline) {
  const eventRows = document.querySelector("#timeline-events");
  const events = timeline?.events || [];
  document.querySelector("#timeline-event-count").textContent = `${formatter.format(events.length)} events`;
  const eventFragment = document.createDocumentFragment();
  for (const event of events.slice(0, 200)) {
    const row = document.createElement("tr");
    const time = document.createElement("td");
    const stream = document.createElement("td");
    const message = document.createElement("td");
    time.textContent = formatOffset(event.offsetSeconds);
    stream.textContent = event.stream;
    stream.className = event.stream === "stderr" ? "stream stderr" : "stream stdout";
    message.textContent = event.message || "";
    message.className = "mono";
    row.append(time, stream, message);
    eventFragment.append(row);
  }
  if (!events.length) {
    eventFragment.append(emptyRow(3, "No stdout or stderr events."));
  } else if (events.length > 200) {
    eventFragment.append(emptyRow(3, `Showing first ${formatter.format(200)} events.`));
  }
  eventRows.replaceChildren(eventFragment);

  const dnsRows = document.querySelector("#timeline-dns");
  const flowRows = document.querySelector("#timeline-flows");
  const dnsQueries = timeline?.network?.dnsQueries || [];
  const flows = timeline?.network?.flows || [];
  document.querySelector("#timeline-network-count").textContent =
    `${formatter.format(dnsQueries.length)} DNS / ${formatter.format(flows.length)} flows`;

  const dnsFragment = document.createDocumentFragment();
  for (const query of dnsQueries.slice(0, 120)) {
    const row = document.createElement("tr");
    const bucket = document.createElement("td");
    const name = document.createElement("td");
    const answers = document.createElement("td");
    bucket.textContent = timelineBucketLabel(query.offsetSeconds, timeline.bucketSeconds);
    name.textContent = query.query || "unknown";
    answers.textContent = (query.answers || []).join(", ") || "none";
    answers.className = "mono";
    row.append(bucket, name, answers);
    dnsFragment.append(row);
  }
  if (!dnsQueries.length) {
    dnsFragment.append(emptyRow(3, "No DNS queries."));
  }
  dnsRows.replaceChildren(dnsFragment);

  const flowFragment = document.createDocumentFragment();
  for (const flow of flows.slice(0, 120)) {
    const row = document.createElement("tr");
    const buckets = document.createElement("td");
    const remote = document.createElement("td");
    const dns = document.createElement("td");
    const bytes = document.createElement("td");
    const activeBuckets = [...new Set((flow.samples || []).map((sample) => timelineBucketLabel(sample.offsetSeconds, timeline.bucketSeconds)))];
    buckets.textContent = activeBuckets.slice(0, 3).join(", ") || timelineBucketLabel(flow.firstSeenOffsetSeconds || 0, timeline.bucketSeconds);
    remote.textContent = `${flow.protocol || "IP"} ${flow.remoteAddress || "unknown"}${flow.remotePort ? `:${flow.remotePort}` : ""}`;
    remote.className = "mono";
    dns.textContent = (flow.dnsNames || []).join(", ") || "unknown";
    bytes.textContent = `${formatBytes(flow.totalRxBytes)} / ${formatBytes(flow.totalTxBytes)}`;
    row.append(buckets, remote, dns, bytes);
    flowFragment.append(row);
  }
  if (!flows.length) {
    flowFragment.append(emptyRow(4, "No network flows."));
  }
  flowRows.replaceChildren(flowFragment);
}

function renderTimeline(timeline, entry) {
  timelineData = timeline;
  document.querySelector("#timeline-title").textContent = `Timeline - ${entry?.label || "validator"}`;
  document.querySelector("#timeline-summary").textContent =
    `${formatter.format(timeline?.buckets?.length || 0)} buckets at ${formatter.format(timeline?.bucketSeconds || 10)}s`;
  renderTimelineChart(timeline);
  renderTimelineTables(timeline);
}

async function selectTimelineValidator(entryId) {
  if (!currentSummary) {
    return;
  }
  const entry = currentSummary.entries.find((item) => item.id === entryId) || currentSummary.entries[0];
  if (!entry) {
    return;
  }
  timelineValidator = entry.id;
  document.querySelectorAll("#validators tr").forEach((row) => {
    row.classList.toggle("is-selected", row.dataset.validator === timelineValidator);
  });
  if (!entry.paths?.timeline) {
    renderTimeline({ bucketSeconds: 10, buckets: [], events: [], network: { dnsQueries: [], flows: [] } }, entry);
    return;
  }
  if (!timelineCache.has(entry.paths.timeline)) {
    document.querySelector("#timeline-summary").textContent = "Loading...";
    timelineCache.set(entry.paths.timeline, await fetchJson(entry.paths.timeline));
  }
  renderTimeline(timelineCache.get(entry.paths.timeline), entry);
}

function renderValidators(summary) {
  const tbody = document.querySelector("#validators");
  const fragment = document.createDocumentFragment();
  for (const entry of summary.entries) {
    const row = document.createElement("tr");
    row.dataset.validator = entry.id;
    row.tabIndex = 0;
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
    row.addEventListener("click", () => selectTimelineValidator(entry.id).catch(showError));
    row.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        selectTimelineValidator(entry.id).catch(showError);
      }
    });
    fragment.append(row);
  }
  tbody.replaceChildren(fragment);
  const nextTimeline = summary.entries.some((entry) => entry.id === timelineValidator) ? timelineValidator : summary.entries[0]?.id;
  if (nextTimeline) {
    selectTimelineValidator(nextTimeline).catch(showError);
  }
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

function decodeResourceRow(row) {
  if (!Array.isArray(row)) {
    return row;
  }
  return {
    key: row[0],
    label: row[1],
    seenBy: row[2] || [],
    missingFrom: row[3] || [],
    divergent: Boolean(row[4]),
    sourceFiles: row[5] || [],
    object: row[6] || {},
  };
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

function renderSeenFilter() {
  const select = document.querySelector("#resource-seen-filter");
  const current = select.value || "all";
  select.replaceChildren(
    option("all", "All resources"),
    option("divergent", "Differences only"),
  );
  if (resourceReport) {
    for (const id of resourceReport.eligibleValidators || []) {
      select.append(
        option(`seen:${id}`, `Seen by ${id}`),
        option(`missing:${id}`, `Missing from ${id}`),
      );
    }
  }
  select.value = [...select.options].some((item) => item.value === current) ? current : "all";
}

function option(value, label) {
  const item = document.createElement("option");
  item.value = value;
  item.textContent = label;
  return item;
}

function filterBySeen(rows, filter) {
  if (filter === "divergent") {
    return rows.filter((row) => row.divergent);
  }
  if (filter.startsWith("seen:")) {
    const id = filter.slice("seen:".length);
    return rows.filter((row) => (row.seenBy || []).includes(id));
  }
  if (filter.startsWith("missing:")) {
    const id = filter.slice("missing:".length);
    return rows.filter((row) => (row.missingFrom || []).includes(id));
  }
  return rows;
}

function renderResources() {
  const tbody = document.querySelector("#resources");
  if (!resourceReport) {
    tbody.replaceChildren(emptyRow(4, "Load a resource report to inspect objects."));
    document.querySelector("#resource-count").textContent = "";
    document.querySelector("#resource-page").textContent = "";
    document.querySelector("#resource-scope").textContent = "";
    return;
  }
  const query = document.querySelector("#resource-search").value.trim().toLowerCase();
  const sort = document.querySelector("#resource-sort").value;
  const seenFilter = document.querySelector("#resource-seen-filter").value;
  let rows = filterBySeen(resourceRows, seenFilter);
  if (query) {
    rows = rows.filter((row) => resourceText(row).includes(query));
  }
  rows = sortResources(rows, sort);
  const shown = rows.slice(0, MAX_ROWS);
  const excluded = (resourceReport.excludedValidators || [])
    .map((validator) => `${validator.label || validator.id}: ${validator.reason}`)
    .join("; ");
  const pages = resourceReport.chunks?.length || 0;
  document.querySelector("#resource-count").textContent =
    `${formatter.format(rows.length)} matching in this page from ${formatter.format(resourceReport.totalObjects)} ${payloadLabels[resourcePayload]} objects`
    + (excluded ? `; excluded: ${excluded}` : "");
  document.querySelector("#resource-page").textContent = pages ? `${resourcePage + 1} / ${pages}` : "";
  document.querySelector("#resource-prev").disabled = resourcePage <= 0;
  document.querySelector("#resource-next").disabled = !pages || resourcePage >= pages - 1;
  const loaded = (resourceReport.chunks || []).filter((chunk) => resourceChunkCache.has(chunk.path)).length;
  document.querySelector("#resource-scope").textContent =
    `Search, sort, and seen filters apply to the current page only. Loaded ${formatter.format(loaded)} of ${formatter.format(pages)} resource chunks.`;
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

async function loadResourceChunk() {
  if (!resourceReport?.chunks?.length) {
    resourceRows = [];
    renderResources();
    return;
  }
  const chunk = resourceReport.chunks[resourcePage];
  if (!resourceChunkCache.has(chunk.path)) {
    document.querySelector("#resources").replaceChildren(emptyRow(4, `Loading page ${resourcePage + 1}...`));
    const data = await fetchJson(chunk.path);
    resourceChunkCache.set(chunk.path, (data.rows || []).map(decodeResourceRow));
  }
  resourceRows = resourceChunkCache.get(chunk.path);
  renderResources();
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
  renderSeenFilter();
  resourcePage = 0;
  await loadResourceChunk();
}

function decodeFileRow(row) {
  if (!Array.isArray(row)) {
    return row;
  }
  return {
    root: row[0],
    path: row[1],
    size: row[2],
    sha256: row[3],
  };
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
    document.querySelector("#file-page").textContent = "";
    document.querySelector("#file-scope").textContent = "";
    return;
  }
  const query = document.querySelector("#file-search").value.trim().toLowerCase();
  const sort = document.querySelector("#file-sort").value;
  let rows = fileRows;
  if (query) {
    rows = rows.filter((row) => fileText(row).includes(query));
  }
  rows = sortFiles(rows, sort);
  const shown = rows.slice(0, MAX_ROWS);
  const pages = fileTree.chunks?.length || 0;
  document.querySelector("#file-count").textContent =
    `${formatter.format(rows.length)} matching in this page from ${formatter.format(fileTree.files)} files`;
  document.querySelector("#file-page").textContent = pages ? `${filePage + 1} / ${pages}` : "";
  document.querySelector("#file-prev").disabled = filePage <= 0;
  document.querySelector("#file-next").disabled = !pages || filePage >= pages - 1;
  const loaded = (fileTree.chunks || []).filter((chunk) => fileChunkCache.has(chunk.path)).length;
  document.querySelector("#file-scope").textContent =
    `Search and sort apply to the current page only. Loaded ${formatter.format(loaded)} of ${formatter.format(pages)} file chunks.`;
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

async function loadFileChunk() {
  if (!fileTree?.chunks?.length) {
    fileRows = [];
    renderFiles();
    return;
  }
  const chunk = fileTree.chunks[filePage];
  if (!fileChunkCache.has(chunk.path)) {
    document.querySelector("#files").replaceChildren(emptyRow(4, `Loading page ${filePage + 1}...`));
    const data = await fetchJson(chunk.path);
    fileChunkCache.set(chunk.path, (data.rows || []).map(decodeFileRow));
  }
  fileRows = fileChunkCache.get(chunk.path);
  renderFiles();
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
    fileCache.set(path, tree);
  }
  fileTree = fileCache.get(path);
  filePage = 0;
  await loadFileChunk();
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
  resourceRows = [];
  resourcePage = 0;
  fileTree = null;
  fileRows = [];
  filePage = 0;
  timelineValidator = null;
  timelineData = null;
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
    resourceRows = [];
    resourcePage = 0;
    loadResourceReport().catch(showError);
  });
  document.querySelector("#resource-search").addEventListener("input", renderResources);
  document.querySelector("#resource-sort").addEventListener("change", renderResources);
  document.querySelector("#resource-seen-filter").addEventListener("change", renderResources);
  document.querySelector("#resource-prev").addEventListener("click", () => {
    resourcePage = Math.max(0, resourcePage - 1);
    loadResourceChunk().catch(showError);
  });
  document.querySelector("#resource-next").addEventListener("click", () => {
    resourcePage = Math.min((resourceReport?.chunks?.length || 1) - 1, resourcePage + 1);
    loadResourceChunk().catch(showError);
  });
  document.querySelector("#file-validator").addEventListener("change", (event) => {
    fileValidator = event.target.value;
    fileTree = null;
    fileRows = [];
    filePage = 0;
    loadFileTree().catch(showError);
  });
  document.querySelector("#file-search").addEventListener("input", renderFiles);
  document.querySelector("#file-sort").addEventListener("change", renderFiles);
  document.querySelector("#file-prev").addEventListener("click", () => {
    filePage = Math.max(0, filePage - 1);
    loadFileChunk().catch(showError);
  });
  document.querySelector("#file-next").addEventListener("click", () => {
    filePage = Math.min((fileTree?.chunks?.length || 1) - 1, filePage + 1);
    loadFileChunk().catch(showError);
  });
  document.querySelectorAll("[data-timeline-series]").forEach((input) => {
    input.addEventListener("change", () => {
      if (timelineData) {
        renderTimelineChart(timelineData);
      }
    });
  });
}

function setupRuns() {
  const select = document.querySelector("#run-select");
  select.replaceChildren();
  for (const run of manifest.runs || []) {
    const option = document.createElement("option");
    option.value = run.id;
    option.dataset.generatedAt = run.generatedAt || "";
    option.dataset.success = String(run.success);
    select.append(option);
  }
  updateRunOptionLabels();
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
  if (!timeRefreshTimer) {
    timeRefreshTimer = window.setInterval(refreshTimes, 1000);
  }
}

main().catch(showError);
