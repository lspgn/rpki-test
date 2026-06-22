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
let timeRefreshTimer = null;
const resourceCache = new Map();
const resourceChunkCache = new Map();
const fileCache = new Map();
const fileChunkCache = new Map();
const timelineCache = new Map();
const timelineByValidator = new Map();
const expandedFlowCharts = new Set();
const expandedLogPanels = new Set();
const collapsedTimelineProfiles = new Set();
const EXPANDED_FLOW_LIMIT = 80;
let timelineScrollRatio = 0;
let syncingTimelineScroll = false;

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

function formatCount(value) {
  return typeof value === "number" ? formatter.format(value) : "unknown";
}

function formatOffset(seconds) {
  if (typeof seconds !== "number") {
    return "unknown";
  }
  const minutes = Math.floor(seconds / 60);
  const remaining = Math.floor(seconds % 60);
  return `${minutes}:${String(remaining).padStart(2, "0")}`;
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

function timelineSeriesConfig(bucketSeconds) {
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
        const packet = ((bucket.flowRxBytes || 0) + (bucket.flowTxBytes || 0)) / (bucketSeconds || 10);
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

function areaPath(points, baseline) {
  if (!points.length) {
    return "";
  }
  const first = points[0];
  const last = points[points.length - 1];
  return `M${first[0].toFixed(1)},${baseline.toFixed(1)} ${linePath(points)} L${last[0].toFixed(1)},${baseline.toFixed(1)} Z`;
}

function seriesStats(values) {
  const numbers = values.filter((value) => typeof value === "number" && !Number.isNaN(value));
  if (!numbers.length) {
    return null;
  }
  return {
    min: Math.min(...numbers),
    max: Math.max(...numbers),
    avg: numbers.reduce((sum, value) => sum + value, 0) / numbers.length,
  };
}

function statsLabel(stats, format, includeMin = false) {
  if (!stats) {
    return "no samples";
  }
  const parts = includeMin ? [`min ${format(stats.min)}`] : [];
  parts.push(`avg ${format(stats.avg)}`, `max ${format(stats.max)}`);
  return parts.join(" / ");
}

function sortedFlows(timeline) {
  return [...(timeline?.network?.flows || [])].sort((left, right) => {
    return (right.totalBytes || 0) - (left.totalBytes || 0)
      || (left.remoteAddress || "").localeCompare(right.remoteAddress || "")
      || (left.remotePort || 0) - (right.remotePort || 0);
  });
}

function groupedByBucket(items, bucketSeconds, offsetValue) {
  const groups = new Map();
  for (const item of items || []) {
    const offset = Math.max(0, offsetValue(item) || 0);
    const index = Math.floor(offset / (bucketSeconds || 10));
    if (!groups.has(index)) {
      groups.set(index, []);
    }
    groups.get(index).push(item);
  }
  return [...groups.entries()]
    .map(([index, values]) => ({
      index,
      bucketSeconds: bucketSeconds || 10,
      offsetSeconds: index * (bucketSeconds || 10),
      values,
    }))
    .sort((left, right) => left.index - right.index);
}

function tooltip() {
  return document.querySelector("#timeline-tooltip");
}

function showTimelineTooltip(event, lines, className = "") {
  const node = tooltip();
  if (!node || !lines.length) {
    return;
  }
  node.replaceChildren(...lines.map((line) => {
    const div = document.createElement("div");
    div.textContent = line;
    return div;
  }));
  node.classList.add("is-visible");
  node.classList.toggle("is-log-tooltip", className === "is-log-tooltip");
  const margin = 14;
  const rect = node.getBoundingClientRect();
  const left = Math.min(event.clientX + margin, window.innerWidth - rect.width - margin);
  const top = Math.min(event.clientY + margin, window.innerHeight - rect.height - margin);
  node.style.left = `${Math.max(margin, left)}px`;
  node.style.top = `${Math.max(margin, top)}px`;
}

function hideTimelineTooltip() {
  const node = tooltip();
  if (node) {
    node.classList.remove("is-visible");
    node.classList.remove("is-log-tooltip");
  }
}

function addTooltipHandlers(node, lines, className = "") {
  node.addEventListener("mousemove", (event) => showTimelineTooltip(event, lines, className));
  node.addEventListener("mouseleave", hideTimelineTooltip);
}

function groupedCounts(items, key, label, limit = 8) {
  const counts = new Map();
  for (const item of items || []) {
    const value = key(item) || "unknown";
    counts.set(value, (counts.get(value) || 0) + 1);
  }
  const rows = [...counts.entries()]
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .slice(0, limit)
    .map(([value, count]) => `${formatCount(count)} ${label}: ${value}`);
  const remaining = Math.max(0, counts.size - limit);
  return remaining ? [...rows, `+${formatCount(remaining)} more ${label} groups`] : rows;
}

function eventLines(group) {
  const stdout = group.values.filter((item) => item.stream === "stdout").length;
  const stderr = group.values.filter((item) => item.stream === "stderr").length;
  const byMessage = groupedCounts(
    group.values,
    (item) => `${item.stream}: ${item.message || ""}`,
    "logs",
  );
  return [
    `${formatOffset(group.offsetSeconds)}-${formatOffset(group.offsetSeconds + group.bucketSeconds)} logs`,
    `${formatCount(stdout)} stdout / ${formatCount(stderr)} stderr`,
    ...byMessage,
  ];
}

function logBucketLines(bucket, group) {
  if (group?.values?.length) {
    return eventLines(group);
  }
  return [
    `${formatOffset(bucket.startOffsetSeconds)}-${formatOffset(bucket.endOffsetSeconds)} logs`,
    `${formatCount(bucket.stdoutCount || 0)} stdout / ${formatCount(bucket.stderrCount || 0)} stderr`,
  ];
}

function dnsLines(group) {
  const byQuery = groupedCounts(
    group.values,
    (item) => `${item.query || "unknown"} -> ${(item.answers || []).slice(0, 3).join(", ") || "none"}`,
    "queries",
  );
  return [
    `${formatOffset(group.offsetSeconds)}-${formatOffset(group.offsetSeconds + group.bucketSeconds)} DNS`,
    `${formatCount(group.values.length)} queries`,
    ...byQuery,
  ];
}

function dnsBucketLines(bucket, group) {
  if (group?.values?.length) {
    return dnsLines(group);
  }
  return [
    `${formatOffset(bucket.startOffsetSeconds)}-${formatOffset(bucket.endOffsetSeconds)} DNS`,
    `${formatCount(bucket.dnsQueryCount || 0)} queries`,
  ];
}

function bucketTooltipLines(entry, bucket, configs, lanes) {
  return [
    `${entry?.label || "Validator"} ${formatOffset(bucket.startOffsetSeconds)}-${formatOffset(bucket.endOffsetSeconds)}`,
    ...lanes.map((key) => `${configs[key].label}: ${configs[key].format(configs[key].value(bucket))}`),
    `Flow bytes: ${formatBytes((bucket.flowRxBytes || 0) + (bucket.flowTxBytes || 0))}`,
    `Logs: ${formatCount((bucket.stdoutCount || 0) + (bucket.stderrCount || 0))}`,
    `DNS: ${formatCount(bucket.dnsQueryCount || 0)}`,
    `Flows: ${formatCount(bucket.flowCount || 0)}`,
  ];
}

function timelineDuration(timeline) {
  const buckets = timeline?.buckets || [];
  const flows = timeline?.network?.flows || [];
  const events = timeline?.events || [];
  return Math.max(
    timeline?.durationSeconds || 0,
    ...buckets.map((bucket) => bucket.endOffsetSeconds || 0),
    ...flows.map((flow) => flow.lastSeenOffsetSeconds || flow.firstSeenOffsetSeconds || 0),
    ...events.map((event) => event.offsetSeconds || 0),
    timeline?.bucketSeconds || 10,
  );
}

function flowLabel(flow) {
  const remote = `${flow.protocol || "IP"} ${flow.remoteAddress || "unknown"}${flow.remotePort ? `:${flow.remotePort}` : ""}`;
  const names = (flow.dnsNames || []).join(", ");
  return names ? `${remote} ${names}` : remote;
}

function flowTotalBytes(flow) {
  return flow?.totalBytes || ((flow?.totalRxBytes || 0) + (flow?.totalTxBytes || 0));
}

function flowHeatBins(flows, duration, bucketSeconds) {
  const secondsPerBin = Math.max(1, bucketSeconds || 10);
  const count = Math.max(1, Math.ceil(duration / secondsPerBin));
  const bins = Array.from({ length: count }, (_, index) => ({
    index,
    start: index * secondsPerBin,
    end: Math.min(duration, (index + 1) * secondsPerBin),
    bytes: 0,
    flows: new Set(),
    topFlows: new Map(),
  }));
  for (const flow of flows || []) {
    const samples = Array.isArray(flow.samples) ? flow.samples : [];
    if (!samples.length) {
      const first = Math.max(0, flow.firstSeenOffsetSeconds || 0);
      const last = Math.max(first, flow.lastSeenOffsetSeconds || first);
      const startIndex = Math.min(count - 1, Math.floor(first / secondsPerBin));
      const endIndex = Math.min(count - 1, Math.floor(last / secondsPerBin));
      const bytes = flowTotalBytes(flow);
      for (let index = startIndex; index <= endIndex; index += 1) {
        bins[index].bytes += bytes / Math.max(1, endIndex - startIndex + 1);
        bins[index].flows.add(flow);
        bins[index].topFlows.set(flow, (bins[index].topFlows.get(flow) || 0) + bytes);
      }
      continue;
    }
    for (const sample of samples) {
      const offset = Math.max(0, sample.offsetSeconds || flow.firstSeenOffsetSeconds || 0);
      const index = Math.min(count - 1, Math.floor(offset / secondsPerBin));
      const bytes = (sample.rxBytes || 0) + (sample.txBytes || 0);
      bins[index].bytes += bytes;
      bins[index].flows.add(flow);
      bins[index].topFlows.set(flow, (bins[index].topFlows.get(flow) || 0) + bytes);
    }
  }
  return bins.map((bin) => ({
    ...bin,
    flowCount: bin.flows.size,
    topFlows: [...bin.topFlows.entries()]
      .sort((left, right) => right[1] - left[1])
      .slice(0, 5),
  }));
}

function heatBinLines(bin) {
  return [
    `${formatOffset(bin.start)}-${formatOffset(bin.end)} flows`,
    `Flow bytes: ${formatBytes(bin.bytes)}`,
    `Flows: ${formatCount(bin.flowCount)}`,
    ...bin.topFlows.map(([flow, bytes]) => `${formatBytes(bytes)} ${flowLabel(flow)}`),
  ];
}

function renderTimelineChart(svg, timeline, entry, scaleDuration = null) {
  svg.replaceChildren();
  const buckets = timeline?.buckets || [];
  const flows = sortedFlows(timeline);
  const events = timeline?.events || [];
  const dnsQueries = timeline?.network?.dnsQueries || [];
  const logGroups = groupedByBucket(events, timeline?.bucketSeconds || 10, (event) => event.offsetSeconds);
  const logGroupByIndex = new Map(logGroups.map((group) => [group.index, group]));
  const dnsGroups = groupedByBucket(dnsQueries, timeline?.bucketSeconds || 10, (query) => query.offsetSeconds);
  const dnsGroupByIndex = new Map(dnsGroups.map((group) => [group.index, group]));
  if (!buckets.length && !flows.length && !events.length) {
    svg.setAttribute("viewBox", "0 0 980 120");
    svg.append(svgElement("text", { x: 24, y: 64, class: "timeline-empty" }));
    svg.lastElementChild.textContent = "No timeline samples";
    return;
  }

  const bucketSeconds = timeline?.bucketSeconds || 10;
  const configs = timelineSeriesConfig(bucketSeconds);
  const enabled = selectedTimelineSeries().filter((key) => configs[key]);
  const lanes = enabled.length ? enabled : ["cpu"];
  const duration = Math.max(scaleDuration || 0, timelineDuration(timeline));
  const width = Math.min(2200, Math.max(980, Math.round(duration * 1.35)));
  const left = 112;
  const right = 24;
  const top = 24;
  const expanded = expandedFlowCharts.has(entry?.id);
  const visibleFlows = expanded ? flows.slice(0, EXPANDED_FLOW_LIMIT) : [];
  const flowTop = top + 12;
  const flowRowHeight = 13;
  const flowHeight = flows.length
    ? (expanded ? Math.max(54, visibleFlows.length * flowRowHeight + 24) : 78)
    : 28;
  const logTop = flowTop + flowHeight + 22;
  const logHeight = 58;
  const dnsTop = logTop + logHeight + 22;
  const dnsHeight = 58;
  const laneTop = dnsTop + dnsHeight + 22;
  const laneHeight = 66;
  const height = laneTop + laneHeight * lanes.length + 34;
  const plotWidth = width - left - right;
  const xForOffset = (offset) => left + (Math.max(0, offset || 0) / duration) * plotWidth;
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.style.minHeight = `${height}px`;
  svg.style.minWidth = `${width}px`;

  const title = svgElement("text", { x: 18, y: 18, class: "timeline-card-title" });
  title.textContent = entry?.label || "Validator";
  svg.append(title);

  const flowLabelNode = svgElement("text", { x: 18, y: flowTop + 17, class: "lane-label" });
  flowLabelNode.textContent = "Flows";
  svg.append(flowLabelNode);
  svg.append(svgElement("rect", { x: left, y: flowTop, width: plotWidth, height: flowHeight, class: "flow-lane" }));
  const verticalTicks = 6;
  for (let index = 0; index <= verticalTicks; index += 1) {
    const x = left + (plotWidth * index) / verticalTicks;
    svg.append(svgElement("line", { x1: x, x2: x, y1: flowTop, y2: height - 24, class: "grid-line vertical" }));
    const label = svgElement("text", { x: x + 3, y: height - 8, class: "axis-label" });
    label.textContent = formatOffset((duration * index) / verticalTicks);
    svg.append(label);
  }
  const maxFlowBytes = Math.max(...flows.map(flowTotalBytes), 1);
  if (!expanded && flows.length) {
    const bins = flowHeatBins(flows, duration, bucketSeconds);
    const maxBinBytes = Math.max(...bins.map((bin) => bin.bytes), 1);
    bins.forEach((bin) => {
      if (!bin.bytes) {
        return;
      }
      const x = xForOffset(bin.start);
      const binWidth = Math.max(2, xForOffset(bin.end) - x);
      const intensity = Math.max(0.16, Math.min(0.9, Math.sqrt(bin.bytes / maxBinBytes)));
      const barHeight = Math.max(5, intensity * (flowHeight - 18));
      const heat = svgElement("rect", {
        x,
        y: flowTop + flowHeight - 7 - barHeight,
        width: binWidth,
        height: barHeight,
        class: "flow-heat",
        opacity: intensity.toFixed(2),
      });
      addTooltipHandlers(heat, heatBinLines(bin));
      svg.append(heat);
    });
    const hint = svgElement("text", { x: left, y: flowTop + 17, class: "flow-label" });
    hint.textContent = `${formatCount(flows.length)} flows, heat by exchanged bytes`;
    svg.append(hint);
  } else {
    visibleFlows.forEach((flow, index) => {
      const y = flowTop + 10 + index * flowRowHeight;
      const start = flow.firstSeenOffsetSeconds || 0;
      const end = Math.max(flow.lastSeenOffsetSeconds || start, start + 0.6);
      const x = xForOffset(start);
      const barWidth = Math.max(3, xForOffset(end) - x);
      const heat = Math.max(0.18, Math.min(0.9, flowTotalBytes(flow) / maxFlowBytes));
      const bar = svgElement("rect", {
        x,
        y,
        width: barWidth,
        height: 9,
        rx: 2,
        class: "flow-bar",
        opacity: heat.toFixed(2),
      });
      addTooltipHandlers(bar, [
        flowLabel(flow),
        `${formatOffset(start)}-${formatOffset(end)}`,
        `Total: ${formatBytes(flowTotalBytes(flow))}`,
        `RX/TX: ${formatBytes(flow.totalRxBytes)} / ${formatBytes(flow.totalTxBytes)}`,
        `Packets: ${formatCount(flow.packetCount || 0)}`,
      ]);
      svg.append(bar);
      const label = svgElement("text", { x: Math.min(x + barWidth + 5, width - right - 210), y: y + 8, class: "flow-label" });
      label.textContent = flowLabel(flow).slice(0, 58);
      svg.append(label);
    });
    if (flows.length > visibleFlows.length) {
      const more = svgElement("text", { x: left, y: flowTop + flowHeight - 4, class: "lane-max" });
      more.textContent = `Showing top ${formatCount(visibleFlows.length)} by bytes; +${formatCount(flows.length - visibleFlows.length)} more`;
      svg.append(more);
    }
  }

  const logLabel = svgElement("text", { x: 18, y: logTop + 17, class: "lane-label" });
  logLabel.textContent = "Logs";
  svg.append(logLabel);
  svg.append(svgElement("rect", { x: left, y: logTop, width: plotWidth, height: logHeight, class: "log-lane" }));
  const logBottom = logTop + logHeight - 12;
  const logPlotHeight = logHeight - 24;
  const totalLogCount = buckets.reduce((sum, bucket) => sum + (bucket.stdoutCount || 0) + (bucket.stderrCount || 0), 0);
  const maxLogCount = Math.max(...buckets.map((bucket) => (bucket.stdoutCount || 0) + (bucket.stderrCount || 0)), 1);
  const logMax = svgElement("text", { x: 18, y: logTop + 37, class: "lane-max" });
  logMax.textContent = `total ${formatCount(totalLogCount)}`;
  svg.append(logMax);
  const logZero = svgElement("text", { x: left - 18, y: logBottom + 4, class: "axis-label" });
  logZero.textContent = "0";
  svg.append(logZero);
  buckets.forEach((bucket) => {
    const stdout = bucket.stdoutCount || 0;
    const stderr = bucket.stderrCount || 0;
    const total = stdout + stderr;
    if (!total) {
      return;
    }
    const x = xForOffset(bucket.startOffsetSeconds || 0);
    const groupIndex = Math.floor((bucket.startOffsetSeconds || 0) / (bucketSeconds || 10));
    const group = logGroupByIndex.get(groupIndex);
    const bucketWidth = Math.max(2, xForOffset(bucket.endOffsetSeconds || ((bucket.startOffsetSeconds || 0) + bucketSeconds)) - x);
    const barWidth = Math.max(2, bucketWidth - 1);
    const stderrHeight = (stderr / maxLogCount) * logPlotHeight;
    const stdoutHeight = (stdout / maxLogCount) * logPlotHeight;
    let y = logBottom;
    if (stdoutHeight > 0) {
      y -= Math.max(1, stdoutHeight);
      const stdoutBar = svgElement("rect", {
        x,
        y,
        width: barWidth,
        height: Math.max(1, stdoutHeight),
        class: "log-bar stdout",
      });
      addTooltipHandlers(stdoutBar, logBucketLines(bucket, group), "is-log-tooltip");
      svg.append(stdoutBar);
    }
    if (stderrHeight > 0) {
      y -= Math.max(1, stderrHeight);
      const stderrBar = svgElement("rect", {
        x,
        y,
        width: barWidth,
        height: Math.max(1, stderrHeight),
        class: "log-bar stderr",
      });
      addTooltipHandlers(stderrBar, logBucketLines(bucket, group), "is-log-tooltip");
      svg.append(stderrBar);
    }
  });
  svg.append(svgElement("line", { x1: left, x2: width - right, y1: logBottom, y2: logBottom, class: "axis" }));

  const dnsLabel = svgElement("text", { x: 18, y: dnsTop + 17, class: "lane-label" });
  dnsLabel.textContent = "DNS";
  svg.append(dnsLabel);
  svg.append(svgElement("rect", { x: left, y: dnsTop, width: plotWidth, height: dnsHeight, class: "dns-lane" }));
  const dnsBottom = dnsTop + dnsHeight - 12;
  const dnsPlotHeight = dnsHeight - 24;
  const totalDnsCount = buckets.reduce((sum, bucket) => sum + (bucket.dnsQueryCount || 0), 0);
  const maxDnsCount = Math.max(...buckets.map((bucket) => bucket.dnsQueryCount || 0), 1);
  const dnsMax = svgElement("text", { x: 18, y: dnsTop + 37, class: "lane-max" });
  dnsMax.textContent = `total ${formatCount(totalDnsCount)}`;
  svg.append(dnsMax);
  const dnsZero = svgElement("text", { x: left - 18, y: dnsBottom + 4, class: "axis-label" });
  dnsZero.textContent = "0";
  svg.append(dnsZero);
  buckets.forEach((bucket) => {
    const total = bucket.dnsQueryCount || 0;
    if (!total) {
      return;
    }
    const x = xForOffset(bucket.startOffsetSeconds || 0);
    const groupIndex = Math.floor((bucket.startOffsetSeconds || 0) / (bucketSeconds || 10));
    const group = dnsGroupByIndex.get(groupIndex);
    const bucketWidth = Math.max(2, xForOffset(bucket.endOffsetSeconds || ((bucket.startOffsetSeconds || 0) + bucketSeconds)) - x);
    const barHeight = Math.max(1, (total / maxDnsCount) * dnsPlotHeight);
    const bar = svgElement("rect", {
      x,
      y: dnsBottom - barHeight,
      width: Math.max(2, bucketWidth - 1),
      height: barHeight,
      class: "dns-bar",
    });
    addTooltipHandlers(bar, dnsBucketLines(bucket, group));
    svg.append(bar);
  });
  svg.append(svgElement("line", { x1: left, x2: width - right, y1: dnsBottom, y2: dnsBottom, class: "axis" }));

  lanes.forEach((key, laneIndex) => {
    const config = configs[key];
    const yTop = laneTop + laneIndex * laneHeight;
    const yBottom = yTop + laneHeight - 22;
    const values = buckets.map((bucket) => config.value(bucket)).filter((value) => typeof value === "number" && !Number.isNaN(value));
    const stats = seriesStats(values);
    const maxValue = Math.max(stats?.max || 0, 0);
    const lane = svgElement("g", { class: "timeline-lane" });
    for (let gridIndex = 0; gridIndex <= 2; gridIndex += 1) {
      const y = yBottom - (gridIndex / 2) * (laneHeight - 30);
      lane.append(svgElement("line", { x1: left, x2: width - right, y1: y, y2: y, class: "grid-line horizontal" }));
    }
    lane.append(svgElement("line", { x1: left, x2: width - right, y1: yBottom, y2: yBottom, class: "axis" }));
    const title = svgElement("text", { x: 18, y: yTop + 18, class: "lane-label" });
    title.textContent = config.label;
    lane.append(title);
    const max = svgElement("text", { x: 18, y: yTop + 38, class: "lane-max" });
    max.textContent = statsLabel(stats, config.format, key === "pids");
    lane.append(max);
    const zero = svgElement("text", { x: left - 18, y: yBottom + 4, class: "axis-label" });
    zero.textContent = "0";
    lane.append(zero);
    const points = buckets
      .map((bucket) => {
        const value = config.value(bucket);
        if (typeof value !== "number" || Number.isNaN(value)) {
          return null;
        }
        const x = xForOffset((bucket.startOffsetSeconds || 0) + bucketSeconds / 2);
        const y = yBottom - (maxValue ? value / maxValue : 0) * (laneHeight - 30);
        return [x, y];
      })
      .filter(Boolean);
    const displayPoints = points.length ? [[left, yBottom], ...points] : [];
    if (displayPoints.length > 1) {
      lane.append(svgElement("path", { d: areaPath(displayPoints, yBottom), class: "timeline-area", fill: config.color }));
    }
    if (points.length === 1) {
      lane.append(svgElement("circle", { cx: points[0][0], cy: points[0][1], r: 3, fill: config.color }));
      lane.append(svgElement("path", { d: linePath(displayPoints), fill: "none", stroke: config.color, "stroke-width": 2.5 }));
    } else if (displayPoints.length > 1) {
      lane.append(svgElement("path", { d: linePath(displayPoints), fill: "none", stroke: config.color, "stroke-width": 2.5 }));
    }
    svg.append(lane);
  });

  buckets.forEach((bucket) => {
    const x = xForOffset(bucket.startOffsetSeconds || 0);
    const bucketWidth = Math.max(2, xForOffset(bucket.endOffsetSeconds || ((bucket.startOffsetSeconds || 0) + bucketSeconds)) - x);
    const hover = svgElement("rect", {
      x,
      y: laneTop,
      width: bucketWidth,
      height: laneHeight * lanes.length,
      class: "bucket-hover",
    });
    addTooltipHandlers(hover, bucketTooltipLines(entry, bucket, configs, lanes));
    svg.append(hover);
  });

  svg.append(svgElement("line", { x1: left, x2: left, y1: flowTop, y2: height - 24, class: "axis" }));
}

function renderLogPanel(timeline) {
  const panel = document.createElement("div");
  panel.className = "timeline-log-panel";
  const events = [...(timeline?.events || [])].sort((left, right) => {
    return (left.offsetSeconds || 0) - (right.offsetSeconds || 0)
      || (left.stream || "").localeCompare(right.stream || "");
  });
  if (!events.length) {
    panel.textContent = "No log events";
    return panel;
  }
  const fragment = document.createDocumentFragment();
  for (const item of events) {
    const row = document.createElement("div");
    row.className = `timeline-log-row ${item.stream === "stderr" ? "stderr" : "stdout"}`;
    const time = document.createElement("span");
    time.className = "timeline-log-time";
    time.textContent = formatOffset(item.offsetSeconds || 0);
    const stream = document.createElement("span");
    stream.className = "timeline-log-stream";
    stream.textContent = item.stream || "log";
    const message = document.createElement("span");
    message.className = "timeline-log-message";
    message.textContent = item.message || "";
    row.append(time, stream, message);
    fragment.append(row);
  }
  panel.append(fragment);
  return panel;
}

function renderTimelineCard(entry, timeline, scaleDuration) {
  const article = document.createElement("article");
  article.className = "timeline-card";
  const collapsed = collapsedTimelineProfiles.has(entry.id);
  if (collapsed) {
    article.classList.add("is-collapsed");
  }
  const head = document.createElement("div");
  head.className = "timeline-card-head";
  const title = document.createElement("h3");
  title.textContent = entry.label;
  const summary = document.createElement("span");
  const actions = document.createElement("div");
  actions.className = "timeline-card-actions";
  const events = timeline?.events?.length || 0;
  const flows = timeline?.network?.flows?.length || 0;
  const dns = timeline?.network?.dnsQueries?.length || 0;
  summary.className = "muted";
  summary.textContent = `${formatter.format(timeline?.buckets?.length || 0)} buckets / ${formatter.format(events)} events / ${formatter.format(dns)} DNS / ${formatter.format(flows)} flows`;
  const flowToggle = document.createElement("button");
  flowToggle.type = "button";
  flowToggle.className = "timeline-flow-toggle";
  flowToggle.textContent = expandedFlowCharts.has(entry.id) ? "Collapse flows" : "Expand flows";
  flowToggle.disabled = flows === 0 || collapsed;
  flowToggle.addEventListener("click", () => {
    if (expandedFlowCharts.has(entry.id)) {
      expandedFlowCharts.delete(entry.id);
    } else {
      expandedFlowCharts.add(entry.id);
    }
    renderAllTimelines();
  });
  const logsToggle = document.createElement("button");
  logsToggle.type = "button";
  logsToggle.className = "timeline-flow-toggle";
  logsToggle.textContent = expandedLogPanels.has(entry.id) ? "Collapse logs" : "Expand logs";
  logsToggle.disabled = events === 0 || collapsed;
  logsToggle.addEventListener("click", () => {
    if (expandedLogPanels.has(entry.id)) {
      expandedLogPanels.delete(entry.id);
    } else {
      expandedLogPanels.add(entry.id);
    }
    renderAllTimelines();
  });
  const profileToggle = document.createElement("button");
  profileToggle.type = "button";
  profileToggle.className = "timeline-flow-toggle";
  profileToggle.textContent = collapsed ? "Show profile" : "Hide profile";
  profileToggle.addEventListener("click", () => {
    if (collapsedTimelineProfiles.has(entry.id)) {
      collapsedTimelineProfiles.delete(entry.id);
    } else {
      collapsedTimelineProfiles.add(entry.id);
    }
    renderAllTimelines();
  });
  actions.append(summary, flowToggle, logsToggle, profileToggle);
  head.append(title, actions);
  article.append(head);
  if (collapsed) {
    return article;
  }
  const wrap = document.createElement("div");
  wrap.className = "timeline-chart-wrap";
  const svg = svgElement("svg", { class: "timeline-chart", role: "img", "aria-label": `${entry.label} timeline` });
  wrap.append(svg);
  article.append(wrap);
  renderTimelineChart(svg, timeline, entry, scaleDuration);
  if (expandedLogPanels.has(entry.id)) {
    article.append(renderLogPanel(timeline));
  }
  return article;
}

function syncTimelineScroll(source) {
  const maxScroll = source.scrollWidth - source.clientWidth;
  timelineScrollRatio = maxScroll > 0 ? source.scrollLeft / maxScroll : 0;
  syncingTimelineScroll = true;
  document.querySelectorAll(".timeline-chart-wrap").forEach((wrap) => {
    if (wrap === source) {
      return;
    }
    const targetMax = wrap.scrollWidth - wrap.clientWidth;
    wrap.scrollLeft = targetMax > 0 ? timelineScrollRatio * targetMax : 0;
  });
  requestAnimationFrame(() => {
    syncingTimelineScroll = false;
  });
}

function attachTimelineScrollSync() {
  document.querySelectorAll(".timeline-chart-wrap").forEach((wrap) => {
    const maxScroll = wrap.scrollWidth - wrap.clientWidth;
    wrap.scrollLeft = maxScroll > 0 ? timelineScrollRatio * maxScroll : 0;
    wrap.addEventListener("scroll", () => {
      if (!syncingTimelineScroll) {
        syncTimelineScroll(wrap);
      }
    });
  });
}

function renderAllTimelines() {
  const container = document.querySelector("#timelines");
  if (!currentSummary?.entries?.length) {
    container.replaceChildren();
    document.querySelector("#timeline-summary").textContent = "";
    return;
  }
  const fragment = document.createDocumentFragment();
  const loadedEntries = currentSummary.entries
    .map((entry) => ({ entry, timeline: timelineByValidator.get(entry.id) }))
    .filter((item) => item.timeline);
  const openDurations = loadedEntries
    .filter((item) => !collapsedTimelineProfiles.has(item.entry.id))
    .map((item) => timelineDuration(item.timeline));
  const fallbackDurations = loadedEntries.map((item) => timelineDuration(item.timeline));
  const scaleDuration = Math.max(...(openDurations.length ? openDurations : fallbackDurations), 0);
  for (const entry of currentSummary.entries) {
    const timeline = timelineByValidator.get(entry.id);
    if (timeline) {
      fragment.append(renderTimelineCard(entry, timeline, scaleDuration));
    } else {
      const pending = document.createElement("article");
      pending.className = "timeline-card";
      pending.textContent = `Loading ${entry.label} timeline...`;
      fragment.append(pending);
    }
  }
  container.replaceChildren(fragment);
  attachTimelineScrollSync();
  const loaded = currentSummary.entries.filter((entry) => timelineByValidator.has(entry.id)).length;
  const open = currentSummary.entries.filter((entry) => timelineByValidator.has(entry.id) && !collapsedTimelineProfiles.has(entry.id)).length;
  document.querySelector("#timeline-summary").textContent =
    `${formatter.format(loaded)} / ${formatter.format(currentSummary.entries.length)} charts loaded, ${formatter.format(open)} open`;
}

async function loadAllTimelines(summary) {
  timelineByValidator.clear();
  collapsedTimelineProfiles.clear();
  expandedLogPanels.clear();
  timelineScrollRatio = 0;
  renderAllTimelines();
  await Promise.all(
    summary.entries.map(async (entry) => {
      if (!entry.paths?.timeline) {
        timelineByValidator.set(entry.id, { bucketSeconds: 10, buckets: [], events: [], network: { dnsQueries: [], flows: [] } });
        return;
      }
      if (!timelineCache.has(entry.paths.timeline)) {
        timelineCache.set(entry.paths.timeline, await fetchJson(entry.paths.timeline));
      }
      timelineByValidator.set(entry.id, timelineCache.get(entry.paths.timeline));
      renderAllTimelines();
    }),
  );
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
  render(summary);
  await loadAllTimelines(summary);
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
      renderAllTimelines();
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
