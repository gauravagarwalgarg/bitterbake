
const STORAGE_KEY = "cve-dashboard-load-log";
const THEME_KEY = "cve-dashboard-theme";
const state = {
  flatIssues: [],
  filtered: [],
  page: 1,
  manifestPackages: new Set(),
  workerFallback: false,
  applying: false,
  themeChoice: localStorage.getItem(THEME_KEY) || "auto",
  pendingFiles: { report: null, manifest: null },
  loadedFiles: { report: null, manifest: null },
  meta: { packageCount: 0, packageNames: [], layerNames: [], duplicatePairCount: 0, totalIssueCount: 0, parseMs: 0 },
  history: loadHistory()
};

let worker = null;
const $ = (id) => document.getElementById(id);

const fileInput = $("fileInput");
const manifestInput = $("manifestInput");
const applyDataBtn = $("applyDataBtn");
const applyHint = $("applyHint");
const resetBtn = $("resetBtn");
const errorBox = $("errorBox");
const statusBox = $("statusBox");
const tableHead = $("tableHead");
const tableBody = $("tableBody");
const packageSelect = $("packageSelect");
const layerSelect = $("layerSelect");
const textSearch = $("textSearch");
const ignorePackages = $("ignorePackages");
const minScoreInput = $("minScore");
const maxScoreInput = $("maxScore");
const incNoScore = $("incNoScore");
const incNoVector = $("incNoVector");
const sortSelect = $("sortSelect");
const displayDuplicates = $("displayDuplicates");
const manifestOnly = $("manifestOnly");
const linuxOnly = $("linuxOnly");
const kernelOnly = $("kernelOnly");
const pageSize = $("pageSize");
const prevPage = $("prevPage");
const nextPage = $("nextPage");
const pageIndicator = $("pageIndicator");
const tableSummary = $("tableSummary");
const loadLog = $("loadLog");
const pendingSummary = $("pendingSummary");
const fileBadges = $("fileBadges");
const reportFileName = $("reportFileName");
const manifestFileName = $("manifestFileName");
const insightList = $("insightList");
const metricPackages = $("metricPackages");
const metricIssues = $("metricIssues");
const metricFiltered = $("metricFiltered");
const metricUnpatched = $("metricUnpatched");
const metricManifest = $("metricManifest");
const metricKernel = $("metricKernel");
const metricParseMs = $("metricParseMs");
const statusChart = $("statusChart");
const linuxChart = $("linuxChart");
const packageChart = $("packageChart");
const statusCaption = $("statusCaption");
const linuxCaption = $("linuxCaption");
const packageCaption = $("packageCaption");
const showColumnsName = $("showColumnsName");
const showColumnsLayer = $("showColumnsLayer");
const showColumnsVersion = $("showColumnsVersion");
const showColumnsComponent = $("showColumnsComponent");
const showColumnsId = $("showColumnsId");
const showV2 = $("showV2");
const showV3 = $("showV3");
const showV4 = $("showV4");
const showStatus = $("showStatus");
const showKernel = $("showKernel");
const showLink = $("showLink");
const showDesc = $("showDesc");
const exportCsvBtn = $("exportCsv");
const exportJsonBtn = $("exportJson");
const exportTextBtn = $("exportText");
const exportLogBtn = $("exportLog");
const themeToggle = $("themeToggle");
const filterStatusCheckboxes = [...document.querySelectorAll(".filter-status")];
const filterImpactCheckboxes = [...document.querySelectorAll(".filter-impact")];
const filterAvCheckboxes = [...document.querySelectorAll(".filter-av")];
const filterCvssVersionCheckboxes = [...document.querySelectorAll(".filter-cvss-version")];

const STATUS_COLORS = { Unpatched: "#ef4444", Patched: "#22c55e", Ignored: "#f59e0b", Unknown: "#94a3b8" };
const IMPACT_COLORS = { Critical: "#dc2626", High: "#f97316", Medium: "#eab308", Low: "#38bdf8" };
const STATUS_NORMALIZATION = new Map([
  ["unpatched", "Unpatched"],
  ["patched", "Patched"],
  ["ignored", "Ignored"],
  ["fixed", "Patched"],
  ["resolved", "Patched"],
  ["not-applicable", "Ignored"],
  ["not applicable", "Ignored"],
  ["whitelisted", "Ignored"],
  ["excluded", "Ignored"]
]);

function applyTheme(choice) {
  state.themeChoice = choice;
  localStorage.setItem(THEME_KEY, choice);
  const resolved = choice === "auto"
    ? (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")
    : choice;
  document.documentElement.dataset.theme = resolved;
  if (themeToggle) {
    const label = { auto: "Theme: Auto", light: "Theme: Light", dark: "Theme: Dark" }[choice] || "Theme: Auto";
    themeToggle.textContent = label;
    themeToggle.title = label;
    themeToggle.setAttribute("aria-label", label);
  }
}

function setupTheme() {
  applyTheme(state.themeChoice);
  const media = window.matchMedia("(prefers-color-scheme: dark)");
  if (typeof media.addEventListener === "function") {
    media.addEventListener("change", () => {
      if (state.themeChoice === "auto") applyTheme("auto");
    });
  }
  if (themeToggle) {
    themeToggle.addEventListener("click", () => {
      const order = ["auto", "dark", "light"];
      const next = order[(order.indexOf(state.themeChoice) + 1) % order.length];
      applyTheme(next);
    });
  }
}

function showNotice(message) {
  statusBox.hidden = !message;
  statusBox.textContent = message || "";
}

function showError(message) {
  errorBox.hidden = false;
  errorBox.textContent = message;
}

function clearError() {
  errorBox.hidden = true;
  errorBox.textContent = "";
}

function toNumber(value) {
  if (value === null || value === undefined || value === "") return null;
  const parsed = Number(value);
  return Number.isNaN(parsed) ? null : parsed;
}

function impactFromScore(score) {
  if (score === null || score === undefined || Number.isNaN(score)) return null;
  if (score >= 9) return "Critical";
  if (score >= 7) return "High";
  if (score >= 4) return "Medium";
  return "Low";
}

function normalizeStatus(value) {
  const normalized = STATUS_NORMALIZATION.get(String(value || "").trim().toLowerCase());
  return normalized || (value ? String(value).trim() : "Unknown");
}

function normalizeAttackVector(issue) {
  const direct = String(issue.vector || issue.attackVector || "").trim().toUpperCase();
  if (direct) {
    if (direct === "ADJACENT_NETWORK") return "ADJACENT";
    if (["NETWORK", "ADJACENT", "LOCAL", "PHYSICAL"].includes(direct)) return direct;
  }
  const vectorString = String(issue.vectorString || issue.cvss_vector || issue.cvss3_vector || issue.cvss || "").toUpperCase();
  const match = vectorString.match(/AV[:=]([NALP])/);
  return match ? ({ N: "NETWORK", A: "ADJACENT", L: "LOCAL", P: "PHYSICAL" }[match[1]] || null) : null;
}

function parseIssueDetail(detail) {
  if (!detail) return "";
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map(parseIssueDetail).filter(Boolean).join(" ");
  if (typeof detail === "object") return Object.values(detail).map(parseIssueDetail).filter(Boolean).join(" ");
  return String(detail);
}

function detectKernelRelated(fields) {
  return /(linux|kernel|kconfig|drivers\/|arch\/|fs\/|net\/|security\/|kernel config|yocto kernel)/i.test(fields);
}
function buildPackageSetFromReport(raw) {
  const packages = raw.package || raw.packages || raw.data || raw.items;
  if (!Array.isArray(packages)) {
    throw new Error(`Parsed JSON does not contain a package array. Top-level keys: ${Object.keys(raw || {}).join(", ")}`);
  }

  const flatIssues = [];
  const packageNames = new Set();
  const layerNames = new Set();
  const seenPairs = new Set();

  for (const pkg of packages) {
    const packageName = String(pkg.name || "Package name missing");
    const layer = String(pkg.layer || pkg.collection || "Unknown");
    const version = String(pkg.version || "");
    const issues = Array.isArray(pkg.issue) ? pkg.issue : [];
    const products = Array.isArray(pkg.products) ? pkg.products : [];
    const component = products.map((entry) => entry && entry.product).filter(Boolean).join(", ");
    const isLinuxRelated = /(linux|kernel|busybox|glibc|systemd)/i.test(packageName);

    packageNames.add(packageName);
    layerNames.add(layer);

    for (const issue of issues) {
      const id = String(issue.id || issue.cve || issue.name || "Unknown");
      seenPairs.add(`${packageName}::${id}`);
      const scorev2 = toNumber(issue.scorev2);
      const scorev3 = toNumber(issue.scorev3);
      const scorev4 = toNumber(issue.scorev4);
      const bestScore = [scorev4, scorev3, scorev2].find((score) => score !== null) ?? null;
      const description = issue.description || issue.summary || parseIssueDetail(issue.detail) || "";
      const summary = issue.summary || issue.description || "";
      const kernelText = [packageName, layer, version, component, summary, description].join(" ");

      flatIssues.push({
        id,
        name: packageName,
        version,
        layer,
        component,
        summary,
        description,
        status: normalizeStatus(issue.status),
        scorev2,
        scorev3,
        scorev4,
        bestScore,
        impact: impactFromScore(bestScore),
        attackVector: normalizeAttackVector(issue),
        vectorString: issue.vectorString || issue.cvss_vector || issue.cvss3_vector || issue.cvss || issue.vector || "",
        link: issue.link || issue.url || "",
        isLinuxRelated,
        isKernelRelated: detectKernelRelated(kernelText),
        manifestMatched: false
      });
    }
  }

  return {
    flatIssues,
    meta: {
      packageCount: packageNames.size,
      packageNames: [...packageNames].sort(),
      layerNames: [...layerNames].sort(),
      duplicatePairCount: flatIssues.length - seenPairs.size,
      totalIssueCount: flatIssues.length
    }
  };
}

function tokenizeManifestText(text) {
  const tokens = new Set();
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const parts = trimmed.split(/[,\s|;]+/).filter(Boolean);
    if (parts.length) tokens.add(parts[0]);
  }
  return [...tokens];
}

function addManifestName(names, value) {
  if (Array.isArray(value)) {
    value.forEach((entry) => addManifestName(names, entry));
    return;
  }
  if (typeof value !== "string") return;
  const trimmed = value.trim();
  if (!trimmed) return;
  names.add(trimmed);
  const docRefMatch = trimmed.match(/DocumentRef-([^:]+):SPDXRef-Package-/);
  if (docRefMatch) names.add(docRefMatch[1]);
  const packageRefMatch = trimmed.match(/SPDXRef-Package-([^:]+)$/);
  if (packageRefMatch) names.add(packageRefMatch[1]);
}

function buildManifestSet(rawText) {
  const text = rawText.trim();
  if (!text) return { packages: [] };
  if (text.startsWith("{") || text.startsWith("[")) {
    const parsed = JSON.parse(text);
    const names = new Set();
    const walk = (node) => {
      if (!node) return;
      if (Array.isArray(node)) {
        node.forEach(walk);
        return;
      }
      if (typeof node !== "object") return;
      addManifestName(names, node.name || node.package || node.component || node.artifact || node.PackageName);
      addManifestName(names, node.SPDXID);
      addManifestName(names, node.spdxElementId);
      addManifestName(names, node.relatedSpdxElement);
      addManifestName(names, node.documentDescribes);
      Object.values(node).forEach((value) => {
        if (typeof value === "object") walk(value);
      });
    };
    walk(parsed);
    return { packages: [...names].sort() };
  }
  return { packages: tokenizeManifestText(text).sort() };
}

function enrichDerivedFlags() {
  state.flatIssues = state.flatIssues.map((issue) => ({
    ...issue,
    manifestMatched: state.manifestPackages.has(issue.name.toLowerCase())
  }));
}

function handleWorkerMessage(event) {
  const { type, payload } = event.data || {};
  if (type === "parse-error") {
    showError(payload.message);
    return;
  }
  if (type === "report-ready") {
    clearError();
    state.flatIssues = payload.flatIssues;
    state.meta = { ...payload.meta, parseMs: payload.parseMs };
    enrichDerivedFlags();
    populateSelect(packageSelect, state.meta.packageNames, "All packages");
    populateSelect(layerSelect, state.meta.layerNames, "All layers");
    appendHistory({ kind: "report", timestamp: new Date().toISOString(), packages: payload.meta.packageCount, issues: payload.meta.totalIssueCount, parseMs: payload.parseMs, filename: state.loadedFiles.report || "unknown" });
    applyFiltersAndRender(true);
    return;
  }
  if (type === "manifest-ready") {
    clearError();
    state.manifestPackages = new Set(payload.packages.map((entry) => entry.toLowerCase()));
    enrichDerivedFlags();
    appendHistory({ kind: "manifest", timestamp: new Date().toISOString(), packages: payload.packages.length, issues: 0, parseMs: payload.parseMs, filename: state.loadedFiles.manifest || "unknown" });
    applyFiltersAndRender(true);
  }
}

function setupWorker() {
  if (typeof Worker !== "function") {
    state.workerFallback = true;
    showNotice("Background worker support is unavailable here. Parsing will run on the main thread.");
    return;
  }
  try {
    worker = new Worker("parser-worker.js");
    worker.onmessage = handleWorkerMessage;
    worker.onerror = () => {
      state.workerFallback = true;
      worker = null;
      showNotice("Opened from file://, so the parser worker is blocked. The dashboard is using main-thread parsing instead.");
    };
    worker.onmessageerror = () => {
      state.workerFallback = true;
      worker = null;
      showNotice("The parser worker returned an unreadable response. The dashboard is using main-thread parsing instead.");
    };
  } catch (error) {
    state.workerFallback = true;
    worker = null;
    showNotice(`Could not start the parser worker (${error && error.message ? error.message : String(error)}). Using main-thread parsing.`);
  }
}

function dispatchParse(type, text) {
  if (worker && !state.workerFallback) {
    try {
      worker.postMessage({ type, text });
      return;
    } catch (error) {
      state.workerFallback = true;
      worker = null;
      showNotice(`Background parsing failed (${error && error.message ? error.message : String(error)}). Using main-thread parsing.`);
    }
  }
  parseLocally(type, text);
}

function parseLocally(type, text) {
  const startedAt = performance.now();
  try {
    if (type === "parse-report") {
      const result = buildPackageSetFromReport(JSON.parse(text));
      handleWorkerMessage({ data: { type: "report-ready", payload: { ...result, parseMs: Math.round(performance.now() - startedAt) } } });
      return;
    }
    if (type === "parse-manifest") {
      const manifest = buildManifestSet(text);
      handleWorkerMessage({ data: { type: "manifest-ready", payload: { ...manifest, parseMs: Math.round(performance.now() - startedAt) } } });
      return;
    }
    throw new Error(`Unsupported parser type: ${type}`);
  } catch (error) {
    showError(error && error.message ? error.message : String(error));
  }
}
function selectedValues(checkboxes) {
  return checkboxes.filter((checkbox) => checkbox.checked).map((checkbox) => checkbox.value);
}

function sortItems(items, mode) {
  const sorted = [...items];
  switch (mode) {
    case "score_asc": return sorted.sort((a, b) => (a.bestScore ?? -1) - (b.bestScore ?? -1));
    case "unpatched_first": return sorted.sort((a, b) => Number(b.status === "Unpatched") - Number(a.status === "Unpatched") || ((b.bestScore ?? 0) - (a.bestScore ?? 0)));
    case "package_asc": return sorted.sort((a, b) => a.name.localeCompare(b.name));
    case "layer_asc": return sorted.sort((a, b) => a.layer.localeCompare(b.layer) || a.name.localeCompare(b.name));
    case "id_desc": return sorted.sort((a, b) => b.id.localeCompare(a.id));
    default: return sorted.sort((a, b) => (b.bestScore ?? -1) - (a.bestScore ?? -1));
  }
}

function applyFiltersAndRender(resetPage = false) {
  if (!state.flatIssues.length) {
    renderEmptyState();
    return;
  }
  if (resetPage) state.page = 1;
  const statuses = selectedValues(filterStatusCheckboxes);
  const impacts = selectedValues(filterImpactCheckboxes);
  const attackVectors = selectedValues(filterAvCheckboxes);
  const cvssVersions = selectedValues(filterCvssVersionCheckboxes);
  const ignoredPackages = new Set(ignorePackages.value.split(/\s+/).filter(Boolean));
  const includeNoScore = incNoScore.checked;
  const includeNoVector = incNoVector.checked;
  const minScore = Number(minScoreInput.value || 0);
  const maxScore = Number(maxScoreInput.value || 10);
  const selectedPackage = packageSelect.value;
  const selectedLayer = layerSelect.value;
  const searchText = textSearch.value.trim().toLowerCase();
  const dedupe = !displayDuplicates.checked;
  const pairSeen = new Set();

  let filtered = state.flatIssues.filter((issue) => {
    const pairKey = `${issue.name}::${issue.id}`;
    if (dedupe && pairSeen.has(pairKey)) return false;
    pairSeen.add(pairKey);
    if (ignoredPackages.has(issue.name)) return false;
    if (selectedPackage && issue.name !== selectedPackage) return false;
    if (selectedLayer && issue.layer !== selectedLayer) return false;
    if (manifestOnly.checked && !issue.manifestMatched) return false;
    if (linuxOnly.checked && !issue.isLinuxRelated) return false;
    if (kernelOnly.checked && !issue.isKernelRelated) return false;
    if (statuses.length && !statuses.includes(issue.status)) return false;
    if (impacts.length) {
      if (!issue.impact) {
        if (!includeNoScore) return false;
      } else if (!impacts.includes(issue.impact)) return false;
    }
    if (attackVectors.length) {
      if (!issue.attackVector) {
        if (!includeNoVector) return false;
      } else if (!attackVectors.includes(issue.attackVector)) return false;
    }
    if (cvssVersions.length) {
      const matchesVersion = cvssVersions.some((version) => {
        const score = issue[`scorev${version}`];
        if (score === null) return includeNoScore;
        return score >= minScore && score <= maxScore;
      });
      if (!matchesVersion) return false;
    }
    if (searchText) {
      const haystack = [issue.id, issue.name, issue.version, issue.layer, issue.component, issue.description, issue.summary, issue.link, issue.attackVector, issue.vectorString, issue.status, issue.impact]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      if (!haystack.includes(searchText)) return false;
    }
    return true;
  });

  state.filtered = sortItems(filtered, sortSelect.value);
  updateMetrics();
  renderCharts();
  renderInsights();
  renderTable();
}

function buildColumns() {
  const columns = [];
  if (showColumnsName.checked) columns.push({ key: "name", label: "Package" });
  if (showColumnsLayer.checked) columns.push({ key: "layer", label: "Layer" });
  if (showColumnsVersion.checked) columns.push({ key: "version", label: "Version" });
  if (showColumnsComponent.checked) columns.push({ key: "component", label: "Component" });
  if (showColumnsId.checked) columns.push({ key: "id", label: "CVE" });
  if (showV2.checked) columns.push({ key: "scorev2", label: "CVSS2" });
  if (showV3.checked) columns.push({ key: "scorev3", label: "CVSS3" });
  if (showV4.checked) columns.push({ key: "scorev4", label: "CVSS4" });
  if (showStatus.checked) columns.push({ key: "status", label: "Status" });
  columns.push({ key: "impact", label: "Impact" });
  columns.push({ key: "attackVector", label: "Attack Vector" });
  columns.push({ key: "manifestMatched", label: "SBOM" });
  if (showKernel.checked) columns.push({ key: "isKernelRelated", label: "Kernel" });
  if (showLink.checked) columns.push({ key: "link", label: "Link" });
  if (showDesc.checked) columns.push({ key: "description", label: "Description" });
  return columns;
}

function renderCell(issue, key) {
  if (key === "name") return `<td><button class="package-link" data-pkg="${escapeHtml(issue.name)}">${escapeHtml(issue.name)}</button></td>`;
  if (key === "status") return `<td><span class="pill" style="--pill-color:${STATUS_COLORS[issue.status] || STATUS_COLORS.Unknown}">${escapeHtml(issue.status)}</span></td>`;
  if (key === "impact") return `<td><span class="pill" style="--pill-color:${IMPACT_COLORS[issue.impact] || "#94a3b8"}">${escapeHtml(issue.impact || "N/A")}</span></td>`;
  if (key === "manifestMatched") return `<td>${issue.manifestMatched ? "Yes" : "No"}</td>`;
  if (key === "isKernelRelated") return `<td>${issue.isKernelRelated ? "Kernel-related" : ""}</td>`;
  if (key === "link") return `<td>${issue.link ? `<a href="${escapeHtml(issue.link)}" target="_blank" rel="noreferrer noopener">Open</a>` : ""}</td>`;
  if (key === "description") return `<td class="description-cell" title="${escapeHtml(issue.description || issue.summary || "")}">${escapeHtml(issue.description || issue.summary || "")}</td>`;
  const value = issue[key];
  return `<td>${value === null || value === undefined ? "" : escapeHtml(String(value))}</td>`;
}

function renderTable() {
  const columns = buildColumns();
  tableHead.innerHTML = `<tr>${columns.map((column) => `<th>${column.label}</th>`).join("")}</tr>`;
  const size = Number(pageSize.value);
  const totalPages = Math.max(1, Math.ceil(state.filtered.length / size));
  state.page = Math.min(state.page, totalPages);
  const start = (state.page - 1) * size;
  const pageItems = state.filtered.slice(start, start + size);
  tableBody.innerHTML = pageItems.map((issue) => `<tr>${columns.map((column) => renderCell(issue, column.key)).join("")}</tr>`).join("");
  pageIndicator.textContent = `Page ${state.page} / ${totalPages}`;
  tableSummary.textContent = `${state.filtered.length.toLocaleString()} issues in view, showing ${pageItems.length.toLocaleString()} rows on this page.`;
  prevPage.disabled = state.page <= 1;
  nextPage.disabled = state.page >= totalPages;
  document.querySelectorAll(".package-link").forEach((node) => {
    node.addEventListener("click", () => {
      packageSelect.value = node.dataset.pkg || "";
      applyFiltersAndRender(true);
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  });
}

function countBy(items, keySelector) {
  return items.reduce((counts, item) => {
    const label = typeof keySelector === "function" ? keySelector(item) : item[keySelector];
    counts[label || "Unknown"] = (counts[label || "Unknown"] || 0) + 1;
    return counts;
  }, {});
}

function topCounts(items, key, limit) {
  return Object.entries(countBy(items, key)).sort((a, b) => b[1] - a[1]).slice(0, limit);
}

function sumCounts(counts) {
  return Object.values(counts).reduce((sum, value) => sum + value, 0);
}

function donutMarkup(counts, colors) {
  const total = sumCounts(counts);
  if (!total) return '<div class="empty-state">No matching issues.</div>';
  let offset = 0;
  const radius = 42;
  const circumference = 2 * Math.PI * radius;
  const rings = Object.entries(counts).filter(([, value]) => value > 0).map(([label, value]) => {
    const length = value / total * circumference;
    const ring = `<circle r="${radius}" cx="60" cy="60" fill="transparent" stroke="${colors[label] || "#94a3b8"}" stroke-width="16" stroke-dasharray="${length} ${circumference - length}" stroke-dashoffset="${-offset}" />`;
    offset += length;
    return ring;
  }).join("");
  const legend = Object.entries(counts).filter(([, value]) => value > 0).map(([label, value]) => `<li><span class="legend-dot" style="background:${colors[label] || "#94a3b8"}"></span>${escapeHtml(label)}<strong>${value}</strong></li>`).join("");
  return `<div class="donut-wrap"><svg viewBox="0 0 120 120" class="donut"><circle r="${radius}" cx="60" cy="60" fill="transparent" stroke="rgba(148, 163, 184, 0.18)" stroke-width="16"></circle>${rings}</svg><div class="donut-total"><strong>${total}</strong><span>items</span></div></div><ul class="legend-list">${legend}</ul>`;
}

function barsMarkup(entries) {
  if (!entries.length) return '<div class="empty-state">No matching packages.</div>';
  const max = Math.max(...entries.map(([, value]) => value));
  return entries.map(([label, value]) => `<div class="bar-row"><span class="bar-label" title="${escapeHtml(label)}">${escapeHtml(label)}</span><div class="bar-track"><span class="bar-fill" style="width:${value / max * 100}%"></span></div><strong>${value}</strong></div>`).join("");
}

function renderCharts() {
  const statusCounts = countBy(state.filtered, "status");
  const linuxCounts = {
    "Linux-related": state.filtered.filter((item) => item.isLinuxRelated).length,
    "Other packages": state.filtered.filter((item) => !item.isLinuxRelated).length
  };
  const packageCounts = topCounts(state.filtered, "name", 10);
  statusChart.innerHTML = donutMarkup(statusCounts, STATUS_COLORS);
  linuxChart.innerHTML = donutMarkup(linuxCounts, { "Linux-related": "#38bdf8", "Other packages": "#818cf8" });
  packageChart.innerHTML = barsMarkup(packageCounts);
  statusCaption.textContent = `${sumCounts(statusCounts)} issues`;
  linuxCaption.textContent = `${linuxCounts["Linux-related"]} linux-related / ${linuxCounts["Other packages"]} other`;
  packageCaption.textContent = `${packageCounts.length} packages shown`;
}
function renderInsights() {
  if (!state.flatIssues.length) {
    insightList.innerHTML = '<div class="empty-state">Load a report to see risk signals.</div>';
    return;
  }
  const unpatched = state.filtered.filter((item) => item.status === "Unpatched").length;
  const kernel = state.filtered.filter((item) => item.isKernelRelated).length;
  const noSbom = state.filtered.filter((item) => !item.manifestMatched).length;
  const cards = [
    { title: "Actionable backlog", body: `${unpatched.toLocaleString()} findings remain unpatched in the current view.` },
    { title: "Kernel focus", body: `${kernel.toLocaleString()} findings appear kernel-related based on package, layer, or issue text.` },
    { title: "SBOM name-match gap", body: `${noSbom.toLocaleString()} findings in the current view do not have an exact package-name match in the staged manifest or SPDX file.` }
  ];
  insightList.innerHTML = cards.map((card) => `<article class="insight-card"><strong>${escapeHtml(card.title)}</strong><span>${escapeHtml(card.body)}</span></article>`).join("");
}

function updateMetrics() {
  metricPackages.textContent = state.meta.packageCount.toLocaleString();
  metricIssues.textContent = state.meta.totalIssueCount.toLocaleString();
  metricFiltered.textContent = state.filtered.length.toLocaleString();
  metricUnpatched.textContent = state.filtered.filter((item) => item.status === "Unpatched").length.toLocaleString();
  metricManifest.textContent = state.filtered.filter((item) => item.manifestMatched).length.toLocaleString();
  metricKernel.textContent = state.filtered.filter((item) => item.isKernelRelated).length.toLocaleString();
  metricParseMs.textContent = `${state.meta.parseMs} ms`;
}

function populateSelect(select, entries, label) {
  const previous = select.value;
  select.innerHTML = `<option value="">${escapeHtml(label)}</option>` + entries.map((entry) => `<option value="${escapeHtml(entry)}">${escapeHtml(entry)}</option>`).join("");
  if (entries.includes(previous)) select.value = previous;
}

function renderEmptyState() {
  updateMetrics();
  tableHead.innerHTML = '<tr><th>Load a CVE report to begin</th></tr>';
  tableBody.innerHTML = "";
  tableSummary.textContent = "Load a report to begin.";
  pageIndicator.textContent = "Page 1 / 1";
  prevPage.disabled = true;
  nextPage.disabled = true;
  statusChart.innerHTML = '<div class="empty-state">No report loaded.</div>';
  linuxChart.innerHTML = '<div class="empty-state">No report loaded.</div>';
  packageChart.innerHTML = '<div class="empty-state">No report loaded.</div>';
  insightList.innerHTML = '<div class="empty-state">Load a report to see risk signals.</div>';
  renderHistory();
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function exportCSV(rows, columns, filename) {
  const escape = (value) => value === null || value === undefined ? "" : `"${String(value).replace(/"/g, '""')}"`;
  const header = columns.map((column) => escape(column)).join(",");
  const body = rows.map((row) => columns.map((column) => escape(row[column])).join(",")).join("\n");
  downloadBlob(new Blob([`${header}\n${body}`], { type: "text/csv;charset=utf-8" }), filename);
}

function exportJSON(value, filename) {
  downloadBlob(new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }), filename);
}

function exportTextReport(rows, filename) {
  const lines = ["CVE Dashboard Report", `Generated: ${new Date().toISOString()}`, `Rows: ${rows.length}`, ""];
  rows.forEach((row) => {
    lines.push(`${row.id} | ${row.name} | ${row.status} | ${row.impact || "N/A"} | SBOM: ${row.manifestMatched ? "Yes" : "No"}`);
    if (row.component) lines.push(`Component: ${row.component}`);
    if (row.description) lines.push(`Summary: ${row.description}`);
    if (row.link) lines.push(`Link: ${row.link}`);
    lines.push("");
  });
  downloadBlob(new Blob([lines.join("\n")], { type: "text/plain;charset=utf-8" }), filename);
}

function escapeHtml(value) {
  return String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function appendHistory(entry) {
  state.history = [entry, ...state.history].slice(0, 20);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state.history));
  renderHistory();
}

function loadHistory() {
  try {
    const parsed = JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function renderHistory() {
  if (!state.history.length) {
    loadLog.className = "load-log empty";
    loadLog.textContent = "No report loaded yet.";
    return;
  }
  loadLog.className = "load-log";
  loadLog.innerHTML = state.history.map((entry) => {
    const when = new Date(entry.timestamp).toLocaleString();
    const details = entry.kind === "report"
      ? `${entry.filename} | ${entry.packages} packages | ${entry.issues} CVEs | ${entry.parseMs} ms`
      : `${entry.filename} | ${entry.packages} entries | ${entry.parseMs} ms`;
    return `<div class="log-item"><strong>${escapeHtml(entry.kind)}</strong><span>${escapeHtml(details)}</span><time>${escapeHtml(when)}</time></div>`;
  }).join("");
}

function updatePendingSummary() {
  fileBadges.innerHTML = "";
  const staged = [
    [state.pendingFiles.report || state.loadedFiles.report, "Report"],
    [state.pendingFiles.manifest || state.loadedFiles.manifest, "SBOM"]
  ].filter(([value]) => Boolean(value));

  pendingSummary.textContent = staged.length
    ? staged.map(([value, label]) => `${label}: ${value.name || value}`).join(" | ")
    : "No files staged yet.";

  staged.forEach(([value, label]) => {
    const badge = document.createElement("span");
    badge.className = "badge";
    badge.textContent = `${label}: ${value.name || value}`;
    fileBadges.appendChild(badge);
  });

  reportFileName.textContent = state.pendingFiles.report ? state.pendingFiles.report.name : (state.loadedFiles.report || "No file selected");
  manifestFileName.textContent = state.pendingFiles.manifest ? state.pendingFiles.manifest.name : (state.loadedFiles.manifest || "Optional");

  const hasStage = Boolean(state.pendingFiles.report || state.pendingFiles.manifest);
  const hasReport = Boolean(state.pendingFiles.report || state.loadedFiles.report);
  applyDataBtn.disabled = state.applying || !hasStage || !hasReport;
  applyHint.textContent = state.applying
    ? "Parsing staged files..."
    : hasStage
      ? "Apply to refresh the dashboard with staged data."
      : "Select at least a CVE summary, then apply.";
}

async function applyStagedFiles() {
  if (state.applying) return;
  if (!(state.pendingFiles.report || state.loadedFiles.report)) {
    showError("Stage a CVE summary JSON before applying.");
    return;
  }
  state.applying = true;
  clearError();
  updatePendingSummary();
  try {
    if (state.pendingFiles.report) {
      state.loadedFiles.report = state.pendingFiles.report.name;
      dispatchParse("parse-report", await state.pendingFiles.report.text());
      state.pendingFiles.report = null;
    }
    if (state.pendingFiles.manifest) {
      state.loadedFiles.manifest = state.pendingFiles.manifest.name;
      dispatchParse("parse-manifest", await state.pendingFiles.manifest.text());
      state.pendingFiles.manifest = null;
    }
  } finally {
    state.applying = false;
    updatePendingSummary();
  }
}

function bindEvents() {
  fileInput.addEventListener("change", (event) => {
    state.pendingFiles.report = event.target.files && event.target.files[0] ? event.target.files[0] : null;
    updatePendingSummary();
  });
  manifestInput.addEventListener("change", (event) => {
    state.pendingFiles.manifest = event.target.files && event.target.files[0] ? event.target.files[0] : null;
    updatePendingSummary();
  });
  applyDataBtn.addEventListener("click", applyStagedFiles);
  resetBtn.addEventListener("click", () => {
    document.querySelectorAll('input[type="checkbox"]').forEach((checkbox) => {
      checkbox.checked = checkbox.defaultChecked;
    });
    textSearch.value = "";
    ignorePackages.value = "";
    packageSelect.value = "";
    layerSelect.value = "";
    minScoreInput.value = "0";
    maxScoreInput.value = "10";
    sortSelect.value = "score_desc";
    pageSize.value = "250";
    state.page = 1;
    clearError();
    applyFiltersAndRender(true);
  });
  [
    ...filterStatusCheckboxes, ...filterImpactCheckboxes, ...filterAvCheckboxes, ...filterCvssVersionCheckboxes,
    textSearch, ignorePackages, packageSelect, layerSelect, minScoreInput, maxScoreInput, incNoScore, incNoVector,
    displayDuplicates, manifestOnly, linuxOnly, kernelOnly, sortSelect, pageSize,
    showColumnsName, showColumnsLayer, showColumnsVersion, showColumnsComponent, showColumnsId, showV2, showV3, showV4, showStatus, showKernel, showLink, showDesc
  ].forEach((element) => element.addEventListener("input", () => applyFiltersAndRender(true)));
  prevPage.addEventListener("click", () => { state.page = Math.max(1, state.page - 1); renderTable(); });
  nextPage.addEventListener("click", () => {
    const totalPages = Math.max(1, Math.ceil(state.filtered.length / Number(pageSize.value)));
    state.page = Math.min(totalPages, state.page + 1);
    renderTable();
  });
  exportCsvBtn.addEventListener("click", () => {
    if (!state.filtered.length) return alert("No filtered data to export.");
    exportCSV(state.filtered, buildColumns().map((column) => column.key), "cve_report.csv");
  });
  exportJsonBtn.addEventListener("click", () => {
    if (!state.filtered.length) return alert("No filtered data to export.");
    exportJSON(state.filtered, "cve_report.json");
  });
  exportTextBtn.addEventListener("click", () => {
    if (!state.filtered.length) return alert("No filtered data to export.");
    exportTextReport(state.filtered, "cve_report.txt");
  });
  exportLogBtn.addEventListener("click", () => exportJSON(state.history, "cve_load_log.json"));
}

setupTheme();
setupWorker();
bindEvents();
updatePendingSummary();
renderHistory();
renderEmptyState();




