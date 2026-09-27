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

function impactFromScore(score) {
  if (score === null || score === undefined || Number.isNaN(score)) return null;
  if (score >= 9) return "Critical";
  if (score >= 7) return "High";
  if (score >= 4) return "Medium";
  return "Low";
}

function toNumber(value) {
  if (value === null || value === undefined || value === "") return null;
  const parsed = Number(value);
  return Number.isNaN(parsed) ? null : parsed;
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
  if (!Array.isArray(packages)) throw new Error(`Parsed JSON does not contain a package array. Top-level keys: ${Object.keys(raw || {}).join(", ")}`);

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
    const productList = products.map((entry) => entry && entry.product).filter(Boolean);
    const productText = productList.join(", ");
    const isLinuxRelated = /(linux|kernel|busybox|glibc|systemd)/i.test(packageName);

    packageNames.add(packageName);
    layerNames.add(layer);

    for (const issue of issues) {
      const id = String(issue.id || issue.cve || issue.name || "Unknown");
      const pairKey = `${packageName}::${id}`;
      seenPairs.add(pairKey);
      const scorev2 = toNumber(issue.scorev2);
      const scorev3 = toNumber(issue.scorev3);
      const scorev4 = toNumber(issue.scorev4);
      const bestScore = [scorev4, scorev3, scorev2].find((score) => score !== null) ?? null;
      const description = issue.description || issue.summary || parseIssueDetail(issue.detail) || "";
      const summary = issue.summary || issue.description || "";
      const kernelText = [packageName, layer, version, productText, summary, description].join(" ");
      flatIssues.push({
        id,
        name: packageName,
        version,
        layer,
        component: productText,
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
        productsInRecord: products.some((entry) => String((entry && entry.cvesInRecord) || "").toLowerCase() === "yes"),
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

self.onmessage = (event) => {
  const { type, text } = event.data || {};
  const startedAt = Date.now();
  try {
    if (type === "parse-report") {
      const parsed = JSON.parse(text);
      const result = buildPackageSetFromReport(parsed);
      self.postMessage({ type: "report-ready", payload: { ...result, parseMs: Date.now() - startedAt } });
      return;
    }
    if (type === "parse-manifest") {
      const manifest = buildManifestSet(text);
      self.postMessage({ type: "manifest-ready", payload: { ...manifest, parseMs: Date.now() - startedAt } });
      return;
    }
    throw new Error(`Unsupported worker message type: ${type}`);
  } catch (error) {
    self.postMessage({ type: "parse-error", payload: { message: error && error.message ? error.message : String(error) } });
  }
};
