export function parseSPDX(json) {
  const packages = [];
  if (json.packages && Array.isArray(json.packages)) {
    json.packages.forEach(pkg => {
      packages.push({
        name: pkg.name,
        version: pkg.versionInfo,
        spdxId: pkg.SPDXID
      });
    });
  }
  return packages;
}
