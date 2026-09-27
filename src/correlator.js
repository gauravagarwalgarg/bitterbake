export function correlate(cveList, spdxPackages) {
  if (!spdxPackages || spdxPackages.length === 0) return cveList;

  return cveList.map(cve => {
    const sbomMatches = [];
    cve.packages.forEach(cpe => {
      const match = spdxPackages.find(sp => 
        sp.name.toLowerCase() === cpe.product.toLowerCase() && 
        (sp.version === cpe.version || cpe.version === '*' || cpe.version === '-')
      );
      if (match) {
        sbomMatches.push(match);
      }
    });

    return {
      ...cve,
      sbomMatches,
      inSbom: sbomMatches.length > 0
    };
  });
}
