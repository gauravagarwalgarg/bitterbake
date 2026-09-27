export function parseCVE(json) {
  const vulnerabilities = [];
  const items = json.CVE_Items || (json.vulnerabilities ? json.vulnerabilities : []);
  
  items.forEach(item => {
    let id, severity, score, vector, description, packages = [];

    if (item.cve && item.cve.CVE_data_meta) {
      id = item.cve.CVE_data_meta.ID;
      description = item.cve.description?.description_data?.[0]?.value || "";
      const impact = item.impact?.baseMetricV3 || item.impact?.baseMetricV2;
      if (impact) {
        score = impact.cvssV3?.baseScore || impact.cvssV2?.baseScore || 0;
        severity = impact.cvssV3?.baseSeverity || impact.severity || "UNKNOWN";
        vector = impact.cvssV3?.vectorString || impact.cvssV2?.vectorString || "";
      }
      const nodes = item.configurations?.nodes || [];
      nodes.forEach(node => {
        const cpeMatches = node.cpe_match || [];
        cpeMatches.forEach(match => {
          if (match.cpe23Uri) {
            const parts = match.cpe23Uri.split(':');
            if (parts.length >= 6) {
              packages.push({ vendor: parts[3], product: parts[4], version: parts[5] });
            }
          }
        });
      });
    } 
    else if (item.cve && item.cve.id) {
       id = item.cve.id;
       description = item.cve.descriptions?.[0]?.value || "";
       const metrics = item.cve.metrics?.cvssMetricV31?.[0] || item.cve.metrics?.cvssMetricV30?.[0] || item.cve.metrics?.cvssMetricV2?.[0];
       if (metrics) {
         score = metrics.cvssData?.baseScore || 0;
         severity = metrics.cvssData?.baseSeverity || "UNKNOWN";
         vector = metrics.cvssData?.vectorString || "";
       }
       const configs = item.cve.configurations || [];
       configs.forEach(config => {
         config.nodes?.forEach(node => {
           node.cpeMatch?.forEach(match => {
             const criteria = match.criteria;
             if (criteria) {
                const parts = criteria.split(':');
                if (parts.length >= 6) {
                  packages.push({ vendor: parts[3], product: parts[4], version: parts[5] });
                }
             }
           });
         });
       });
    }

    if (id) {
      vulnerabilities.push({
        id,
        severity: severity?.toUpperCase() || "UNKNOWN",
        score: parseFloat(score) || 0,
        vector,
        description,
        packages
      });
    }
  });

  return vulnerabilities;
}
