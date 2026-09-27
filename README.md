# VulnCanvas

[![GitHub Issues](https://img.shields.io/github/issues/gauravagarwalgarg/VulnCanvas)](https://github.com/gauravagarwalgarg/VulnCanvas/issues)
[![GitHub Forks](https://img.shields.io/github/forks/gauravagarwalgarg/VulnCanvas)](https://github.com/gauravagarwalgarg/VulnCanvas/network)
[![GitHub Stars](https://img.shields.io/github/stars/gauravagarwalgarg/VulnCanvas)](https://github.com/gauravagarwalgarg/VulnCanvas/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

VulnCanvas is a static, serverless web application that processes and analyzes standard CVE summary JSON files, with support for Yocto Scarthgap SPDX JSON files and generic SBOMs (CycloneDX, etc.).

## Features
- **Zero-trust local parsing:** All data parsing happens directly in the browser via the native File API. No server uploads.
- **Generic CVE Parser:** Processes standard NVD/CVE JSON formats.
- **SBOM Correlation:** Correlates Yocto SPDX package lists and other SBOM formats with CVE data to map vulnerabilities to a Software Bill of Materials.
- **Dashboard:** Interactive UI with metrics, data tables, and risk heatmaps.

## Local Development

### Frontend
```bash
npm install
npm run dev
```

### Documentation
```bash
pip install mkdocs-material
mkdocs serve
```

## Documentation
Full documentation can be found at [https://gauravagarwalgarg.github.io/VulnCanvas/docs](https://gauravagarwalgarg.github.io/VulnCanvas/docs).

## License
MIT License
