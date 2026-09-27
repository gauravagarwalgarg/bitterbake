# bitterbake

[![GitHub Issues](https://img.shields.io/github/issues/gauravagarwalgarg/bitterbake)](https://github.com/gauravagarwalgarg/bitterbake/issues)
[![GitHub Forks](https://img.shields.io/github/forks/gauravagarwalgarg/bitterbake)](https://github.com/gauravagarwalgarg/bitterbake/network)
[![GitHub Stars](https://img.shields.io/github/stars/gauravagarwalgarg/bitterbake)](https://github.com/gauravagarwalgarg/bitterbake/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

bitterbake is a static, serverless web application that processes and analyzes standard CVE summary JSON files, with support for Yocto Scarthgap SPDX JSON files and generic SBOMs (CycloneDX, etc.).

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
Full documentation can be found at [https://gauravagarwalgarg.github.io/bitterbake/docs](https://gauravagarwalgarg.github.io/bitterbake/docs).

## License
MIT License
