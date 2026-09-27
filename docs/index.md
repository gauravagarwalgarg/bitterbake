# Welcome to VulnCanvas

VulnCanvas is a powerful, static, and serverless web application designed to process and analyze standard CVE summary JSON files alongside Software Bill of Materials (SBOM) data, such as Yocto Scarthgap SPDX files.

## Features

- **Zero-Trust Local Engine**: Privacy and security are paramount. VulnCanvas relies entirely on the browser's native File API. When you drag and drop your sensitive vulnerability scans and SBOMs into the dashboard, all parsing, correlation, and rendering happens locally on your machine. No data is ever uploaded to a remote server.
- **Generic CVE Parsing**: Automatically ingests and normalizes complex NVD/CVE JSON datasets.
- **SPDX SBOM Correlation**: Maps discovered vulnerabilities directly to your firmware or software dependencies to filter out the noise.
- **Interactive Risk Dashboard**: Provides immediate, actionable insights through metrics, sortable data tables, and visual risk heatmaps.

## Getting Started

Simply run the application, drag your CVE and (optional) SPDX JSON files into the drop zones, and let the local engine do the rest.
