# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]
- Added: Amass step now monitors output file and terminates if no new results for 20 minutes, moving to next phase automatically.
- Added: Verbose progress messages for all recon steps.
- Fixed: __future__ import order for Python 3.13 compatibility.
- Added: Caching for passive subdomain enumeration.
- Improved: Parallel execution of recon steps for faster results.

## [2025-09-26]
### Added
- Robust subdomain aggregation in `export_to_json.py` (merges subfinder, assetfinder, and subs_unique.txt)
- Ensured exported JSON report always includes all available findings
- Committed and pushed outputs for test run
