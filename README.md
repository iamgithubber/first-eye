# ai-recon

An automated reconnaissance framework that integrates the best open-source recon tools with a Python orchestration layer and LLM-ready structured output. The goal: fast, repeatable recon with AI-powered analysis.

## Recent Updates
- **[2025-09-30]**: Amass step now monitors output file and terminates if no new results for 20 minutes, moving to next phase automatically.
- Added verbose progress messages for all recon steps.
- Fixed import order for Python 3.13 compatibility.
- Added caching for passive subdomain enumeration.
- Improved parallel execution for faster results.
- **[2025-09-26]**: Improved subdomain aggregation in `export_to_json.py` (merges subfinder, assetfinder, and subs_unique.txt for robust reporting)
- Added `CHANGELOG.md` to track all notable changes
- Exported JSON report now always includes all available findings

🚀 **Features**

- **Subdomain Enumeration** → subfinder, assetfinder, amass, crt.sh, censys, shodan
- **DNS Resolution** → dnsx, massdns, dnsrecon
- **Port & Service Scanning** → nmap, naabu
- **Web Recon** → httpx, whatweb, wafwoof, hakrawler, katana, gobuster
- **Takeover Detection** → subjack, subzy
- **Parameter Discovery** → arjun, paramspider, waybackurls
- **JavaScript/Secrets Analysis** → linkfinder, jsfinder, secretfinder, lazyegg
- **Vulnerability Scanning** → nuclei (with template support)
- **LLM Integration** → Structured JSON output for AI-powered triage (via LM Studio, GPT, etc.)
- **Reporting** → JSON/Markdown/HTML reports with summaries and “juicy” findings

📂 **Project Structure**

```
ai-recon/
│── recon_tools/        # Individual tool wrappers (Python)
│── scripts/            # Helper scripts
│── data/               # Raw tool outputs
│── reports/            # Final parsed reports
│── recon.py            # Main orchestrator (runs tools, collects results)
│── requirements.txt    # Python dependencies
│── Dockerfile          # Containerized setup
│── README.md           # Documentation
```

⚙️ **Installation**

**Prerequisites**
- Linux / macOS (recommended; Windows WSL2 works too)
- Python 3.9+
- Docker (optional, for containerized setup)
- API keys for Shodan, Censys (if used)

**Clone Repository**
```sh
git clone https://github.com/yourname/ai-recon.git
cd ai-recon
```

**Install Python Requirements**
```sh
pip install -r requirements.txt
```

**Install Recon Tools**

Manually install required tools or let the Docker container handle it:
- subfinder, assetfinder, amass
- httpx, dnsx, naabu, nuclei
- hakrawler, katana, gobuster, etc.

⚡ Tip: For reproducibility, use the Docker build.


🛠 **Usage**


Run Recon
```sh
python3 main.py
```

Or use the orchestrator directly:
```sh
python3 recon.py -d example.com -o output.json
```

**Arguments:**
- `-d` / `--domain` → Target domain
- `-o` / `--output` → Output JSON file (LLM-ready schema)

**Example**
```sh
python3 recon.py -d hackerone.com -o reports/h1.json
```


🤖 **LLM Post-Processing**

Feed the JSON into an LLM (LM Studio / GPT / Claude) for triage:

Prompt example:
```
You are a security analyst.
Input: [Recon JSON].
Task:
1. Summarize key findings.
2. Highlight interesting URLs/directories.
3. Prioritize hosts by severity.
Output: JSON {summary, interesting_urls, high_priority_hosts}
```


📊 **Roadmap**
- Add chunking for large inputs (LLM handling)
- CI/CD with GitHub Actions
- Automated HTML/PDF report generator
- Multi-target batch mode


📄 **Changelog**
See `CHANGELOG.md` for a list of all notable changes and release notes.

⚠️ **Legal Disclaimer**

This tool is for educational and authorized security testing only.
Do not use against systems without explicit written permission.
The authors take no responsibility for misuse.


✨ Happy Hacking & Recon!
