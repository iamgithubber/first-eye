#!/usr/bin/env python3
"""
export_to_json.py - Compress recon outputs into a single AI/LLM-readable JSON file.

Usage:
    python3 export_to_json.py --indir outputs/<run_id> --out output.json --target example.com
"""
import argparse
import json
from pathlib import Path

def read_file_lines(path):
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]

def main():
    parser = argparse.ArgumentParser(description="Export recon outputs to a single JSON file for LLMs.")
    parser.add_argument('--indir', required=True, help='Input directory with recon outputs')
    parser.add_argument('--out', required=True, help='Output JSON file')
    parser.add_argument('--target', required=True, help='Target domain')
    args = parser.parse_args()

    indir = Path(args.indir)
    # Aggregate subdomains from all available sources
    subs_unique = read_file_lines(indir / "subs_unique.txt")
    if not subs_unique:
        # Fallback: merge from assetfinder.txt and subfinder.txt
        assetfinder = read_file_lines(indir / "assetfinder.txt")
        subfinder = read_file_lines(indir / "subfinder.txt")
        subs_set = set(assetfinder) | set(subfinder)
        subs_unique = sorted(subs_set)
    output = {
        "target": args.target,
        "subdomains": subs_unique,
        "dns_info": (indir / "dnsrecon.txt").read_text(encoding="utf-8", errors="ignore") if (indir / "dnsrecon.txt").exists() else "",
        "httpx": read_file_lines(indir / "httpx.txt"),
        "naabu": read_file_lines(indir / "naabu.txt"),
        "nuclei": read_file_lines(indir / "nuclei.json"),
        "waybackurls": read_file_lines(indir / "waybackurls.txt"),
        "gau": read_file_lines(indir / "gau.txt"),
        "meta": json.loads((indir / "run_meta.json").read_text(encoding="utf-8", errors="ignore")) if (indir / "run_meta.json").exists() else {},
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    print(f"[+] Exported recon results to {args.out}")

if __name__ == "__main__":
    main()
