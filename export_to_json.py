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
    # Extract IPs from amass_passive.txt
    def extract_ips(path):
        import re
        ips = set()
        if not path.exists():
            return []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            # Match IPv4 and IPv6 addresses
            for ip in re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|\b(?:[a-fA-F0-9:]+:+)+[a-fA-F0-9]+\b", line):
                ips.add(ip)
        return sorted(ips)

    ip_blocks = extract_ips(indir / "amass_passive.txt")

    # Parse amass_passive.txt into structured records
    def parse_amass(path):
        import re
        results = []
        if not path.exists():
            return results
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            # Example: foo.com (FQDN) --> a_record --> 1.2.3.4 (IPAddress)
            m = re.match(r"(.+?) \((FQDN|Netblock|ASN|RIROrganization|IPAddress)\) --> ([^ ]+) --> (.+?) \((FQDN|Netblock|ASN|RIROrganization|IPAddress)?\)", line)
            if m:
                src, src_type, rel, dst, dst_type = m.groups()
                rec = {"src": src, "src_type": src_type, "relation": rel, "dst": dst, "dst_type": dst_type}
                # If IP address, add ip/type keys
                if dst_type == "IPAddress":
                    rec["ip"] = dst
                    rec["ip_type"] = "ipv6" if ":" in dst else "ipv4"
                results.append(rec)
            else:
                # fallback: try to extract IP
                ip_match = re.search(r"((?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:[a-fA-F0-9:]+:+)+[a-fA-F0-9]+)", line)
                if ip_match:
                    results.append({"raw": line, "ip": ip_match.group(1), "ip_type": "ipv6" if ":" in ip_match.group(1) else "ipv4"})
                else:
                    results.append({"raw": line})
        return results

    amass_structured = parse_amass(indir / "amass_passive.txt")

    output = {
        "target": args.target,
        "subdomains": subs_unique,
        "dns_info": (indir / "dnsrecon.txt").read_text(encoding="utf-8", errors="ignore") if (indir / "dnsrecon.txt").exists() else "",
        "httpx": read_file_lines(indir / "httpx.txt"),
        "naabu": read_file_lines(indir / "naabu.txt"),
        "nuclei": read_file_lines(indir / "nuclei.json"),
        "waybackurls": read_file_lines(indir / "waybackurls.txt"),
        "gau": read_file_lines(indir / "gau.txt"),
        "ip_blocks": ip_blocks,
        "amass": amass_structured,
        "meta": json.loads((indir / "run_meta.json").read_text(encoding="utf-8", errors="ignore")) if (indir / "run_meta.json").exists() else {},
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    print(f"[+] Exported recon results to {args.out}")

if __name__ == "__main__":
    main()
