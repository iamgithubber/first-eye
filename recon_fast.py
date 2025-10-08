#!/usr/bin/env python3
"""
recon_fast.py - High-throughput, production-grade recon orchestrator

- Fast, parallel, and robust recon pipeline for authorized security testing.
- Supports Findomain, masscan, async DNS, streaming httpx, juicy scoring, and more.
- CLI flags for tool selection, concurrency, benchmarking, and safety.
- See README.md for usage, safety, and tuning tips.
"""
import argparse
import logging
import os
import shlex
import subprocess
import sys
import time
import json
import gzip
import tempfile
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Timer
from typing import List, Set, Dict, Optional

# Optional: async DNS
try:
    import aiodns
    import asyncio
except ImportError:
    aiodns = None
    asyncio = None

# --- Config ---
TOOLS = {
    "subfinder": "subfinder",
    "assetfinder": "assetfinder",
    "amass": "amass",
    "findomain": "findomain",
    "dnsx": "dnsx",
    "dnsrecon": "dnsrecon",
    "httpx": "httpx",
    "httprobe": "httprobe",
    "naabu": "naabu",
    "masscan": "masscan",
    "nuclei": "nuclei",
    "waybackurls": "waybackurls",
    "gau": "gau",
    "katana": "katana",
    "hakrawler": "hakrawler",
    "paramspider": "paramspider",
}

DEFAULT_CONCURRENCY = 32
DEFAULT_TIMEOUT = 600
DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8"]

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("recon_fast")

# --- Utility functions ---
def which(tool):
    from shutil import which as _which
    return _which(tool)

def safe_run(cmd, timeout=DEFAULT_TIMEOUT, dry_run=False, shell=True, input_data=None):
    logger.debug(f"[safe_run] {cmd}")
    if dry_run:
        logger.info(f"[dry-run] would run: {cmd}")
        return 0, ""
    try:
        proc = subprocess.run(cmd, shell=shell, input=input_data, capture_output=True, timeout=timeout)
        return proc.returncode, proc.stdout.decode("utf-8", errors="ignore")
    except subprocess.TimeoutExpired:
        logger.warning(f"[safe_run] Timeout: {cmd}")
        return 124, ""
    except Exception as e:
        logger.error(f"[safe_run] Exception: {e}")
        return 1, str(e)

def dedup_write(lines: List[str], out_path: Path, compress=False):
    seen = set()
    if compress:
        with gzip.open(out_path, "wt", encoding="utf-8") as f:
            for line in lines:
                if line not in seen:
                    f.write(line + "\n")
                    seen.add(line)
    else:
        with out_path.open("w", encoding="utf-8") as f:
            for line in lines:
                if line not in seen:
                    f.write(line + "\n")
                    seen.add(line)

def now():
    return time.time()

def timing_report(start_times: Dict[str, float], end_times: Dict[str, float], outdir: Path):
    report = {k: end_times[k] - start_times[k] for k in start_times if k in end_times}
    with (outdir / "timing_report.json").open("w") as f:
        json.dump(report, f, indent=2)
    logger.info(f"Timing report written to {outdir}/timing_report.json")

# --- Passive subdomain enumeration ---
def run_findomain(target: str, outdir: Path, dry_run: bool):
    out = outdir / "findomain.txt"
    if not which(TOOLS["findomain"]):
        logger.warning("findomain not found; skipping.")
        out.write_text("")
        return
    cmd = f"{TOOLS['findomain']} -t {shlex.quote(target)} -u {shlex.quote(str(out))}"
    safe_run(cmd, dry_run=dry_run)

def run_subfinder(target: str, outdir: Path, dry_run: bool):
    out = outdir / "subfinder.txt"
    if not which(TOOLS["subfinder"]):
        logger.warning("subfinder not found; skipping.")
        out.write_text("")
        return
    cmd = f"{TOOLS['subfinder']} -d {shlex.quote(target)} -all -silent -o {shlex.quote(str(out))}"
    safe_run(cmd, dry_run=dry_run)

def run_assetfinder(target: str, outdir: Path, dry_run: bool):
    out = outdir / "assetfinder.txt"
    if not which(TOOLS["assetfinder"]):
        logger.warning("assetfinder not found; skipping.")
        out.write_text("")
        return
    cmd = f"{TOOLS['assetfinder']} --subs-only {shlex.quote(target)} > {shlex.quote(str(out))}"
    safe_run(cmd, dry_run=dry_run)

def run_amass(target: str, outdir: Path, dry_run: bool, timeout=DEFAULT_TIMEOUT):
    out = outdir / "amass.txt"
    if not which(TOOLS["amass"]):
        logger.warning("amass not found; skipping.")
        out.write_text("")
        return
    cmd = f"{TOOLS['amass']} enum -passive -d {shlex.quote(target)} -o {shlex.quote(str(out))}"
    safe_run(cmd, dry_run=dry_run, timeout=timeout)

# ...existing code for DNS, httpx, naabu, masscan, juicy scoring, orchestration, CLI, etc...
