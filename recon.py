#!/usr/bin/env python3
"""
recon.py - Python recon orchestrator

Replaces recon.sh with a modular Python orchestration script.

Usage examples:
    python3 recon.py --target example.com --outdir outputs --fast --confirm-owned
    python3 recon.py --target example.com --outdir outputs --deep --confirm-owned --export-llm

Important safety:
 - By default this script will refuse to run deep/aggressive scans unless environment
   variable I_HAVE_AUTH=1 is set (or --confirm-owned is passed).
 - You can provide an AUTH_TARGETS file (one domain per line). If provided, the target
   must be listed there unless --confirm-owned is specified.

Outputs:
 - outputs/<run_id>/subfinder.txt, amass_passive.txt, assetfinder.txt, subs_unique.txt, dnsx.txt,
   httpx.txt (or httpx.json), naabu.txt, nuclei.txt, waybackurls.txt, run_meta.json, and optionally
   report_input.json (if export_to_json.py is present and --export-llm is used).
"""

from __future__ import annotations
import argparse
import logging
import os
import shlex
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
from datetime import datetime
from pathlib import Path
import json
import shutil

# ---------------------------
# Configuration defaults
# ---------------------------
TOOLS = {
    "subfinder": "subfinder",
    "assetfinder": "assetfinder",
    "amass": "amass",
    "dnsx": "dnsx",
    "httpx": "httpx",
    "naabu": "naabu",
    "nuclei": "nuclei",
    "waybackurls": "waybackurls",
    "gau": "gau",  # optional
    "subjack": "subjack",
    "subzy": "subzy",
    "massdns": "massdns",
    "nmap": "nmap",
    "whatweb": "whatweb",
    "wafw00f": "wafw00f",
    "hakrawler": "hakrawler",
    "katana": "katana",
    "paramspider": "paramspider",
    "arjun": "arjun",
    "gobuster": "gobuster",
}

DEFAULT_CONCURRENCY = 10
DEFAULT_MAX_JUICY = 20

# ---------------------------
# Logging
# ---------------------------
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("recon")

# ---------------------------
# Helpers
# ---------------------------


def which(binary: str) -> bool:
    """Return True if `binary` exists on PATH."""
    return shutil.which(binary) is not None


def check_binaries(required: list[str], quiet: bool = False) -> dict[str, bool]:
    """Check availability of binaries and return dict tool->bool."""
    avail = {}
    for t in required:
        binname = TOOLS.get(t, t)
        ok = which(binname)
        avail[t] = ok
        if not ok and not quiet:
            logger.warning("Tool not found on PATH: %s (expected binary: %s)", t, binname)
    return avail


def safe_run(cmd: str, cwd: Path | None = None, out_path: Path | None = None, dry_run: bool = False) -> int:
    """Run a shell command safely. If out_path provided, stdout is written to file.
    Returns process exit code."""
    logger.debug("Running command: %s", cmd)
    if dry_run:
        logger.info("[dry-run] %s", cmd)
        return 0
    try:
        if out_path:
            # ensure parent exists
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with out_path.open("wb") as fh:
                proc = subprocess.run(shlex.split(cmd), stdout=fh, stderr=subprocess.PIPE)
                if proc.returncode != 0:
                    logger.debug("Command stderr: %s", proc.stderr.decode(errors="ignore"))
                return proc.returncode
        else:
            proc = subprocess.run(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)
            if proc.returncode != 0:
                logger.debug("Command stderr: %s", proc.stderr.decode(errors="ignore"))
            return proc.returncode
    except FileNotFoundError:
        logger.error("Command not found: %s", cmd.split()[0])
        return 127
    except Exception as exc:
        logger.exception("Error running command: %s", exc)
        return 1


# ---------------------------
# Pipeline steps
# ---------------------------


def step_subdomain_passive(target: str, outdir: Path, dry_run: bool, concurrency: int):
    """Run subfinder, assetfinder, amass (passive) and combine outputs."""
    logger.info("Step: passive subdomain enumeration for %s", target)
    tasks = []
    sf_out = outdir / "subfinder.txt"
    af_out = outdir / "assetfinder.txt"
    amass_out = outdir / "amass_passive.txt"

    # subfinder
    if which(TOOLS["subfinder"]):
        tasks.append((f"{TOOLS['subfinder']} -d {target} -silent -o {sf_out}", sf_out))
    else:
        logger.warning("subfinder binary not found; skipping subfinder step")

    # assetfinder
    if which(TOOLS["assetfinder"]):
        tasks.append((f"{TOOLS['assetfinder']} --subs-only {target} > {af_out}", af_out))
    else:
        logger.warning("assetfinder binary not found; skipping assetfinder step")

    # amass passive
    if which(TOOLS["amass"]):
        tasks.append((f"{TOOLS['amass']} enum -passive -d {target} -o {amass_out}", amass_out))
    else:
        logger.warning("amass binary not found; skipping amass passive step")

    # Execute tasks in parallel (bounded)
    with ThreadPoolExecutor(max_workers=min(len(tasks) or 1, concurrency)) as ex:
        futures = [ex.submit(safe_run, cmd, None, out, dry_run) for cmd, out in tasks]
        for f in as_completed(futures):
            ret = f.result()
            if ret != 0:
                logger.debug("Passive task returned code %s", ret)

    # combine into subs_unique.txt
    combined = outdir / "subs_raw_combined.txt"
    subs_unique = outdir / "subs_unique.txt"
    if not dry_run:
        with combined.open("w", encoding="utf-8") as fh:
            for path in (sf_out, af_out, amass_out):
                if path.exists():
                    for ln in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                        ln = ln.strip()
                        if ln:
                            fh.write(ln + "\n")
        # simple normalization and dedupe
        seen = set()
        with subs_unique.open("w", encoding="utf-8") as outfh:
            for ln in combined.read_text(encoding="utf-8", errors="ignore").splitlines():
                s = ln.strip().strip(".").lstrip("*.").lower()
                if s and s not in seen:
                    seen.add(s)
                    outfh.write(s + "\n")
        logger.info("Passive enumeration complete — subs_unique: %d entries", len(seen))
    else:
        logger.info("[dry-run] would combine outputs into %s", subs_unique)


def step_resolve_dnsx(indir: Path, outdir: Path, dry_run: bool, concurrency: int):
    """Resolve subs_unique.txt using dnsx and write dnsx.txt with lines host ip"""
    logger.info("Step: DNS resolution using dnsx")
    subs_file = indir / "subs_unique.txt" if (indir / "subs_unique.txt").exists() else indir / "subs_raw_combined.txt"
    out_file = outdir / "dnsx.txt"
    if not which(TOOLS["dnsx"]):
        logger.warning("dnsx not found; skipping DNS resolution")
        return
    if not subs_file.exists():
        logger.warning("No subdomain list found at %s; skipping dnsx", subs_file)
        return
    cmd = f"cat {subs_file} | {TOOLS['dnsx']} -silent -a -resp -o {out_file}"
    rc = safe_run(cmd, dry_run=dry_run)
    if rc == 0:
        logger.info("dnsx completed and wrote %s", out_file)
    else:
        logger.warning("dnsx returned exit code %s", rc)


def step_httpx(outdir: Path, dry_run: bool, concurrency: int):
    """Run httpx against resolved hosts or subs_unique to probe HTTP endpoints."""
    logger.info("Step: HTTP probing using httpx")
    dnsx_file = outdir / "dnsx.txt"
    subs_file = outdir / "subs_unique.txt"
    httpx_out_txt = outdir / "httpx.txt"
    httpx_out_json = outdir / "httpx.json"
    if not which(TOOLS["httpx"]):
        logger.warning("httpx not found; skipping httpx")
        return
    src = dnsx_file if dnsx_file.exists() else subs_file
    if not src.exists():
        logger.warning("No source for httpx found (%s); skipping", src)
        return
    # prefer json output if available
    cmd = f"cat {src} | {TOOLS['httpx']} -silent -status-code -title -tech-detect -json -o {httpx_out_json}"
    rc = safe_run(cmd, dry_run=dry_run)
    if rc != 0:
        logger.info("httpx json path failed or not supported; falling back to text output")
        cmd2 = f"cat {src} | {TOOLS['httpx']} -silent -status-code -title -tech-detect -o {httpx_out_txt}"
        safe_run(cmd2, dry_run=dry_run)
    else:
        logger.info("httpx json output written to %s", httpx_out_json)


def step_naabu(outdir: Path, dry_run: bool, concurrency: int, rate: int = 1000):
    """Quick port scan using naabu on hosts/IPs found in dnsx.txt (fast mode)."""
    logger.info("Step: quick port enumeration using naabu")
    dnsx_file = outdir / "dnsx.txt"
    naabu_out = outdir / "naabu.txt"
    if not which(TOOLS["naabu"]):
        logger.warning("naabu not found; skipping naabu")
        return
    if not dnsx_file.exists():
        logger.warning("dnsx output missing; skipping naabu")
        return
    # extract IPs (best-effort: tokens that look like IPs)
    ips = set()
    for ln in dnsx_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        for token in ln.split():
            if token.count(".") == 3:
                ips.add(token.strip(","))
    if not ips:
        logger.warning("No IPs found in dnsx output; skipping naabu")
        return
    ips_list_file = outdir / "ips_for_naabu.txt"
    ips_list_file.write_text("\n".join(sorted(ips)), encoding="utf-8")
    cmd = f"cat {ips_list_file} | {TOOLS['naabu']} -silent -rate {rate} -o {naabu_out}"
    rc = safe_run(cmd, dry_run=dry_run)
    if rc == 0:
        logger.info("naabu output written to %s", naabu_out)
    else:
        logger.warning("naabu returned exit code %s", rc)


def step_nuclei(outdir: Path, dry_run: bool, concurrency: int, templates: str | None = None):
    """Run nuclei against live hosts (httpx output)."""
    logger.info("Step: nuclei scan")
    httpx_json = outdir / "httpx.json"
    httpx_txt = outdir / "httpx.txt"
    nuclei_out = outdir / "nuclei.json"
    if not which(TOOLS["nuclei"]):
        logger.warning("nuclei not found; skipping nuclei step")
        return
    # choose input list
    if httpx_json.exists():
        # nuclei accepts stdin of urls
        cmd = f"cat {httpx_json} | jq -r '.url' | {TOOLS['nuclei']} -json -o {nuclei_out}"
        # try to use jq; check if available
        if not which("jq"):
            # fallback: transform manually - simpler to use httpx.txt if present
            if httpx_txt.exists():
                cmd = f"cat {httpx_txt} | cut -d ' ' -f1 | {TOOLS['nuclei']} -json -o {nuclei_out}"
            else:
                logger.warning("jq not present and httpx txt not found; skipping nuclei")
                return
    elif httpx_txt.exists():
        cmd = f"cat {httpx_txt} | cut -d ' ' -f1 | {TOOLS['nuclei']} -json -o {nuclei_out}"
    else:
        logger.warning("No httpx outputs found; skipping nuclei")
        return
    if templates:
        cmd += f" -t {shlex.quote(templates)}"
    rc = safe_run(cmd, dry_run=dry_run)
    if rc == 0:
        logger.info("nuclei results written to %s", nuclei_out)
    else:
        logger.warning("nuclei returned exit code %s", rc)


def step_wayback(outdir: Path, dry_run: bool):
    """Harvest wayback + gau urls from subdomains."""
    logger.info("Step: historical URL harvesting (waybackurls/gau)")
    subs_file = outdir / "subs_unique.txt"
    wb_out = outdir / "waybackurls.txt"
    gau_out = outdir / "gau.txt"
    if subs_file.exists():
        if which(TOOLS["waybackurls"]):
            cmd = f"cat {subs_file} | {TOOLS['waybackurls']} > {wb_out}"
            safe_run(cmd, dry_run=dry_run)
        if which(TOOLS["gau"]):
            cmd2 = f"cat {subs_file} | {TOOLS['gau']} > {gau_out}"
            safe_run(cmd2, dry_run=dry_run)
    else:
        logger.warning("subs_unique.txt missing; skipping wayback/gau")


def step_deep_extra(outdir: Path, dry_run: bool):
    """Optional deep steps: hakrawler, katana, paramspider, gobuster, arjun, secret finders etc."""
    logger.info("Step: DEEP extras (crawler/fuzz/params)")
    subs_file = outdir / "subs_unique.txt"
    if not subs_file.exists():
        logger.warning("No subs file; skipping deep extras")
        return
    # example: run hakrawler for each host (best-effort; careful with rate)
    if which(TOOLS["hakrawler"]):
        hak_out = outdir / "hakrawler.txt"
        cmd = f"cat {subs_file} | xargs -n1 -P5 -I{{}} {TOOLS['hakrawler']} -u https://{{}} -plain >> {hak_out}"
        safe_run(cmd, dry_run=dry_run)
    if which(TOOLS["katana"]):
        kat_out = outdir / "katana.txt"
        cmd = f"cat {subs_file} | xargs -n1 -P2 -I{{}} {TOOLS['katana']} -u https://{{}} -o {kat_out}"
        safe_run(cmd, dry_run=dry_run)
    # paramspider (example)
    if which(TOOLS["paramspider"]):
        para_out = outdir / "paramspider.txt"
        cmd = f"python3 {TOOLS['paramspider']} -d {shlex.quote(outdir.name)} -o {para_out}"
        # paramspider usage varies; this is a placeholder
        safe_run(cmd, dry_run=dry_run)


# ---------------------------
# Export to JSON (LLM-ready)
# ---------------------------

def call_export_script(indir: Path, outpath: Path, target: str, dry_run: bool):
    """If export_to_json.py exists in repo, call it to create report_input.json"""
    script = Path("export_to_json.py")
    if not script.exists():
        logger.warning("export_to_json.py not found in repo; skipping LLM export")
        return
    cmd = f"python3 {script} --indir {shlex.quote(str(indir))} --out {shlex.quote(str(outpath))} --target {shlex.quote(target)} --max-juicy {DEFAULT_MAX_JUICY}"
    rc = safe_run(cmd, dry_run=dry_run)
    if rc == 0:
        logger.info("LLM-ready JSON written to %s", outpath)
    else:
        logger.warning("export_to_json.py returned non-zero code %s", rc)


# ---------------------------
# Safety and auth
# ---------------------------

def check_authorization(target: str, auth_file: Path | None, confirm_owned: bool, aggressive: bool) -> bool:
    """Perform simple safety checks before running the pipeline."""
    if confirm_owned:
        logger.info("--confirm-owned provided; continuing")
        return True
    if auth_file and auth_file.exists():
        allowed = [ln.strip().lower() for ln in auth_file.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip()]
        if target.lower() in allowed:
            logger.info("Target %s found in AUTH_TARGETS; continuing", target)
            return True
        else:
            logger.error("Target %s is NOT listed in AUTH_TARGETS (%s). Aborting.", target, auth_file)
            return False
    # if deep/aggressive then require env var I_HAVE_AUTH=1
    if aggressive:
        if os.environ.get("I_HAVE_AUTH", "") == "1":
            logger.info("Aggressive mode allowed via I_HAVE_AUTH=1")
            return True
        else:
            logger.error("Aggressive (--deep or --aggressive) requires environment variable I_HAVE_AUTH=1 for safety. Aborting.")
            return False
    # fallback: require confirm-owned
    logger.warning("No AUTH_TARGETS file provided and --confirm-owned not set. Use --confirm-owned to assert ownership.")
    return False



# ---------------------------
# Main orchestration
# ---------------------------

def orchestrate(target: str, outdir: Path, fast: bool, deep: bool, dry_run: bool, concurrency: int, confirm_owned: bool, auth_file: Path | None, export_llm: bool):
    logger.info("Starting reconciliation run for %s", target)
    run_id = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    run_out = outdir / run_id
    if not dry_run:
        run_out.mkdir(parents=True, exist_ok=True)

    # record run meta
    run_meta = {
        "target": target,
        "run_id": run_id,
        "started_at": datetime.utcnow().isoformat() + "Z",
        "fast": fast,
        "deep": deep,
        "tools_checked": {},
    }

    # safety check
    if not check_authorization(target, auth_file, confirm_owned, aggressive=deep):
        logger.error("Authorization failed. Exiting.")
        sys.exit(2)

    # check basic tool availability (fast set)
    basic_tools = ["subfinder", "assetfinder", "amass", "dnsx", "httpx", "naabu", "nuclei", "waybackurls", "gau"]
    tool_avail = check_binaries(basic_tools, quiet=True)
    run_meta["tools_checked"] = tool_avail
    logger.info("Tool availability: %s", {k: ("yes" if v else "no") for k, v in tool_avail.items()})

    # --- Periodic status update thread ---
    stop_event = threading.Event()
    def status_updater():
        while not stop_event.is_set():
            logger.info("Recon is still running... (%s)", datetime.utcnow().strftime("%H:%M:%S"))
            stop_event.wait(20)
    status_thread = threading.Thread(target=status_updater, daemon=True)
    status_thread.start()

    # Steps
    try:
        step_subdomain_passive(target=target, outdir=run_out, dry_run=dry_run, concurrency=concurrency)
        step_resolve_dnsx(indir=run_out, outdir=run_out, dry_run=dry_run, concurrency=concurrency)
        step_httpx(outdir=run_out, dry_run=dry_run, concurrency=concurrency)
        step_naabu(outdir=run_out, dry_run=dry_run, concurrency=concurrency)
        # optional wayback
        step_wayback(outdir=run_out, dry_run=dry_run)
        # fast nuclei run
        step_nuclei(outdir=run_out, dry_run=dry_run, concurrency=concurrency)
        # deep extras
        if deep:
            step_deep_extra(outdir=run_out, dry_run=dry_run)
        # write run_meta
        run_meta["finished_at"] = datetime.utcnow().isoformat() + "Z"
        if not dry_run:
            (run_out / "run_meta.json").write_text(json.dumps(run_meta, indent=2), encoding="utf-8")
            logger.info("Run meta written to %s", run_out / "run_meta.json")
        else:
            logger.info("[dry-run] run meta would be written to %s", run_out / "run_meta.json")

        # call export_to_json if requested
        if export_llm:
            out_json = run_out / "report_input.json"
            call_export_script(indir=run_out, outpath=out_json, target=target, dry_run=dry_run)

    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
    except Exception:
        logger.exception("Unexpected error during orchestration")
    finally:
        stop_event.set()
        status_thread.join(timeout=1)
        logger.info("Run completed. Outputs (if any) are in: %s", run_out)


# ---------------------------
# CLI
# ---------------------------

def parse_args():
    p = argparse.ArgumentParser(description="Recon orchestration script (python replacement for recon.sh)")
    p.add_argument("--target", required=True, help="Target root domain (e.g., example.com)")
    p.add_argument("--outdir", default="outputs", help="Base output directory (default: outputs)")
    p.add_argument("--fast", action="store_true", help="Run fast pipeline (default behavior if set)")
    p.add_argument("--deep", action="store_true", help="Run deep pipeline (includes more intrusive steps)")
    p.add_argument("--dry-run", action="store_true", help="Print commands but do not execute them")
    p.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY, help="Max parallel tasks for passive steps")
    p.add_argument("--confirm-owned", action="store_true", help="Confirm you own the target (bypass AUTH_TARGETS check)")
    p.add_argument("--auth-file", type=str, default="AUTH_TARGETS", help="Path to AUTH_TARGETS file listing allowed domains (one per line)")
    p.add_argument("--export-llm", action="store_true", help="Call export_to_json.py at the end to produce LLM-ready JSON if available")
    return p.parse_args()


def main():
    args = parse_args()
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    auth_file = Path(args.auth_file) if args.auth_file else None

    # run
    orchestrate(
        target=args.target,
        outdir=outdir,
        fast=args.fast,
        deep=args.deep,
        dry_run=args.dry_run,
        concurrency=args.concurrency,
        confirm_owned=args.confirm_owned,
        auth_file=auth_file,
        export_llm=args.export_llm,
    )


if __name__ == "__main__":
    main()
