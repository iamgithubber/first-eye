
from __future__ import annotations
# ---------------------------
# Cache helpers
# ---------------------------
def cache_dir(target: str, outdir: Path) -> Path:
        """Return the cache directory for a given target."""
        return outdir / "cache" / target.replace('.', '_')

def cache_path(target: str, outdir: Path, step: str) -> Path:
        """Return the cache file path for a given step."""
        return cache_dir(target, outdir) / f"{step}.txt"
#!/usr/bin/env python3
"""
recon.py - Python recon orchestrator (multithreaded refactor)

This is a refactor of the original recon.py to add safe, bounded
concurrency between independent pipeline steps and within DNS resolution.

Key changes:
 - DNS resolution (`dnsrecon`) is parallelized using ThreadPoolExecutor.
 - Independent heavy steps (naabu, nuclei, wayback, deep extras) are run
     in parallel after httpx finishes, with a bounded ThreadPoolExecutor.
 - Preserves safety checks, dry-run behavior, and existing command shapes.
 - Improves logging and error handling.

Usage remains the same as original.
"""

import argparse
import logging
import os
import shlex
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
from datetime import datetime, timezone
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
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with out_path.open("wb") as fh:
                proc = subprocess.run(shlex.split(cmd), stdout=fh, stderr=subprocess.PIPE, cwd=cwd)
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


def step_subdomain_passive(target: str, outdir: Path, dry_run: bool, concurrency: int, use_cache: bool = False, refresh_cache: bool = False):
    """Run subfinder, assetfinder, amass (passive) and combine outputs."""
    logger.info("Step: passive subdomain enumeration for %s", target)
    cachefile = cache_path(target, outdir, "subs_unique")
    if use_cache and cachefile.exists() and not refresh_cache:
        logger.info("[cache] Using cached subdomain results from %s", cachefile)
        # Copy cache to output location
        subs_unique = outdir / "subs_unique.txt"
        subs_unique.parent.mkdir(parents=True, exist_ok=True)
        subs_unique.write_text(cachefile.read_text(encoding="utf-8"), encoding="utf-8")
        return

    import subprocess
    sf_out = outdir / "subfinder.txt"
    af_out = outdir / "assetfinder.txt"
    amass_out = outdir / "amass_passive.txt"
    tasks = []
    if which(TOOLS["subfinder"]):
        tasks.append((f"{TOOLS['subfinder']} -d {shlex.quote(target)} -silent -o {shlex.quote(str(sf_out))}", sf_out))
    if which(TOOLS["assetfinder"]):
        tasks.append((f"{TOOLS['assetfinder']} --subs-only {shlex.quote(target)} > {shlex.quote(str(af_out))}", af_out))
    # amass watcher as a function
    def run_amass_watcher():
        if not which(TOOLS["amass"]):
            logger.warning("amass binary not found; skipping amass passive step")
            return 127
        logger.info("[amass] Starting: %s", f"{TOOLS['amass']} enum -passive -d {target} -o {amass_out}")
        cmd = [TOOLS['amass'], 'enum', '-passive', '-d', target, '-o', str(amass_out)]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        last_size = 0
        last_change = time.time()
        max_wait = 1200  # 20 minutes
        check_interval = 30
        while True:
            time.sleep(check_interval)
            if amass_out.exists():
                size = amass_out.stat().st_size
                if size > last_size:
                    last_size = size
                    last_change = time.time()
            if time.time() - last_change > max_wait:
                logger.warning("[amass] Output stalled for 20 minutes. Terminating and moving to next phase.")
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except Exception:
                    proc.kill()
                break
            if proc.poll() is not None:
                break
        ret = proc.returncode if proc.returncode is not None else 1
        if ret == 0:
            logger.info("[amass] Finished successfully.")
        else:
            logger.warning("[amass] Failed with code %s", ret)
        return ret
    # Run all in parallel
    with ThreadPoolExecutor(max_workers=3) as ex:
        futures = []
        for cmd, out in tasks:
            logger.info(f"[Passive] Starting: {cmd}")
            futures.append(ex.submit(safe_run, cmd, None, out, dry_run))
        futures.append(ex.submit(run_amass_watcher))
        for i, f in enumerate(as_completed(futures)):
            ret = f.result()
            if i < len(tasks):
                step_name = tasks[i][0].split()[0]
            else:
                step_name = "amass"
            if ret == 0:
                logger.info(f"[{step_name}] Finished successfully.")
            else:
                logger.warning(f"[{step_name}] Failed with code {ret}")

    # combine into subs_unique.txt
    combined = outdir / "subs_raw_combined.txt"
    subs_unique = outdir / "subs_unique.txt"
    if not dry_run:
        with combined.open("w", encoding="utf-8") as fh:
            for path in (sf_out, af_out, amass_out):
                if path.exists():
                    try:
                        for ln in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                            ln = ln.strip()
                            if ln:
                                fh.write(ln + "\n")
                    except Exception:
                        logger.debug("Failed to read %s", path)
        # simple normalization and dedupe
        seen = set()
        with subs_unique.open("w", encoding="utf-8") as outfh:
            try:
                for ln in combined.read_text(encoding="utf-8", errors="ignore").splitlines():
                    s = ln.strip().strip(".").lstrip("*.").lower()
                    if s and s not in seen:
                        seen.add(s)
                        outfh.write(s + "\n")
            except Exception:
                logger.debug("Failed to process combined subs file: %s", combined)
        logger.info("Passive enumeration complete — subs_unique: %d entries", len(seen))
        # Save to cache
        cachefile.parent.mkdir(parents=True, exist_ok=True)
        cachefile.write_text(subs_unique.read_text(encoding="utf-8"), encoding="utf-8")
    else:
        logger.info("[dry-run] would combine outputs into %s", subs_unique)


def _run_dnsrecon_for_domain(domain: str) -> tuple[str, int, str]:
    """Helper to run dnsrecon for a single domain and return (domain, rc, stdout)."""
    cmd = f"dnsrecon -d {shlex.quote(domain)} -t std"
    logger.debug("[dnsrecon] resolving: %s", domain)
    try:
        proc = subprocess.run(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout = proc.stdout.decode("utf-8", errors="ignore") if proc.stdout else ""
        stderr = proc.stderr.decode("utf-8", errors="ignore") if proc.stderr else ""
        if proc.returncode == 0:
            return (domain, 0, stdout)
        else:
            return (domain, proc.returncode, stderr or stdout)
    except FileNotFoundError:
        return (domain, 127, "dnsrecon not found")
    except Exception as exc:
        return (domain, 1, str(exc))


def step_resolve_dnsrecon(indir: Path, outdir: Path, dry_run: bool, concurrency: int):
    """Resolve subs_unique.txt using dnsrecon and write dnsrecon.txt with DNS info.

    This implementation parallelizes DNS resolution across domains using a
    ThreadPoolExecutor bounded by `concurrency`.
    """
    logger.info("Step: DNS resolution using dnsrecon")
    subs_file = indir / "subs_unique.txt" if (indir / "subs_unique.txt").exists() else indir / "subs_raw_combined.txt"
    out_file = outdir / "dnsrecon.txt"
    if not subs_file.exists():
        logger.warning("No subdomain list found at %s; skipping dnsrecon", subs_file)
        return
    with subs_file.open("r", encoding="utf-8", errors="ignore") as f:
        domains = [line.strip() for line in f if line.strip()]
    if not domains:
        logger.warning("No domains to resolve in %s; skipping dnsrecon", subs_file)
        return

    results: list[str] = []
    if dry_run:
        logger.info("[dry-run] would run dnsrecon for %d domains", len(domains))
    else:
        logger.info("[dnsrecon] Starting DNS resolution for %d domains", len(domains))
        with ThreadPoolExecutor(max_workers=max(1, concurrency)) as ex:
            futures = {ex.submit(_run_dnsrecon_for_domain, d): d for d in domains}
            for fut in as_completed(futures):
                domain = futures[fut]
                try:
                    d, rc, out = fut.result()
                    if rc == 0:
                        logger.info("[dnsrecon] Success for %s", d)
                        results.append(out)
                    else:
                        logger.warning("[dnsrecon] Failed for %s (rc=%s): %s", d, rc, out.strip().splitlines()[0] if out else "(no output)")
                except Exception as exc:
                    logger.exception("[dnsrecon] Exception for %s: %s", domain, exc)

    if not dry_run:
        try:
            out_file.parent.mkdir(parents=True, exist_ok=True)
            with out_file.open("w", encoding="utf-8") as f:
                for res in results:
                    f.write(res + "\n")
            logger.info("dnsrecon completed and wrote %s", out_file)
        except Exception:
            logger.exception("Failed writing dnsrecon output to %s", out_file)
    else:
        logger.info("[dry-run] would write dnsrecon output to %s", out_file)


def step_httpx(outdir: Path, dry_run: bool, concurrency: int):
    """Run httpx against resolved hosts or subs_unique to probe HTTP endpoints."""
    logger.info("Step: HTTP probing using httpx")
    dnsrecon_file = outdir / "dnsrecon.txt"
    subs_file = outdir / "subs_unique.txt"
    httpx_out_txt = outdir / "httpx.txt"
    httpx_out_json = outdir / "httpx.json"
    if not which(TOOLS["httpx"]):
        logger.warning("httpx not found; skipping httpx")
        return
    # Extract hostnames from dnsrecon.txt if it exists, else use subs_unique.txt
    if dnsrecon_file.exists():
        hosts = set()
        try:
            with dnsrecon_file.open("r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    ln = line.strip()
                    if not ln:
                        continue
                    # heuristics: look for tokens like 'A ' or 'CNAME '
                    if "A " in ln or "CNAME " in ln:
                        parts = ln.split()
                        if len(parts) >= 2:
                            hosts.add(parts[1])
        except Exception:
            logger.debug("Failed to parse dnsrecon output for hosts")
        if not hosts:
            logger.warning("No hosts found in dnsrecon.txt; falling back to subs_unique.txt")
            src = subs_file
        else:
            temp_hosts = outdir / "hosts_for_httpx.txt"
            temp_hosts.write_text("\n".join(sorted(hosts)), encoding="utf-8")
            src = temp_hosts
    else:
        src = subs_file
    if not src.exists():
        logger.warning("No source for httpx found (%s); skipping", src)
        return
    # prefer json output if available
    cmd = f"cat {shlex.quote(str(src))} | {TOOLS['httpx']} -silent -status-code -title -tech-detect -json -o {shlex.quote(str(httpx_out_json))}"
    logger.info("[httpx] Starting HTTP probing: %s", cmd)
    rc = safe_run(cmd, dry_run=dry_run)
    if rc != 0:
        logger.warning("[httpx] JSON output failed; falling back to text output")
        cmd2 = f"cat {shlex.quote(str(src))} | {TOOLS['httpx']} -silent -status-code -title -tech-detect -o {shlex.quote(str(httpx_out_txt))}"
        logger.info("[httpx] Running fallback: %s", cmd2)
        safe_run(cmd2, dry_run=dry_run)
    else:
        logger.info("[httpx] JSON output written to %s", httpx_out_json)


def step_naabu(outdir: Path, dry_run: bool, concurrency: int, rate: int = 1000):
    """Quick port scan using naabu on hosts/IPs found in dnsrecon.txt (fast mode)."""
    logger.info("Step: quick port enumeration using naabu")
    dnsrecon_file = outdir / "dnsrecon.txt"
    naabu_out = outdir / "naabu.txt"
    if not which(TOOLS["naabu"]):
        logger.warning("naabu not found; skipping naabu")
        return
    if not dnsrecon_file.exists():
        logger.warning("dnsrecon output missing; skipping naabu")
        return
    # extract IPs (best-effort: tokens that look like IPs)
    ips = set()
    try:
        txt = dnsrecon_file.read_text(encoding="utf-8", errors="ignore")
        for ln in txt.splitlines():
            for token in ln.split():
                t = token.strip().strip(',')
                if t.count('.') == 3 and all(p.isdigit() and 0 <= int(p) <= 255 for p in t.split('.')):
                    ips.add(t)
    except Exception:
        logger.debug("Failed to extract IPs from dnsrecon output")
    if not ips:
        logger.warning("No IPs found in dnsrecon output; skipping naabu")
        return
    ips_list_file = outdir / "ips_for_naabu.txt"
    ips_list_file.write_text("\n".join(sorted(ips)), encoding="utf-8")
    cmd = f"cat {shlex.quote(str(ips_list_file))} | {TOOLS['naabu']} -silent -rate {rate} -o {shlex.quote(str(naabu_out))}"
    logger.info("[naabu] Starting port scan: %s", cmd)
    rc = safe_run(cmd, dry_run=dry_run)
    if rc == 0:
        logger.info("[naabu] Output written to %s", naabu_out)
    else:
        logger.warning("[naabu] Returned exit code %s", rc)


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
        cmd = f"cat {shlex.quote(str(httpx_json))} | jq -r '.url' | {TOOLS['nuclei']} -json -o {shlex.quote(str(nuclei_out))}"
        if not which("jq"):
            if httpx_txt.exists():
                cmd = f"cat {shlex.quote(str(httpx_txt))} | cut -d ' ' -f1 | {TOOLS['nuclei']} -json -o {shlex.quote(str(nuclei_out))}"
            else:
                logger.warning("jq not present and httpx txt not found; skipping nuclei")
                return
    elif httpx_txt.exists():
        cmd = f"cat {shlex.quote(str(httpx_txt))} | cut -d ' ' -f1 | {TOOLS['nuclei']} -json -o {shlex.quote(str(nuclei_out))}"
    else:
        logger.warning("No httpx outputs found; skipping nuclei")
        return
    if templates:
        cmd += f" -t {shlex.quote(templates)}"
    logger.info("[nuclei] Starting scan: %s", cmd)
    rc = safe_run(cmd, dry_run=dry_run)
    if rc == 0:
        logger.info("[nuclei] Results written to %s", nuclei_out)
    else:
        logger.warning("[nuclei] Returned exit code %s", rc)


def step_wayback(outdir: Path, dry_run: bool):
    """Harvest wayback + gau urls from subdomains."""
    logger.info("Step: historical URL harvesting (waybackurls/gau)")
    subs_file = outdir / "subs_unique.txt"
    wb_out = outdir / "waybackurls.txt"
    gau_out = outdir / "gau.txt"
    if subs_file.exists():
        if which(TOOLS["waybackurls"]):
            cmd = f"cat {shlex.quote(str(subs_file))} | {TOOLS['waybackurls']} > {shlex.quote(str(wb_out))}"
            logger.info("[waybackurls] Starting: %s", cmd)
            safe_run(cmd, dry_run=dry_run)
        if which(TOOLS["gau"]):
            cmd2 = f"cat {shlex.quote(str(subs_file))} | {TOOLS['gau']} > {shlex.quote(str(gau_out))}"
            logger.info("[gau] Starting: %s", cmd2)
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
        cmd = f"cat {shlex.quote(str(subs_file))} | xargs -n1 -P5 -I{{}} {TOOLS['hakrawler']} -u https://{{}} -plain >> {shlex.quote(str(hak_out))}"
        logger.info("[hakrawler] Starting: %s", cmd)
        safe_run(cmd, dry_run=dry_run)
    if which(TOOLS["katana"]):
        kat_out = outdir / "katana.txt"
        cmd = f"cat {shlex.quote(str(subs_file))} | xargs -n1 -P2 -I{{}} {TOOLS['katana']} -u https://{{}} -o {shlex.quote(str(kat_out))}"
        logger.info("[katana] Starting: %s", cmd)
        safe_run(cmd, dry_run=dry_run)
    # paramspider (example)
    if which(TOOLS["paramspider"]):
        para_out = outdir / "paramspider.txt"
        cmd = f"python3 {shlex.quote(TOOLS['paramspider'])} -d {shlex.quote(outdir.name)} -o {shlex.quote(str(para_out))}"
        logger.info("[paramspider] Starting: %s", cmd)
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
    cmd = f"python3 {shlex.quote(str(script))} --indir {shlex.quote(str(indir))} --out {shlex.quote(str(outpath))} --target {shlex.quote(target)} --max-juicy {DEFAULT_MAX_JUICY}"
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


def orchestrate(target: str, outdir: Path, fast: bool, deep: bool, dry_run: bool, concurrency: int, confirm_owned: bool, auth_file: Path | None, export_llm: bool, use_cache: bool = False, refresh_cache: bool = False):
    logger.info("Starting reconciliation run for %s", target)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    run_out = outdir / run_id
    if not dry_run:
        run_out.mkdir(parents=True, exist_ok=True)

    # record run meta
    run_meta = {
        "target": target,
        "run_id": run_id,
        "started_at": datetime.now(timezone.utc).isoformat(),
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
            logger.info("Recon is still running... (%s)", datetime.now(timezone.utc).strftime("%H:%M:%S"))
            stop_event.wait(20)

    status_thread = threading.Thread(target=status_updater, daemon=True)
    status_thread.start()

    # Steps

    try:
        with ThreadPoolExecutor(max_workers=3) as ex:
            # 1) passive subdomain enumeration
            fut_subs = ex.submit(step_subdomain_passive, target, run_out, dry_run, concurrency, use_cache, refresh_cache)
            # 2) DNS resolution (waits for subs_unique.txt)
            def dns_step():
                fut_subs.result()  # Wait for subdomain step to finish
                step_resolve_dnsrecon(indir=run_out, outdir=run_out, dry_run=dry_run, concurrency=concurrency)
            fut_dns = ex.submit(dns_step)
            # 3) httpx probing (waits for DNS step)
            def httpx_step():
                fut_dns.result()  # Wait for DNS step to finish
                step_httpx(outdir=run_out, dry_run=dry_run, concurrency=concurrency)
            fut_httpx = ex.submit(httpx_step)

            # 4) run independent heavy steps concurrently after httpx is done
            def after_httpx():
                fut_httpx.result()
                with ThreadPoolExecutor(max_workers=4) as ex2:
                    futures = {}
                    futures[ex2.submit(step_naabu, run_out, dry_run, concurrency)] = "naabu"
                    futures[ex2.submit(step_wayback, run_out, dry_run)] = "wayback"
                    futures[ex2.submit(step_nuclei, run_out, dry_run, concurrency)] = "nuclei"
                    if deep:
                        futures[ex2.submit(step_deep_extra, run_out, dry_run)] = "deep"
                    for fut in as_completed(futures):
                        name = futures[fut]
                        try:
                            fut.result()
                            logger.info("Step %s finished", name)
                        except Exception:
                            logger.exception("Step %s failed", name)
            fut_after = ex.submit(after_httpx)
            fut_after.result()

        # write run_meta
        run_meta["finished_at"] = datetime.now(timezone.utc).isoformat()
        if not dry_run:
            try:
                (run_out / "run_meta.json").write_text(json.dumps(run_meta, indent=2), encoding="utf-8")
                logger.info("Run meta written to %s", run_out / "run_meta.json")
            except Exception:
                logger.exception("Failed to write run_meta.json")
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
    p.add_argument("--use-cache", action="store_true", help="Use cached results for steps if available")
    p.add_argument("--refresh-cache", action="store_true", help="Force refresh of cache for all steps")
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
        use_cache=args.use_cache,
        refresh_cache=args.refresh_cache,
    )


if __name__ == "__main__":
    main()