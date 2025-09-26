#!/usr/bin/env python3
"""
main.py - Unified entry point for ai-recon

Usage:
    python3 main.py --target example.com --outdir outputs --fast --deep --confirm-owned --export-llm
"""
import subprocess
import sys
import argparse
from pathlib import Path
import threading
import time
import select


def run_recon(args, stop_event):
    cmd = [sys.executable, "recon.py"]
    cmd += ["--target", args.target, "--outdir", args.outdir]
    if args.fast:
        cmd.append("--fast")
    if args.deep:
        cmd.append("--deep")
    if args.confirm_owned:
        cmd.append("--confirm-owned")
    if args.export_llm:
        cmd.append("--export-llm")
    print(f"[+] Running recon.py: {' '.join(cmd)}")
    proc = subprocess.Popen(cmd)
    while proc.poll() is None:
        if stop_event.is_set():
            print("[!] Stopping recon scan early due to user request.")
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            break
        time.sleep(1)

def run_export(args, run_id):
    outdir = Path(args.outdir) / run_id
    output_json = outdir / "report_input.json"
    cmd = [sys.executable, "export_to_json.py", "--indir", str(outdir), "--out", str(output_json), "--target", args.target]
    print(f"[+] Exporting results to JSON: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)
    print(f"[+] JSON output: {output_json}")



def check_for_update():
    print("[+] Checking for updates from GitHub...")
    try:
        subprocess.run(["git", "fetch"], check=True)
        local = subprocess.check_output(["git", "rev-parse", "main"]).strip()
        remote = subprocess.check_output(["git", "rev-parse", "origin/main"]).strip()
        if local != remote:
            print("[!] Update available. Pulling latest changes...")
            subprocess.run(["git", "pull", "origin", "main"], check=True)
            print("[+] Update complete. Please restart the tool.")
            sys.exit(0)
        else:
            print("[+] Already up to date.")
    except Exception as e:
        print(f"[!] Update check failed: {e}")
        sys.exit(1)




def main():
    print("\n=== AI Recon Interactive Runner ===\n")
    update = input("Check for updates before running? [y/N]: ").strip().lower() in ("y", "yes")
    if update:
        check_for_update()
    target = input("Enter target domain (e.g., example.com): ").strip()
    outdir = input("Enter output directory [outputs]: ").strip() or "outputs"
    fast = input("Run fast pipeline? [Y/n]: ").strip().lower() in ("", "y", "yes")
    deep = input("Run deep pipeline (more intrusive)? [y/N]: ").strip().lower() in ("y", "yes")
    confirm_owned = input("Confirm you own the target? [Y/n]: ").strip().lower() in ("", "y", "yes")
    export_llm = input("Export results to LLM-ready JSON? [Y/n]: ").strip().lower() in ("", "y", "yes")

    print("\nSummary:")
    print(f"  Target: {target}")
    print(f"  Output dir: {outdir}")
    print(f"  Fast: {fast}")
    print(f"  Deep: {deep}")
    print(f"  Confirm owned: {confirm_owned}")
    print(f"  Export LLM JSON: {export_llm}")
    print("\nPress 'o' at any time to stop the scan and export collected data.\n")
    proceed = input("Proceed with these settings? [Y/n]: ").strip().lower()
    if proceed not in ("", "y", "yes"):
        print("Aborted by user.")
        sys.exit(0)

    class Args:
        pass
    args = Args()
    args.target = target
    args.outdir = outdir
    args.fast = fast
    args.deep = deep
    args.confirm_owned = confirm_owned
    args.export_llm = export_llm

    stop_event = threading.Event()

    def key_listener():
        try:
            import sys, termios, tty
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            tty.setcbreak(fd)
            while not stop_event.is_set():
                if sys.stdin in select.select([sys.stdin], [], [], 0.1)[0]:
                    ch = sys.stdin.read(1)
                    if ch.lower() == 'o':
                        stop_event.set()
                        print("\n[o] Key pressed: Stopping scan and exporting data...\n")
                        break
        except Exception:
            pass
        finally:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            except Exception:
                pass

    import select
    listener_thread = threading.Thread(target=key_listener, daemon=True)
    listener_thread.start()

    # Run recon.py (in main thread)
    run_recon(args, stop_event)

    # Find latest run_id in outdir
    outdir_path = Path(outdir)
    run_dirs = sorted([d for d in outdir_path.iterdir() if d.is_dir()], reverse=True)
    if not run_dirs:
        print("[!] No output run directories found.")
        sys.exit(1)
    run_id = run_dirs[0].name

    # Export to JSON if requested or if scan was stopped
    if export_llm or stop_event.is_set():
        run_export(args, run_id)

if __name__ == "__main__":
    main()
