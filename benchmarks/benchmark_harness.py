#!/usr/bin/env python3
"""
Benchmark harness for recon.py and recon_fast.py
"""
import time
import subprocess
import json
from pathlib import Path
import statistics
from typing import List, Dict
import argparse

def run_single_benchmark(cmd: str, desc: str, runs: int = 3) -> Dict:
    """Run a single benchmark multiple times and return stats"""
    times = []
    for i in range(runs):
        start = time.time()
        rc = subprocess.call(cmd, shell=True)
        duration = time.time() - start
        times.append(duration)
        print(f"Run {i+1}/{runs} completed in {duration:.2f}s, exit code {rc}")
    
    stats = {
        "description": desc,
        "command": cmd,
        "runs": runs,
        "mean_time": statistics.mean(times),
        "min_time": min(times),
        "max_time": max(times),
        "std_dev": statistics.stdev(times) if len(times) > 1 else 0
    }
    return stats

def run_benchmarks(target: str = "example.test", runs: int = 3):
    """Run all benchmark scenarios"""
    outdir = Path("outputs/bench")
    outdir.mkdir(parents=True, exist_ok=True)
    
    scenarios = [
        # Basic recon
        {
            "cmd": f"python3 recon.py --target {target} --outdir {outdir}/basic --dry-run",
            "desc": "Basic recon (recon.py)"
        },
        {
            "cmd": f"python3 recon_fast.py --target {target} --outdir {outdir}/basic_fast --dry-run",
            "desc": "Basic recon (recon_fast.py)"
        },
        
        # Full recon with all tools
        {
            "cmd": f"python3 recon.py --target {target} --outdir {outdir}/full --dry-run --deep",
            "desc": "Full recon with all tools (recon.py)"
        },
        {
            "cmd": f"python3 recon_fast.py --target {target} --outdir {outdir}/full_fast --dry-run --deep --use-findomain",
            "desc": "Full recon with all tools (recon_fast.py)"
        },
        
        # Cached runs
        {
            "cmd": f"python3 recon.py --target {target} --outdir {outdir}/cached --dry-run --use-cache",
            "desc": "Cached run (recon.py)"
        },
        {
            "cmd": f"python3 recon_fast.py --target {target} --outdir {outdir}/cached_fast --dry-run --use-cache",
            "desc": "Cached run (recon_fast.py)"
        }
    ]
    
    results = []
    for scenario in scenarios:
        print(f"\nRunning benchmark: {scenario['desc']}")
        stats = run_single_benchmark(scenario["cmd"], scenario["desc"], runs)
        results.append(stats)
        print(f"Average time: {stats['mean_time']:.2f}s (± {stats['std_dev']:.2f}s)")
    
    # Save results
    results_file = outdir / "benchmark_results.json"
    results_file.write_text(json.dumps(results, indent=2))
    print(f"\nBenchmark results saved to {results_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run recon benchmarks")
    parser.add_argument("--target", default="example.test", help="Target domain for benchmarking")
    parser.add_argument("--runs", type=int, default=3, help="Number of runs per scenario")
    args = parser.parse_args()
    
    run_benchmarks(args.target, args.runs)
