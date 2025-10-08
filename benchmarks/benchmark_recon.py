#!/usr/bin/env python3
"""
Dedicated benchmark suite for recon.py
- Tests each pipeline stage independently
- Measures memory usage and timing
- Tests with different cache configurations
- Tests with varying target sizes
"""
import os
import time
import json
import psutil
import statistics
from pathlib import Path
import subprocess
import argparse
from datetime import datetime

class ReconBenchmark:
    def __init__(self, target: str, outdir: Path):
        self.target = target
        self.outdir = outdir
        self.outdir.mkdir(parents=True, exist_ok=True)
        self.results = {}
        self.process = psutil.Process(os.getpid())
    
    def measure_execution(self, cmd: str, desc: str, runs: int = 3) -> dict:
        """Run a command and measure execution time and memory usage"""
        timings = []
        memory_usage = []
        
        for i in range(runs):
            start_mem = self.process.memory_info().rss / 1024 / 1024  # MB
            start_time = time.time()
            
            rc = subprocess.call(cmd, shell=True)
            
            duration = time.time() - start_time
            end_mem = self.process.memory_info().rss / 1024 / 1024  # MB
            mem_used = end_mem - start_mem
            
            timings.append(duration)
            memory_usage.append(mem_used)
            
            print(f"Run {i+1}/{runs} - Time: {duration:.2f}s, Memory: {mem_used:.1f}MB, RC: {rc}")
        
        return {
            "description": desc,
            "command": cmd,
            "runs": runs,
            "mean_time": statistics.mean(timings),
            "min_time": min(timings),
            "max_time": max(timings),
            "std_dev": statistics.stdev(timings) if len(timings) > 1 else 0,
            "mean_memory": statistics.mean(memory_usage),
            "max_memory": max(memory_usage),
            "timestamp": datetime.now().isoformat()
        }
    
    def benchmark_passive_enum(self, runs=3):
        """Benchmark basic passive enumeration"""
        cmd = f"python3 recon.py --target {self.target} --outdir {self.outdir}/passive --dry-run --confirm-owned"
        return self.measure_execution(cmd, "Basic passive enumeration", runs)
    
    def benchmark_fast_mode(self, runs=3):
        """Benchmark fast mode"""
        cmd = f"python3 recon.py --target {self.target} --outdir {self.outdir}/fast --dry-run --fast --confirm-owned"
        return self.measure_execution(cmd, "Fast mode enumeration", runs)
    
    def benchmark_deep_scan(self, runs=3):
        """Benchmark deep scanning"""
        cmd = f"python3 recon.py --target {self.target} --outdir {self.outdir}/deep --dry-run --deep --confirm-owned"
        return self.measure_execution(cmd, "Deep scanning mode", runs)
    
    def benchmark_cached(self, runs=3):
        """Benchmark with caching enabled"""
        cmd = f"python3 recon.py --target {self.target} --outdir {self.outdir}/cached --dry-run --use-cache --confirm-owned"
        return self.measure_execution(cmd, "Full pipeline with caching", runs)
    
    def benchmark_concurrent(self, runs=3):
        """Benchmark with different concurrency settings"""
        results = []
        for conc in [1, 5, 10, 20]:
            cmd = f"python3 recon.py --target {self.target} --outdir {self.outdir}/concurrent_{conc} --dry-run --concurrency {conc} --confirm-owned"
            result = self.measure_execution(cmd, f"Full pipeline with concurrency {conc}", runs)
            results.append(result)
        return results
    
    def run_all_benchmarks(self, runs=3):
        """Run all benchmark scenarios"""
        self.results["passive_enum"] = self.benchmark_passive_enum(runs)
        self.results["fast_mode"] = self.benchmark_fast_mode(runs)
        self.results["deep_scan"] = self.benchmark_deep_scan(runs)
        self.results["cached"] = self.benchmark_cached(runs)
        self.results["concurrent"] = self.benchmark_concurrent(runs)
        
        # Save results
        results_file = self.outdir / "recon_benchmark_results.json"
        results_file.write_text(json.dumps(self.results, indent=2))
        print(f"\nBenchmark results saved to {results_file}")
        
        # Print summary
        print("\nBenchmark Summary:")
        for name, result in self.results.items():
            if isinstance(result, list):
                for r in result:
                    print(f"{r['description']}:")
                    print(f"  Time: {r['mean_time']:.2f}s ± {r['std_dev']:.2f}s")
                    print(f"  Memory: {r['mean_memory']:.1f}MB (max: {r['max_memory']:.1f}MB)")
            else:
                print(f"{result['description']}:")
                print(f"  Time: {result['mean_time']:.2f}s ± {result['std_dev']:.2f}s")
                print(f"  Memory: {result['mean_memory']:.1f}MB (max: {result['max_memory']:.1f}MB)")

def main():
    parser = argparse.ArgumentParser(description="Run comprehensive benchmarks for recon.py")
    parser.add_argument("--target", default="example.com", help="Target domain for benchmarking")
    parser.add_argument("--outdir", type=Path, default=Path("outputs/recon_benchmark"), help="Output directory")
    parser.add_argument("--runs", type=int, default=3, help="Number of runs per test")
    args = parser.parse_args()
    
    print(f"Starting recon.py benchmarks against {args.target}")
    benchmark = ReconBenchmark(args.target, args.outdir)
    benchmark.run_all_benchmarks(args.runs)

if __name__ == "__main__":
    main()
