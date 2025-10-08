import pytest
import os
from pathlib import Path
import tempfile
import json
from recon import (
    which,
    cache_dir,
    cache_path,
    TOOLS
)

def test_cache_path_structure():
    with tempfile.TemporaryDirectory() as tmpdir:
        outdir = Path(tmpdir)
        target = "example.com"
        
        # Test cache directory path construction
        target_cache = cache_dir(target, outdir)
        assert str(target_cache).endswith("cache/example_com")
        
        # Test cache file paths for different tools
        for tool in ["subfinder", "amass", "httpx"]:
            cache_file = cache_path(target, outdir, tool)
            assert str(cache_file).endswith(f"cache/example_com/{tool}.txt")
            assert cache_file.parent == target_cache
            
        # Test with dots in target name
        complex_target = "sub.example.com"
        complex_cache = cache_dir(complex_target, outdir)
        assert "_" in str(complex_cache)
        assert "." not in str(complex_cache).split("/")[-1]
