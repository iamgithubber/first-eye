import pytest
import os
from pathlib import Path
import tempfile
import json
from recon import (
    cache_dir,
    cache_path
)

def test_cache_paths():
    with tempfile.TemporaryDirectory() as tmpdir:
        outdir = Path(tmpdir)
        target = "example.com"
        
        # Test cache_dir
        cache_directory = cache_dir(target, outdir)
        assert str(cache_directory).endswith("cache/example_com")
        
        # Test cache_path
        step = "subfinder"
        cache_file = cache_path(target, outdir, step)
        assert str(cache_file).endswith("cache/example_com/subfinder.txt")
