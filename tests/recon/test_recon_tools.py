import pytest
import os
from pathlib import Path
import tempfile
from recon import (
    which,
    check_binaries,
    TOOLS
)

def test_which():
    # Test for common Unix commands that should exist
    assert which("ls") == True
    assert which("nonexistentbinary123") == False

def test_check_binaries():
    # Test with common tools
    required = ["ls", "cat", "nonexistentbinary123"]
    results = check_binaries(required, quiet=True)
    
    assert results["ls"] == True
    assert results["cat"] == True
    assert results["nonexistentbinary123"] == False

def test_tools_dict():
    # Verify essential tools are in TOOLS dict
    assert "subfinder" in TOOLS
    assert "assetfinder" in TOOLS
    assert "amass" in TOOLS
    assert "httpx" in TOOLS
    
    # Verify tool names are strings
    for tool, binary in TOOLS.items():
        assert isinstance(tool, str)
        assert isinstance(binary, str)
