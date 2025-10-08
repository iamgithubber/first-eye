"""
Helper script to make recon.py importable as a module.
"""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))
