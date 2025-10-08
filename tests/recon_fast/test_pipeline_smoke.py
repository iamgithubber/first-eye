import subprocess

def test_pipeline_dry_run():
    rc = subprocess.call('python3 recon_fast.py --target example.test --dry-run --use-findomain', shell=True)
    assert rc == 0
