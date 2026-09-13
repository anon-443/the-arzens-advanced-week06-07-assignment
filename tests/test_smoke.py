import csv, json, subprocess, sys
from pathlib import Path
ROOT = Path(__file__).parents[1]
def test_enricher_demo():
    out = subprocess.check_output([sys.executable, str(ROOT/'week06_ti/ti_enricher.py'), '--indicator', '8.8.8.8', '--format', 'json'], text=True)
    row = json.loads(out)[0]
    assert row['indicator'] == '8.8.8.8' and row['status'] in {'demo','live','error'}
def test_ioc_manager_help():
    subprocess.check_call([sys.executable, str(ROOT/'week06_ioc/ioc_manager.py'), '--help'], stdout=subprocess.DEVNULL)
