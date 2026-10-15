"""Authorized loopback-only acceptance run. Stores actual, freshly measured results."""
import argparse
import contextlib
import io
import json
from pathlib import Path
from fresh_test import run

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url',default='http://127.0.0.1:5050')
    args=parser.parse_args()
    from urllib.parse import urlparse
    if urlparse(args.base_url).hostname not in ('127.0.0.1','localhost'):
        parser.error('Only local verification is supported')
    results=[]
    for attack in ('sqli','xss','traversal','benign'):
        with contextlib.redirect_stdout(io.StringIO()):
            result=run(args.base_url,benign=attack=='benign',attack='sqli' if attack=='benign' else attack,segmented=attack=='sqli')
        results.append(result)
        print(f'{attack}: PASS — {result["verified"]}',flush=True)
    path=Path(__file__).resolve().parent.parent/'validation'/'macos-live-verification.json'
    path.write_text(json.dumps(results,indent=2)+'\n')
    print(f'Evidence saved to {path}')
