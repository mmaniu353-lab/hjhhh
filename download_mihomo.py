"""Fetch a pinned official Linux release; reject any unexpected archive."""
import argparse
import gzip
import hashlib
from pathlib import Path

import requests

VERSION = 'v1.19.32'
ASSET = f'mihomo-linux-amd64-compatible-{VERSION}.gz'
SHA256 = 'ba3ce607747a07f948fc35780e108a4a7c7f552a38b9bd4d115f313ebcb89c20'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    response = requests.get(f'https://github.com/MetaCubeX/mihomo/releases/download/{VERSION}/{ASSET}', timeout=120)
    response.raise_for_status()
    if hashlib.sha256(response.content).hexdigest() != SHA256:
        raise RuntimeError('Official Mihomo archive SHA256 verification failed')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(gzip.decompress(response.content))
    args.output.chmod(0o700)
    print('Official Mihomo', VERSION, 'archive digest verified')


if __name__ == '__main__':
    main()
