"""Verify the actual VLESS -> Worker -> SSTP -> HTTPS path before publishing."""
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
from urllib.parse import quote

import requests
import yaml

HTTPS_CASES = [('https://www.gstatic.com/generate_204', '204'),
               ('https://www.cloudflare.com/cdn-cgi/trace', '200')]


def check_https_node(node, session, api_url, timeout_ms=15000):
    from vpngate import node_name
    result = dict(node)
    delays = []
    try:
        for url, expected in HTTPS_CASES:
            proxy_url = api_url + '/proxies/' + quote(node_name(node), safe='')
            response = session.get(proxy_url + '/delay',
                                   params={'url':url, 'expected':expected, 'timeout':timeout_ms},
                                   timeout=timeout_ms / 1000 + 5)
            if response.status_code != 200:
                raise RuntimeError(f'HTTPS verification returned HTTP {response.status_code}')
            delay = response.json().get('delay')
            if type(delay) is not int or delay < 0:
                raise RuntimeError('HTTPS verification returned invalid latency')
            # URLTest can return a positive delay even when expected-status failed.
            # Its per-URL alive flag is the authoritative status check.
            state = session.get(proxy_url, timeout=5)
            if state.status_code != 200 or state.json().get('extra', {}).get(url, {}).get('alive') is not True:
                raise RuntimeError('HTTPS response did not match expected HTTP status ' + expected)
            delays.append(delay)
        result['https_checks'] = len(delays)
        result['https_latency_ms'] = max(delays)
    except Exception as error:
        result.update(success=False, status='failed', error=f'HTTPS verification: {error}')
    return result


def verify_nodes(results, binary):
    from vpngate import build_proxy, get_entry_addresses, log, node_name
    candidates = [node for node in results if node.get('success')]
    if not candidates:
        return results
    entries = get_entry_addresses()
    proxies = [build_proxy(node, entries[index % len(entries)]) for index, node in enumerate(candidates)]
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    api_url = f'http://127.0.0.1:{port}'
    secret = secrets.token_hex(24)
    core = None
    with tempfile.TemporaryDirectory(prefix='gate-https-') as directory:
        config = {'external-controller':f'127.0.0.1:{port}', 'secret':secret, 'ipv6':False,
                  'mode':'rule', 'log-level':'warning', 'tun':{'enable':False},
                  'dns':{'enable':False}, 'proxies':proxies, 'rules':['MATCH,REJECT']}
        path = Path(directory) / 'config.yaml'
        path.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding='utf-8')
        with (Path(directory) / 'mihomo.log').open('wb') as logfile:
            try:
                core = subprocess.Popen([str(Path(binary).resolve()), '-d', directory, '-f', str(path)],
                                        stdout=logfile, stderr=subprocess.STDOUT,
                                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
                control = requests.Session()
                control.trust_env = False
                control.headers['Authorization'] = 'Bearer ' + secret
                ready = False
                for _ in range(100):
                    if core.poll() is not None:
                        raise RuntimeError('HTTPS verifier core exited before startup')
                    try:
                        ready = control.get(api_url + '/version', timeout=0.5).status_code == 200
                    except requests.RequestException:
                        pass
                    if ready:
                        break
                    time.sleep(0.1)
                if not ready:
                    raise RuntimeError('HTTPS verifier core did not start')

                def verify(node):
                    with requests.Session() as session:
                        session.trust_env = False
                        session.headers['Authorization'] = 'Bearer ' + secret
                        result = check_https_node(node, session, api_url)
                    log('HTTPS END TO END', f"{node_name(node)}: " + ('通过两个 HTTPS 目标' if result['success'] else result['error']))
                    return result

                with ThreadPoolExecutor(max_workers=4) as pool:
                    checked = list(pool.map(verify, candidates))
                lookup = {(node['host'], node['port']):node for node in checked}
                return [lookup.get((node['host'], node['port']), node) for node in results]
            finally:
                if core is not None:
                    core.terminate()
                    try:
                        core.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        core.kill()
                        core.wait(timeout=5)
