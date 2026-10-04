"""Verify the actual VLESS -> Worker -> SSTP -> HTTPS path before publishing."""
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import math
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
               ('https://cp.cloudflare.com/generate_204', '204')]
STABILITY_CASES = [('https://1.1.1.1/', '301')] * 2


def remaining_timeout(maximum, deadline):
    if deadline is None:
        return maximum
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('HTTPS stage budget exhausted')
    return min(maximum, remaining)


def failed_verification(node, error):
    result = dict(node, success=False, status='failed', error='HTTPS verification: ' + str(error))
    for field in ('https_checks', 'stability_tls_checks', 'https_latency_ms', 'entry_address'):
        result.pop(field, None)
    return result


def check_https_node(node, session, api_url, timeout_ms=15000, proxy_name=None, deadline=None):
    from vpngate import node_name
    result = dict(node)
    delays = []
    for field in ('https_checks', 'stability_tls_checks', 'https_latency_ms', 'entry_address'):
        result.pop(field, None)
    try:
        for url, expected in HTTPS_CASES + STABILITY_CASES:
            proxy_url = api_url + '/proxies/' + quote(proxy_name or node_name(node), safe='')
            request_timeout = remaining_timeout(timeout_ms / 1000 + 5, deadline)
            effective_timeout_ms = timeout_ms
            if deadline is not None:
                # These controller requests use a literal loopback address. Split the
                # remaining budget between connect/read, leaving the core a margin.
                connect_timeout = min(0.25, request_timeout / 4)
                read_timeout = request_timeout - connect_timeout
                effective_timeout_ms = min(timeout_ms, int(read_timeout * 900))
                if effective_timeout_ms < 1:
                    raise TimeoutError('HTTPS stage budget exhausted')
                request_timeout = (connect_timeout, read_timeout)
            response = session.get(proxy_url + '/delay',
                                   params={'url':url, 'expected':expected, 'timeout':effective_timeout_ms},
                                   timeout=request_timeout)
            if response.status_code != 200:
                raise RuntimeError(f'HTTPS verification returned HTTP {response.status_code}')
            delay = response.json().get('delay')
            if type(delay) is not int or delay < 0:
                raise RuntimeError('HTTPS verification returned invalid latency')
            # URLTest can return a positive delay even when expected-status failed.
            # Its per-URL alive flag is the authoritative status check.
            state_timeout = remaining_timeout(5, deadline)
            if deadline is not None:
                connect_timeout = min(0.25, state_timeout / 4)
                state_timeout = (connect_timeout, state_timeout - connect_timeout)
            state = session.get(proxy_url, timeout=state_timeout)
            if state.status_code != 200 or state.json().get('extra', {}).get(url, {}).get('alive') is not True:
                raise RuntimeError('HTTPS response did not match expected HTTP status ' + expected)
            delays.append(delay)
        remaining_timeout(1, deadline)
        result['https_checks'] = len(HTTPS_CASES)
        result['stability_tls_checks'] = len(STABILITY_CASES)
        result['https_latency_ms'] = max(delays[:len(HTTPS_CASES)])
    except Exception as error:
        result = failed_verification(node, error)
    return result


def check_entry_routes(node, session, api_url, entries, deadline=None):
    """Publish the exact entry which passed both HTTPS destinations, retrying a failed route."""
    from vpngate import node_name
    result = dict(node, success=False, status='failed', error='No configured entry route')
    result.pop('entry_address', None)
    for entry in entries:
        try:
            remaining_timeout(1, deadline)
        except TimeoutError as error:
            return failed_verification(node, error)
        result = check_https_node(node, session, api_url, proxy_name=node_name(node) + '@' + entry,
                                  deadline=deadline)
        result.pop('entry_address', None)
        if result.get('success'):
            result['entry_address'] = entry
            return result
    return result


def check_candidates(candidates, verify, workers=4, deadline=None):
    """Keep at most workers in flight; unstarted nodes never inherit checker success."""
    checked = [failed_verification(node, 'HTTPS stage budget exhausted before verification')
               for node in candidates]
    next_index = 0
    pending = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        while pending or next_index < len(candidates):
            while len(pending) < workers and next_index < len(candidates):
                if deadline is not None and time.monotonic() >= deadline:
                    break
                pending[pool.submit(verify, candidates[next_index])] = next_index
                next_index += 1
            if not pending:
                break
            timeout = None if deadline is None else max(0, deadline - time.monotonic())
            done, _ = wait(pending, timeout=timeout, return_when=FIRST_COMPLETED)
            if not done:
                break
            for future in done:
                checked[pending.pop(future)] = future.result()
        # There is no queued backlog. In-flight HTTP calls share the same deadline
        # and finish without starting another case or entry after it expires.
    for future, index in pending.items():
        checked[index] = future.result()
    return checked


def verify_nodes(results, binary):
    from vpngate import build_proxy, get_entry_addresses, log, node_name
    candidates = [node for node in results if node.get('success')]
    if not candidates:
        return results
    workers = max(1, int(os.environ.get('HTTPS_CHECK_CONCURRENCY', '4')))
    budget = float(os.environ.get('HTTPS_STAGE_BUDGET_SECONDS', '0'))
    if not math.isfinite(budget) or budget < 0:
        raise ValueError('HTTPS_STAGE_BUDGET_SECONDS must be finite and non-negative')
    deadline = time.monotonic() + budget if budget else None
    entries = get_entry_addresses()
    proxies = []
    for node in candidates:
        for entry in entries:
            proxy = build_proxy(node, entry)
            proxy['name'] = node_name(node) + '@' + entry
            proxies.append(proxy)
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
                        ready = control.get(api_url + '/version', timeout=remaining_timeout(0.5, deadline)).status_code == 200
                    except requests.RequestException:
                        pass
                    except TimeoutError:
                        return [failed_verification(node, 'HTTPS stage budget exhausted during startup')
                                if node.get('success') else node for node in results]
                    if ready:
                        break
                    time.sleep(remaining_timeout(0.1, deadline))
                if not ready:
                    raise RuntimeError('HTTPS verifier core did not start')

                def verify(node):
                    with requests.Session() as session:
                        session.trust_env = False
                        session.headers['Authorization'] = 'Bearer ' + secret
                        result = check_entry_routes(node, session, api_url, entries, deadline=deadline)
                    log('HTTPS END TO END', f"{node_name(node)}: " + ('通过两个 HTTPS 目标' if result['success'] else result['error']))
                    return result

                log('HTTPS END TO END', f'候选 {len(candidates)}，并发 {workers}，阶段预算 {budget:g}s (0=不限)')
                checked = check_candidates(candidates, verify, workers, deadline)
                if deadline is not None and time.monotonic() >= deadline:
                    log('HTTPS END TO END', '阶段预算耗尽；只保留本轮完成所有 HTTPS 检查的节点')
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
