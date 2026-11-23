#!/usr/bin/env python3
"""Behaviour tests for the proxy's upstream session window.

A mock upstream records the arrival time of every request, so we can assert
the real invariant: at most MAX_PER_WINDOW sends per WINDOW seconds per
account, including retries.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, 'codearts-proxy-aksk.py')


class MockState:
    def __init__(self):
        self.lock = threading.Lock()
        self.hits = []
        self.fail_next = 0
        self.delay = 0.0
        self.ports = []
        self.session_ids = []
        self.slow_after_first = False
        self.slow_delay = 0.0
        self.aborted = False


class MockHandler(BaseHTTPRequestHandler):
    state = None
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        self.rfile.read(length)
        with self.state.lock:
            self.state.hits.append(time.monotonic())
            self.state.ports.append(self.client_address[1])
            self.state.session_ids.append(self.headers.get('Session-Id'))
            fail = self.state.fail_next > 0
            if fail:
                self.state.fail_next -= 1
            delay = self.state.delay
        if delay:
            time.sleep(delay)
        if fail:
            data = json.dumps({'error_code': 'TM.00001041',
                               'error_msg': 'session limit'}).encode()
            self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        first = ('data: ' + json.dumps({
            'id': 'chatcmpl-test',
            'object': 'chat.completion.chunk',
            'model': 'test-model',
            'choices': [{'index': 0, 'delta': {'content': 'ok'}, 'finish_reason': None}],
        }) + '\n\n').encode()
        rest = ('data: ' + json.dumps({
            'id': 'chatcmpl-test',
            'object': 'chat.completion.chunk',
            'model': 'test-model',
            'choices': [{'index': 0, 'delta': {}, 'finish_reason': 'stop'}],
        }) + '\n\ndata: [DONE]\n\n').encode()
        if self.state.slow_after_first:
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Content-Length', str(len(first) + len(rest)))
            self.end_headers()
            try:
                self.wfile.write(first)
                self.wfile.flush()
                time.sleep(self.state.slow_delay)
                self.wfile.write(rest)
                self.wfile.flush()
                # A close can surface on the second write; probe once more.
                self.wfile.write(b': ping\n\n')
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                with self.state.lock:
                    self.state.aborted = True
            return
        data = first + rest
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class ProxyFixture:
    def __init__(self, accounts, window, limit, max_wait, retries=0,
                 retry_delays='0.2', max_per_session=0):
        self.accounts = accounts
        self.window = window
        self.limit = limit
        self.max_wait = max_wait
        self.retries = retries
        self.retry_delays = retry_delays
        self.max_per_session = max_per_session
        self.tmp = tempfile.mkdtemp(prefix='proxy-test-')

    def start(self):
        self.state = MockState()
        handler = type('BoundMockHandler', (MockHandler,), {'state': self.state})
        self.mock = ThreadingHTTPServer(('127.0.0.1', 0), handler)
        threading.Thread(target=self.mock.serve_forever, daemon=True).start()
        mock_port = self.mock.server_address[1]

        aksk_path = os.path.join(self.tmp, 'aksk.json')
        with open(aksk_path, 'w') as f:
            json.dump(self.accounts, f)
        env_path = os.path.join(self.tmp, 'proxy.env')
        with open(env_path, 'w') as f:
            f.write('LOCAL_API_KEY=test-key\n')

        self.port = free_port()
        env = os.environ.copy()
        env.update({
            'PROXY_AKSK_FILE': aksk_path,
            'PROXY_ENV_FILE': env_path,
            'PROXY_LOCK_FILE': os.path.join(self.tmp, 'proxy.lock'),
            'PROXY_UPSTREAM_URL': f'http://127.0.0.1:{mock_port}/api/v2/chat/completions',
            'PROXY_HOST': '127.0.0.1',
            'PROXY_PORT': str(self.port),
            'PROXY_WINDOW_SECONDS': str(self.window),
            'PROXY_MAX_PER_WINDOW': str(self.limit),
            'PROXY_MAX_WAIT_SECONDS': str(self.max_wait),
            'PROXY_MAX_PER_SESSION': str(self.max_per_session),
            'PROXY_SESSION_RETRIES': str(self.retries),
            'PROXY_RETRY_DELAYS': self.retry_delays,
            'PROXY_UPSTREAM_TIMEOUT': '10',
        })
        self.env = env
        self.proc = subprocess.Popen([sys.executable, SCRIPT], env=env,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                out, err = self.proc.communicate(timeout=2)
                raise RuntimeError(f'proxy died: {out}\n{err}')
            try:
                with urllib.request.urlopen(self.url('/healthz'), timeout=0.5):
                    return self
            except Exception:
                time.sleep(0.05)
        raise RuntimeError('proxy did not become healthy')

    def url(self, path):
        return f'http://127.0.0.1:{self.port}{path}'

    def chat(self, timeout=30, content='hi', **extra):
        payload = {'model': 'test-model',
                   'messages': [{'role': 'user', 'content': content}]}
        payload.update(extra)
        body = json.dumps(payload).encode()
        req = urllib.request.Request(self.url('/v1/chat/completions'), data=body,
                                     headers={'Authorization': 'Bearer test-key',
                                              'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def stop(self):
        if getattr(self, 'proc', None):
            self.proc.terminate()
            try:
                self.proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if getattr(self, 'mock', None):
            self.mock.shutdown()
            self.mock.server_close()


class WindowTests(unittest.TestCase):
    def make(self, accounts, **kwargs):
        fixture = ProxyFixture(accounts, **kwargs).start()
        self.addCleanup(fixture.stop)
        return fixture

    def test_window_caps_sends_per_account(self):
        proxy = self.make([{'access_key_id': 'ak', 'secret_access_key': 'sk'}],
                          window=1.0, limit=2, max_wait=10)
        with ThreadPoolExecutor(max_workers=5) as pool:
            results = list(pool.map(lambda _: proxy.chat(), range(5)))
        self.assertEqual([s for s, _ in results], [200] * 5)
        hits = sorted(proxy.state.hits)
        self.assertEqual(len(hits), 5)
        for i in range(len(hits) - 2):
            self.assertGreaterEqual(hits[i + 2] - hits[i], 0.9,
                                    f'window breached: {hits}')

    def test_retry_re_enters_the_window(self):
        proxy = self.make([{'access_key_id': 'ak', 'secret_access_key': 'sk'}],
                          window=1.0, limit=1, max_wait=10,
                          retries=1, retry_delays='0.2')
        proxy.state.fail_next = 1
        status, body = proxy.chat()
        self.assertEqual(status, 200)
        hits = sorted(proxy.state.hits)
        self.assertEqual(len(hits), 2, 'retry must send a second upstream request')
        self.assertGreaterEqual(hits[1] - hits[0], 0.9,
                                'retry must wait for a new window slot, not slip past it')

    def test_multiple_accounts_add_their_windows(self):
        proxy = self.make([{'access_key_id': 'ak1', 'secret_access_key': 'sk1'},
                           {'access_key_id': 'ak2', 'secret_access_key': 'sk2'}],
                          window=1.0, limit=2, max_wait=10)
        start = time.monotonic()
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: proxy.chat(), range(4)))
        elapsed = time.monotonic() - start
        self.assertEqual([s for s, _ in results], [200] * 4)
        hits = sorted(proxy.state.hits)
        self.assertEqual(len(hits), 4)
        self.assertLess(hits[3] - hits[0], 0.8, f'two accounts should not queue: {hits}')
        self.assertLess(elapsed, 1.5)

    def test_queue_timeout_returns_429(self):
        proxy = self.make([{'access_key_id': 'ak', 'secret_access_key': 'sk'}],
                          window=2.0, limit=1, max_wait=0.3)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: proxy.chat(), range(2)))
        codes = sorted(s for s, _ in results)
        self.assertEqual(codes, [200, 429])
        limited = [b for s, b in results if s == 429][0]
        self.assertIn(b'rate_limit', limited)

    def test_upstream_1041_is_mapped_to_429(self):
        proxy = self.make([{'access_key_id': 'ak', 'secret_access_key': 'sk'}],
                          window=5.0, limit=3, max_wait=5, retries=0)
        proxy.state.fail_next = 1
        status, body = proxy.chat()
        self.assertEqual(status, 429)
        self.assertIn(b'TM.00001041', body)

    def test_disconnect_drops_queued_request(self):
        proxy = self.make([{'access_key_id': 'ak', 'secret_access_key': 'sk'}],
                          window=2.0, limit=1, max_wait=10)
        self.assertEqual(proxy.chat()[0], 200)
        with self.assertRaises((socket.timeout, TimeoutError, urllib.error.URLError)):
            proxy.chat(timeout=0.3)
        time.sleep(2.5)
        self.assertEqual(len(proxy.state.hits), 1,
                         'a disconnected client must not send the queued request')

    def test_lease_covers_the_whole_response(self):
        proxy = self.make([{'access_key_id': 'ak', 'secret_access_key': 'sk'}],
                          window=1.0, limit=1, max_wait=10)
        proxy.state.delay = 1.0
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(proxy.chat)
            time.sleep(0.2)
            second = pool.submit(proxy.chat)
            self.assertEqual(first.result()[0], 200)
            self.assertEqual(second.result()[0], 200)
        hits = sorted(proxy.state.hits)
        self.assertEqual(len(hits), 2)
        self.assertGreaterEqual(hits[1] - hits[0], 0.9,
                                'the lease must be held until the response ends')

    def test_same_session_requests_are_serialized(self):
        proxy = self.make([{'access_key_id': 'ak', 'secret_access_key': 'sk'}],
                          window=5.0, limit=3, max_wait=10, max_per_session=1)
        proxy.state.delay = 0.5
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: proxy.chat(), range(2)))
        self.assertEqual([s for s, _ in results], [200, 200])
        hits = sorted(proxy.state.hits)
        self.assertGreaterEqual(hits[1] - hits[0], 0.4,
                                'same conversation must not run two upstream requests at once')

    def test_different_sessions_run_in_parallel(self):
        proxy = self.make([{'access_key_id': 'ak', 'secret_access_key': 'sk'}],
                          window=5.0, limit=3, max_wait=10, max_per_session=1)
        proxy.state.delay = 0.5
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(proxy.chat, content='one'),
                       pool.submit(proxy.chat, content='two')]
            results = [f.result() for f in futures]
        self.assertEqual([s for s, _ in results], [200, 200])
        hits = sorted(proxy.state.hits)
        self.assertLess(hits[1] - hits[0], 0.3,
                        'different conversations should still run in parallel')

    def test_aux_requests_use_aux_accounts(self):
        accounts = {
            'accounts': [{'access_key_id': 'ak1', 'secret_access_key': 'sk1'}],
            'aux_accounts': [{'access_key_id': 'ak2', 'secret_access_key': 'sk2'}],
        }
        proxy = self.make(accounts, window=5.0, limit=3, max_wait=5)
        proxy.chat(content='hello')
        proxy.chat(content='make a short title', max_tokens=48)
        ids = proxy.state.session_ids
        self.assertEqual(len(ids), 2)
        self.assertNotEqual(ids[0], ids[1],
                            'auxiliary request should go through aux_accounts')

    def test_disconnect_aborts_upstream(self):
        proxy = self.make([{'access_key_id': 'ak', 'secret_access_key': 'sk'}],
                          window=5.0, limit=3, max_wait=5)
        proxy.state.slow_after_first = True
        proxy.state.slow_delay = 0.6
        with self.assertRaises((socket.timeout, TimeoutError, urllib.error.URLError)):
            proxy.chat(timeout=0.3)
        time.sleep(1.2)
        self.assertTrue(proxy.state.aborted,
                        'client disconnect must close the upstream request')

    def test_upstream_connection_is_reused(self):
        proxy = self.make([{'access_key_id': 'ak', 'secret_access_key': 'sk'}],
                          window=5.0, limit=3, max_wait=5)
        for _ in range(3):
            self.assertEqual(proxy.chat()[0], 200)
        ports = proxy.state.ports
        self.assertEqual(len(ports), 3)
        self.assertEqual(len(set(ports)), 1,
                         f'keep-alive should reuse one upstream connection: {ports}')

    def test_second_instance_is_refused(self):
        proxy = self.make([{'access_key_id': 'ak', 'secret_access_key': 'sk'}],
                          window=1.0, limit=2, max_wait=5)
        env = dict(proxy.env)
        env['PROXY_PORT'] = str(free_port())
        proc = subprocess.run([sys.executable, SCRIPT], env=env,
                              capture_output=True, text=True, timeout=15)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn('already running', (proc.stderr + proc.stdout).lower())


if __name__ == '__main__':
    unittest.main(verbosity=2)