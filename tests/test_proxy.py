#!/usr/bin/env python3
"""Behaviour tests for the proxy's upstream session window.

A mock upstream records the arrival time of every request, so we can assert
the real invariant: at most MAX_PER_WINDOW sends per WINDOW seconds per
account, including retries.
"""
import importlib.util
import json
import signal

import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

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
        self.stream_flags = []
        self.fail_next_504 = 0
        self.slow_after_first = False
        self.slow_delay = 0.0
        self.aborted = False
        self.hang_next = 0


class MockHandler(BaseHTTPRequestHandler):
    state = None
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(length)
        try:
            stream_flag = json.loads(raw).get('stream')
        except Exception:
            stream_flag = None
        with self.state.lock:
            self.state.hits.append(time.monotonic())
            self.state.ports.append(self.client_address[1])
            self.state.session_ids.append(self.headers.get('Session-Id'))
            self.state.stream_flags.append(stream_flag)
            fail = self.state.fail_next > 0
            if fail:
                self.state.fail_next -= 1
            delay = self.state.delay
        first_token_fast = (stream_flag is True
                            and self.state.slow_after_first)
        if delay and not first_token_fast:
            time.sleep(delay)
        with self.state.lock:
            hang = self.state.hang_next > 0
            if hang:
                self.state.hang_next -= 1
        if hang:
            time.sleep(15)
            return
        if fail:
            data = json.dumps({'error_code': 'TM.00001041',
                               'error_msg': 'session limit'}).encode()
            self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if stream_flag is False and self.state.fail_next_504 > 0:
            with self.state.lock:
                self.state.fail_next_504 -= 1
            data = json.dumps({'error_msg': 'Backend timeout',
                               'error_code': 'APIG.0203'}).encode()
            self.send_response(504)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if stream_flag is False:
            data = json.dumps({
                'id': 'chatcmpl-test',
                'object': 'chat.completion',
                'model': 'test-model',
                'choices': [{'index': 0,
                             'message': {'role': 'assistant', 'content': 'ok',
                                         'reasoning_content': 'think'},
                             'finish_reason': 'stop'}],
                'usage': {'prompt_tokens': 1, 'completion_tokens': 1,
                          'total_tokens': 2},
            }).encode()
            self.send_response(200)
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
                 retry_delays='0.2', max_per_session=0, session_key='auto',
                 nonstream_timeout=None, upstream_timeout=None,
                 first_byte_timeout=None, drain_seconds=None):
        self.accounts = accounts
        self.window = window
        self.limit = limit
        self.max_wait = max_wait
        self.retries = retries
        self.retry_delays = retry_delays
        self.max_per_session = max_per_session
        self.session_key = session_key
        self.nonstream_timeout = nonstream_timeout
        self.upstream_timeout = upstream_timeout
        self.first_byte_timeout = first_byte_timeout
        self.drain_seconds = drain_seconds
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
            'PROXY_SESSION_KEY': self.session_key,
            'PROXY_SESSION_RETRIES': str(self.retries),
            'PROXY_RETRY_DELAYS': self.retry_delays,
            'PROXY_UPSTREAM_TIMEOUT': str(self.upstream_timeout
                                          if self.upstream_timeout is not None
                                          else 10),
        })
        if self.nonstream_timeout is not None:
            env['PROXY_NONSTREAM_TIMEOUT'] = str(self.nonstream_timeout)
        if self.first_byte_timeout is not None:
            env['PROXY_FIRST_BYTE_TIMEOUT'] = str(self.first_byte_timeout)
        if self.drain_seconds is not None:
            env['PROXY_DRAIN_SECONDS'] = str(self.drain_seconds)
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

    def chat(self, timeout=30, content='hi', headers=None, **extra):
        payload = {'model': 'test-model',
                   'messages': [{'role': 'user', 'content': content}]}
        payload.update(extra)
        body = json.dumps(payload).encode()
        hdrs = {'Authorization': 'Bearer test-key',
                'Content-Type': 'application/json'}
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(self.url('/v1/chat/completions'), data=body,
                                     headers=hdrs)
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

    def test_nonstream_client_uses_streaming_upstream(self):
        proxy = self.make([{'access_key_id': 'ak', 'secret_access_key': 'sk'}],
                          window=5.0, limit=3, max_wait=5)
        status, body = proxy.chat()
        self.assertEqual(status, 200)
        self.assertIn(b'ok', body)
        self.assertEqual(proxy.state.stream_flags, [True],
                         'a non-stream client request must go upstream as '
                         'streaming so long generations keep flowing')

    def test_stale_connection_first_byte_timeout_retries(self):
        proxy = self.make([{'access_key_id': 'ak', 'secret_access_key': 'sk'}],
                          window=5.0, limit=3, max_wait=5,
                          first_byte_timeout=0.5)
        proxy.state.hang_next = 1
        status, body = proxy.chat(stream=True)
        self.assertEqual(status, 200)
        self.assertIn(b'ok', body)
        self.assertEqual(len(proxy.state.hits), 2,
                         'a hung first byte must retry on a fresh connection')

    def test_nonstream_long_generation_survives_short_timeout(self):
        proxy = self.make([{'access_key_id': 'ak', 'secret_access_key': 'sk'}],
                          window=5.0, limit=3, max_wait=5,
                          upstream_timeout=1)
        proxy.state.delay = 2.0
        proxy.state.slow_after_first = True
        proxy.state.slow_delay = 0.3
        status, body = proxy.chat()
        self.assertEqual(status, 200)
        self.assertIn(b'ok', body)

    def test_streaming_1041_falls_back_to_nonstream(self):
        proxy = self.make([{'access_key_id': 'ak', 'secret_access_key': 'sk'}],
                          window=5.0, limit=3, max_wait=5, retries=0)
        proxy.state.fail_next = 1
        status, body = proxy.chat(stream=True)
        self.assertEqual(status, 200)
        self.assertIn(b'ok', body)
        self.assertEqual(proxy.state.stream_flags, [True, False],
                         '1041 on the streaming attempt must convert to a '
                         'non-stream fallback, not a 429')

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

    def test_messages_key_uses_first_last_and_count(self):
        proxy = self.make([{'access_key_id': 'ak', 'secret_access_key': 'sk'}],
                          window=5.0, limit=3, max_wait=10, max_per_session=1)
        proxy.state.delay = 0.5
        sys_msg = {'role': 'system', 'content': 'sys'}
        last = {'role': 'user', 'content': 'q-a'}
        # Same first + last + count, different middle: one conversation.
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(proxy.chat, messages=[sys_msg, {'role': 'user', 'content': 'mid-x'}, last]),
                pool.submit(proxy.chat, messages=[sys_msg, {'role': 'user', 'content': 'mid-y'}, last]),
            ]
            results = [f.result() for f in futures]
        self.assertEqual([s for s, _ in results], [200, 200])
        hits = sorted(proxy.state.hits)
        self.assertGreaterEqual(hits[1] - hits[0], 0.4,
                                'same first/last/count must serialize')
        # Same first, different last: different conversations, run in parallel.
        # Fresh proxy: the first part left two leases lingering in its window.
        proxy2 = self.make([{'access_key_id': 'ak', 'secret_access_key': 'sk'}],
                           window=5.0, limit=3, max_wait=10, max_per_session=1)
        proxy2.state.delay = 0.5
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(proxy2.chat, messages=[sys_msg, last]),
                pool.submit(proxy2.chat, messages=[sys_msg, {'role': 'user', 'content': 'q-b'}]),
            ]
            results = [f.result() for f in futures]
        self.assertEqual([s for s, _ in results], [200, 200])
        hits = sorted(proxy2.state.hits)
        self.assertLess(hits[1] - hits[0], 0.3,
                        'different last message must not serialize')

    def test_streaming_falls_back_to_nonstream_when_window_full(self):
        proxy = self.make([{'access_key_id': 'ak', 'secret_access_key': 'sk'}],
                          window=5.0, limit=3, max_wait=10, max_per_session=1)
        proxy.state.delay = 0.5
        # Fill all 3 leases with streaming requests; they linger 5 s after.
        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(
                lambda i: proxy.chat(content=f'fill-{i}', stream=True), range(3)))
        self.assertEqual([s for s, _ in results], [200, 200, 200])
        start = time.monotonic()
        status, body = proxy.chat(content='overflow', stream=True)
        elapsed = time.monotonic() - start
        self.assertEqual(status, 200)
        self.assertIn(b'ok', body)
        self.assertLess(elapsed, 2.5,
                        'overflow request must use the non-stream fallback, '
                        'not wait out the 5 s window')
        self.assertIn(False, proxy.state.stream_flags,
                      'fallback must send stream=false upstream')
        # And a non-stream client request still works through the normal path.
        status, body = proxy.chat(content='plain')
        self.assertEqual(status, 200)

    def test_nonstream_504_falls_back_to_queued_stream(self):
        proxy = self.make([{'access_key_id': 'ak', 'secret_access_key': 'sk'}],
                          window=2.0, limit=3, max_wait=10, max_per_session=1)
        proxy.state.delay = 0.3
        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(
                lambda i: proxy.chat(content=f'fill-{i}', stream=True), range(3)))
        self.assertEqual([s for s, _ in results], [200, 200, 200])
        proxy.state.fail_next_504 = 1
        start = time.monotonic()
        status, body = proxy.chat(content='overflow', stream=True)
        elapsed = time.monotonic() - start
        self.assertEqual(status, 200)
        self.assertIn(b'ok', body)
        self.assertGreaterEqual(elapsed, 1.0,
                                '504 fallback must wait for a lease, not '
                                'return the 504')
        self.assertLess(elapsed, 8.0)
        self.assertIn(False, proxy.state.stream_flags,
                      'fallback must try stream=false upstream first')

    def test_nonstream_timeout_falls_back_to_queued_stream(self):
        proxy = self.make([{'access_key_id': 'ak', 'secret_access_key': 'sk'}],
                          window=2.0, limit=3, max_wait=10, max_per_session=1,
                          nonstream_timeout=0.3)
        proxy.state.delay = 1.0
        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(
                lambda i: proxy.chat(content=f'fill-{i}', stream=True), range(3)))
        self.assertEqual([s for s, _ in results], [200, 200, 200])
        start = time.monotonic()
        status, body = proxy.chat(content='overflow', stream=True)
        elapsed = time.monotonic() - start
        self.assertEqual(status, 200)
        self.assertIn(b'ok', body)
        self.assertLess(elapsed, 8.0)
        self.assertIn(False, proxy.state.stream_flags,
                      'timed-out fallback must have tried stream=false')

    def test_header_session_key_serializes_different_messages(self):
        proxy = self.make([{'access_key_id': 'ak', 'secret_access_key': 'sk'}],
                          window=5.0, limit=3, max_wait=10,
                          max_per_session=1, session_key='header')
        proxy.state.delay = 0.5
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(proxy.chat, content='one',
                            headers={'X-Session-Id': 'same-conversation'}),
                pool.submit(proxy.chat, content='two',
                            headers={'X-Session-Id': 'same-conversation'}),
            ]
            results = [f.result() for f in futures]
        self.assertEqual([s for s, _ in results], [200, 200])
        hits = sorted(proxy.state.hits)
        self.assertGreaterEqual(hits[1] - hits[0], 0.4,
                                'X-Session-Id must serialize different messages')

    def test_ip_session_key_serializes_different_messages(self):
        proxy = self.make([{'access_key_id': 'ak', 'secret_access_key': 'sk'}],
                          window=5.0, limit=3, max_wait=10,
                          max_per_session=1, session_key='ip')
        proxy.state.delay = 0.5
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(proxy.chat, content='one'),
                       pool.submit(proxy.chat, content='two')]
            results = [f.result() for f in futures]
        self.assertEqual([s for s, _ in results], [200, 200])
        hits = sorted(proxy.state.hits)
        self.assertGreaterEqual(hits[1] - hits[0], 0.4,
                                'ip mode must serialize same-source requests')

    def test_short_non_streaming_request_uses_aux(self):
        accounts = {
            'accounts': [{'access_key_id': 'ak1', 'secret_access_key': 'sk1'}],
            'aux_accounts': [{'access_key_id': 'ak2', 'secret_access_key': 'sk2'}],
        }
        proxy = self.make(accounts, window=5.0, limit=3, max_wait=5)
        proxy.chat(content='hello there')
        proxy.chat(content='hi', stream=False)
        ids = proxy.state.session_ids
        self.assertEqual(len(ids), 2)
        self.assertNotEqual(ids[0], ids[1],
                            'short non-streaming request should use aux_accounts')

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


class _FakeResp:
    def __init__(self, status=200):
        self.status = status

    def read(self, amt=None):
        return b'{}'


class _FakeConn:
    def __init__(self, fail_with=None):
        self.fail_with = fail_with
        self.closed = False
        self.sock = None
        self.timeout = None
        self.requests = 0
        self.resp = _FakeResp(200)

    def request(self, method, path, body=None, headers=None):
        self.requests += 1
        if self.fail_with is not None:
            raise self.fail_with

    def getresponse(self):
        return self.resp

    def close(self):
        self.closed = True


class _FakePool:
    def __init__(self, conns):
        self.conns = list(conns)
        self.released = []

    def acquire(self):
        return self.conns.pop(0)

    def release(self, conn):
        self.released.append(conn)


def _load_proxy_module(tmp):
    aksk_path = os.path.join(tmp, 'aksk.json')
    with open(aksk_path, 'w') as f:
        json.dump([{'access_key_id': 'ak', 'secret_access_key': 'sk'}], f)
    env_path = os.path.join(tmp, 'proxy.env')
    with open(env_path, 'w') as f:
        f.write('LOCAL_API_KEY=test-key\n')
    env = {
        'PROXY_AKSK_FILE': aksk_path,
        'PROXY_ENV_FILE': env_path,
        'PROXY_LOCK_FILE': os.path.join(tmp, 'proxy.lock'),
        'PROXY_UPSTREAM_URL': 'http://127.0.0.1:9/api/v2/chat/completions',
        'PROXY_HOST': '127.0.0.1',
        'PROXY_PORT': '18099',
        'PROXY_WINDOW_SECONDS': '60',
        'PROXY_MAX_PER_WINDOW': '3',
        'PROXY_MAX_WAIT_SECONDS': '120',
        'PROXY_MAX_PER_SESSION': '1',
        'PROXY_SESSION_KEY': 'auto',
        'PROXY_SESSION_RETRIES': '0',
        'PROXY_RETRY_DELAYS': '0.2',
        'PROXY_UPSTREAM_TIMEOUT': '10',
    }
    with mock.patch.dict(os.environ, env):
        spec = importlib.util.spec_from_file_location(
            'proxy_under_test', SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    return mod


class GracefulShutdownTests(unittest.TestCase):
    def make(self, accounts, **kwargs):
        fixture = ProxyFixture(accounts, **kwargs).start()
        self.addCleanup(fixture.stop)
        return fixture

    def test_sigterm_waits_for_in_flight_request(self):
        proxy = self.make([{'access_key_id': 'ak', 'secret_access_key': 'sk'}],
                          window=60.0, limit=3, max_wait=10,
                          max_per_session=1, drain_seconds=10)
        proxy.state.delay = 2.0
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(proxy.chat, content='slow', stream=True)
            time.sleep(0.5)
            proxy.proc.send_signal(signal.SIGTERM)
            status, body = future.result(timeout=15)
        self.assertEqual(status, 200)
        self.assertIn(b'ok', body)
        self.assertEqual(proxy.proc.wait(timeout=10), 0,
                         'proxy must exit 0 after draining')


class PoolLivenessTests(unittest.TestCase):
    def test_sock_alive(self):
        mod = _load_proxy_module(tempfile.mkdtemp(prefix='proxy-alive-'))
        a, b = socket.socketpair()
        try:
            self.assertTrue(mod._sock_alive(a))
            b.close()
            self.assertFalse(mod._sock_alive(a))
        finally:
            a.close()

    def test_acquire_discards_dead_pooled_connection(self):
        mod = _load_proxy_module(tempfile.mkdtemp(prefix='proxy-alive-'))
        pool = mod.ConnectionPool('127.0.0.1', 443, True)
        a, b = socket.socketpair()
        dead = _FakeConn()
        dead.sock = a
        pool.idle.append(dead)
        b.close()  # peer closed: the pooled socket is now readable (FIN)
        conn = pool.acquire()
        self.assertIsNot(conn, dead)
        self.assertTrue(dead.closed)
        a.close()


class UpstreamRetryTests(unittest.TestCase):
    def test_write_failure_retries_on_fresh_connection(self):
        mod = _load_proxy_module(tempfile.mkdtemp(prefix='proxy-retry-'))
        bad = _FakeConn(fail_with=ssl.SSLWantWriteError(
            'The write operation timed out'))
        good = _FakeConn()
        mod.POOL = _FakePool([bad, good])
        account = types.SimpleNamespace(ak='ak', sk='sk',
                                        session_id='sess-1')
        result = mod._post_upstream(account, b'{"model": "m"}')
        self.assertIs(result._resp, good.resp)
        self.assertEqual(good.requests, 1)
        self.assertTrue(bad.closed, 'failed connection must be closed')
        self.assertIsInstance(result, mod.PooledResponse)

    def test_write_failure_twice_raises(self):
        mod = _load_proxy_module(tempfile.mkdtemp(prefix='proxy-retry-'))
        bad1 = _FakeConn(fail_with=ssl.SSLWantWriteError(
            'The write operation timed out'))
        bad2 = _FakeConn(fail_with=ssl.SSLWantWriteError(
            'The write operation timed out'))
        mod.POOL = _FakePool([bad1, bad2])
        account = types.SimpleNamespace(ak='ak', sk='sk',
                                        session_id='sess-1')
        with self.assertRaises(ssl.SSLWantWriteError):
            mod._post_upstream(account, b'{"model": "m"}')
        self.assertTrue(bad1.closed and bad2.closed)
