#!/usr/bin/env python3
"""codearts-proxy-aksk: OpenAI-compatible relay for Huawei snap-access.

Signs every upstream request with a permanent AK/SK (SDK-HMAC-SHA256), so no
IAM token and no renewal are needed.

Upstream session model (verified against the live endpoint):
  * every POST /api/v2/chat/completions counts as ONE session;
  * a session lingers server-side for roughly 60 s after the request ends;
  * an AK/SK may have at most 3 such sessions alive at the same time,
    otherwise the endpoint answers HTTP 400 with TM.00001041.

This means the limit is a request-rate limit, not a connection limit: three
requests inside 60 s fill the account even if they all finish in a second.
The proxy therefore tracks a sliding window per AK/SK and queues sends until
a slot in that window is free. Multiple AK/SK accounts can be configured; each
one adds its own window, which is the only way to actually increase throughput.

Endpoints: POST /v1/chat/completions, POST /chat/completions,
GET /v1/models, GET /models, GET /healthz.
"""
import collections
import hashlib
import hmac
import http.client
import json
import os
import select
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX
    fcntl = None

BASE = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.environ.get('PROXY_ENV_FILE', os.path.join(BASE, 'codearts-proxy-aksk.env'))


def load_env(path):
    env = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                k, v = line.split('=', 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    return env


ENV = load_env(ENV_PATH)


def cfg(name, default):
    """Process env wins, then the .env file, then the built-in default."""
    return os.environ.get(name) or ENV.get(name) or default


AKSK_PATH = cfg('PROXY_AKSK_FILE', os.path.join(BASE, 'codearts-aksk.json'))
LOCK_PATH = cfg('PROXY_LOCK_FILE', os.path.join(BASE, '.codearts-proxy.lock'))
SNAP_URL = cfg(
    'PROXY_UPSTREAM_URL',
    'https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions')
MODEL = cfg('PROXY_MODEL', 'deepseek-v4.1-flash-1017')
LISTEN_HOST = cfg('PROXY_HOST', '0.0.0.0')
LISTEN_PORT = int(cfg('PROXY_PORT', '18000'))
LOCAL_API_KEY = cfg('LOCAL_API_KEY', '')

# Upstream allows 3 live sessions per AK/SK. Default to 2 so the proxy always
# leaves one slot for other clients on the same account (IDE, CLI, ...) and
# never fills the account by itself.
WINDOW = float(cfg('PROXY_WINDOW_SECONDS', '60'))
MAX_PER_WINDOW = max(1, int(cfg('PROXY_MAX_PER_WINDOW', '2')))
# How long a client request may wait for a session lease before 429. 0 = no cap.
MAX_WAIT = float(cfg('PROXY_MAX_WAIT_SECONDS', '120'))
# Retries on TM.00001041. Each retry consumes another session lease, so keep
# this small; 1 means "one extra attempt after the first failure".
RETRIES = max(0, int(cfg('PROXY_SESSION_RETRIES', '1')))
RETRY_DELAYS = [
    float(x) for x in cfg('PROXY_RETRY_DELAYS', '5,15').split(',') if x.strip()
]
# Hard ceiling on concurrent client threads so a burst cannot exhaust memory.
MAX_ACTIVE = max(1, int(cfg('PROXY_MAX_ACTIVE', '64')))
UPSTREAM_TIMEOUT = float(cfg('PROXY_UPSTREAM_TIMEOUT', '300'))


def sign(ak, sk, method, url, body_bytes):
    """SDK-HMAC-SHA256 sign for one upstream request."""
    u = urlparse(url)
    now = datetime.now(timezone.utc)
    sdk_date = now.strftime('%Y%m%dT%H%M%SZ')
    payload_hash = hashlib.sha256(body_bytes).hexdigest()
    headers = {'host': u.netloc, 'x-sdk-date': sdk_date, 'content-type': 'application/json'}
    signed = ';'.join(sorted(headers.keys()))
    canon_headers = ''.join(f'{k}:{headers[k].strip()}\n' for k in sorted(headers.keys()))
    canon_uri = u.path if u.path.endswith('/') else u.path + '/'
    canon_req = '\n'.join([method, canon_uri, u.query, canon_headers, signed, payload_hash])
    string_to_sign = '\n'.join(['SDK-HMAC-SHA256', sdk_date,
                                hashlib.sha256(canon_req.encode()).hexdigest()])
    sig = hmac.new(sk.encode(), string_to_sign.encode(), hashlib.sha256).hexdigest()
    out = dict(headers)
    out['Authorization'] = f'SDK-HMAC-SHA256 Access={ak}, SignedHeaders={signed}, Signature={sig}'
    return out


class Account:
    """One AK/SK plus the session budget that tracks its upstream sessions.

    Upstream starts counting a session when the request is sent and keeps it
    for WINDOW seconds after the response finishes. A lease therefore stays
    held for the whole response and only then starts its linger timer.
    """

    def __init__(self, ak, sk):
        self.ak = ak
        self.sk = sk
        self.session_id = uuid.uuid4().hex
        self.active = 0
        self.linger = collections.deque()
        self.lock = threading.Lock()

    def try_reserve(self, now):
        """Take a lease. Returns 0 on success, else seconds until retry."""
        with self.lock:
            while self.linger and now - self.linger[0] >= WINDOW:
                self.linger.popleft()
            if self.active + len(self.linger) < MAX_PER_WINDOW:
                self.active += 1
                return 0.0
            if self.linger:
                return max(0.05, self.linger[0] + WINDOW - now)
            # Only in-flight requests occupy the budget; poll briefly so a
            # short response frees the slot without a long stall.
            return 0.1

    def release(self, now):
        with self.lock:
            if self.active > 0:
                self.active -= 1
            self.linger.append(now)

    def used(self, now):
        with self.lock:
            while self.linger and now - self.linger[0] >= WINDOW:
                self.linger.popleft()
            return self.active + len(self.linger)


def load_accounts(path):
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, dict) and 'accounts' in data:
        items = data['accounts']
    elif isinstance(data, list):
        items = data
    else:
        items = [data]
    accounts = []
    for item in items:
        ak = item.get('access_key_id') or item.get('ak')
        sk = item.get('secret_access_key') or item.get('sk')
        if ak and sk:
            accounts.append(Account(ak, sk))
    if not accounts:
        raise SystemExit(f'no valid access_key_id/secret_access_key in {path}')
    return accounts


ACCOUNTS = load_accounts(AKSK_PATH)
ACTIVE = threading.BoundedSemaphore(MAX_ACTIVE)


class ClientGone(Exception):
    """The HTTP client disappeared while we were queued or retrying."""


class QueueTimeout(Exception):
    def __init__(self, wait):
        super().__init__(f'no upstream session slot within {MAX_WAIT}s')
        self.wait = wait


def _sleep_cancellable(seconds, cancel):
    end = time.monotonic() + seconds
    while True:
        if cancel is not None and cancel.is_set():
            raise ClientGone()
        left = end - time.monotonic()
        if left <= 0:
            return
        time.sleep(min(left, 0.2))


def reserve_send(cancel=None):
    """Block until one account has a free session lease, then take it."""
    start = time.monotonic()
    last_log = start
    while True:
        if cancel is not None and cancel.is_set():
            raise ClientGone()
        now = time.monotonic()
        waits = []
        for account in ACCOUNTS:
            wait = account.try_reserve(now)
            if wait <= 0:
                return account
            waits.append(wait)
        wait = min(waits)
        # If the projected total wait would exceed the cap, fail fast instead
        # of sleeping past it and succeeding later.
        if MAX_WAIT > 0 and (now - start) + wait > MAX_WAIT:
            raise QueueTimeout(max(wait, 1.0))
        if now - last_log >= 5:
            print(f'[queue] all session leases busy, waiting {wait:.1f}s',
                  file=sys.stderr, flush=True)
            last_log = now
        _sleep_cancellable(wait, cancel)


_UPSTREAM = urlparse(SNAP_URL)
_UPSTREAM_PATH = _UPSTREAM.path + (f'?{_UPSTREAM.query}' if _UPSTREAM.query else '')


class ConnectionPool:
    """Keep-alive pool for upstream TLS connections.

    Reusing the connection skips the TLS handshake on every request, which is
    the largest fixed cost after queueing. Each connection is used by one
    request at a time; it is returned only after the body has been read fully.
    """

    def __init__(self, host, port, https, max_idle=8):
        self.host = host
        self.port = port
        self.https = https
        self.max_idle = max_idle
        self.idle = collections.deque()
        self.lock = threading.Lock()

    def acquire(self):
        with self.lock:
            while self.idle:
                conn = self.idle.pop()
                if conn.sock is not None:
                    return conn
                try:
                    conn.close()
                except Exception:
                    pass
        cls = http.client.HTTPSConnection if self.https else http.client.HTTPConnection
        return cls(self.host, self.port, timeout=UPSTREAM_TIMEOUT)

    def release(self, conn):
        if conn.sock is None:
            return
        with self.lock:
            if len(self.idle) < self.max_idle:
                self.idle.append(conn)
                return
        try:
            conn.close()
        except Exception:
            pass


POOL = ConnectionPool(
    _UPSTREAM.hostname,
    _UPSTREAM.port or (443 if _UPSTREAM.scheme == 'https' else 80),
    _UPSTREAM.scheme == 'https')


class PooledResponse:
    """Forward a response and return its connection to the pool on EOF."""

    def __init__(self, resp, conn):
        self._resp = resp
        self._conn = conn
        self._eof = False
        self._closed = False

    def read(self, amt=None):
        data = self._resp.read(amt)
        if amt is None or data == b'':
            self._eof = True
        return data

    def read1(self, amt=None):
        data = self._resp.read1(amt)
        if data == b'':
            self._eof = True
        return data

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            self._resp.close()
        finally:
            if self._eof and self._conn.sock is not None:
                POOL.release(self._conn)
            else:
                try:
                    self._conn.close()
                except Exception:
                    pass


def _post_upstream(account, body):
    headers = sign(account.ak, account.sk, 'POST', SNAP_URL, body)
    # Session headers are added after signing (not part of the canonical
    # request). Chat-Id and Session-Id stay stable per account: a fresh id per
    # request used to be counted as an extra session.
    headers['Chat-Id'] = account.session_id
    headers['Session-Id'] = account.session_id
    headers['lang'] = 'en'
    headers['Connection'] = 'keep-alive'
    conn = POOL.acquire()
    try:
        conn.request('POST', _UPSTREAM_PATH, body=body, headers=headers)
        resp = conn.getresponse()
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        raise
    if resp.status >= 400:
        err_body = resp.read()
        try:
            resp.close()
        finally:
            POOL.release(conn)
        raise urllib.error.HTTPError(SNAP_URL, resp.status, resp.reason,
                                     resp.headers, _BodyReader(err_body))
    return PooledResponse(resp, conn)


def call_upstream(body, cancel=None):
    """Send one chat completion, queueing inside the per-account budget.

    Every send, including retries, goes through reserve_send first, so a retry
    can never silently exceed the budget. On success the caller receives
    (account, response) and must call account.release() after consuming the
    response; that is what starts the server-side linger timer.
    """
    attempts = 1 + RETRIES
    last = None
    for attempt in range(attempts):
        account = reserve_send(cancel)
        try:
            return account, _post_upstream(account, body)
        except urllib.error.HTTPError as e:
            err_body = e.read()
            account.release(time.monotonic())
            last = (e, err_body)
            _log_upstream_error(e.code, err_body)
            if b'TM.00001041' in err_body and attempt + 1 < attempts:
                delay = RETRY_DELAYS[min(attempt, len(RETRY_DELAYS) - 1)]
                print(
                    f'[session-limit] attempt {attempt + 1}/{attempts}, '
                    f'retrying in {delay:.1f}s (must take a new lease)',
                    file=sys.stderr, flush=True)
                _sleep_cancellable(delay, cancel)
                continue
            break
        except Exception:
            account.release(time.monotonic())
            raise
    if last is None:
        raise RuntimeError('call_upstream ended without a result')
    e, err_body = last
    raise urllib.error.HTTPError(e.url, e.code, e.msg, e.headers, _BodyReader(err_body))


def _log_upstream_error(code, err_body):
    text = err_body.decode('utf-8', 'replace')[:600]
    print(f'[upstream-error] status={code} body={text}', file=sys.stderr, flush=True)


class _BodyReader:
    """Minimal file-like wrapper so an HTTPError can carry a pre-read body."""

    def __init__(self, data):
        self._data = data

    def read(self, *a, **k):
        return self._data

    def close(self):
        pass


def _watch_client(conn, cancel, stop):
    """Set cancel when the client closes the connection before we answer."""
    while not stop.is_set() and not cancel.is_set():
        try:
            readable, _, _ = select.select([conn], [], [], 0.5)
            if not readable:
                continue
            try:
                data = conn.recv(1, socket.MSG_PEEK)
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:
                cancel.set()
                return
            if data == b'':
                cancel.set()
                return
        except (OSError, ValueError):
            cancel.set()
            return


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def setup(self):
        super().setup()
        try:
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

    def log_message(self, fmt, *args):
        sys.stderr.write('%s %s\n' % (self.command, self.path))

    def _send_json(self, code, obj, headers=None):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, str(value))
        self.end_headers()
        self.wfile.write(data)

    def _auth_ok(self):
        if not LOCAL_API_KEY:
            return True
        return self.headers.get('Authorization', '') == 'Bearer ' + LOCAL_API_KEY

    def do_GET(self):
        if self.path in ('/v1/models', '/models'):
            models = []
            try:
                with open(os.path.join(BASE, 'snap_models.json')) as f:
                    for m in json.load(f):
                        models.append({'id': m['id'], 'object': 'model', 'owned_by': 'codearts'})
            except Exception:
                models = [{'id': MODEL, 'object': 'model', 'owned_by': 'codearts'}]
            self._send_json(200, {'object': 'list', 'data': models})
        elif self.path in ('/healthz', '/health'):
            now = time.monotonic()
            self._send_json(200, {
                'status': 'ok',
                'model': MODEL,
                'auth': 'aksk',
                'accounts': len(ACCOUNTS),
                'window_seconds': WINDOW,
                'max_per_window': MAX_PER_WINDOW,
                'used': [a.used(now) for a in ACCOUNTS],
                'max_wait_seconds': MAX_WAIT,
                'max_active': MAX_ACTIVE,
            })
        else:
            self._send_json(404, {'error': 'not found'})

    def do_POST(self):
        if self.path not in ('/v1/chat/completions', '/chat/completions'):
            self._send_json(404, {'error': 'not found'})
            return
        if not self._auth_ok():
            self._send_json(401, {'error': {'message': 'invalid api key', 'type': 'auth'}})
            return
        if not ACTIVE.acquire(timeout=30):
            self._send_json(503, {'error': {'message': 'proxy too busy, retry later',
                                            'type': 'server_error'}})
            return
        cancel = threading.Event()
        self._cancel_event = cancel
        stop = threading.Event()
        watcher = threading.Thread(target=_watch_client,
                                   args=(self.connection, cancel, stop), daemon=True)
        watcher.start()
        try:
            self._handle_completion()
        finally:
            stop.set()
            ACTIVE.release()

    def _handle_completion(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        try:
            req = json.loads(body)
        except Exception:
            self._send_json(400, {'error': 'invalid json'})
            return
        req.setdefault('model', MODEL)
        upstream_body = json.dumps(req).encode()
        cancel = getattr(self, '_cancel_event', None)
        try:
            account, uresp = call_upstream(upstream_body, cancel)
        except ClientGone:
            return
        except QueueTimeout as e:
            self._send_json(429, {
                'error': {'message': f'upstream session window full, retry after '
                                     f'{max(1, int(e.wait))}s', 'type': 'rate_limit'},
            }, headers={'Retry-After': max(1, int(e.wait))})
            return
        except urllib.error.HTTPError as e:
            err_body = e.read()
            if b'TM.00001041' in err_body:
                self._send_json(429, {
                    'error': {'message': 'upstream session limit (TM.00001041), retry later',
                              'type': 'rate_limit', 'upstream': err_body.decode('utf-8', 'replace')},
                }, headers={'Retry-After': max(1, int(WINDOW))})
                return
            try:
                self.send_response(e.code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(err_body)))
                self.end_headers()
                self.wfile.write(err_body)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        except Exception as e:
            self._send_json(502, {'error': f'upstream error: {e}'})
            return

        try:
            if req.get('stream'):
                self._relay_stream(uresp, cancel)
            else:
                self._relay_json(uresp)
        finally:
            # The upstream session stays alive for WINDOW seconds after the
            # response ends, so the lease is only released here.
            account.release(time.monotonic())

    def _relay_stream(self, uresp, cancel):
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Cache-Control', 'no-cache')
        # SSE has no Content-Length. Without chunked framing or a close the
        # client cannot tell where the body ends except by the [DONE] marker;
        # close after the stream so generic HTTP clients also finish cleanly.
        self.send_header('Connection', 'close')
        self.close_connection = True
        self.end_headers()
        saw_finish = False
        last_id = None
        last_model = None
        buf = b''
        try:
            while True:
                chunk = uresp.read1(4096) if hasattr(uresp, 'read1') else uresp.read(4096)
                if not chunk:
                    break
                buf += chunk
                while b'\n' in buf:
                    line, buf = buf.split(b'\n', 1)
                    line += b'\n'
                    stripped = line.decode('utf-8', 'replace').strip()
                    if stripped == 'data: [DONE]':
                        continue
                    if stripped.startswith('data:'):
                        payload = stripped[5:].strip()
                        if payload:
                            try:
                                obj = json.loads(payload)
                                if obj.get('id'):
                                    last_id = obj['id']
                                if obj.get('model'):
                                    last_model = obj['model']
                                for ch in obj.get('choices') or []:
                                    if ch.get('finish_reason'):
                                        saw_finish = True
                            except Exception:
                                pass
                    try:
                        self.wfile.write(line)
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        if cancel is not None:
                            cancel.set()
                        return
        finally:
            try:
                uresp.close()
            except Exception:
                pass
        if not saw_finish:
            try:
                final = {'choices': [{'delta': {}, 'finish_reason': 'stop', 'index': 0}],
                         'created': int(time.time()),
                         'id': last_id or ('as-' + uuid.uuid4().hex[:12]),
                         'model': last_model or MODEL,
                         'object': 'chat.completion.chunk'}
                self.wfile.write(('data: ' + json.dumps(final) + '\n\n').encode())
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                return
        try:
            self.wfile.write(b'data: [DONE]\n\n')
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _relay_json(self, uresp):
        try:
            raw = uresp.read().decode('utf-8', 'replace')
        finally:
            try:
                uresp.close()
            except Exception:
                pass
        merged = None
        content_parts = []
        for line in raw.splitlines():
            line = line.strip()
            if not line.startswith('data:'):
                continue
            payload = line[5:].strip()
            if payload == '[DONE]':
                continue
            try:
                obj = json.loads(payload)
            except Exception:
                continue
            merged = obj
            try:
                ch = obj['choices'][0]
                if 'message' in ch and ch['message'].get('content'):
                    content_parts = [ch['message']['content']]
                elif 'delta' in ch and ch['delta'].get('content'):
                    content_parts.append(ch['delta']['content'])
                elif 'message' in ch and ch['message'].get('reasoning_content'):
                    content_parts = [ch['message']['reasoning_content']]
                elif 'delta' in ch and ch['delta'].get('reasoning_content'):
                    content_parts.append(ch['delta']['reasoning_content'])
            except Exception:
                pass
        if merged is None:
            data = raw.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if content_parts:
            try:
                orig_msg = merged['choices'][0].get('message') or {}
                new_msg = {'role': 'assistant', 'content': ''.join(content_parts)}
                if orig_msg.get('content') and orig_msg.get('reasoning_content'):
                    new_msg['reasoning_content'] = orig_msg['reasoning_content']
                if orig_msg.get('tool_calls'):
                    new_msg['tool_calls'] = orig_msg['tool_calls']
                merged['choices'][0]['message'] = new_msg
                merged['choices'][0].pop('delta', None)
                merged['choices'][0]['finish_reason'] = (
                    merged['choices'][0].get('finish_reason') or 'stop')
            except Exception:
                pass
        else:
            try:
                if merged.get('choices'):
                    merged['choices'][0]['finish_reason'] = (
                        merged['choices'][0].get('finish_reason') or 'stop')
            except Exception:
                pass
        data = json.dumps(merged).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def _single_instance():
    if fcntl is None:
        return None
    handle = open(LOCK_PATH, 'a+')
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        raise SystemExit('another codearts-proxy-aksk instance is already running')
    return handle


if __name__ == '__main__':
    lock = _single_instance()
    srv = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    print(f'codearts-proxy-aksk listening on {LISTEN_HOST}:{LISTEN_PORT} '
          f'model={MODEL} accounts={len(ACCOUNTS)} '
          f'window={MAX_PER_WINDOW}/{WINDOW:.0f}s', flush=True)
    srv.serve_forever()