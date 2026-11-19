#!/usr/bin/env python3
"""codearts-proxy-aksk: OpenAI-compatible relay for Huawei snap-access.
Unlike the original codearts-proxy (which reads a rotating IAM token from a
file), this one signs every upstream request with the permanent AK/SK
(SDK-HMAC-SHA256). No token, no renewal, no expiry.

Listens on 127.0.0.1:18000. Client auth: Authorization: Bearer <LOCAL_API_KEY>
from /home/ubuntu/codearts-proxy-aksk.env (generated at deploy time).
Upstream: https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions
Model: deepseek-v4.1-flash-1017

Endpoints: POST /v1/chat/completions, POST /chat/completions,
GET /v1/models, GET /models, GET /healthz.
Streams SSE through chunk-by-chunk when the client asks stream:true.
"""
import hashlib
import hmac
import json
import os
import threading
import time
import urllib.request
import urllib.error
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

BASE = os.path.dirname(os.path.abspath(__file__))
AKSK_PATH = os.path.join(BASE, 'codearts-aksk.json')
ENV_PATH = os.path.join(BASE, 'codearts-proxy-aksk.env')
SNAP_URL = 'https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions'
MODEL = 'deepseek-v4.1-flash-1017'
LISTEN_HOST = os.environ.get('PROXY_HOST', '0.0.0.0')
LISTEN_PORT = int(os.environ.get('PROXY_PORT', '18000'))


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
LOCAL_API_KEY = ENV.get('LOCAL_API_KEY', '')
AKSK = json.load(open(AKSK_PATH))
AK = AKSK['access_key_id']
SK = AKSK['secret_access_key']


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
    out['X-Sdk-Date'] = sdk_date
    return out


# Upstream allows at most 3 concurrent sessions per AK/SK (TM.00001041).
# A session is identified by its Session-Id, and sessions linger after a
# request finishes, so rapid calls from any client sharing the account
# stack up and hit the cap even when each client only has one conversation
# open. Mitigations, all in this proxy:
#   1. Cap concurrent upstream calls at 2 (a semaphore): at most two
#      sessions in parallel, leaving 1 of the account's 3-session cap
#      (TM.00001041) free for other clients sharing the account
#      (CodeArts IDE, etc.). 1 session serialized everything and 503d
#      under any concurrency.
#   2. On TM.00001041, retry with a FRESH Session-Id and growing delay:
#      a fresh id can land in a slot freed since the last attempt, while
#      reusing a stuck id keeps failing. Up to 10 attempts (~60s total).
_SESSION_SLOTS = [{'id': uuid.uuid4().hex, 'busy': False} for _ in range(2)]
_SESSION_SEM = threading.Semaphore(2)
_SESSION_LOCK = threading.Lock()
SESSION_RETRIES = 5
SESSION_RETRY_DELAYS = [3, 3, 5, 5, 8]


def _acquire_slot():
    """Take a free slot (up to 30s). Raises TimeoutError if all slots busy."""
    if not _SESSION_SEM.acquire(timeout=30):
        raise TimeoutError('no free session slot within 30s')
    with _SESSION_LOCK:
        for slot in _SESSION_SLOTS:
            if not slot['busy']:
                slot['busy'] = True
                return slot
    # Semaphore guarantees a slot is free; unreachable.
    _SESSION_SEM.release()
    raise RuntimeError('no free session slot')


def _release_slot(slot):
    with _SESSION_LOCK:
        slot['busy'] = False
    _SESSION_SEM.release()


def call_upstream(upstream_body, timeout=60):
    """POST to snap-access with AK/SK signing + session headers.

    At most 3 upstream calls run concurrently (one per slot); a further
    call waits for a free slot instead of opening a 4th session. Retries
    on TM.00001041 (session limit) with a fresh Session-Id and growing
    delay. Returns (status, headers_dict, response). Raises on transport
    failure. Raises urllib.error.HTTPError for non-2xx that is not the
    session limit after retries are exhausted (caller reads the error
    body from it).
    """
    import sys
    last_err_body = None
    last_err_code = None
    slot = _acquire_slot()
    try:
        for attempt in range(SESSION_RETRIES):
            # Normal calls reuse the slot's stable id; retries mint a fresh
            # one so a stuck id does not keep failing while a freed slot
            # exists.
            session_id = slot['id'] if attempt == 0 else uuid.uuid4().hex
            headers = sign(AK, SK, 'POST', SNAP_URL, upstream_body)
            # Session headers are added AFTER signing (they do not take part
            # in the SDK-HMAC-SHA256 canonical request), matching the
            # reference client.
            headers['Chat-Id'] = uuid.uuid4().hex
            headers['Session-Id'] = session_id
            headers['lang'] = 'en'
            ureq = urllib.request.Request(SNAP_URL, data=upstream_body, headers=headers, method='POST')
            try:
                uresp = urllib.request.urlopen(ureq, timeout=timeout)
                return uresp.status, dict(uresp.headers), uresp
            except urllib.error.HTTPError as e:
                err_body = e.read()
                last_err_body = err_body
                last_err_code = e.code
                if b'TM.00001041' in err_body and attempt < SESSION_RETRIES - 1:
                    delay = SESSION_RETRY_DELAYS[attempt]
                    print(f'session limit hit (attempt {attempt + 1}), '
                          f'retrying with a fresh session in {delay}s',
                          file=sys.stderr, flush=True)
                    time.sleep(delay)
                    continue
                # Re-raise with the body preserved: build a fresh HTTPError
                # carrying the bytes we already read, so the caller can
                # forward it.
                raise urllib.error.HTTPError(e.url, e.code, e.msg, e.headers,
                                             _BodyReader(err_body))
    finally:
        _release_slot(slot)
    # Retries exhausted on the session limit: raise the last captured error.
    raise urllib.error.HTTPError(SNAP_URL, last_err_code or 400, 'session limit', {},
                                 _BodyReader(last_err_body or b''))


class _BodyReader:
    """Minimal file-like wrapper so an HTTPError can carry a pre-read body."""

    def __init__(self, data):
        self._data = data

    def read(self, *a, **k):
        return self._data

    def close(self):
        pass


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, fmt, *args):
        # keep logs quiet: only method + path + status, no bodies, no secrets
        import sys
        sys.stderr.write('%s %s\n' % (self.command, self.path))

    def _send_json(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _auth_ok(self):
        if not LOCAL_API_KEY:
            return True
        auth = self.headers.get('Authorization', '')
        return auth == 'Bearer ' + LOCAL_API_KEY

    def do_GET(self):
        if self.path in ('/v1/models', '/models'):
            models = []
            try:
                with open(os.path.join(BASE, 'snap_models.json')) as f:
                    for m in json.load(f):
                        models.append({'id': m['id'], 'object': 'model',
                                       'owned_by': 'codearts'})
            except Exception:
                models = [{'id': MODEL, 'object': 'model', 'owned_by': 'codearts'}]
            self._send_json(200, {'object': 'list', 'data': models})
        elif self.path in ('/healthz', '/health'):
            self._send_json(200, {'status': 'ok', 'model': MODEL, 'auth': 'aksk',
                                  'sessions': len(_SESSION_SLOTS),
                                  'max_concurrent': len(_SESSION_SLOTS)})
        else:
            self._send_json(404, {'error': 'not found'})

    def do_POST(self):
        if self.path not in ('/v1/chat/completions', '/chat/completions'):
            self._send_json(404, {'error': 'not found'})
            return
        if not self._auth_ok():
            self._send_json(401, {'error': {'message': 'invalid api key', 'type': 'auth'}})
            return
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        try:
            req = json.loads(body)
        except Exception:
            self._send_json(400, {'error': 'invalid json'})
            return
        # pass through the client's model; default to deepseek-v4.1-flash-1017
        # when none is given. Upstream supports several models (see
        # /home/ubuntu/snap_models.json); the proxy does not restrict them.
        req.setdefault('model', MODEL)
        upstream_body = json.dumps(req).encode()
        try:
            status, resp_headers, uresp = call_upstream(upstream_body)
        except TimeoutError:
            self._send_json(503, {'error': 'all upstream sessions busy, retry later'})
            return
        except urllib.error.HTTPError as e:
            err_body = e.read()
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
        is_stream = bool(req.get('stream'))
        if is_stream:
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'keep-alive')
            self.end_headers()
            saw_finish = False
            last_id = None
            last_model = None
            buf = b''
            try:
                while True:
                    chunk = uresp.read(4096)
                    if not chunk:
                        break
                    buf += chunk
                    # process complete lines; keep a trailing partial line buffered
                    while b'\n' in buf:
                        line, buf = buf.split(b'\n', 1)
                        line += b'\n'
                        stripped = line.decode('utf-8', 'replace').strip()
                        if stripped == 'data: [DONE]':
                            # hold [DONE]: inject finish_reason first if needed
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
                                        d = ch.get('delta') or {}
                                        # strip reasoning: MD must look like
                                        # any other model (content only)
                                        d.pop('reasoning_content', None)
                                    # rewrite the line with the patched object
                                    line = ('data: ' + json.dumps(obj, ensure_ascii=False) + '\n').encode()
                                except Exception:
                                    pass
                        try:
                            self.wfile.write(line)
                            self.wfile.flush()
                        except (BrokenPipeError, ConnectionResetError):
                            raise
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                try:
                    uresp.close()
                except Exception:
                    pass
            if not saw_finish:
                try:
                    final = {'choices': [{'delta': {}, 'finish_reason': 'stop',
                                          'index': 0}],
                             'created': int(time.time()),
                             'id': last_id or ('as-' + uuid.uuid4().hex[:12]),
                             'model': last_model or MODEL,
                             'object': 'chat.completion.chunk'}
                    self.wfile.write(('data: ' + json.dumps(final) + '\n\n').encode())
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass
            try:
                self.wfile.write(b'data: [DONE]\n\n')
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        else:
            # Upstream returns SSE even for non-streaming requests: one or
            # more "data: {...}" lines. Collapse them into a single JSON object.
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
                # not SSE at all; return the raw body as-is
                data = raw.encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            if content_parts:
                try:
                    _orig_msg = merged['choices'][0].get('message') or {}
                    _new_msg = {
                        'role': 'assistant',
                        'content': ''.join(content_parts),
                    }
                    # reasoning_content is stripped: MD looks like any
                    # other model (content only, no thinking field)
                    # keep tool_calls: a model may return both content and
                    # tool calls; dropping them breaks function calling.
                    if _orig_msg.get('tool_calls'):
                        _new_msg['tool_calls'] = _orig_msg['tool_calls']
                    merged['choices'][0]['message'] = _new_msg
                    merged['choices'][0].pop('delta', None)
                    merged['choices'][0]['finish_reason'] = (
                        merged['choices'][0].get('finish_reason') or 'stop')
                except Exception:
                    pass
            else:
                # upstream gave no content: still attach a finish_reason
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


if __name__ == '__main__':
    srv = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    print(f'codearts-proxy-aksk listening on {LISTEN_HOST}:{LISTEN_PORT} model={MODEL}', flush=True)
    srv.serve_forever()
