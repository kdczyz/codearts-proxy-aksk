#!/usr/bin/env python3
"""Test every model in /home/ubuntu/snap_models.json via the local ARM proxy
(POST /v1/chat/completions, max_tokens 4, 'hi'). Also tests the dated
deepseek-v4.1-flash-1017 id. Prints model -> HTTP status + first content chars.
No credentials printed."""
import json
import urllib.request
import urllib.error

KEY = open('/home/ubuntu/codearts-proxy-aksk.env').read().split('=', 1)[1].strip()
MODELS = json.load(open('/home/ubuntu/snap_models.json'))
IDS = [m['id'] for m in MODELS]
if 'deepseek-v4.1-flash-1017' not in IDS:
    IDS.append('deepseek-v4.1-flash-1017')


def test(mid):
    body = json.dumps({
        'model': mid,
        'messages': [{'role': 'user', 'content': 'hi'}],
        'max_tokens': 4,
    }).encode()
    req = urllib.request.Request(
        'http://127.0.0.1:18000/v1/chat/completions',
        data=body,
        headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + KEY},
        method='POST')
    try:
        resp = urllib.request.urlopen(req, timeout=60)
        data = json.loads(resp.read().decode())
        ch = data.get('choices', [{}])[0]
        msg = ch.get('message', {})
        content = msg.get('content', '') or msg.get('reasoning_content', '') or ''
        return resp.status, content[:60].replace('\n', ' ')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:120]
    except Exception as e:
        return 0, str(e)[:120]


for mid in IDS:
    status, info = test(mid)
    print(f'{mid}: HTTP {status} | {info}')
