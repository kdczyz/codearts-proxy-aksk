# codearts-proxy-aksk

OpenAI-compatible relay for Huawei Cloud **snap-access** (CodeArts) chat models,
signed with a permanent **AK/SK** (SDK-HMAC-SHA256). No IAM token, no renewal,
no expiry.

Upstream endpoint: `https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions`

## What it does

- `POST /v1/chat/completions` and `POST /chat/completions` — OpenAI-compatible
  chat completions, streaming and non-streaming. Upstream returns SSE even for
  non-streaming requests; the proxy collapses `data:` lines into one JSON object.
- `GET /v1/models` / `GET /models` — serves the model list from `snap_models.json`.
- `GET /healthz` — liveness check.
- Client auth: `Authorization: Bearer <LOCAL_API_KEY>` (a local key you choose;
  it only protects your own proxy, it is not a Huawei credential).

## Upstream session limit

Snap-access allows at most **3 concurrent sessions per AK/SK**. Exceeding it
returns `TM.00001041`. The proxy handles this by:

- capping concurrent upstream calls at 3 (a semaphore) with one session id per
  in-flight call; sequential calls reuse one slot, so a single conversation
  occupies exactly one slot;
- retrying on `TM.00001041` with a fresh session id and growing delays
  (up to 10 attempts, ~60 s total).

Sessions linger server-side for roughly 60 s after a burst, so a burst of more
than 3 parallel calls may still take a while to drain. That is a server-side
session TTL, not something the proxy can change. For more concurrency, use
additional Huawei accounts (each has its own 3 slots) and round-robin between
them.

## Setup

Python 3, standard library only — no dependencies.

```bash
# 1. Huawei credentials (create in the Huawei Cloud console: My Credentials >
#    Access Keys). Never commit the real file.
cp codearts-aksk.json.example codearts-aksk.json
# edit codearts-aksk.json with your own access_key_id / secret_access_key

# 2. Local client key (any random string; used as the Bearer token).
cp codearts-proxy-aksk.env.example codearts-proxy-aksk.env
# edit codearts-proxy-aksk.env: LOCAL_API_KEY=your-random-key

# 3. Run it
python3 codearts-proxy-aksk.py
# listens on 0.0.0.0:18000 by default; PROXY_HOST / PROXY_PORT override it
```

To run as a service (systemd), copy `codearts-proxy-aksk.service` to
`/etc/systemd/system/`, adjust the paths, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now codearts-proxy-aksk.service
```

## Files

| File | Purpose |
| --- | --- |
| `codearts-proxy-aksk.py` | The proxy (stdlib only) |
| `snap_models.json` | Model list served by `/v1/models` |
| `test_all_models.py` | Smoke-test every model via the local proxy |
| `codearts-proxy-aksk.service` | systemd unit |
| `codearts-aksk.json.example` | Credential template (placeholders only) |
| `codearts-proxy-aksk.env.example` | Local-key template (placeholders only) |

## Security

- `codearts-aksk.json` and `codearts-proxy-aksk.env` hold real secrets and are
  git-ignored. Only the `.example` templates are committed.
- Restrict the listening port: bind to `127.0.0.1` or firewall it to the hosts
  that may call it (e.g. only your gateway server).
