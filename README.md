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
returns `TM.00001041` (as HTTP 400). The proxy handles this by:

- capping concurrent upstream calls at 2 (a semaphore) with one stable
  session id per slot, leaving 1 slot free for other clients sharing the
  account (e.g. CodeArts IDE); sequential calls reuse one slot, so a
  single conversation occupies exactly one slot;
- retrying on `TM.00001041` by reusing the SAME session id with growing
  delays (5/10/15/20/30 s). Never minting a fresh id on retry: the server
  lingers sessions ~60 s, so a fresh id counts as an extra session and
  makes the limit worse.

Sessions linger server-side for roughly 60 s after a burst, so a burst of more
than 3 parallel calls may still take a while to drain. That is a server-side
session TTL, not something the proxy can change. For more concurrency, use
additional Huawei accounts (each has its own 3 slots) and round-robin between
them.

## Reasoning / thinking

Huawei's models return `reasoning_content` alongside `content`. The proxy
keeps `reasoning_content` as its own field (streaming deltas and the
non-streaming message) so clients like DSH can show it as a separate
thinking block; it is never merged into `content`. The only exception is
the empty-content fallback: when a response has no `content` at all, the
reasoning text is used as the content to avoid a "no content" error.

## Daily sign-in (100 points/day)

`codearts-daily-claim.py` claims the CodeArts daily sign-in (100 points,
campaign 34, "每日签到领100积分") plus the new-user bonus (campaign 4) using
the same permanent AK/SK — no OAuth login, no token renewal, no expiry.
It talks to the snap-access ops endpoints with the same SDK-HMAC-SHA256
signing as the proxy:

- `GET /v1/ops/delivery?channel=IDE` — list available benefit campaigns
- `POST /v1/ops/claim` — claim a campaign
- `POST /v1/ops/confirm` — confirm the claim

The daily campaign id is **34** (not 1). An earlier auto-claim tool
(codearts2api) hardcoded campaign 1 for the daily sign-in, so it never
claimed it — only the new-user bonus (campaign 4). This script matches the
real ids.

Run it by hand, or put it in cron (twice a day is harmless — an already
claimed day just reports "已领取" and does nothing):

```bash
python3 codearts-daily-claim.py
# cron: 30 0,12 * * * /usr/bin/python3 /path/to/codearts-daily-claim.py >> /path/to/codearts-daily-claim.log 2>&1
```

It reads the AK/SK from `codearts-aksk.json` (same file as the proxy).

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
| `codearts-daily-claim.py` | Daily sign-in claim (100 pts/day) via AK/SK |
| `codearts-aksk.json.example` | Credential template (placeholders only) |
| `codearts-proxy-aksk.env.example` | Local-key template (placeholders only) |

## Security

- `codearts-aksk.json` and `codearts-proxy-aksk.env` hold real secrets and are
  git-ignored. Only the `.example` templates are committed.
- Restrict the listening port: bind to `127.0.0.1` or firewall it to the hosts
  that may call it (e.g. only your gateway server).
