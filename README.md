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

Snap-access counts **one session per request**, and a session lingers on the
server for roughly **60 s** after the response ends. An AK/SK may have at most
**3 sessions** alive at once, so the real limit is **at most 3 live sessions
per AK/SK**, where a live session is a request in flight plus the ~60 s the
server keeps it after the response ends. Three short requests in the same
second already fill the account; the fourth gets `TM.00001041` (HTTP 400).

This is why a single chat window can look like it is "eating three sessions":
one agent turn often sends several requests (tool rounds, title generation,
retries), and each one counts. The proxy cannot change the server-side limit;
it can only stay inside it and queue politely.

What the proxy does:

- the default budget is 3 live sessions per account. A conversation is
  serialized, so one chat cannot take all three; set
  `PROXY_MAX_PER_WINDOW=2` to leave one slot for another client sharing the
  same AK/SK;
- one session lease per AK/SK: a request takes the lease *before* it is sent
  and keeps it until the response has been fully relayed. Only then does the
  lease start its `PROXY_WINDOW_SECONDS` (default 60) linger, matching the
  server-side TTL. A long streaming response therefore cannot be under-counted,
  and sequential calls, retries and parallel clients share the same budget;
- retries on `TM.00001041` go back through the window instead of slipping past
  it, so a retry can never silently become an extra session;
- a request that cannot get a slot within `PROXY_MAX_WAIT_SECONDS` (default 120)
  returns **HTTP 429** with `Retry-After` instead of hanging; set the client
  timeout above that value if you want the proxy to wait;
- each conversation is serialized (`PROXY_MAX_PER_SESSION=1`): a client that
  sends the main reply plus title/summary/suggestion requests cannot occupy
  several upstream sessions at once. The conversation key comes from
  `X-Session-Id`/`Chat-Id`/`Session-Id`, then body ids, then a hash of the
  first two messages;
- auxiliary requests (small `max_tokens`, or prompts mentioning title/summary/
  suggestion) are routed to `aux_accounts` when configured, so they never
  compete with the main conversation;
- queued requests are cancelled as soon as the client disconnects, and an
  in-flight upstream response is closed too, so the upstream stops generating
  and releases its session within ~200 ms;
- one proxy process per lock file; a second instance exits instead of quietly
  doubling the request rate against the same AK/SK.

### More throughput: multiple accounts

Each AK/SK adds its own 3/60 s window. `codearts-aksk.json` accepts either one
account or a list:

```json
{"accounts": [
  {"access_key_id": "AK1", "secret_access_key": "SK1"},
  {"access_key_id": "AK2", "secret_access_key": "SK2"}
]}
```

The proxy always sends through the account whose window frees up first. Two
accounts give 6 requests / 60 s; this is the only way to really raise
throughput.

`aux_accounts` is a separate pool for companion requests (title, summary,
suggestions). Put additional accounts there so the main conversation keeps the
primary account to itself:

```json
{
  "accounts": [
    {"access_key_id": "AK1", "secret_access_key": "SK1"}
  ],
  "aux_accounts": [
    {"access_key_id": "AK2", "secret_access_key": "SK2"}
  ]
}
```

### Tuning

| Variable | Default | Meaning |
|---|---|---|
| `PROXY_WINDOW_SECONDS` | `60` | linger after a response ends, per account |
| `PROXY_MAX_PER_WINDOW` | `3` | max live sessions per account (in flight + linger); set 2 to leave a slot for other clients |
| `PROXY_MAX_PER_SESSION` | `1` | max in-flight requests per conversation (`0` disables serialization) |
| `PROXY_MAX_WAIT_SECONDS` | `120` | max queue time before 429 (`0` = wait forever) |
| `PROXY_SESSION_RETRIES` | `0` | retries on `TM.00001041` (each retry costs a slot) |
| `PROXY_AUX_MAX_TOKENS` | `256` | `max_tokens` at or below this marks a request as auxiliary |
| `PROXY_AUX_KEYWORDS` | `title,summary,suggest,follow-up,标题,摘要,推荐,续写建议` | prompt keywords that mark a request as auxiliary |
| `PROXY_RETRY_DELAYS` | `5,15` | backoff before each retry |
| `PROXY_MAX_ACTIVE` | `64` | max concurrent client requests |
| `PROXY_UPSTREAM_TIMEOUT` | `300` | upstream read timeout in seconds |

These can go in `codearts-proxy-aksk.env` or in the systemd unit.

### Latency (time to first byte)

The proxy adds very little on its own:

- upstream TLS connections are kept alive in a small pool, so only the first
  request pays the handshake (typically 100-300 ms on a WAN);
- `TCP_NODELAY` is set on client sockets, avoiding Nagle delays on small SSE
  chunks;
- streaming uses `read1`, so the first token is forwarded as soon as it
  arrives instead of waiting for a 4 KiB buffer;
- SSE lines are forwarded verbatim, with no JSON re-encode;
- the upstream queue polls every 100 ms, so a freed lease is picked up quickly;
- a client disconnect closes the upstream socket, so a slow first token cannot
  keep a session alive after the user pressed stop.

If TTFB is still high, check in this order: `[queue]` lines in the log (waiting
for a session lease, fixed by more accounts), then `time_appconnect` from
`curl` (TLS), then the model itself (first token). A client that does not send
`stream: true` always waits for the full response.

### If TM.00001041 still appears

With the defaults the proxy cannot exceed the account by itself: one lease per
in-flight response plus a 60 s linger, a hard cap of 3 live sessions (one per
conversation thanks to serialization), and a lock that refuses a second
proxy process. If `TM.00001041` still shows up, the
same AK/SK is being used somewhere else: CodeArts IDE, the CLI, a leftover
proxy process, or the daily-claim cron.

```bash
pgrep -af codearts-proxy-aksk
journalctl -u codearts-proxy-aksk -f | grep -E "upstream-error|session-limit|queue"
```

Two knobs decide what the client sees while the account is busy:

- `PROXY_MAX_WAIT_SECONDS=0` — queue instead of returning 429 after 120 s;
- `PROXY_MAX_PER_SESSION=1` — keep companion requests from multiplying the
  conversation's upstream sessions;
- `aux_accounts` — move title/summary traffic to a second AK/SK;
- `PROXY_SESSION_RETRIES=1` plus a client timeout of 300 s or more — absorb a
  1041 caused by another client instead of surfacing it.

The client timeout must be larger than `PROXY_MAX_WAIT_SECONDS`; otherwise the
client disconnects first and the request looks "interrupted" while the proxy is
still queuing normally.

### Tests

`tests/test_proxy.py` starts a mock upstream and checks the invariant that
matters: never more than `PROXY_MAX_PER_WINDOW` sends per window, retries
re-enter the window, multiple accounts add up, disconnects drop queued work,
and a second instance is refused.

```bash
python3 -m unittest discover -s tests -v
```

## Reasoning / thinking

Huawei's models return `reasoning_content` alongside `content`. The proxy
keeps `reasoning_content` as its own field (streaming deltas and the
non-streaming message) so clients like DSH can show it as a separate
thinking block; it is never merged into `content`. The only exception is
the empty-content fallback: when a response has no `content` at all, the
reasoning text is used as the content to avoid a "no content" error.

## Daily benefit claimer (all campaigns)

`codearts-daily-claim.py` claims **every** claimable CodeArts benefit campaign
with the same permanent AK/SK — no OAuth login, no token renewal, no expiry.
Each run fetches all campaigns from the snap-access ops endpoint and claims
any that is `ELIGIBLE` + claimable: the daily sign-in (100 points, campaign
34), the new-user bonus (campaign 4), the student monthly bonus (5000
points/month, campaign 39), the student certification bonus (4000 points,
campaign 2), competition rewards, and anything new that shows up later.
Already-claimed campaigns are left alone.

It talks to the snap-access ops endpoints with the same SDK-HMAC-SHA256
signing as the proxy:

- `GET /v1/ops/delivery?channel=IDE` — list available benefit campaigns
- `POST /v1/ops/claim` — claim a campaign
- `POST /v1/ops/confirm` — confirm the claim

Note: the daily campaign id is **34** (not 1). An earlier auto-claim tool
(codearts2api) hardcoded campaign 1 for the daily sign-in, so it never
claimed it — only the new-user bonus (campaign 4). This script matches the
real ids and, more importantly, does not hardcode any id at all: it claims
whatever the delivery endpoint reports as eligible.

Run it by hand, or put it in cron (twice a day is harmless — an already
claimed day just reports "已领取" and does nothing):

```bash
python3 codearts-daily-claim.py
# cron: 30 0,12 * * * /usr/bin/python3 /path/to/codearts-daily-claim.py >> /path/to/codearts-daily-claim.log 2>&1
```

It reads the AK/SK from `codearts-aksk.json` (same file as the proxy).
Some campaigns need a qualification first (e.g. the student bonuses need
student certification on the Huawei account); those show as "未获得活动资格"
until the certification takes effect, and the script picks them up
automatically once they become eligible.

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
| `codearts-daily-claim.py` | Daily benefit claimer (all campaigns) via AK/SK |
| `codearts-aksk.json.example` | Credential template (placeholders only) |
| `codearts-proxy-aksk.env.example` | Local-key template (placeholders only) |

## Security

- `codearts-aksk.json` and `codearts-proxy-aksk.env` hold real secrets and are
  git-ignored. Only the `.example` templates are committed.
- Restrict the listening port: bind to `127.0.0.1` or firewall it to the hosts
  that may call it (e.g. only your gateway server).
