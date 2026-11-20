#!/usr/bin/env python3
"""Claim CodeArts daily sign-in (campaign 1) + new-user (campaign 4) via AK/SK.

Replicates codearts2api's check-in flow against snap-access, but signs with the
permanent IAM AK/SK from /home/ubuntu/codearts-aksk.json instead of the OAuth
token (codearts2api was deleted). Endpoints:
  GET  /v1/ops/delivery?channel=IDE
  POST /v1/ops/claim   {campaignId, channel, idempotentKey}
  POST /v1/ops/confirm {campaignId}
Signing: SDK-HMAC-SHA256 over ALL request headers (same as codearts2api).
"""
import hashlib
import hmac
import json
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from urllib.parse import urlparse, quote, parse_qsl

SNAP = "https://snap-access.cn-north-4.myhuaweicloud.com"
AKSK_PATH = "/home/ubuntu/codearts-aksk.json"


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def canon_uri(path: str) -> str:
    segs = [quote(s, safe="") for s in path.split("/")]
    out = "/".join(segs)
    if not out.endswith("/"):
        out += "/"
    return out


def canon_query(raw: str) -> str:
    if not raw:
        return ""
    pairs = parse_qsl(raw, keep_blank_values=True)
    pairs.sort(key=lambda kv: (kv[0], kv[1]))
    return "&".join(f"{quote(k, safe='')}={quote(v, safe='')}" for k, v in pairs)


def sign(ak: str, sk: str, method: str, url: str, body: bytes):
    u = urlparse(url)
    now = datetime.now(timezone.utc)
    sdk_date = now.strftime("%Y%m%dT%H%M%SZ")
    payload_hash = sha256_hex(body)
    headers = {
        "agent-type": "PromptCenter",
        "content-type": "application/json",
        "host": u.netloc,
        "x-language": "zh-cn",
        "x-sdk-content-sha256": payload_hash,
        "x-sdk-date": sdk_date,
    }
    signed = ";".join(sorted(headers.keys()))
    canon_headers = "".join(f"{k}:{headers[k].strip()}\n" for k in sorted(headers.keys()))
    canon_req = "\n".join([method, canon_uri(u.path), canon_query(u.query),
                           canon_headers, signed, payload_hash])
    string_to_sign = "\n".join(["SDK-HMAC-SHA256", sdk_date,
                                sha256_hex(canon_req.encode())])
    sig = hmac.new(sk.encode(), string_to_sign.encode(), hashlib.sha256).hexdigest()
    out = {k: v for k, v in headers.items()}
    out["Authorization"] = (f"SDK-HMAC-SHA256 Access={ak}, "
                            f"SignedHeaders={signed}, Signature={sig}")
    out["X-Sdk-Date"] = sdk_date
    out["X-Sdk-Content-Sha256"] = payload_hash
    out["Agent-Type"] = "PromptCenter"
    out["X-Language"] = "zh-cn"
    out["Content-Type"] = "application/json"
    return out


def call(ak: str, sk: str, method: str, path: str, body_obj=None):
    body = json.dumps(body_obj).encode() if body_obj is not None else b""
    url = SNAP + path
    hdrs = sign(ak, sk, method, url, body)
    req = urllib.request.Request(url, data=body if method != "GET" else None,
                                 headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        return -1, str(e)


def main():
    with open(AKSK_PATH) as f:
        cred = json.load(f)
    ak = cred["access_key_id"]
    sk = cred["secret_access_key"]

    status, text = call(ak, sk, "GET", "/v1/ops/delivery?channel=IDE")
    print(f"delivery http={status}")
    if status != 200:
        print("body:", text[:400])
        sys.exit(1)
    env = json.loads(text)
    if env.get("code") != 0:
        print("business code:", env.get("code"), env.get("message"))
        sys.exit(1)
    items = (env.get("data") or {}).get("items") or []
    print(f"campaigns: {len(items)}")
    for c in items:
        print(f"  id={c.get("campaignId")} title={c.get('title')} status={c.get('status')} "
              f"claimable={c.get('claimable')} amount={c.get('benefitAmount')} "
              f"pending={c.get('pendingTotalAmount')}")

    now_ms = int(time.time() * 1000)
    for c in items:
        cid = c.get("campaignId")
        if cid not in (34, 4):
            continue
        if c.get("benefitUnit") not in ("", "CREDIT"):
            continue
        st = (c.get("status") or "").strip()
        title = c.get("title") or f"活动 {cid}"
        if st in ("CONFIRMED", "CONSUMED"):
            print(f"[{title}] 已领取")
            continue
        if st == "CLAIMED":
            pass  # fall through to confirm
        elif st == "ELIGIBLE":
            if not c.get("claimable"):
                print(f"[{title}] 暂不可领取，稍后重试")
                continue
            s2, t2 = call(ak, sk, "POST", "/v1/ops/claim",
                          {"campaignId": cid, "channel": "IDE",
                           "idempotentKey": f"claim_{cid}_{now_ms}"})
            print(f"[{title}] claim http={s2} {t2[:200]}")
            if s2 != 200:
                continue
        elif st == "":
            print(f"[{title}] 未获得活动资格")
            continue
        else:
            print(f"[{title}] 未知状态: {st}")
            continue
        s3, t3 = call(ak, sk, "POST", "/v1/ops/confirm", {"campaignId": cid})
        print(f"[{title}] confirm http={s3} {t3[:200]}")


if __name__ == "__main__":
    main()
