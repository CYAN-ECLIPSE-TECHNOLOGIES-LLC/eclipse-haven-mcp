#!/usr/bin/env python3
"""End-to-end stdio smoke for Eclipse Haven v0.1 (C0).

Temp state. Drives initialize -> auth_status (OAuth only) ->
token-auth refusal -> ticket_search -> ticket_get (injection
quarantined, visibility preserved) -> reply_draft -> reply_send
without token (DENY) -> reply_send with bound token -> receipt_list
(chain valid, no content).
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).parent


def rpc(proc, rid, method, params=None):
    req = {"jsonrpc": "2.0", "id": rid, "method": method,
           "params": params or {}}
    proc.stdin.write(json.dumps(req) + "\n")
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())


def call(proc, rid, name, args):
    response = rpc(proc, rid, "tools/call",
                   {"name": name, "arguments": args})
    return json.loads(response["result"]["content"][0]["text"])


def main():
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(os.environ)
        env["ECLIPSE_HAVEN_STATE"] = str(Path(tmp) / "state.json")
        proc = subprocess.Popen(
            [sys.executable, str(HERE / "server.py")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
            cwd=str(HERE), env=env)
        try:
            init = rpc(proc, 1, "initialize",
                       {"protocolVersion": "2025-03-26"})
            assert init["result"]["serverInfo"]["name"] == "eclipse-haven"
            print("initialize OK")
            status = call(proc, 2, "auth_status", {})
            assert status["mode"] == "oauth2"
            assert status["token_auth"] == "not_implemented"
            print("auth_status OK: OAuth2 only, token auth not "
                  "implemented (sunset 2027-04-30)")
            refused = call(proc, 3, "ticket_get", {
                "ticket_id": 9001,
                "auth": {"type": "api_token", "token": "deadbeef"}})
            assert "TOKEN_AUTH_NOT_IMPLEMENTED" in refused["error"]
            print("api_token presentation refused by name OK")
            found = call(proc, 4, "ticket_search", {"status": "open"})
            assert found["count"] == 1
            view = call(proc, 5, "ticket_get", {"ticket_id": 9001})
            assert view["quarantined_comment_ids"] == ["c2"], view
            vis = {c["comment_id"]: c["visibility"]
                   for c in view["conversation"]}
            assert vis["c3"] == "internal_note"
            assert view["requester"]["email"] == "***@acme.example"
            print("ticket_get OK: c2 quarantined, internal note "
                  "distinct, requester masked")
            draft = call(proc, 6, "reply_draft",
                         {"ticket_id": 9001})["draft"]
            assert "MISSING_FACT" in draft["body"]
            assert "refund" not in draft["body"].lower()
            print("reply_draft OK: record facts only, no resolution "
                  "invented")
            denied = call(proc, 7, "reply_send", {
                "draft_id": draft["draft_id"], "approval_token": "x"})
            assert "APPROVAL_REQUIRED" in denied["error"]
            print("reply_send without token DENIED OK")
            token = f"approve-send-{draft['draft_id']}-" \
                    f"{draft['content_hash'][:12]}"
            sent = call(proc, 8, "reply_send", {
                "draft_id": draft["draft_id"],
                "approval_token": token})
            assert sent["sent"] is True
            print("reply_send with bound token OK -> fixture comment",
                  sent["comment_id"])
            receipts = call(proc, 9, "receipt_list", {})
            assert receipts["chain_valid"]
            blob = json.dumps(receipts)
            assert "maya.chen@acme.example" not in blob
            assert "Invoice export fails" not in blob
            types = [r["type"] for r in receipts["receipts"]]
            assert "reply_send_denied" in types
            print("receipt_list OK: chain valid; DENY receipted;",
                  receipts["count"], "receipts, zero content")
            print("SMOKE PASS")
        finally:
            proc.terminate()


if __name__ == "__main__":
    main()
