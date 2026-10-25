#!/usr/bin/env python3
"""Eclipse Haven MCP — v0.1.0, phase C0 (Zendesk BUILD adapter,
fixtures).

Powered by Cyan Eclipse Technologies (cetech.ai).

Descriptor (family spec, eclipse-customer-family-spec-20261025): the
Eclipse customer adapter family — one canonical Customer Graph becomes
governed reads, internal writes, and owner-approved drafts and sends
across the popular CRM and customer-service platforms, according to
what each platform actually sanctions. Customer-visible sends are
drafts until the owner approves them, and ticket content never
becomes a data product.

Haven is the family's flagship BUILD (spec section 12): Zendesk is
the largest installed base in the support wing and ships NO official
MCP server. Haven is an Eclipse MCP server over Zendesk's public
REST API v2 shape — built OAuth-first from the first commit:

  * API TOKENS ARE A DYING CREDENTIAL. Zendesk's published sunset:
    unused tokens auto-deleted from 2026-07-28, new token creation
    blocked 2026-10-27 [verify per instance], ALL API tokens stop
    working 2027-04-30. Token auth is therefore NOT IMPLEMENTED in
    Haven — not even as a fallback. A fallback to a credential with
    a published death date is migration debt disguised as
    compatibility. The auth surface is OAuth-shaped only
    (authorization code for user-acting flows, client credentials
    for service flows). Any caller presenting an API token is
    refused by name. A static test asserts the refusal is the only
    place a token code path exists.

Tier mapping (spec 12.3): search/get/list -> T0; ticket create,
internal notes, tags, internal fields -> T1; public reply SEND,
status solve/close, assignee change -> T2 behind an approval token
bound to the ticket + the exact change/draft hash; delete, ticket
merge, bulk, macro/trigger edits -> PROHIBITED in v1 (denylist).

Visibility is never flattened (VISIBILITY_GAP, spec 5.4): public
replies and internal notes are distinct message classes end to end.

Injection posture (spec 12.4): requester-authored text is untrusted
data. Instruction-shaped comments are quarantined at read/draft time
— flagged, reported, never obeyed, never a fact source (Herald
Security Law #1, bench-tested in C0 fixtures).

C0 SCOPE: fixtures shaped like Zendesk REST API v2 responses
(fixtures/zendesk.json), loaded into local state; mutations apply
to the local fixture state only. NO Zendesk instance is contacted,
no credential exists, nothing is sent anywhere real. Synthetic data
only. Live connection is C1, owner-account-gated.

Transport: MCP over stdio (newline-delimited JSON-RPC 2.0), stdlib only.
State: $ECLIPSE_HAVEN_STATE or ./data/state.json beside this file.
"""
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).parent
STATE_PATH = Path(os.environ.get(
    "ECLIPSE_HAVEN_STATE", HERE / "data" / "state.json"))
FIXTURES_PATH = HERE / "fixtures" / "zendesk.json"

STATUS_CLASS = {"new": "open", "open": "open", "pending": "waiting",
                "hold": "on_hold", "solved": "resolved",
                "closed": "closed"}

INJECTION_MARKERS = (
    "ignore your instructions", "ignore previous instructions",
    "ignore all instructions", "disregard your instructions",
    "you must refund", "refund my", "refund me", "forward this",
    "send this thread", "reveal your system", "system prompt",
)

# Change keys that stay inside the house (T1) vs keys a customer can
# see change (T2, approval-gated) — spec 12.3.
INTERNAL_CHANGE_KEYS = {"tags", "internal_fields", "internal_note"}
VISIBLE_CHANGE_KEYS = {"status", "assignee_id", "priority_public_note"}


class ToolError(Exception):
    pass


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


# ------------------------------------------------------------------- state
def empty_state() -> dict:
    fixtures = json.loads(FIXTURES_PATH.read_text())
    return {"platform": fixtures, "drafts": {}, "receipts": [],
            "sent": []}


def load_state() -> dict:
    if STATE_PATH.exists():
        return json.loads(STATE_PATH.read_text())
    return empty_state()


def save_state(state: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, indent=1))


# ---------------------------------------------------------------- receipts
def emit_receipt(state: dict, rtype: str, detail: dict) -> dict:
    """Append-only, hash-chained; IDs + hashes + verdicts only."""
    prev = state["receipts"][-1]["hash"] if state["receipts"] else "GENESIS"
    entry = {"seq": len(state["receipts"]) + 1, "ts": int(time.time()),
             "type": rtype, "prev_hash": prev, "detail": detail}
    entry["hash"] = sha(prev + canon(
        {k: v for k, v in entry.items() if k != "hash"}))
    state["receipts"].append(entry)
    return entry


def verify_receipt_chain(receipts) -> bool:
    prev = "GENESIS"
    for entry in receipts:
        if entry.get("prev_hash") != prev:
            return False
        expected = sha(prev + canon(
            {k: v for k, v in entry.items() if k != "hash"}))
        if entry.get("hash") != expected:
            return False
        prev = entry["hash"]
    return True


# -------------------------------------------------------------------- auth
def check_auth(args) -> None:
    """OAuth-shaped auth only. An API token presented anywhere is
    refused by name — token auth is not implemented (spec 12.2)."""
    auth = args.get("auth")
    if auth is None:
        return
    atype = str(auth.get("type") or "").lower()
    if atype in ("api_token", "token", "basic"):
        raise ToolError(
            "TOKEN_AUTH_NOT_IMPLEMENTED: Haven is OAuth-first by "
            "construction. Zendesk API tokens stop working "
            "2027-04-30 (sunset published by Zendesk); token auth "
            "is not implemented, not even as a fallback (spec 12.2). "
            "Use an OAuth authorization-code or client-credentials "
            "grant.")
    if atype not in ("oauth2", "oauth"):
        raise ToolError(f"unknown auth type '{atype}' "
                        f"(oauth2 is the only implemented shape)")


def t_auth_status(state, args):
    check_auth(args)
    return {"mode": "oauth2",
            "flows": ["authorization_code", "client_credentials"],
            "scopes_shape": ["tickets:read", "tickets:write",
                             "users:read", "organizations:read"],
            "token_auth": "not_implemented",
            "token_auth_reason": "Zendesk API-token sunset: all "
                                 "tokens stop 2027-04-30 (spec 12.2)",
            "live_credentials_in_c0": False}


# ----------------------------------------------------------------- masking
def mask_email(value, surface):
    if not isinstance(value, str):
        return value
    if surface == "owner":
        return value
    local, _, domain = value.partition("@")
    return f"***@{domain}" if domain else "***"


def mask_phone(value):
    if not value:
        return value
    digits = "".join(ch for ch in str(value) if ch.isdigit())
    return f"***{digits[-2:]}" if len(digits) >= 2 else "***"


def user_view(state, user, surface):
    if user is None:
        return None
    return {"id": user["id"], "name": user["name"],
            "email": mask_email(user.get("email"), surface),
            "phone": mask_phone(user.get("phone")),
            "role": user.get("role"),
            "organization_id": user.get("organization_id"),
            "time_zone": user.get("time_zone")}


def find_user(state, user_id):
    for user in state["platform"]["users"]:
        if user["id"] == user_id:
            return user
    return None


def find_ticket(state, ticket_id):
    for ticket in state["platform"]["tickets"]:
        if str(ticket["id"]) == str(ticket_id):
            return ticket
    raise ToolError(f"unknown ticket: {ticket_id}")


def is_instruction_shaped(text) -> bool:
    if not isinstance(text, str):
        return False
    low = text.lower()
    return any(marker in low for marker in INJECTION_MARKERS)


def comment_view(state, ticket, comment):
    author = find_user(state, comment["author_id"])
    is_requester = author and author.get("role") == "end-user"
    quarantined = bool(is_requester
                       and is_instruction_shaped(comment.get("body")))
    return {"comment_id": comment["id"],
            "author_id": comment["author_id"],
            "author_role": author.get("role") if author else None,
            "visibility": "public_reply" if comment["public"]
                          else "internal_note",
            "trust": "untrusted_data" if is_requester else "trusted",
            "quarantined": quarantined,
            "body": comment["body"],
            "created_at": comment["created_at"]}


def ticket_view(state, ticket, surface, with_comments=False):
    view = {
        "ticket_id": f"ticket-zd-{ticket['id']}",
        "platform_ticket_id": ticket["id"],
        "subject": ticket["subject"],
        "status": ticket["status"],
        "status_class": STATUS_CLASS.get(ticket["status"],
                                         ticket["status"]),
        "priority": ticket["priority"],
        "requester": user_view(
            state, find_user(state, ticket["requester_id"]), surface),
        "assignee_id": ticket.get("assignee_id"),
        "organization_id": ticket.get("organization_id"),
        "tags": ticket.get("tags", []),
        "satisfaction_rating": ticket.get("satisfaction_rating"),
        "created_at": ticket["created_at"],
    }
    if with_comments:
        comments = state["platform"]["comments"].get(
            str(ticket["id"]), [])
        view["conversation"] = [comment_view(state, ticket, c)
                                for c in comments]
        view["quarantined_comment_ids"] = [
            c["comment_id"] for c in view["conversation"]
            if c["quarantined"]]
    return view


# ------------------------------------------------------------------- tools
def t_ticket_search(state, args):
    check_auth(args)
    surface = str(args.get("surface") or "analytic").lower()
    status = args.get("status")
    query = str(args.get("query") or "").lower()
    hits = []
    for ticket in state["platform"]["tickets"]:
        if status and ticket["status"] != status:
            continue
        if query and query not in ticket["subject"].lower() \
                and query not in " ".join(ticket.get("tags", [])):
            continue
        hits.append(ticket_view(state, ticket, surface))
    emit_receipt(state, "ticket_search", {
        "tier": 0, "hit_count": len(hits),
        "query_hash": sha(query) if query else None,
        "verdict": "ALLOW"})
    return {"tickets": hits, "count": len(hits), "surface": surface}


def t_ticket_get(state, args):
    check_auth(args)
    surface = str(args.get("surface") or "analytic").lower()
    ticket = find_ticket(state, args.get("ticket_id"))
    receipt = emit_receipt(state, "ticket_read", {
        "ticket_id": ticket["id"], "tier": 0, "surface": surface,
        "verdict": "ALLOW"})
    view = ticket_view(state, ticket, surface, with_comments=True)
    view["receipt_seq"] = receipt["seq"]
    return view


def t_user_get(state, args):
    check_auth(args)
    surface = str(args.get("surface") or "analytic").lower()
    user = find_user(state, args.get("user_id"))
    if not user:
        raise ToolError(f"unknown user: {args.get('user_id')}")
    emit_receipt(state, "user_read", {"user_id": user["id"],
                                      "tier": 0, "verdict": "ALLOW"})
    return user_view(state, user, surface)


def t_org_get(state, args):
    check_auth(args)
    for org in state["platform"]["organizations"]:
        if org["id"] == args.get("organization_id"):
            emit_receipt(state, "org_read", {
                "organization_id": org["id"], "tier": 0,
                "verdict": "ALLOW"})
            return dict(org)
    raise ToolError(
        f"unknown organization: {args.get('organization_id')}")


def t_ticket_create(state, args):
    check_auth(args)
    subject = str(args.get("subject") or "").strip()
    if not subject:
        raise ToolError("ticket_create requires a subject")
    requester = find_user(state, args.get("requester_id"))
    if not requester:
        raise ToolError("ticket_create requires a known requester_id")
    new_id = max(t["id"] for t in state["platform"]["tickets"]) + 1
    ticket = {"id": new_id, "subject": subject, "status": "new",
              "priority": args.get("priority") or "normal",
              "requester_id": requester["id"],
              "assignee_id": None,
              "organization_id": requester.get("organization_id"),
              "tags": args.get("tags") or [],
              "custom_fields": [], "satisfaction_rating": None,
              "created_at": now_iso()}
    state["platform"]["tickets"].append(ticket)
    state["platform"]["comments"][str(new_id)] = []
    if args.get("first_comment"):
        state["platform"]["comments"][str(new_id)].append({
            "id": f"c{new_id}00", "author_id": requester["id"],
            "body": str(args["first_comment"]), "public": True,
            "created_at": now_iso()})
    receipt = emit_receipt(state, "ticket_created", {
        "ticket_id": new_id, "tier": 1, "verdict": "ALLOW"})
    return {"ticket": ticket_view(state, ticket, "owner"),
            "receipt_seq": receipt["seq"]}


def update_token(ticket_id, changes):
    return f"approve-update-{ticket_id}-" \
           f"{sha(canon(changes))[:12]}"


def t_ticket_update(state, args):
    check_auth(args)
    ticket = find_ticket(state, args.get("ticket_id"))
    changes = args.get("changes")
    if not isinstance(changes, dict) or not changes:
        raise ToolError("ticket_update requires a non-empty changes map")
    unknown = set(changes) - INTERNAL_CHANGE_KEYS - VISIBLE_CHANGE_KEYS
    if unknown:
        raise ToolError(
            f"unclassified change keys refused: {sorted(unknown)} "
            f"(internal: {sorted(INTERNAL_CHANGE_KEYS)}; visible: "
            f"{sorted(VISIBLE_CHANGE_KEYS)})")
    visible = {k: v for k, v in changes.items()
               if k in VISIBLE_CHANGE_KEYS}
    if visible:
        expected = update_token(ticket["id"], changes)
        if str(args.get("approval_token") or "") != expected:
            emit_receipt(state, "ticket_update_denied", {
                "ticket_id": ticket["id"], "tier": 2,
                "reason": "APPROVAL_TOKEN_INVALID_OR_MISSING",
                "change_keys": sorted(changes), "verdict": "DENY"})
            raise ToolError(
                "APPROVAL_REQUIRED: customer-visible changes "
                f"(status/assignee) are T2; token must be "
                f"{expected} — bound to this ticket + exact change "
                f"hash (spec 6.3)")
    if "tags" in changes:
        ticket["tags"] = list(changes["tags"])
    if "internal_fields" in changes:
        ticket.setdefault("internal_fields", {}).update(
            changes["internal_fields"])
    if "internal_note" in changes:
        comments = state["platform"]["comments"].setdefault(
            str(ticket["id"]), [])
        comments.append({
            "id": f"n{len(comments) + 1}-{ticket['id']}",
            "author_id": ticket.get("assignee_id") or 3001,
            "body": str(changes["internal_note"]), "public": False,
            "created_at": now_iso()})
    if "status" in changes:
        if changes["status"] not in STATUS_CLASS:
            raise ToolError(f"unknown Zendesk status: "
                            f"{changes['status']}")
        ticket["status"] = changes["status"]
    if "assignee_id" in changes:
        ticket["assignee_id"] = changes["assignee_id"]
    receipt = emit_receipt(state, "ticket_updated", {
        "ticket_id": ticket["id"],
        "tier": 2 if visible else 1,
        "change_keys": sorted(changes),
        "changes_hash": sha(canon(changes)), "verdict": "ALLOW"})
    return {"ticket": ticket_view(state, ticket, "owner"),
            "receipt_seq": receipt["seq"]}


def t_reply_draft(state, args):
    check_auth(args)
    ticket = find_ticket(state, args.get("ticket_id"))
    requester = find_user(state, ticket["requester_id"])
    comments = state["platform"]["comments"].get(str(ticket["id"]), [])
    quarantined = [c["id"] for c in comments
                   if find_user(state, c["author_id"])
                   and find_user(state, c["author_id"]).get("role")
                   == "end-user"
                   and is_instruction_shaped(c.get("body"))]
    citations = [{"record": f"zendesk:ticket:{ticket['id']}",
                  "field": "subject"},
                 {"record": f"zendesk:ticket:{ticket['id']}",
                  "field": "status"}]
    lines = [f"Hello {requester['name'].split()[0]},"
             if requester else "Hello,",
             f"Thank you for contacting us about: "
             f"{ticket['subject']}.",
             f"Your ticket is currently recorded as: "
             f"{ticket['status']}."]
    resolution = (ticket.get("internal_fields") or {}).get("resolution")
    missing = []
    if resolution:
        lines.append(f"Recorded resolution: {resolution}")
        citations.append({"record": f"zendesk:ticket:{ticket['id']}",
                          "field": "internal_fields.resolution"})
    else:
        missing.append("resolution")
        lines.append("[MISSING_FACT: resolution — no resolution is "
                     "recorded on this ticket; no outcome is "
                     "asserted]")
    body = "\n".join(lines)
    draft_id = str(args.get("draft_id") or f"draft-{ticket['id']}")
    draft = {"draft_id": draft_id, "ticket_id": ticket["id"],
             "body": body, "content_hash": sha(body),
             "citations": citations, "missing_facts": missing,
             "quarantined_comment_ids": quarantined,
             "status": "draft", "created_at": now_iso()}
    state["drafts"][draft_id] = draft
    receipt = emit_receipt(state, "reply_drafted", {
        "draft_id": draft_id, "ticket_id": ticket["id"],
        "content_hash": draft["content_hash"], "tier": 1,
        "quarantined_comment_ids": quarantined, "verdict": "ALLOW"})
    return {"draft": draft, "receipt_seq": receipt["seq"]}


def send_token(draft):
    return f"approve-send-{draft['draft_id']}-" \
           f"{draft['content_hash'][:12]}"


def t_reply_send(state, args):
    """T2: the ONLY send-shaped tool. Requires the approval token
    bound to the draft id + the draft's CURRENT content hash — any
    re-draft (edit) moves the hash and kills prior tokens."""
    check_auth(args)
    draft = state["drafts"].get(str(args.get("draft_id")))
    if not draft:
        raise ToolError(f"unknown draft: {args.get('draft_id')}")
    if draft["status"] != "draft":
        raise ToolError(f"draft is {draft['status']}, not draft")
    expected = send_token(draft)
    if str(args.get("approval_token") or "") != expected:
        emit_receipt(state, "reply_send_denied", {
            "draft_id": draft["draft_id"], "ticket_id": draft["ticket_id"],
            "tier": 2, "reason": "APPROVAL_TOKEN_INVALID_OR_MISSING",
            "verdict": "DENY"})
        raise ToolError(
            "APPROVAL_REQUIRED: a customer-visible reply send is T2; "
            f"token must be {expected} — bound to this draft + its "
            f"exact content hash (spec 6.3). Drafts-only is the "
            f"default (spec 8.1).")
    ticket = find_ticket(state, draft["ticket_id"])
    comments = state["platform"]["comments"].setdefault(
        str(ticket["id"]), [])
    comment = {"id": f"s{len(comments) + 1}-{ticket['id']}",
               "author_id": ticket.get("assignee_id") or 3001,
               "body": draft["body"], "public": True,
               "created_at": now_iso()}
    comments.append(comment)
    draft["status"] = "sent"
    state["sent"].append({"draft_id": draft["draft_id"],
                          "ticket_id": ticket["id"],
                          "comment_id": comment["id"],
                          "content_hash": draft["content_hash"]})
    receipt = emit_receipt(state, "reply_sent", {
        "draft_id": draft["draft_id"], "ticket_id": ticket["id"],
        "comment_id": comment["id"],
        "content_hash": draft["content_hash"], "tier": 2,
        "verdict": "ALLOW"})
    return {"sent": True, "comment_id": comment["id"],
            "ticket_id": ticket["id"], "receipt_seq": receipt["seq"]}


def t_receipt_list(state, args):
    check_auth(args)
    limit = args.get("limit")
    receipts = state["receipts"]
    if limit is not None:
        receipts = receipts[-int(limit):]
    return {"receipts": receipts, "count": len(state["receipts"]),
            "chain_valid": verify_receipt_chain(state["receipts"])}


TOOLS = {
    "auth_status": (
        t_auth_status,
        "Show Haven's auth shape: OAuth2 only (authorization code + "
        "client credentials). API-token auth is NOT implemented — "
        "Zendesk tokens stop working 2027-04-30 (spec 12.2).",
        {"auth": {"type": "object"}}, []),
    "ticket_search": (
        t_ticket_search,
        "Search fixture tickets by status and/or subject/tag query. "
        "T0 read; requester emails masked unless surface=owner.",
        {"status": {"type": "string"}, "query": {"type": "string"},
         "surface": {"type": "string"},
         "auth": {"type": "object"}}, []),
    "ticket_get": (
        t_ticket_get,
        "Read one ticket with its conversation. Public replies and "
        "internal notes stay distinct visibility classes; "
        "requester-authored text is tagged untrusted and "
        "instruction-shaped comments are quarantined. T0.",
        {"ticket_id": {"type": "integer"},
         "surface": {"type": "string"},
         "auth": {"type": "object"}}, ["ticket_id"]),
    "user_get": (
        t_user_get,
        "Read one fixture user, masked per surface. T0.",
        {"user_id": {"type": "integer"},
         "surface": {"type": "string"},
         "auth": {"type": "object"}}, ["user_id"]),
    "org_get": (
        t_org_get,
        "Read one fixture organization. T0.",
        {"organization_id": {"type": "integer"},
         "auth": {"type": "object"}}, ["organization_id"]),
    "ticket_create": (
        t_ticket_create,
        "Create a ticket in the local fixture state. T1 — internal "
        "record creation; nothing is sent to any customer.",
        {"subject": {"type": "string"},
         "requester_id": {"type": "integer"},
         "priority": {"type": "string"},
         "tags": {"type": "array", "items": {"type": "string"}},
         "first_comment": {"type": "string"},
         "auth": {"type": "object"}}, ["subject", "requester_id"]),
    "ticket_update": (
        t_ticket_update,
        "Update a ticket. Internal keys (tags, internal_fields, "
        "internal_note) are T1. Customer-visible keys (status, "
        "assignee_id) are T2 and require an approval token bound "
        "to the ticket + exact changes hash. Unclassified keys are "
        "refused.",
        {"ticket_id": {"type": "integer"},
         "changes": {"type": "object"},
         "approval_token": {"type": "string"},
         "auth": {"type": "object"}}, ["ticket_id", "changes"]),
    "reply_draft": (
        t_reply_draft,
        "Draft a public reply from the ticket record only, with "
        "citations. Missing facts become MISSING_FACT markers. "
        "Sends nothing. T1.",
        {"ticket_id": {"type": "integer"},
         "draft_id": {"type": "string"},
         "auth": {"type": "object"}}, ["ticket_id"]),
    "reply_send": (
        t_reply_send,
        "Send a drafted reply (appends a public comment to the "
        "FIXTURE ticket). T2 — requires the approval token bound "
        "to the draft id + its current content hash; re-drafting "
        "invalidates prior tokens. There is no direct send path.",
        {"draft_id": {"type": "string"},
         "approval_token": {"type": "string"},
         "auth": {"type": "object"}},
        ["draft_id", "approval_token"]),
    "receipt_list": (
        t_receipt_list,
        "List the append-only, hash-chained receipts and verify the "
        "chain. Receipts carry IDs + hashes only — never content.",
        {"limit": {"type": "integer"},
         "auth": {"type": "object"}}, []),
}

# Capability denylist, stated in code (spec 6.2 + 8.5): no deletes,
# no platform merges, no bulk, no macro/trigger/automation edits,
# no refund actions, and NO token-auth or session route at any tier.
FORBIDDEN_TOOL_NAMES = {
    "ticket_delete", "ticket_merge", "bulk_update", "macro_edit",
    "macro_create", "trigger_edit", "automation_edit",
    "refund_issue", "refund_record", "token_connect",
    "api_token_connect", "session_login", "cookie_reuse",
    "scrape_tickets",
}


def tool_list():
    return [{"name": name, "description": description,
             "inputSchema": {"type": "object", "properties": props,
                             "required": required}}
            for name, (_, description, props, required) in TOOLS.items()]


def handle(req: dict):
    method, rid = req.get("method", ""), req.get("id")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": req.get("params", {}).get(
                "protocolVersion", "2025-03-26"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "eclipse-haven", "version": "0.1.0"}}}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": rid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid,
                "result": {"tools": tool_list()}}
    if method == "tools/call":
        name = req["params"]["name"]
        args = req["params"].get("arguments", {})
        if name in FORBIDDEN_TOOL_NAMES or name not in TOOLS:
            return {"jsonrpc": "2.0", "id": rid, "error": {
                "code": -32602,
                "message": f"unknown or v1-forbidden tool {name}"}}
        state = load_state()
        try:
            out = TOOLS[name][0](state, args)
            save_state(state)
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text",
                             "text": json.dumps(out, indent=1)}]}}
        except ToolError as exc:
            # Denials are receipts too (spec 7.4): persist the state
            # so the DENY entry survives. Denied tools raise before
            # any fixture mutation by construction.
            save_state(state)
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text",
                             "text": json.dumps({"error": str(exc)})}],
                "isError": True}}
    if rid is not None:
        return {"jsonrpc": "2.0", "id": rid, "error": {
            "code": -32601, "message": f"method not found: {method}"}}
    return None


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            response = handle(json.loads(line))
        except Exception as exc:  # never crash the transport
            response = {"jsonrpc": "2.0", "id": None, "error": {
                "code": -32603, "message": str(exc)}}
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
