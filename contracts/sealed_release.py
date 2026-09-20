# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""Sealed Release: a secret that opens only when a stated fact comes true.

A secret kept for a condition is a promise nobody can audit. "Release these
files if I am arrested." "Publish this exploit once the fix ships." "Send the
password to my family if I stop checking in." Today that promise lives in a
person, a lawyer, or a server, and every one of them can open it early, refuse
to open it, or simply be gone when the moment comes.

Sealed Release turns the promise into a contract that holds no secret and trusts
no one to watch the world. The author commits only the SHA-256 digest of the
secret, the condition in plain words, and the address of the page where the
condition would become true. The secret itself never touches the chain until it
is due.

Anyone may then call check. The contract fetches that page itself and puts one
question to a round of validators: reading this page, is the condition true now?
Only when they agree it is does the record turn releasable, and only then does a
reveal whose secret matches the committed digest succeed. The opening is gated by
a fact the author named in advance and a hash the contract verifies in code, so
neither the author nor the checker can force it early or hold it shut.

## What it is for

A composable release gate. Another contract reads status(id) or revealed(id) and
acts on it: an escrow that pays when the sealed brief is opened, a bounty that
settles when an embargoed advisory is published, a registry that unlocks records
on a verified event. The condition is judged from live evidence, not asserted by
a party to it.

## What it refuses

It never opens on silence. A page that cannot be read, or that does not speak to
the condition, is CANNOT_TELL, which changes nothing: an unreachable source is
not a met condition. It never opens on a guess: the reveal is checked against the
committed digest in deterministic code, so a wrong secret opens nothing and a
right one cannot be forged from the digest. And the author binds themselves, not
a passed-in name: the owner is the caller, and check is open to anybody, because
a gate only its author could trip would be a switch, not a condition.

## Where it stops, plainly

It judges what a page says, not whether the page tells the truth. A source the
author chose can be wrong or captured; a condition worded loosely can be read two
ways. Name a page a third party controls and a condition a stranger could check,
and say so to whoever relies on it. It also holds no money on this network: the
consequence it moves is the record's status, which a settlement contract layers
on top.
"""

from genlayer import *
import json
import hashlib

MET = "MET"
NOT_MET = "NOT_MET"
CANNOT_TELL = "CANNOT_TELL"
DECISIONS = (MET, NOT_MET, CANNOT_TELL)

SEALED = "SEALED"
RELEASABLE = "RELEASABLE"
REVEALED = "REVEALED"

MAX_CONDITION = 400
MAX_URL = 300
MAX_PAGE = 6000
MAX_REASON = 300
MAX_QUOTE = 300
MAX_SECRET = 2000

FETCH_FAILED = "__FETCH_FAILED__"


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _clip(text: str, limit: int) -> str:
    text = str(text).strip()
    return text if len(text) <= limit else text[:limit] + " [...]"


def _digest(value) -> str:
    # A SHA-256 digest, normalised: no 0x, lower case, exactly 64 hex characters.
    # The secret never arrives here, only this fingerprint of it.
    text = str(value).strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    if len(text) != 64:
        return ""
    for character in text:
        if character not in "0123456789abcdef":
            return ""
    return text


def _url_ok(url: str) -> bool:
    text = str(url).strip()
    if len(text) < 8 or len(text) > MAX_URL or " " in text:
        return False
    return text.startswith("https://") or text.startswith("http://")


def _field(raw: str, name: str, allowed, fallback: str) -> str:
    try:
        text = str(raw).strip()
        obj = json.loads(text[text.index("{"):text.rindex("}") + 1])
        if isinstance(obj, dict):
            said = str(obj.get(name, "")).strip().upper()
            return said if said in allowed else fallback
    except Exception:
        pass
    return fallback


def _text_field(raw: str, name: str, limit: int) -> str:
    try:
        text = str(raw).strip()
        obj = json.loads(text[text.index("{"):text.rindex("}") + 1])
        if isinstance(obj, dict):
            return _clip(str(obj.get(name, "")), limit)
    except Exception:
        pass
    return ""


def _task(condition: str, page: str) -> str:
    return f"""A sealed record may be opened only when one stated condition has become true.
Read the page below and decide whether it is true now.

THE CONDITION, in the words of whoever sealed the record:
{condition}

THE PAGE THEY NAMED AS THE PLACE IT WOULD BECOME TRUE:
{page}

Decide one of:
  {MET} the page plainly shows the condition is now true
  {NOT_MET} the page was read and the condition is not true in it
  {CANNOT_TELL} the page could not be read, or does not speak to the condition either way

Judge only what the page actually says. Do not assume, and do not treat an
unreachable or unrelated page as either true or false: that is {CANNOT_TELL}.
Opening a sealed record cannot be undone, so answer {MET} only when the page
leaves no reasonable doubt.

Reply with bare JSON and nothing else:
{{"decision": "{MET}" or "{NOT_MET}" or "{CANNOT_TELL}",
  "quote": "the sentence on the page that decided it, or empty",
  "reason": "one sentence naming what decided it"}}"""


class SealedRelease(gl.Contract):
    """Sealed records, each opened only by a fact its author named in advance."""

    # str(id) -> the record as JSON. Flat, because a storage collection cannot be
    # created in user code, so nothing nested is kept.
    items: TreeMap[str, str]
    # Append only, so the register can be listed in the order things were sealed.
    ids: DynArray[str]

    def __init__(self) -> None:
        pass

    @gl.public.write
    def seal(self, digest: str, condition: str, url: str) -> str:
        """Seal a secret behind a plain-language condition and the page that will show it true.

        The caller commits only the SHA-256 digest of the secret, never the secret
        itself. The owner is the caller. Anyone may later check the page; only when
        validators agree the condition is met does the record become releasable.
        """
        owner = gl.message.sender_address.as_hex.lower()
        fingerprint = _digest(digest)
        condition_text = _clip(condition, MAX_CONDITION)
        link = str(url).strip()
        if not fingerprint:
            return json.dumps({"ok": False,
                               "error": "digest must be a 64-character SHA-256 hex string"})
        if not condition_text:
            return json.dumps({"ok": False, "error": "give the condition in plain words"})
        if not _url_ok(link):
            return json.dumps({"ok": False,
                               "error": "give an http(s) URL the condition can be read at"})

        sid = str(len(self.ids))
        record = {
            "id": sid,
            "owner": owner,
            "created_at": _now_iso(),
            "condition": condition_text,
            "url": link,
            "algo": "sha256",
            "digest": fingerprint,
            "status": SEALED,
            "checks": 0,
            "decision": "",
            "reason": "",
            "quote": "",
            "released_at": "",
            "secret": "",
            "revealed_by": "",
            "revealed_at": "",
        }
        self.items[sid] = json.dumps(record)
        self.ids.append(sid)
        return json.dumps({"ok": True, "id": sid, "status": SEALED})

    @gl.public.write
    def check(self, seal_id: str) -> str:
        """Read the named page and, if the condition is met, make the record releasable.

        Open to anybody: a record only its author could open would be a switch, not
        a condition. The page is fetched by the contract itself inside the round, so
        no caller can pass in the answer.
        """
        sid = str(seal_id).strip()
        stored = self.items.get(sid, None)
        if stored is None:
            return json.dumps({"ok": False, "error": "no sealed record with that id"})
        record = json.loads(stored)
        if record["status"] != SEALED:
            return json.dumps({"ok": False,
                               "error": "this record is already " + record["status"].lower(),
                               "status": record["status"]})

        # Everything the round needs is copied into locals first. Nothing inside
        # the block reads self and nothing inside it raises: either would end the
        # whole transaction rather than the round, and a round that ends says
        # nothing about why.
        condition = record["condition"]
        url = record["url"]

        def look() -> str:
            page = ""
            try:
                got = gl.nondet.web.render(url)
                page = got if isinstance(got, str) else getattr(got, "body", "")
                if isinstance(page, (bytes, bytearray)):
                    page = page.decode("utf-8", "replace")
                page = _clip(str(page), MAX_PAGE)
            except Exception:
                page = FETCH_FAILED
            if not page or page == FETCH_FAILED:
                return json.dumps({"decision": CANNOT_TELL, "quote": "",
                                   "reason": "the page could not be read"})
            try:
                return str(gl.nondet.exec_prompt(_task(condition, page)))
            except Exception as error:
                return json.dumps({"decision": CANNOT_TELL, "quote": "",
                                   "reason": _clip("the prompt failed: " + str(error),
                                                   MAX_REASON)})

        raw = gl.eq_principle.prompt_comparative(
            look,
            principle=(
                f"Both answers must carry the same value in the field named decision, one of "
                f"{MET}, {NOT_MET} or {CANNOT_TELL}. That single field decides whether a sealed "
                "record becomes openable, so two readers differing on it are not wording a "
                "judgement differently, they disagree about whether the fact has happened. The "
                "quote and the reason are not compared, and the two readers will not have "
                "fetched byte-identical copies of the page."
            ),
        )

        decision = _field(raw, "decision", DECISIONS, "")
        if not decision:
            return json.dumps({"ok": False,
                               "error": "the round produced no decision this contract recognises",
                               "round_said": _clip(str(raw), 400)})

        record["checks"] = int(record.get("checks", 0)) + 1
        record["decision"] = decision
        record["reason"] = _text_field(raw, "reason", MAX_REASON)
        record["quote"] = _text_field(raw, "quote", MAX_QUOTE)
        if decision == MET:
            record["status"] = RELEASABLE
            record["released_at"] = _now_iso()
        self.items[sid] = json.dumps(record)
        return json.dumps({"ok": True, "id": sid, "decision": decision,
                           "status": record["status"], "reason": record["reason"]})

    @gl.public.write
    def reveal(self, seal_id: str, secret: str) -> str:
        """Open a releasable record by presenting the secret, checked against the sealed digest.

        Deterministic: the contract hashes the secret and compares it to the digest
        committed at seal time. A record that is not releasable, or a secret that
        does not match, changes nothing and takes nothing.
        """
        sid = str(seal_id).strip()
        stored = self.items.get(sid, None)
        if stored is None:
            return json.dumps({"ok": False, "error": "no sealed record with that id"})
        record = json.loads(stored)
        if record["status"] == REVEALED:
            return json.dumps({"ok": False, "error": "already revealed", "status": REVEALED})
        if record["status"] != RELEASABLE:
            return json.dumps({"ok": False,
                               "error": "not releasable yet; the condition has not been met",
                               "status": record["status"]})
        computed = hashlib.sha256(str(secret).encode("utf-8")).hexdigest()
        if computed != record["digest"]:
            return json.dumps({"ok": False,
                               "error": "the secret does not match the sealed digest"})

        record["status"] = REVEALED
        record["secret"] = _clip(str(secret), MAX_SECRET)
        record["revealed_by"] = gl.message.sender_address.as_hex.lower()
        record["revealed_at"] = _now_iso()
        self.items[sid] = json.dumps(record)
        return json.dumps({"ok": True, "id": sid, "status": REVEALED})

    # ------------------------------------------------------------------ reads

    @gl.public.view
    def status(self, seal_id: str) -> str:
        """The one field a downstream contract gates on, plus why it stands where it does."""
        sid = str(seal_id).strip()
        stored = self.items.get(sid, None)
        if stored is None:
            return json.dumps({"exists": False})
        record = json.loads(stored)
        return json.dumps({"exists": True, "id": sid, "status": record["status"],
                           "checks": record["checks"], "decision": record["decision"],
                           "reason": record["reason"]})

    @gl.public.view
    def get(self, seal_id: str) -> str:
        """The whole record. The secret is present only once the record is revealed."""
        sid = str(seal_id).strip()
        stored = self.items.get(sid, None)
        if stored is None:
            return json.dumps({"exists": False})
        return stored

    @gl.public.view
    def revealed(self, seal_id: str) -> str:
        """The opened secret, or empty while the record is still sealed or releasable."""
        sid = str(seal_id).strip()
        stored = self.items.get(sid, None)
        if stored is None:
            return json.dumps({"exists": False})
        record = json.loads(stored)
        opened = record["status"] == REVEALED
        return json.dumps({"exists": True, "id": sid, "revealed": opened,
                           "secret": record["secret"] if opened else ""})

    @gl.public.view
    def size(self) -> str:
        """How many records are sealed, releasable and revealed."""
        sealed = 0
        releasable = 0
        revealed = 0
        for position in range(len(self.ids)):
            record = json.loads(self.items[self.ids[position]])
            state = record["status"]
            if state == SEALED:
                sealed += 1
            elif state == RELEASABLE:
                releasable += 1
            elif state == REVEALED:
                revealed += 1
        return json.dumps({"total": len(self.ids), "sealed": sealed,
                           "releasable": releasable, "revealed": revealed})
