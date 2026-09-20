# Sealed Release

**A secret that opens only when a stated fact comes true, judged from live evidence and verified by a hash.**

A secret kept for a condition is a promise nobody can audit. *Release these files if I am arrested. Publish this exploit once the fix ships. Send the password to my family if I stop checking in.* Today that promise lives in a person, a lawyer, or a server, and every one of them can open it early, refuse to open it, or be gone when the moment comes.

Sealed Release turns the promise into a contract that holds no secret and trusts no one to watch the world.

## How it works

1. **`seal(digest, condition, url)`** — the author commits only the **SHA-256 digest** of the secret (never the secret), the **condition** in plain words, and the **URL** of the page where it would become true. The owner is bound to the caller. Status: `SEALED`.
2. **`check(id)`** — open to anybody. The contract **fetches the page itself** inside a validator round and asks one question: reading this page, is the condition true now? Validators agree on a single field, `MET` / `NOT_MET` / `CANNOT_TELL`. On `MET` the record turns `RELEASABLE`.
3. **`reveal(id, secret)`** — only works once `RELEASABLE`. The contract hashes the secret and compares it to the committed digest **in deterministic code**. A wrong secret opens nothing; a right one cannot be forged from the digest. Status: `REVEALED`.

Reads for composition: `status(id)`, `get(id)`, `revealed(id)`, `size()`.

## Why it needs GenLayer

The gate is a judgement about the real world (*has the advisory been published?*) that no ordinary contract can make, plus a hash check that no oracle is needed for. GenLayer validators fetch the page and reach consensus on the one categorical field that decides the opening; the reveal is pure deterministic verification on chain.

## What it refuses

- **Never opens on silence.** An unreachable or off-topic page is `CANNOT_TELL` and changes nothing.
- **Never opens on a guess.** The reveal is checked against the committed digest; the secret is never on chain until it is due.
- **Binds the author, not a passed-in name.** `owner` is `gl.message.sender_address`; `check` is open to anybody, because a gate only its author could trip is a switch, not a condition.

## What it is for

A composable release gate other contracts settle on: an escrow that pays when a sealed brief opens, a bounty that settles when an embargoed advisory is published, a registry that unlocks records on a verified event.

## Live

- **Contract (GenLayer Asimov):** `0x6776ece05607a55228E7fa3b5cbb661279c0D90B`
- Explorer: https://explorer-asimov.genlayer.com/address/0x6776ece05607a55228E7fa3b5cbb661279c0D90B

## Proven on Asimov

Two seals against two real evidence pages in this repo:
- `docs/advisory-2026-001-published.txt` states the advisory is published → `check` returns **MET** → the record becomes `RELEASABLE` → `reveal` with the matching secret succeeds.
- `docs/advisory-2026-002-embargoed.txt` states it is still embargoed → `check` returns **NOT_MET** → the record stays `SEALED` → `reveal` is refused.

See `results/proved.json` for the transcript.

## Try it

```
genlayer call 0x6776ece05607a55228E7fa3b5cbb661279c0D90B size
genlayer call 0x6776ece05607a55228E7fa3b5cbb661279c0D90B status --args '"0"'
```

## Where it stops, plainly

It judges what a page says, not whether the page tells the truth. A source the author chose can be wrong or captured, and a loosely worded condition can be read two ways. Name a page a third party controls and a condition a stranger could check. It also holds no native value on this network; the consequence it moves is the record's status, which a settlement contract layers on top.

## Licence

AGPL-3.0-or-later.
