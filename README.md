# Guard Agent — NEAR Hackathon: Build Beyond Boundaries

## Problem
An AI agent that can move money across chains is useful and dangerous in
equal measure. Today, giving an agent a private key means it can sign
anything, to anyone, for any amount. One bad prompt, one compromised
instruction, and the funds are gone.

## Solution
A guard agent built on NEAR Chain Signatures. One NEAR account controls
a derived address on another chain (Bitcoin testnet for this demo), but
the agent itself never holds a private key. Every signing request must
pass three guards before the NEAR MPC signer is even asked:

1. **Allowlist** — the destination address must be on an explicit list
   the owner set. Anything else is refused, no matter what the agent
   was told to do.
2. **Limit** — a per-transaction cap and a daily cap. Over either cap,
   the request is refused.
3. **Approval** — amounts above a small threshold need a human approval
   flag. Without it, the request waits, it does not sign.

If any guard fails, nothing is signed and the refusal is logged with
the reason. That log is the demo's point: you can see the agent being
told to do something bad, and the guard stopping it.

## Tracks
AI Security & Defense (primary), Agent Economy (secondary).

## Tools used
NEAR Chain Signatures (MPC signer: testnet `v1.signer-prod.testnet`),
NEAR testnet account, Bitcoin testnet derived address. No mainnet, no
real funds, no real private keys in this prototype.

## Try it (2 minutes, no keys, no funds)
```
python3 src/demo.py
```
It fetches the live MPC key from NEAR testnet, derives the demo's
Bitcoin testnet address, then runs three signing requests:
1. 10,000 sats to the allowlisted address — `APPROVED`, and it prints
   the exact sign request + near-CLI command to get the MPC signature
   (run it with your own testnet account; nothing is signed here).
2. 150,000 sats — `REFUSED: per-transaction cap exceeded`, nothing signed.
3. 60,000 sats — `REFUSED: human approval required`, held, not signed;
   with a human approval flag it is `APPROVED`. No network? The guard
   decisions still run offline and the same command is printed.

Files: `src/guard.py` (policy + tests), `src/testnet.py` (testnet
wiring: MPC key, derived address, sign request), `src/demo.py`
(the three-case demo). Standard library only — `python3`, no installs.

## Status
Guard demo complete 2026-11-09 and verified live against testnet:
guard tests pass, demo runs end-to-end (derived address
`tb1q232pr7elx6n95550852ra9c2cq3hzxsy47wd90`, 0 sats, 0 txs).
Honest limit: no live MPC signature — signing needs the operator's
own funded testnet account, and the demo address is unfunded, so the
payload is the SHA-256 of the spend intent (a live spend substitutes
the BIP-143 sighash; the sign request shape is identical). Repo is
public. Submission still needs Origo's own X demo post and a NEAR
account address — those are his steps, not APEX's.

## Deadline
Repo public + submission by 14 Nov 2026, 23:59 UTC. Judging 16–18 Nov.
