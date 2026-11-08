"""Guard demo: three signing requests — one allowed, one blocked, one held.

Usage: python3 src/demo.py

The guard decisions run offline. The testnet step is best-effort: when
the network is reachable it fetches the live MPC key, derives the
Bitcoin testnet address for the demo NEAR account, checks its balance,
and prints the exact near-CLI command the operator runs with their own
testnet account to get the signature. No keys, no funds — nothing is
signed by this script.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import testnet
from guard import GuardPolicy

# Demo policy: 100k sats per tx, 200k sats per day, human approval
# required above 50k sats.
PER_TX_CAP = 100_000
DAILY_CAP = 200_000
APPROVAL_THRESHOLD = 50_000

FALLBACK_ADDRESS = "tb1qguarddemoallowlisted"


def live_address():
    """Fetch the live derived Bitcoin testnet address, or None if the
    network is unreachable. Returns (address, balance_sats, tx_count)."""
    key = testnet.mpc_public_key()
    derived = testnet.derived_public_key(testnet.DEMO_ACCOUNT,
                                         testnet.DERIVATION_PATH)
    address = testnet.secp256k1_key_to_btc_testnet_address(derived)
    confirmed, _mempool, tx_count = testnet.btc_balance(address)
    print("testnet live: MPC root key %s..." % key[:24])
    print("testnet live: derived address %s" % address)
    print("testnet live: balance %d sats, %d txs" % (confirmed, tx_count))
    return address


def show_signing(address, amount):
    """Build the exact sign request + near-CLI command for an approved
    spend. Prints them; does not sign."""
    payload = testnet.demo_payload(address, amount,
                                   testnet.DEMO_ACCOUNT,
                                   testnet.DERIVATION_PATH)
    request = testnet.sign_request(payload)
    print("  payload (sha256 of spend intent): %s" % payload.hex())
    print("  sign request: %s" % request)
    print("  run with your own testnet account:")
    print("  %s" % testnet.near_cli_sign_command(testnet.DEMO_ACCOUNT,
                                                 request))


def main():
    print("== NEAR Guard Agent demo ==\n")
    try:
        address = live_address()
    except Exception as exc:  # offline: guard decisions still run
        print("testnet unreachable (%s) — guard decisions run offline" % exc)
        address = FALLBACK_ADDRESS

    policy = GuardPolicy(
        allowlist={address},
        per_tx_cap=PER_TX_CAP,
        daily_cap=DAILY_CAP,
        auto_approve_threshold=APPROVAL_THRESHOLD,
    )
    print("policy: allowlist={%s}, per-tx cap %d, daily cap %d, "
          "approval above %d sats\n" % (address, PER_TX_CAP, DAILY_CAP,
                                        APPROVAL_THRESHOLD))

    # (a) Small tx to the allowlisted address: ALLOWED.
    print("(a) 10,000 sats -> %s" % address)
    ok, reason = policy.approve(address, 10_000)
    print("  guard: %s (%s)" % ("APPROVED" if ok else "REFUSED", reason))
    if ok:
        show_signing(address, 10_000)

    # (b) Over-limit tx: BLOCKED by the per-transaction cap.
    print("\n(b) 150,000 sats -> %s" % address)
    ok, reason = policy.check(address, 150_000)
    print("  guard: %s (%s)" % ("APPROVED" if ok else "REFUSED", reason))
    print("  nothing signed — cap exceeded, request dropped.")

    # (c) Above-threshold tx: HELD for human approval, then released.
    print("\n(c) 60,000 sats -> %s" % address)
    ok, reason = policy.check(address, 60_000)
    print("  guard: %s (%s)" % ("APPROVED" if ok else "REFUSED", reason))
    print("  held: waiting for a human, not signed.")
    ok, reason = policy.approve(address, 60_000, human_approved=True)
    print("  human approved -> guard: %s (%s)"
          % ("APPROVED" if ok else "REFUSED", reason))
    if ok:
        show_signing(address, 60_000)

    print("\nspent today: %d / %d sats" % (policy.spent_today, DAILY_CAP))
    print("demo done: 1 allowed, 1 blocked, 1 held-then-approved.")


if __name__ == "__main__":
    main()
