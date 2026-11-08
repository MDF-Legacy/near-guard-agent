"""Guard policy for the NEAR Chain Signatures guard agent.

Pure logic, no chain calls, no keys, no funds. A signing request is
approved only if ALL three guards pass:
  1. destination is allowlisted
  2. amount is within the per-transaction cap
  3. amount is within the remaining daily cap, and if the amount is
     above the auto-approve threshold, a human approval flag is set.
Any failure returns a refusal with a reason, and nothing is signed.
"""

from dataclasses import dataclass, field


@dataclass
class GuardPolicy:
    allowlist: set
    per_tx_cap: int          # smallest unit, e.g. satoshis
    daily_cap: int
    auto_approve_threshold: int
    spent_today: int = 0

    def check(self, destination: str, amount: int, human_approved: bool = False):
        if destination not in self.allowlist:
            return False, "destination not allowlisted"
        if amount <= 0:
            return False, "amount must be positive"
        if amount > self.per_tx_cap:
            return False, "per-transaction cap exceeded"
        if self.spent_today + amount > self.daily_cap:
            return False, "daily cap exceeded"
        if amount > self.auto_approve_threshold and not human_approved:
            return False, "human approval required"
        return True, "approved"

    def approve(self, destination: str, amount: int, human_approved: bool = False):
        ok, reason = self.check(destination, amount, human_approved)
        if ok:
            self.spent_today += amount
        return ok, reason


def run_tests():
    p = GuardPolicy(
        allowlist={"tb1qallowlistedexample"},
        per_tx_cap=100_000,
        daily_cap=200_000,
        auto_approve_threshold=50_000,
    )
    cases = [
        # (destination, amount, approved, expected_ok, expected_reason_fragment)
        ("tb1qallowlistedexample", 10_000, False, True, "approved"),
        ("tb1qattacker", 10_000, False, False, "not allowlisted"),
        ("tb1qallowlistedexample", 150_000, False, False, "per-transaction"),
        ("tb1qallowlistedexample", 60_000, False, False, "human approval"),
        ("tb1qallowlistedexample", 60_000, True, True, "approved"),
        ("tb1qallowlistedexample", 0, False, False, "positive"),
    ]
    for dest, amt, appr, want_ok, want_frag in cases:
        ok, reason = p.check(dest, amt, appr)
        assert ok == want_ok, (dest, amt, ok, reason)
        assert want_frag in reason, (dest, amt, reason)
    # Daily cap: approve 100k, then 100k, then a further 1 should fail.
    p2 = GuardPolicy(
        allowlist={"tb1qallowlistedexample"},
        per_tx_cap=100_000,
        daily_cap=200_000,
        auto_approve_threshold=200_000,
    )
    assert p2.approve("tb1qallowlistedexample", 100_000)[0]
    assert p2.approve("tb1qallowlistedexample", 100_000)[0]
    ok, reason = p2.approve("tb1qallowlistedexample", 1)
    assert not ok and "daily cap" in reason, reason
    print("guard tests: all passed")


if __name__ == "__main__":
    run_tests()
