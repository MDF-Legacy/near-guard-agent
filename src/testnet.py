"""NEAR testnet wiring for the Guard Agent demo.

Pure standard library — no keys, no funds, no signing by this module.
Everything here is either a read-only call to NEAR testnet / mempool.space
or a pure computation (address derivation, sign-request construction).

Live testnet facts this module relies on (verified 2026-11-09):
  - NEAR testnet RPC: https://rpc.testnet.near.org
  - MPC signer contract: v1.signer-prod.testnet
  - view methods that exist on that contract: public_key,
    derived_public_key. (latest_key_version and
    experimantal_signature_deposit do NOT exist on this contract —
    they return MethodNotFound, so key_version 0 is used and the
    signature deposit is attached at signing time, see below.)
  - Derivation path "bitcoin,1" is the documented Bitcoin example path.

What this module does NOT do (honest wall, not a gap to fake):
  - It does not produce a live MPC signature. Signing requires the
    operator's own NEAR testnet account (a funded account id + key),
    and no such account exists for this demo. The demo builds the exact
    sign request and prints the exact near-CLI command the operator
    runs with their own account.
  - It does not build a real Bitcoin sighash. A real sighash needs a
    funded UTXO in the derived address, and the demo address is
    unfunded (0 tx, 0 balance — checked live). The demo payload is the
    SHA-256 of the canonical spend intent, clearly labelled as such;
    for a live spend the payload is the BIP-143 sighash of the funded
    transaction, and the same sign request shape carries it.
"""

import base64
import hashlib
import json
import urllib.request

NEAR_RPC = "https://rpc.testnet.near.org"
SIGNER_CONTRACT = "v1.signer-prod.testnet"
MEMPOOL_TESTNET = "https://mempool.space/testnet/api"

# The demo's NEAR account id. It does not need to exist: the MPC
# derivation is a pure function of (account id, path). The operator
# substitutes their own testnet account id at demo/submission time.
DEMO_ACCOUNT = "guard-demo.testnet"
DERIVATION_PATH = "bitcoin,1"
DESTINATION_PATH = "bitcoin,2"
KEY_VERSION = 0
SIGN_GAS_TGAS = 300  # documented example gas for a sign call


# ---------------------------------------------------------------- RPC

def rpc_view(contract, method_name, args, finality="final", timeout=30):
    """Call a read-only view method on a NEAR contract. Returns the
    decoded JSON result (or a decoded string). Raises on failure."""
    args_b64 = base64.b64encode(json.dumps(args).encode()).decode()
    body = json.dumps({
        "jsonrpc": "2.0", "id": "1", "method": "query",
        "params": {
            "request_type": "call_function",
            "account_id": contract,
            "method_name": method_name,
            "args_base64": args_b64,
            "finality": finality,
        },
    }).encode()
    req = urllib.request.Request(
        NEAR_RPC, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        res = json.load(resp)
    out = res.get("result", {})
    if "error" in out:
        raise RuntimeError(f"{contract}.{method_name}: {out['error']}")
    raw = bytes(out["result"])
    try:
        return json.loads(raw.decode())
    except (ValueError, UnicodeDecodeError):
        return raw.decode(errors="replace")


def mpc_public_key():
    """The MPC network's root secp256k1 public key, live from testnet."""
    return rpc_view(SIGNER_CONTRACT, "public_key", {})


def derived_public_key(account_id, path):
    """The secp256k1 public key the MPC derives for (account, path),
    computed on-chain by the signer contract itself."""
    return rpc_view(SIGNER_CONTRACT, "derived_public_key",
                    {"predecessor": account_id, "path": path})


# ------------------------------------------------------- address math

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58decode(s):
    n = 0
    for c in s:
        n = n * 58 + _B58.index(c)
    pad = 0
    for c in s:
        if c == "1":
            pad += 1
        else:
            break
    h = "%x" % n
    if len(h) % 2:
        h = "0" + h
    return b"\x00" * pad + bytes.fromhex(h)


_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(vals):
    chk = 1
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    for v in vals:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= gen[i]
    return chk


def _hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _convertbits(data, frm, to, pad=True):
    acc, bits, ret = 0, 0, []
    maxv = (1 << to) - 1
    for v in data:
        acc = (acc << frm) | v
        bits += frm
        while bits >= to:
            bits -= to
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (to - bits)) & maxv)
    return ret


def secp256k1_key_to_btc_testnet_address(key_str):
    """NEAR 'secp256k1:<base58>' key -> Bitcoin testnet P2WPKH address
    (tb1q...). NEAR stores the key as 64 raw bytes x||y; we compress it,
    hash160 it, and bech32-encode with human-readable part 'tb'."""
    if not key_str.startswith("secp256k1:"):
        raise ValueError("expected a secp256k1: key, got %r" % key_str[:20])
    raw = _b58decode(key_str.split(":", 1)[1])
    if len(raw) != 64:
        raise ValueError("expected 64-byte secp256k1 key, got %d" % len(raw))
    x, y = raw[:32], raw[32:]
    compressed = (b"\x03" if y[-1] & 1 else b"\x02") + x
    h160 = hashlib.new("ripemd160",
                       hashlib.sha256(compressed).digest()).digest()
    data = [0] + _convertbits(h160, 8, 5)
    checksum = [(_bech32_polymod(_hrp_expand("tb") + data + [0] * 6) ^ 1)
                >> (5 * (5 - i)) & 31 for i in range(6)]
    return "tb1" + "".join(_BECH32[d] for d in data + checksum)


# ------------------------------------------------------------ balances

def btc_balance(address):
    """Live balance of a Bitcoin testnet address from mempool.space.
    Returns (confirmed_sats, mempool_sats, tx_count)."""
    req = urllib.request.Request(MEMPOOL_TESTNET + "/address/" + address)
    with urllib.request.urlopen(req, timeout=30) as resp:
        info = json.load(resp)
    chain = info.get("chain_stats", {})
    mempool = info.get("mempool_stats", {})
    return (chain.get("funded_txo_sum", 0) - chain.get("spent_txo_sum", 0),
            mempool.get("funded_txo_sum", 0) - mempool.get("spent_txo_sum", 0),
            chain.get("tx_count", 0))


# ------------------------------------------------------- sign request

def demo_payload(destination, amount_sats, account_id, path):
    """The 32-byte payload for the demo's sign request: SHA-256 of the
    canonical spend intent. This is a DEMO payload, not a sighash — a
    live spend substitutes the BIP-143 sighash of the funded
    transaction (which needs a funded UTXO in the derived address).
    The sign request shape is identical either way."""
    intent = json.dumps({
        "destination": destination,
        "amount_sats": amount_sats,
        "account": account_id,
        "path": path,
        "key_version": KEY_VERSION,
    }, sort_keys=True).encode()
    return hashlib.sha256(intent).digest()


def sign_request(payload_bytes, path=DERIVATION_PATH,
                 key_version=KEY_VERSION):
    """The exact SignRequest the MPC contract's sign() method takes."""
    if len(payload_bytes) != 32:
        raise ValueError("payload must be 32 bytes")
    return {
        "payload": list(payload_bytes),
        "path": path,
        "key_version": key_version,
    }


def near_cli_sign_command(account_id, request):
    """The exact near-CLI command the operator runs with their own
    testnet account to get the MPC signature for the request.
    The deposit is the small, network-dependent MPC fee; 0.01 NEAR is
    a generous example — attach it at signing time and adjust if the
    contract reports the fee is higher."""
    args = json.dumps({"request": request})
    return (
        "near contract call-function as-transaction "
        f"{SIGNER_CONTRACT} sign json-args '{args}' "
        f"prepaid-gas '{SIGN_GAS_TGAS}.0 Tgas' "
        "attached-deposit '0.01 NEAR' "
        f"sign-as {account_id} network-config testnet "
        "sign-with-keychain send"
    )
