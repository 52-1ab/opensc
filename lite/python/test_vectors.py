"""Replays lite/vectors/vectors.json against the Python reference (the same KATs the C uses)."""

import json
import pathlib

import opensc_lite as o

VECTORS = pathlib.Path(__file__).resolve().parent.parent / "vectors" / "vectors.json"

_DISPATCH = {
    "alias": lambda a: o.alias(*a),
    "sha256b64": lambda a: o.sha256_b64(*a),
    "sha1id35": lambda a: o.sha1_id35(*a),
    "debit_payload": lambda a: o.debit_payload(*a),
    "vaultsig": lambda a: o.vault_sig_message(*a),
    "pac": lambda a: str(o.pac_applies(*a)),
    "pvr_set": lambda a: o.pvr_set(*a),
    "litex_txn_id": lambda a: o.litex_txn_id(*a),
}


def run() -> int:
    n = 0
    for line in VECTORS.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        v = json.loads(line)
        got = _DISPATCH[v["op"]](v["in"])
        assert got == v["out"], f"{v['op']} {v['in']}: got {got!r} want {v['out']!r}"
        n += 1
    return n


def test_vectors():
    assert run() >= 40


if __name__ == "__main__":
    print(f"OK {run()} vectors")
