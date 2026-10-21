#!/usr/bin/env python3
"""Cold-transaction reader benchmark on an explicit local Anvil instance.

No third-party Python packages, funded mainnet signer, or deployed verifier.
All inputs/outputs are local artifact paths supplied on the command line.
"""
import argparse
import json
import time
import urllib.parse
import urllib.request
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc", default="http://127.0.0.1:18597")
    parser.add_argument("--fixtures", required=True, type=Path)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--variants", nargs="+", choices=["raw", "shared", "dag", "dag-derived"], default=["raw", "shared", "dag", "dag-derived"])
    args = parser.parse_args()
    assert urllib.parse.urlparse(args.rpc).hostname in ("127.0.0.1", "localhost"), "local benchmark only"

    def rpc(method, params):
        payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        with urllib.request.urlopen(urllib.request.Request(args.rpc, payload, {"Content-Type": "application/json"}), timeout=120) as response:
            result = json.load(response)
        if "error" in result:
            raise RuntimeError(result["error"])
        return result["result"]

    assert int(rpc("eth_chainId", []), 16) == 31337, "local Anvil chain required"
    account = rpc("eth_accounts", [])[0]
    artifact = json.loads(args.artifact.read_text())
    word = lambda x: int(x).to_bytes(32, "big")

    def send(data, to=None):
        tx = {"from": account, "data": "0x" + data.hex(), "gas": hex(16_777_216)}
        if to:
            tx["to"] = to
        tx_hash = rpc("eth_sendTransaction", [tx])
        for _ in range(100):
            receipt = rpc("eth_getTransactionReceipt", [tx_hash])
            if receipt:
                assert int(receipt["status"], 16) == 1, f"reader transaction reverted: {tx_hash}"
                return receipt
            time.sleep(0.05)
        raise RuntimeError("transaction was not mined")

    reports = []
    for name in args.variants:
        manifest = json.loads((args.fixtures / f"{name}.json").read_text())
        packet = (args.fixtures / f"{name}.bin").read_bytes()
        ranges = [leaf["field_start"] | (leaf["field_count"] << 32) for leaf in manifest["leaves"]]
        constructor = (bytes.fromhex(manifest["profile_id"].removeprefix("0x")) + word(manifest["mode"])
                       + word(manifest["field_count"]) + word(manifest["digest_references"]) + word(160)
                       + word(len(ranges)) + b"".join(map(word, ranges)))
        creation = bytes.fromhex(artifact["bytecode"]["object"].removeprefix("0x")) + constructor
        deployed = send(creation)
        address = deployed["contractAddress"]
        selector = bytes.fromhex(artifact["methodIdentifiers"]["readWitnessDigest(bytes)"])
        call = selector + word(32) + word(len(packet)) + packet + bytes((-len(packet)) % 32)
        expected = "0x" + manifest["witness_digest"].removeprefix("0x")
        result = rpc("eth_call", [{"from": account, "to": address, "data": "0x" + call.hex(), "gas": hex(16_777_216)}, "latest"])
        assert result == expected, f"Rust/Solidity parity failed for {name}"
        zero = call.count(0)
        tokens = zero + 4 * (len(call) - zero)
        receipt = send(call, address)
        reports.append({"variant": name, "packet_bytes": len(packet), "abi_calldata_bytes": len(call),
                        "abi_tokens": tokens, "calldata_gas": 4 * tokens,
                        "eip7623_floor": 21000 + 10 * tokens,
                        "cold_reader_transaction_gas": int(receipt["gasUsed"], 16),
                        "reader_deployment_gas": int(deployed["gasUsed"], 16),
                        "reader_transaction_hash": receipt["transactionHash"],
                        "full_proof_verification_gas": None})
        print(json.dumps(reports[-1]), flush=True)
    args.out.write_text(json.dumps({"chain_id": 31337, "description": "Transport decoding only, not STARK verification; actual cold transactions with ABI overhead and EIP-7623 floor", "variants": reports}, indent=2) + "\n")


if __name__ == "__main__":
    main()
