import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

import requests
from ape import chain, networks
from devtools import debug
from eth_abi import decode, encode
from eth_utils import encode_hex, keccak
from evm_trace import vmtrace
from hexbytes import HexBytes
from toolz import valfilter
from tqdm import tqdm
from typer import Typer

app = Typer()


def make_request(method: str, params: List) -> Dict:
    response = chain.provider.web3.provider.make_request(method, params)
    if "error" in response:
        raise ValueError(response["error"]["message"])
    return response["result"]


def raw_request(method: str, params: List) -> bytes:
    payload = {"method": method, "params": params, "id": None, "jsonrpc": "2.0"}
    response = requests.post(chain.provider.uri, json=payload)
    if response.status_code != 200:
        raise ValueError(response.json()["error"]["message"])
    return response.content


def batch_request(calls: List[Tuple[str, List]]):
    payload = [
        {"method": method, "params": params, "id": None, "jsonrpc": "2.0"}
        for method, params in calls
    ]
    batch_repsonse = requests.post(chain.provider.uri, json=payload).json()
    for response in batch_repsonse:
        if "error" in response:
            raise ValueError(response["error"]["message"])
        yield response["result"]


def get_storage_keys(account):
    return make_request("parity_listStorageKeys", [account, 1_000_000, None, "latest"])


def get_storage_values(account, keys):
    values = batch_request([("eth_getStorageAt", [account, key, "latest"]) for key in keys])
    return list(values)


def get_storage_diff(txhash: str):
    state_diff = make_request("trace_replayTransaction", [txhash, ["stateDiff"]])["stateDiff"]
    storage_diff = {}
    for contract, diff in state_diff.items():
        storage_diff[contract] = {}
        for slot, change in diff["storage"].items():
            for op, delta in change.items():
                if op == "+":
                    storage_diff[contract][slot] = delta
                elif op == "*":
                    storage_diff[contract][slot] = delta["to"]
                else:
                    raise NotImplementedError(f"op {op} in state diff")

    return valfilter(bool, storage_diff)


def to_int(value):
    if isinstance(value, str):
        return int(value, 16)
    if isinstance(value, bytes):
        return int.from_bytes(value, "big")

    raise ValueError("invalid type %s", type(value))


def find_preimages(txhash: str):
    response = raw_request("trace_replayTransaction", [txhash, ["vmTrace"]])
    trace = vmtrace.from_rpc_response(response)
    preimages = {}

    for frame in vmtrace.to_trace_frames(trace):
        if frame.op in ["SHA3", "KECCAK256"]:
            size, offset = [to_int(x) for x in frame.stack[-2:]]
            if size != 64:
                continue
            preimage = HexBytes(frame.memory[offset : offset + size])
            hashed = HexBytes(keccak(preimage))
            key, slot = preimage[:32], preimage[32:]
            preimages[hashed.hex()] = {"key": key.hex(), "slot": slot.hex()}

        if frame.op == "SSTORE":
            value, slot = frame.stack[-2:]

    return preimages


@app.command()
def storage(contract: str):
    keys = get_storage_keys(contract)
    values = get_storage_values(contract, keys)

    kv = dict(zip(keys, values))
    debug(kv)


def int_to_bytes32(value):
    return encode_hex(encode(["uint256"], [value]))


def unwrap_slot(slot, value, preimages, slot_lookup):
    def unwrap(slot, path):
        if slot in slot_lookup:
            return {**slot_lookup[slot], "path": path, "value": value}

        if slot in preimages:
            p_slot, p_key = preimages[slot]["slot"], preimages[slot]["key"]
            from_slot = unwrap(p_slot, path + [p_key])
            from_key = unwrap(p_key, path + [p_slot])
            return from_slot or from_key

    return unwrap(slot, [])


def decode_types(item):
    values = b"".join(HexBytes(i) for i in item["path"]) + HexBytes(item["value"])
    decoded = decode([item["abi_type"]], values)
    out = decoded

    if item["path"]:
        out = decoded[-1]
        for p, v in zip(item["path"], decoded):
            out = {v: out}

    return {item["name"]: out}


def merge(source, destination):
    for key, value in source.items():
        if isinstance(value, dict):
            node = destination.setdefault(key, {})
            merge(value, node)
        else:
            destination[key] = value

    return destination


@app.command()
def layout(txhash: str):
    storage_layout = {"0xda816459f1ab5631232fe5e97a05bbbb94970c95": json.load(open("layout.json"))}
    slot_lookup = {
        contract: {int_to_bytes32(item["pos"]): item for item in data}
        for contract, data in storage_layout.items()
    }

    storage_diff = get_storage_diff(txhash)
    debug(storage_diff)

    preimages = find_preimages(txhash)
    debug(preimages)

    results = defaultdict(dict)

    for contract, storage in storage_diff.items():
        if contract not in slot_lookup:
            continue
        for slot, value in storage.items():
            item = unwrap_slot(slot, value, preimages, slot_lookup[contract])
            if item is None:
                debug("could not decode", slot)
                continue
            decoded = decode_types(item)
            results[contract] = merge(results[contract], decoded)

    debug(results)


@app.command()
def index_txs(contract: str):
    """
    Find all calls of a contract which might have modified storage.
    """
    contract = contract.lower()
    path = Path(f"cache/calls/{contract}.csv")
    path.parent.mkdir(parents=True, exist_ok=True)
    last_block = 0
    traces_found = 0
    head = chain.blocks.height
    need_header = True

    if path.exists():
        need_header = False
        cached = csv.DictReader(path.open("rt"))
        for item in cached:
            last_block = int(item["block_number"]) + 1
            traces_found += 1

    writer = csv.DictWriter(path.open("at"), ["block_number", "transaction_hash"])
    if need_header:
        writer.writeheader()

    seen = set()
    traces = chain.provider.stream_request(
        "trace_filter", [{"toAddress": [contract], "fromBlock": hex(last_block)}]
    )
    bar = tqdm(traces, unit=" traces")
    for item in bar:
        if "error" in item:
            continue
        if item["transactionHash"] in seen:
            continue
        is_call = item["type"] == "call" and item["action"]["callType"] == "call"
        is_create = item["type"] == "create" and item["result"]["address"] == "contract"
        if not is_call and not is_create:
            continue

        seen.add(item["transactionHash"])
        traces_found += 1
        writer.writerow(
            {"block_number": item["blockNumber"], "transaction_hash": item["transactionHash"]}
        )
        bar.set_postfix({"blocks": f"{head - item['blockNumber']:,d}", "traces": traces_found})


def main():
    with networks.ethereum.mainnet.use_default_provider():
        app()


if __name__ == "__main__":
    main()
