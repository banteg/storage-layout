import json
from collections import defaultdict
from typing import Dict, List, Tuple

import requests
from ape import chain, networks
from devtools import debug
from eth_abi import decode_single, encode_single
from eth_utils import encode_hex, keccak
from evm_trace import vmtrace
from hexbytes import HexBytes
from toolz import valfilter
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
    storage_diff = {
        contract: {slot: item["*"]["to"] for slot, item in diff["storage"].items()}
        for contract, diff in state_diff.items()
    }
    return valfilter(bool, storage_diff)


def to_int(value):
    if isinstance(value, str):
        return int(value, 16)
    if isinstance(value, bytes):
        return int.from_bytes(value, "big")

    raise ValueError("invalid type %s", type(value))


@app.command()
def find_preimages(txhash: str):
    response = raw_request("trace_replayTransaction", [txhash, ["vmTrace"]])
    trace = vmtrace.from_rpc_response(response)
    preimages = {}

    for frame in vmtrace.to_trace_frames(trace):
        if frame.op == "SHA3":
            size, offset = [to_int(x) for x in frame.stack[-2:]]
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
    return encode_hex(encode_single("uint256", value))


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
    decoded = decode_single(item["abi_type"], values)
    out = decoded

    if item["path"]:
        out = decoded[-1]
        for p, v in zip(item["path"], decoded):
            out = {v: out}

    return {item["name"]: out}


@app.command()
def layout(txhash: str):
    storage_layout = {"0xda816459f1ab5631232fe5e97a05bbbb94970c95": json.load(open("layout.json"))}
    slot_lookup = {
        contract: {int_to_bytes32(item["pos"]): item for item in data}
        for contract, data in storage_layout.items()
    }

    storage_diff = get_storage_diff(txhash)

    preimages = find_preimages(txhash)

    results = defaultdict(dict)

    for contract, storage in storage_diff.items():
        if contract not in slot_lookup:
            print(f"no layout avaiable for {contract}")
            continue
        for slot, value in storage.items():
            item = unwrap_slot(slot, value, preimages, slot_lookup[contract])
            decoded = decode_types(item)
            results[contract].update(decoded)

    debug(results)


if __name__ == "__main__":
    with networks.ethereum.mainnet.use_default_provider():
        app()
