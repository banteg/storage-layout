from typing import Dict, List, Tuple

import requests
from ape import chain, networks
from devtools import debug
from typer import Typer
from evm_trace import vmtrace
from hexbytes import HexBytes
from eth_utils import keccak

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


def to_int(value):
    return int.from_bytes(value, "big")


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
            preimages[hashed] = {"key": key, "slot": slot}
            debug("found preimage", size, offset, preimage, key, slot)

        if frame.op == "SSTORE":
            value, slot = frame.stack[-2:]
            debug(slot, value, slot in preimages)

    debug(preimages)


@app.command()
def storage(contract: str):
    keys = get_storage_keys(contract)
    values = get_storage_values(contract, keys)

    kv = dict(zip(keys, values))
    debug(kv)


if __name__ == "__main__":
    with networks.ethereum.mainnet.use_default_provider():
        app()
