from typing import List, Tuple

import requests
from ape import chain, networks
from devtools import debug
from typer import Typer

app = Typer()


def make_request(method: str, params: List):
    response = chain.provider.web3.provider.make_request(method, params)
    if "error" in response:
        raise ValueError(response["error"]["message"])
    return response["result"]


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


@app.command()
def storage(contract: str):
    keys = get_storage_keys(contract)
    values = get_storage_values(contract, keys)
    
    kv = dict(zip(keys, values))
    debug(kv)


if __name__ == "__main__":
    with networks.ethereum.mainnet.use_default_provider():
        app()
