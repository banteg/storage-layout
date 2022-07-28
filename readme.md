# storage layout

a tool to get readable state diffs and enumerate complete contract storage

🚧 status: proof of concept 🚧

## usage

- `storage-layout storage <contract>` print all slots and values
- `storage-layout layout <txhash>` print a decoded state diff

## how it works

1. get storage layout of a contract, which comes as one of compiler output format. here i use a [modified vyper compiler](https://github.com/banteg/vyper/tree/v0.2.12-storage) with a test contract.
2. get storage diff, here i use `trace_replayTransaction` in `stateDiff` mode. this is not strictly necessary since you can get all `SSTORE` from `vmTrace`.
3. extract preimages from a trace. we look for all `SHA3` calls which hash two words and write down `key` and `slot`.
4. then we unwrap storage slots using preimages we have collected until we reach basic storage indexes we have in the layout. for exmaple, a `slot` value for mapping could be among preimages, we record a path we traversed to construct nested keys.
5. decode abi types using metadata from contract storage layout.

## further research

how to dump the complete contract storage and print it in a readable way.

this tool can already dump the entire storage using `parity_listStorageKeys`, but to decode it we need to collect all preimages.

for this we can find all calls to the address using `trace_filter` and then `vmTrace` all transactions and record all preimages.
