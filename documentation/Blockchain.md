# `PWN::Blockchain` — read-only blockchain intelligence

Source: `lib/pwn/blockchain/{btc,eth}.rb`. Use each module's `.help` for exact options.
These modules do not manage keys, sign, broadcast transactions, or modify wallets.
They report on-chain observations, not real-world identity, ownership, or criminality.

## Assessment and changes

Previously, BTC offered chain status, block lookup and an unbounded date-to-transaction-ID
scan. Its chain status lookup also invoked AI and printed the result. The date scan
binary-searched block timestamps even though those timestamps are not monotonic.
ETH offered only two BlockCypher lookups. Both transports disabled TLS verification;
tests checked only that help/authors existed. Earlier versions of this document
incorrectly advertised balance, broadcast, and key-management APIs.

Both modules now provide structured, read-only intelligence with validated inputs,
verified HTTPS, request timeouts, credential-safe errors and deterministic tests.
BTC no longer invokes AI implicitly. `PWN::AI::Agent::BTC` remains a separate,
explicit analysis interface; its prose is not independent blockchain evidence.

## Bitcoin Core

BTC uses the existing `PWN::Env[:plugins][:blockchain][:bitcoin]` settings:
`rpc_host`, `rpc_port`, `rpc_user`, and `rpc_pass`. Optional `rpc_scheme: 'https'`
enables verified TLS; the existing HTTP default is retained. Use a trusted local
connection or protected tunnel for HTTP. No prompts or configuration writes occur.

| API | Evidence returned |
|---|---|
| `get_latest_block` | Backward-compatible JSON-RPC chain-status envelope, without stdout or AI |
| `chain_status` | Chain identity, synchronization, tip and pruning status |
| `get_block_details` | Block at an explicit height or tip, verbosity 0–3 |
| `inspect_transaction` | Input/output references, exact integer satoshis, fees only with complete prevouts |
| `inspect_outpoint` | Current UTXO evidence; null means spent **or unknown**, not proof of spending |
| `mempool_summary` | Aggregate node-local mempool statistics |
| `trace_transaction` | Bounded ancestor graph of actual input references, missing evidence and truncation reasons |
| `scan_transactions` | Paginated explicit-height scan filtered by inclusive UTC header dates |
| `get_transactions` | Legacy transaction-ID array, only for a complete explicitly bounded scan |
| `scan_address_activity` | Script-matched received/spent outputs within explicit block heights |

```ruby
btc = PWN::Blockchain::BTC
tip = btc.chain_status[:blocks]
block = btc.get_block_details(height: tip - 6, verbosity: 1)
tx = btc.inspect_transaction(txid: block[:tx].first, blockhash: block[:hash])
graph = btc.trace_transaction(txid: tx[:txid], blockhash: block[:hash],
                              max_depth: 2, max_transactions: 20, max_edges: 100)
page = btc.scan_transactions(from: '2009-01-12', to: '2009-01-12',
                             start_height: 160, end_height: 180, max_blocks: 10)
# Resume with start_height: page[:next_height]; keep end_height fixed.
```

Migration: `get_transactions(from:, to:)` now also requires `start_height:` and
`end_height:`. It raises rather than return a silently partial array. For larger
ranges use `scan_transactions` and inspect `next_height`, `complete`,
`missing_blocks`, `reorg_detected` and `anchor`. Dates use UTC block-header times,
not a guaranteed real-world transaction time. Every selected height is examined.

Historical transaction retrieval may require `txindex`; supplying `blockhash`
helps locate the root transaction but does not locate all its ancestors.
Pruning, absent undo data and lookup budgets can leave evidence incomplete.
Address activity is not an address index or a historical/current balance service.
Ancestor edges prove spending references, not ownership, change, or how mixed
input value is allocated to outputs. Completeness is limited to the requested
range or traversal. Scans detect some reorgs, but are not atomic snapshots;
compare anchors across pages and restart if they change.

## Ethereum

New RPC APIs take an explicit `rpc_url:`; no persistent configuration is required.
URLs with embedded userinfo are rejected. Endpoint credentials in paths/query
strings are not included in module errors. Use HTTPS for remote endpoints.
Existing `get_latest_block(token:)` and `get_block_details(height:, token:)`
continue to use BlockCypher; they are separate from the JSON-RPC APIs below.

| API | Evidence returned |
|---|---|
| `chain_status` | Chain ID, head height, sync state |
| `block` | Block by number, hash or tag; optional full transactions |
| `transaction` | Transaction/receipt consistency, pending/success/reverted state, exact wei and gas fees, creation evidence |
| `account` | Balance, nonce and bytecode pinned to one block hash |
| `address_activity` | Bounded, whole-block pagination of top-level from/to transactions |
| `event_logs` | Bounded event query with validated Transfer layouts and explicit provider-completeness caveat |
| `decode_transfer` | Standard ERC20/ERC721 Transfer layout decoding, not proof of contract conformance |
| `call` | Read-only ABI-encoded `eth_call`, pinned to a canonical block |
| `token_metadata` | Optional name, symbol, decimals and total supply, with unavailable ABI fields identified |

```ruby
eth = PWN::Blockchain::ETH
rpc = { rpc_url: 'https://YOUR_ETHEREUM_RPC_ENDPOINT' }
status = eth.chain_status(rpc)
block = eth.block(rpc.merge(block: 'finalized', full_transactions: true))[:block]
tx = eth.transaction(rpc.merge(hash: block[:transactions].first[:hash]))
state = eth.account(rpc.merge(address: tx[:transaction][:from], block: block[:hash]))
```

Pinned account/call/metadata reads require EIP-1898 support. Address scans cover
top-level transactions, not internal calls, token events, or a full account history;
their pages are not reorg-safe. Event queries cannot independently establish that
a provider returned every log, and report `provider_completeness: :unverified`.
ERC1155 events are not labeled ERC20/ERC721. Token names and event layouts do not
prove token legitimacy or standards conformance. Fees include execution and blob
components when supplied, not chain-specific L2 surcharges. Optional metadata RPC
failures propagate; malformed/unsupported returned ABI layouts are marked unavailable.

## Verification

Default specs use deterministic transport fixtures and need no live credentials.
Read-only live checks also exercised BTC chain/block/transaction/ancestor/UTXO/date/
address/mempool paths against the configured unpruned mainnet node, and Ethereum
chain/block/receipt/pinned-account/activity/Transfer-log/USDC-metadata paths against
a public mainnet RPC. These checks establish those observed paths, not universal
provider compatibility or complete attribution. Never put RPC credentials in
fixtures, documentation, logs, or generated skills.

[← Home](Home.md)
