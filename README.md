# reorg-watch

Watches a Bitcoin Knots node for chain reorganizations, names the pools on
both sides, and mails you when one is deep enough to matter. It also follows
the rewards: which pool has moved how much of what it mined, and whether one
wallet is collecting under more than one pool name.

Everything comes from the node's REST interface. No electrs, no address
index, no RPC credentials.

A node's built-in fork warning fires only when it sees an invalid chain with
six blocks more work than its own. A reorg made of valid blocks, which is
what a majority miner produces, triggers nothing, and Knots has no
reorg-depth option. With half the BLAKE2b hashrate behind one pool, a
minute-by-minute record of what the chain actually did is the cheapest thing
anyone can run.

## What it checks

Once a minute, from the node's REST interface:

| Event | Level | Meaning |
|---|---|---|
| reorg, depth 1 | INFO | Two blocks at one height and the node switched. Ordinary at short block intervals. |
| reorg, depth 2 or more | ALERT | Confirmed blocks were replaced. Both sides are attributed to pools. |
| reorg beyond window | ALERT | No common ancestor within the saved window. The window is reseeded. |
| explorer mismatch | ALERT | The explorer has a different block at our tip height for two consecutive checks. |
| node behind explorer | ALERT | The explorer is three or more blocks ahead for three consecutive checks. Partition, stall, or eclipse. |
| node unreachable | ALERT | REST did not answer for three consecutive runs. |

Pool attribution uses the coinbase payout address first, then the coinbase
tag, matched against Kilombino's `pools-v2.json`, the list mempool.guide and
mempool.kilombino.com use. Tags are self-declared. Treat names as claims,
not proof.

## Reward flow

The watcher keeps its own small index instead of asking an address indexer:
every coinbase output since the fork, about 8,000 entries, built once from
the raw blocks in half a minute and then extended one block at a time. Each
new block's inputs are checked against it, so every spend of a mining reward
is caught the minute it confirms.

From that it reports, per pool: blocks, BTC mined, matured, moved, held, and
the last movement with its shape. Payout means three or more outputs, sweep
means several rewards into one or two outputs, transfer means one reward to
one or two outputs. Moved means a coinbase output was spent. The chain shows
movement, not a sale.

It also reads who built each block's template from the coinbase layout the
DATUM gateway writes: height push, one tag push (primary, 0x0F, secondary,
0x00), a unique-id push of 3 bytes when the gateway runs standalone or 7 or
more when a DATUM pool is upstream, then the 14-byte extranonce push. That
gives three classes:

- **DATUM pool**: the miner's own gateway and node built the block. The pool
  only coordinated payout and could not have chosen the transactions.
- **Gateway, stratum v1**: the gateway software running standalone, so the
  node of whoever owns the payout address built the block. For a pool label
  that is the pool's node; for a solo label it is the miner's.
- **Other software**: a coinbase this tool does not recognize.

Per block the page shows the tags, transaction count, coinbase outputs,
reward, fees, and the header fields that say how it was mined: the ASIC
profile (low two bits of the flags byte), whether the gateway allowed the
hasher to roll the timestamp (flag bit 4) and the offset it recorded, whether
the Sia time slot (nonce3) carries the timestamp, and whether the xor mask
was used. Every BLAKE2b block has three nonce fields by design; per pool the template mix and how the reward leaves the
block (one output kept by the pool, two outputs, or paid directly to miners
in the coinbase).

It also merges labels that belong to one wallet: labels whose blocks pay the
same pool address, or whose pool addresses are spent together. A pool that
lets miners write their own tag into the coinbase shows up as one wallet
with many labels, which is the honest picture of who built those blocks.
A pool's address is one paid in at least 90 percent of that label's blocks;
miners paid directly in a coinbase recur far less and do not count.

| Event | Level | Meaning |
|---|---|---|
| reward sweep | INFO | At least `--sweep-btc` BTC of rewards (default 10) moved into one or two outputs. |
| label overlap | ALERT | Two pool names with at least 100 blocks each turn out to share a wallet. |
| wallet share | ALERT | One wallet with more than one label mined a third or more of the last 24 hours. |

`--no-rewards` turns all of this off.

`--tz America/New_York` renders every time on the page in that zone, with
the zone name in the hourly heading and the timestamp. Logs and the JSON
files always stay in UTC. Requires Python 3.9 for `zoneinfo`.

## Requirements

- Bitcoin Knots with `rest=1` in bitcoin.conf. REST is unauthenticated on
  localhost, so the watcher runs as any local user and needs no RPC cookie.
- Python 3.9 or later. Standard library only.
- Outbound HTTPS to mempool.guide and raw.githubusercontent.com. Without it,
  run with `--explorer ""` and live without the cross-check; attribution
  falls back to address prefixes.

## Install

```
cp reorg-watch.py ~/bin/
~/bin/reorg-watch.py --init
crontab -e
```

Add one line:

```
* * * * * $HOME/bin/reorg-watch.py --notify 'mail -s "reorg-watch ALERT" you@example.com' >> $HOME/reorg-watch.log 2>&1
```

`--notify` receives the alert text on stdin and in `$REORG_MSG`, so anything
that reads stdin works:

```
--notify 'mail -s "reorg-watch ALERT" you@example.com'
--notify 'curl -s -d @- https://ntfy.sh/your-topic'
```

A reorg alerts once. The explorer and node-unreachable conditions repeat
every 30 minutes while they persist. Nothing is printed on a quiet run, so
the cron log stays empty until something happens.

On testnet4 add `--rest http://127.0.0.1:48332/rest --floor 150308`.

## Output

Everything lives in `~/.reorg-watch/` (change with `--state`):

- `reorg-log.md`: the human-readable log, written to be published as is.
  Heights, hashes, pool names, timestamps. No local paths.
- `events.jsonl`: one JSON object per event, for scripts.
- `state.json`: the saved window, one attribution record per block, and counters.
- `rewards.json`: every coinbase output since the fork and every transaction that spent one.
- `pools-v2.json`: cached pool list, refreshed every six hours.

`reorg-watch.py --report` prints the tip, the window, the explorer counters,
reorg counts for the last day and week, and the last ten events.

Cron log line and `reorg-log.md` entry from a test run. The saved state was
rewound onto a real stale block at 969652 plus one invented hash at 969653,
so the watcher saw a depth-2 reorg against the live chain:

```
2026-09-08 10:39:14Z ALERT reorg depth=2 heights=969652-969653 out=[AlphaPool,unknown (no block data)] in=[AlphaPool,AlphaPool] tip=969806
```

```
## 2026-09-08 10:39:14Z - reorg depth 2 (heights 969652-969653)
- Common ancestor: 969651 `000000000000000d3e9475cdde9a510754acf83047d22b647a9fdf47dce01e7d`
- Disconnected:
  - 969652 AlphaPool `000000000000000d65d4865e6639a6d1cc6d5f6c43e250c50664db2e10f60a2d` (11 tx, 2026-09-08 00:50:00Z)
  - 969653 unknown (no block data) `0000000000000000000000000000000000000000000000000000000000000000` (no block data on this node)
- Replaced by:
  - 969652 AlphaPool `0000000000000008290e8516e2d2594335bf486a5ec8fd4b0145e4dced856029` (11 tx, 2026-09-08 00:50:00Z)
  - 969653 AlphaPool `00000000000000006987397fc100f08aec2f24f710b36a1d1f36e69137100cb1` (4 tx, 2026-09-08 00:50:10Z)
- New tip: 969806 `000000000000000088cc70f5b95804bb184eba1d9c93500314ac249bb2057a88` (153 further blocks)
```

## Status page

`--html FILE` writes a self-contained page after every run: node and explorer
status, blocks by pool for the last 24 hours with an hourly breakdown, reward
flow and blocks by wallet, latest blocks, recent reward movements, and recent
events. Every column header and every classification says how it was
determined on hover or focus, and a "How this page decides" section at the
bottom repeats the method in plain text for readers on phones. Tables never
scroll sideways: they use fixed layout with wrapping, and below about 700px
each row reflows into labeled lines. One file, no external assets, no scripts beyond a staleness
check. Serve it from wherever you already serve static files.

Pool names are HTML-escaped on the way out. Coinbase tags are text the miner
chose and must never reach a browser raw.

The page refreshes itself every five minutes and shows a red banner when it
is more than 15 minutes old, so a dead generator is visible to readers
instead of silent.

```
* * * * * $HOME/bin/reorg-watch.py --html /var/www/reorg/index.html --notify 'mail -s "reorg-watch ALERT" you@example.com' >> $HOME/reorg-watch.log 2>&1
```

## How it decides

The state holds the hash of every height in a 400-height window. Each run
reads the tip from `chaininfo.json`, then walks down from the lower of the
old and new tip heights until a stored hash matches the node's hash at that
height. That is the common ancestor. Depth is the old tip height minus the
ancestor height. In the normal case the first comparison matches and the run
costs three REST calls.

Disconnected blocks are fetched by their old hashes. The node keeps stale
blocks it validated, and REST returns them with `confirmations: -1`, which
is what makes attributing the losing side possible. Blocks the node never
downloaded show as `unknown (no block data)`.

## Limits

- One node's view. The explorer cross-check adds a second vantage point, and
  that is all it is.
- Polls once a minute. A reorg done and undone inside a minute is missed.
- Attribution is only as good as the pools list, and a coinbase tag can be
  spoofed. Payout addresses are harder to fake and are matched first, which
  has one known wart: a block whose coinbase pays a listed pool's address
  because that pool's operator won another pool's lottery is credited to the
  listed pool, not to the pool whose tag it carries.
- The template classes come from one piece of software's coinbase layout.
  A pool running something else lands in Other software even if it is a
  plain stratum v1 server.
- Depth-1 reorgs are noise at five-minute block intervals and are not alerts.
  Change that with `--alert-depth 1`.
- Anything deeper than the window is reported as beyond the window, without
  per-block attribution. Raise `--keep` if that bothers you; each height is
  one line of JSON.

## Testing

There is no test suite. What was run before the first release, against a
mainnet Bitcoin Knots 29.4.1 node:

- seed, then a quiet run;
- a simulated depth-2 reorg made by rewinding the saved state onto a real
  stale block, checking attribution of both sides and the notify hook;
- a fake explorer on localhost returning a wrong hash and a tip five blocks
  ahead, checking that the mismatch alert fires on the second run and the
  behind alert on the third;
- an unreachable explorer, checking that it stays quiet for ten runs;
- a run from a cron-like empty environment;
- a real mail delivery through a local postfix relay;
- the status page against a hostile pool name, checking it renders as text;
- the reward index against an independent scan of the same blocks (same
  spend count, same wallet clusters), and a reorg rollback that must drop and
  rebuild the affected heights without re-announcing old movements.

## License

MIT. See `LICENSE`. The knot mark in the status page header is the Bitcoin
Knots logo from the Knots repository (`src/qt/res/src/bitcoinknots-logo.svg`),
also MIT, designed by Kurtis Stirling, Blissmode, Skyler, and Steven Hay.
