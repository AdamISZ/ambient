# Partial UTXO Set Design

Ambient maintains a **partial UTXO set** to enable trustless validation of incoming SNICKER proposals without running a full node.

## The Problem

Light clients using BIP157 compact block filters can only see UTXOs matching their own wallet scripts. When someone proposes a coinjoin, the receiver has no way to verify that the proposer's UTXO actually exists and is unspent. An attacker could:

- Send proposals with fake UTXOs (never existed)
- Send proposals with spent UTXOs (already consumed)
- Lock up the receiver's capital with invalid transactions

## The Solution

Instead of tracking the entire Bitcoin UTXO set (~14 GB), we maintain a small, focused subset:

| What | Size |
|------|------|
| Full Bitcoin UTXO set | ~14 GB |
| Our partial UTXO set | ~60-100 MB |

This works because SNICKER has natural constraints:
- Only taproot (P2TR) outputs matter
- Only economically significant amounts matter (≥ 3000 sats)
- Only recent UTXOs matter (stale liquidity is poor for coinjoins)

## The "Lobotomized Full Node" Approach

Normal BIP157 light clients selectively download blocks that match their wallet scripts. This reveals information about which blocks contain your transactions.

Ambient downloads **every block** instead:

| Aspect | Full Node | Light Client | Ambient |
|--------|-----------|--------------|---------|
| Downloads | All blocks | ~1-5% of blocks | All blocks |
| Stores | Full chain (600+ GB) | Headers only (~100 MB) | Headers + partial UTXO (~100 MB) |
| Validates | Full consensus | SPV proofs | SPV proofs |
| UTXO set | Full (14 GB) | None | Partial (~100 MB) |
| Privacy | Perfect | Reveals block interest | Perfect (looks like observer) |

**Privacy benefit**: Downloading every block makes us indistinguishable from full nodes, block explorers, or chain analysis services.

## Filtering Strategy

Every block is scanned for outputs matching these criteria:

1. **Script type**: P2TR only (taproot required for SNICKER)
2. **Amount**: ≥ 3000 sats (`MIN_UTXO_SIZE` constant)
3. **Age**: Last ~1000 blocks (configurable scan window)

Combined effect per block:
```
5000 outputs → 1500 P2TR (30%) → 750 above threshold (50%)
```

Over a 1000-block window: ~750,000 UTXOs × 83 bytes ≈ 62 MB

## Real-Time Scanning

Blocks are scanned as they arrive during normal wallet sync:

```
On each new block:
  1. Process inputs → mark spent UTXOs
  2. Process outputs → add new P2TR UTXOs ≥ 3000 sats
  3. Prune UTXOs outside the scan window
```

On startup, any missed blocks since last run are scanned to catch up.

## Validation Workflow

When a proposal arrives:

```
1. Query partial UTXO set (local, instant)
   ├─ Found & unspent → Accept (trustless validation)
   ├─ Found & spent → Reject
   └─ Not found → Either reject (strict mode) or query external API (fallback mode)
```

Most proposals use recent UTXOs, so the partial set handles the vast majority with instant, trustless validation.

## Configuration

```toml
[partial_utxo_set]
scan_window_blocks = 1000        # ~1 week of blocks
min_utxo_amount_sats = 3000      # Matches MIN_UTXO_SIZE constant

[snicker_protocol]
max_utxo_age_delta_blocks = 1000 # Proposer UTXO can't be much older than receiver's
validation_mode = "strict"        # "strict" or "fallback"
```

**Note**: `min_utxo_amount_sats` must equal `MIN_UTXO_SIZE` (3000 sats). This value is used both for filtering the partial UTXO set and as the minimum change output size when creating proposals. They must match to ensure we don't create outputs we can't later track.

## Resource Usage

**Storage**: ~60-100 MB for the partial UTXO set (trivial on desktop)

**Bandwidth**: ~79 GB/year downloading all blocks
- Daily: ~216 MB
- Hourly: ~9 MB
- For comparison: Netflix HD uses ~3 GB/hour

## Edge Cases

**Reorgs**: When a chain reorganization is detected, the partial UTXO set rolls back to the fork point and rescans.

**UTXOs below threshold**: Proposals with UTXOs below 3000 sats are rejected in strict mode. This is intentional - dust-level coinjoins aren't useful anyway.

**First run**: Initial sync builds the partial UTXO set by scanning the last ~1000 blocks. Takes 10-30 minutes depending on bandwidth.

## Summary

The partial UTXO set provides:
- Trustless validation for ~90% of proposals (those with recent UTXOs)
- Better privacy than selective block downloads
- Minimal storage (~100 MB vs 14 GB full UTXO set)
- Acceptable bandwidth for desktop broadband

This makes SNICKER viable in a light client without compromising security or privacy.
