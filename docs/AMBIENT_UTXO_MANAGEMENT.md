● SNICKER Partial UTXO Set: Complete Design Document

  Project: Ambient SNICKER Light Client
  Target Platform: Linux Desktop
  Date: 2024-12-23
  Status: Design Finalized

  ---
  Table of Contents

  1. #1-core-problem
  2. #2-solution-partial-utxo-set
  3. #3-the-lobotomized-full-node-approach
  4. #4-three-dimensional-filtering
  5. #5-real-time-scanning-architecture
  6. #6-protocol-constraint-age-matching
  7. #7-privacy-analysis
  8. #8-implementation-details
  9. #9-storage-and-bandwidth
  10. #10-validation-workflow
  11. #11-configuration
  12. #12-edge-cases
  13. #13-comparison-to-alternatives

  ---
  1. Core Problem

  The DoS Attack Vector

  Light client receivers cannot validate proposer UTXOs, enabling attacks:

  Attacker creates proposals with:
    • Fake UTXOs (never existed)
    • Spent UTXOs (already consumed)
    • Wrong ownership (invalid signatures)

  Naive receiver:
    → Accepts proposal
    → Co-signs transaction
    → Broadcasts
    → Transaction rejected by network (invalid inputs)
    → Receiver's UTXO marked 'pending' but stuck forever
    → DoS: Attacker locks up receiver's capital without spending real UTXOs

  Why Light Clients Can't Validate

  Full node: Query UTXO set → instant validation
  Light client (BIP157): Can only see UTXOs matching subscribed scripts → cannot validate arbitrary proposer UTXOs

  The Two Problems We Must Solve

  1. Track OUR SNICKER UTXOs (creation, spends, confirmations)
  2. Validate PROPOSER'S UTXOs (exist, unspent, owned correctly)

  ---
  2. Solution: Partial UTXO Set

  Core Concept

  Instead of tracking the entire Bitcoin UTXO set (140M UTXOs, ~14 GB), maintain a small, focused subset of UTXOs relevant for SNICKER.

  Why It Works

  SNICKER has natural constraints that allow aggressive filtering:
  - Only cares about taproot (P2TR) outputs
  - Only cares about economically significant amounts (dust irrelevant)
  - Only cares about recent UTXOs (stale liquidity is bad)

  Result

  Global UTXO Set:  140,000,000 UTXOs × ~100 bytes = 14 GB
  Partial UTXO Set:     750,000 UTXOs ×  83 bytes = 60 MB

  Reduction factor: ~233x smaller

  60 MB is trivial on desktop Linux - could even go 10x larger if needed.

  ---
  3. The "Lobotomized Full Node" Approach

  Normal BIP157/158 Light Client

  For each block:
    1. Download compact filter (~20 KB)
    2. Check: filter.matches(my_scripts)?
       ├─ YES → Download full block (~1.5 MB)
       │         Privacy: Hidden in ~5000 outputs
       └─ NO  → Skip block (save bandwidth)

  Result:
    • Downloads ~1-5% of blocks (only matches)
    • Bandwidth: ~40-200 GB/year
    • Privacy: Reveals interest in specific blocks

  Our "Lobotomized Full Node"

  For each block:
    1. Skip filter check entirely
    2. Download full block (~1.5 MB) ALWAYS
    3. Scan entire block for:
       • Our wallet UTXOs (BDK)
       • SNICKER candidates (pattern matching)
       • Partial UTXO set (all P2TR >= 5000 sats)

  Result:
    • Downloads 100% of blocks
    • Bandwidth: ~79 GB/year
    • Privacy: Looks like full node observer (better!)

  Why "Lobotomized"?

  | Aspect    | Full Node            | Light Client            | Lobotomized Full Node (Us)     |
  |-----------|----------------------|-------------------------|--------------------------------|
  | Downloads | All blocks           | ~1-5% of blocks         | All blocks                     |
  | Stores    | Full chain (600+ GB) | Headers only (~100 MB)  | Headers + partial UTXO (60 MB) |
  | Validates | Full consensus rules | SPV proofs              | SPV proofs (trust Kyoto)       |
  | UTXO set  | Full set (14 GB)     | None                    | Partial set (60 MB)            |
  | Privacy   | Perfect              | Reveals script interest | Perfect (looks like observer)  |

  "Lobotomized" = Full node's download behavior, light client's storage/validation

  ---
  4. Three-Dimensional Filtering

  Filter 1: Script Type (P2TR Only)

  WHERE script_pubkey.is_p2tr()

  Rationale:
  - SNICKER requires Schnorr signatures (taproot)
  - Non-taproot outputs irrelevant
  - Reduction: ~70% of outputs discarded

  Filter 2: Amount (>= 5000 sats)

  WHERE amount >= 5000

  Rationale:
  - Dust and inscription spam irrelevant
  - Economic minimum for SNICKER liquidity
  - Bitcoin dust limit: 546 sats (P2TR)
  - Our minimum: 5000 sats (safety margin + anti-spam)
  - Reduction: ~50% of remaining outputs discarded

  Wallet constraint: Must respect this in SNICKER operations:
  const MIN_SNICKER_OUTPUT: u64 = 5000;

  // If change < 5000, add to fee instead
  if change_amount > 0 && change_amount < MIN_SNICKER_OUTPUT {
      fee += change_amount;  // Don't create dust output
  }

  Filter 3: Age (Last N Blocks)

  WHERE block_height >= (tip_height - SCAN_WINDOW_BLOCKS)

  Rationale:
  - SNICKER benefits from fresh liquidity
  - Stale UTXOs likely spent or inactive
  - Scan window: 1000 blocks (~1 week) default
  - Configurable: 500-5000 blocks (desktop can handle it)
  - Reduction: ~99.9% of outputs discarded

  Combined Effect

  Block N arrives with 5000 outputs:
    ├─ Filter 1 (P2TR): 5000 → 1500 (30% pass)
    ├─ Filter 2 (>= 5000 sats): 1500 → 750 (50% pass)
    └─ Filter 3 (age): Automatic (scanning recent blocks)

  Result: ~750 UTXOs per block added to partial set

  Over 1000 block window:
  - 750 UTXOs/block × 1000 blocks = 750,000 UTXOs
  - 750,000 × 83 bytes = 62.25 MB

  ---
  5. Real-Time Scanning Architecture

  NOT Batch Scanning

  ❌ Wrong approach:
  Every 10 blocks:
    → Scan last 1000 blocks
    → Re-process blocks 991-1000 multiple times
    → Wasteful, delayed

  Real-Time Per-Block Scanning

  ✅ Correct approach:
  Startup:
    1. Load last_scanned_height from DB
    2. Scan [last_scanned_height+1 .. tip]
    3. Build/update partial UTXO set

  Running (continuous):
    On each new block:
      1. Block already downloaded (for wallet sync)
      2. Scan block for partial UTXO set
      3. Add new UTXOs (P2TR, >= 5000 sats)
      4. Mark spends of existing UTXOs
      5. Prune UTXOs outside window
      6. Update last_scanned_height
      7. Continue automation logic

  Restart:
    1. Load last_scanned_height
    2. Scan [last_scanned_height+1 .. tip]
    3. Resume real-time scanning

  Benefits

  | Aspect     | Batch Scanning       | Real-Time Scanning |
  |------------|----------------------|--------------------|
  | Efficiency | Re-scans blocks 10x  | Each block once    |
  | Latency    | Up to 100 minutes    | ~10 minutes        |
  | Complexity | Timers + batch logic | Simple event hook  |
  | Accuracy   | Delayed              | Immediate          |

  Implementation: Hook Into background_sync

  async fn background_sync(
      wallet: Arc<Mutex<PersistedWallet>>,
      update_subscriber: Arc<Mutex<UpdateSubscriber>>,
      partial_utxo_set: Arc<Mutex<PartialUtxoSet>>,  // NEW
      ...
  ) {
      loop {
          // Wait for next block/update from Kyoto
          let mut sub = update_subscriber.lock().await;
          let update = sub.update().await?;
          drop(sub);

          // Apply to wallet (existing)
          let mut wallet = wallet.lock().await;
          wallet.apply_update(update.clone())?;
          let new_height = wallet.local_chain().tip().height();
          drop(wallet);

          // NEW: Scan new blocks for partial UTXO set
          let new_blocks = extract_blocks_from_update(&update)?;

          if !new_blocks.is_empty() {
              let mut utxo_set = partial_utxo_set.lock().await;

              for (height, block) in new_blocks {
                  utxo_set.scan_block(height, &block)?;
              }

              // Prune old UTXOs
              utxo_set.prune_older_than(
                  new_height.saturating_sub(SCAN_WINDOW_BLOCKS)
              )?;

              utxo_set.set_last_scanned_height(new_height)?;
          }

          // Continue with other tasks...
      }
  }

  Key insight: We're already downloading blocks for wallet sync, so scanning them for partial UTXO set is essentially free - just additional
  processing of data we already have.

  ---
  6. Protocol Constraint: Age Matching

  Rule: Proposer-Receiver UTXO Age Proximity

  "A proposer UTXO does not propose against receiver UTXOs created more than X blocks after its own creation."

  Example:
  Block 1000: Proposer UTXO created
  Block 1500: Receiver UTXO created (500 blocks newer)

  If max_age_delta = 200:
    → REJECT (proposer UTXO too old)

  If max_age_delta = 1000:
    → ACCEPT (within window)

  Rationale

  1. Liquidity freshness: Both parties operate in similar timeframes
  2. Scan window alignment: Receiver scans last N blocks, proposer must be within that window
  3. Prevents stale proposals: Old UTXOs likely spent or inactive
  4. Natural validation: Proposer UTXO outside receiver's scan window → automatic reject

  Configuration

  [snicker_protocol]
  max_utxo_age_delta_blocks = 1000  # ~1 week
  scan_window_blocks = 1000          # Must match or exceed age delta

  ---
  7. Privacy Analysis

  Selective Download (Normal BIP157)

  Download blocks: 1000, 1005, 1023, 1050, ...

  Observer sees:
    → "This user has scripts in these specific blocks"
    → Fingerprint: ~4-10 active addresses
    → Anonymity set: ~20,000-50,000 scripts (across downloaded blocks)

  Privacy leak: Reveals approximate wallet activity pattern

  Download Everything (Our Approach)

  Download blocks: ALL

  Observer sees:
    → "This user wants all blocks"
    → Looks like: Full node, block explorer, researcher, chain analyst
    → Anonymity set: ∞ (indistinguishable from any global observer)

  Privacy gain: No wallet-specific fingerprint revealed

  Paradoxical Privacy Improvement

  More bandwidth = Better privacy

  Downloading every block makes us indistinguishable from:
  - Full node operators
  - Block explorers (mempool.space, blockstream.info)
  - Chain analysis companies
  - Academic researchers
  - Any other entity that monitors the full blockchain

  No leaked information about our specific wallet contents.

  ---
  8. Implementation Details

  8.1 Database Schema

  CREATE TABLE partial_utxo_set (
      txid TEXT NOT NULL,
      vout INTEGER NOT NULL,
      amount INTEGER NOT NULL,          -- Satoshis
      script_pubkey BLOB NOT NULL,      -- Raw script bytes
      block_height INTEGER NOT NULL,    -- Creation height
      status TEXT NOT NULL DEFAULT 'unspent',  -- 'unspent' | 'spent'
      spent_in_txid TEXT,               -- NULL if unspent
      spent_at_height INTEGER,          -- NULL if unspent
      created_at INTEGER NOT NULL,      -- Unix timestamp
      PRIMARY KEY (txid, vout)
  );

  CREATE INDEX idx_status ON partial_utxo_set(status);
  CREATE INDEX idx_height ON partial_utxo_set(block_height);
  CREATE INDEX idx_amount ON partial_utxo_set(amount);

  -- Metadata table
  CREATE TABLE partial_utxo_metadata (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
  );

  -- Track last scanned height
  INSERT INTO partial_utxo_metadata (key, value)
  VALUES ('last_scanned_height', '0');

  8.2 Core: scan_block()

  impl PartialUtxoSet {
      /// Scan a single block and update the partial UTXO set
      pub fn scan_block(&mut self, height: u32, block: &Block) -> Result<()> {
          let mut utxos_added = 0;
          let mut utxos_spent = 0;

          for tx in &block.txdata {
              let txid = tx.compute_txid();

              // ═══════════════════════════════════════════
              // PHASE 1: Track spends (process inputs)
              // ═══════════════════════════════════════════
              for input in &tx.input {
                  if self.exists(&input.previous_output)? {
                      self.mark_spent(
                          input.previous_output,
                          txid,
                          height
                      )?;
                      utxos_spent += 1;
                  }
              }

              // ═══════════════════════════════════════════
              // PHASE 2: Track creations (process outputs)
              // ═══════════════════════════════════════════
              for (vout, output) in tx.output.iter().enumerate() {
                  // Filter 1: P2TR only
                  if !output.script_pubkey.is_p2tr() {
                      continue;
                  }

                  // Filter 2: >= 5000 sats only
                  let amount = output.value.to_sat();
                  if amount < MIN_SNICKER_OUTPUT {
                      continue;
                  }

                  // Filter 3: Age is implicit (we're scanning recent blocks)

                  // Add to partial set
                  self.insert(PartialUtxo {
                      txid,
                      vout: vout as u32,
                      amount,
                      script_pubkey: output.script_pubkey.clone(),
                      block_height: height,
                      status: UtxoStatus::Unspent,
                      spent_in_txid: None,
                      spent_at_height: None,
                      created_at: SystemTime::now()
                          .duration_since(UNIX_EPOCH)?
                          .as_secs(),
                  })?;

                  utxos_added += 1;
              }
          }

          if utxos_added > 0 || utxos_spent > 0 {
              tracing::debug!(
                  "Block {}: +{} UTXOs, -{} spends",
                  height, utxos_added, utxos_spent
              );
          }

          Ok(())
      }

      /// Prune UTXOs older than the scan window
      pub fn prune_older_than(&mut self, min_height: u32) -> Result<usize> {
          let deleted = self.conn.execute(
              "DELETE FROM partial_utxo_set WHERE block_height < ?",
              [min_height],
          )?;

          if deleted > 0 {
              tracing::info!("Pruned {} UTXOs older than height {}", deleted, min_height);
          }

          Ok(deleted)
      }
  }

  8.3 Startup: Initial Catch-Up

  pub async fn initialize_partial_utxo_set(&mut self) -> Result<()> {
      let last_scanned = self.partial_utxo_set.get_last_scanned_height()?;
      let tip = self.get_tip_height().await?;

      if last_scanned == 0 {
          // First run: build from scratch
          info!(
              "🔧 First run: building partial UTXO set from last {} blocks",
              SCAN_WINDOW_BLOCKS
          );

          let start_height = tip.saturating_sub(SCAN_WINDOW_BLOCKS - 1);
          self.scan_block_range(start_height, tip).await?;

          info!(
              "✅ Partial UTXO set initialized: {} UTXOs",
              self.partial_utxo_set.count()?
          );

      } else if tip > last_scanned {
          // Restart: catch up on missed blocks
          let missed = tip - last_scanned;
          info!("🔄 Catching up on {} missed blocks", missed);

          self.scan_block_range(last_scanned + 1, tip).await?;

          info!(
              "✅ Caught up. Partial UTXO set: {} UTXOs",
              self.partial_utxo_set.count()?
          );

      } else {
          info!(
              "✅ Partial UTXO set up to date (height {}, {} UTXOs)",
              last_scanned,
              self.partial_utxo_set.count()?
          );
      }

      Ok(())
  }

  async fn scan_block_range(&mut self, start: u32, end: u32) -> Result<()> {
      info!("📥 Downloading and scanning blocks {}-{}", start, end);

      let block_hashes = self
          .get_block_hashes_from_headers_db(start, end)
          .await?;

      let total = block_hashes.len();
      for (i, (height, hash)) in block_hashes.into_iter().enumerate() {
          if i % 100 == 0 {
              info!("Progress: {}/{} blocks scanned", i, total);
          }

          let block = self.requester.get_block(hash).await?.block;
          self.partial_utxo_set.scan_block(height, &block)?;
      }

      // Prune to keep only last SCAN_WINDOW_BLOCKS
      let window_start = end.saturating_sub(SCAN_WINDOW_BLOCKS);
      self.partial_utxo_set.prune_older_than(window_start)?;

      // Update checkpoint
      self.partial_utxo_set.set_last_scanned_height(end)?;

      Ok(())
  }

  ---
  9. Storage and Bandwidth

  Storage (Partial UTXO Set)

  Baseline (1000 block window):
  Outputs per block:     ~5,000
  P2TR (30%):            ~1,500
  >= 5000 sats (50%):      ~750

  UTXOs in set: 750 × 1000 = 750,000
  Size per UTXO: 83 bytes
  Total: 62.25 MB

  Extended window options (desktop can handle):
  | Window                  | UTXOs     | Storage |
  |-------------------------|-----------|---------|
  | 500 blocks (~3.5 days)  | 375,000   | 31 MB   |
  | 1,000 blocks (~1 week)  | 750,000   | 62 MB   |
  | 2,000 blocks (~2 weeks) | 1,500,000 | 124 MB  |
  | 5,000 blocks (~1 month) | 3,750,000 | 310 MB  |

  All trivial on desktop Linux.

  Bandwidth

  Annual:
  Blocks per year: 52,560
  Block size: ~1.5 MB average
  Total: 52,560 × 1.5 = 78.84 GB/year

  Daily:
  Blocks per day: 144
  Total: 144 × 1.5 = 216 MB/day

  Hourly:
  Blocks per hour: 6
  Total: 6 × 1.5 = 9 MB/hour

  Comparison:
  - Netflix HD streaming: ~3 GB/hour (333x more)
  - YouTube 1080p: ~2.5 GB/hour (277x more)
  - Our blockchain sync: ~9 MB/hour

  Totally acceptable for desktop with broadband.

  ---
  10. Validation Workflow

  When Receiving a Proposal

  pub async fn validate_proposal(
      &self,
      proposal: &Proposal,
  ) -> Result<ValidationResult> {
      let proposer_utxo = proposal.extract_proposer_utxo();

      // ═══════════════════════════════════════════════════
      // STEP 1: Query partial UTXO set (local, instant)
      // ═══════════════════════════════════════════════════
      match self.partial_utxo_set.get(proposer_utxo)? {

          Some(utxo) if utxo.status == UtxoStatus::Unspent => {
              // ✅ TRUSTLESS validation (we saw it in our scan)
              info!("✅ Proposer UTXO validated via partial UTXO set");

              // Additional checks
              if utxo.amount != proposal.expected_amount {
                  return Ok(ValidationResult::Reject("Amount mismatch"));
              }

              // Check age constraint
              let our_utxo_height = self.get_our_utxo_height(proposal)?;
              let age_delta = our_utxo_height.saturating_sub(utxo.block_height);

              if age_delta > self.config.max_utxo_age_delta_blocks {
                  return Ok(ValidationResult::Reject(
                      "Proposer UTXO too old for our UTXO"
                  ));
              }

              return Ok(ValidationResult::Accept);
          }

          Some(utxo) if utxo.status == UtxoStatus::Spent => {
              // ❌ We saw this UTXO spent in our scans
              info!(
                  "❌ Proposer UTXO already spent at height {}",
                  utxo.spent_at_height.unwrap()
              );
              return Ok(ValidationResult::Reject("UTXO already spent"));
          }

          None => {
              // ⚠️ UTXO not in our partial set
              warn!("⚠️  Proposer UTXO not found in partial UTXO set");
              warn!("    This could mean:");
              warn!("    • UTXO older than our scan window");
              warn!("    • UTXO doesn't exist (fake)");
              warn!("    • UTXO < 5000 sats (below our filter)");

              // ═══════════════════════════════════════════
              // STEP 2: Fallback strategy (configurable)
              // ═══════════════════════════════════════════
              match self.config.validation_mode {
                  ValidationMode::Strict => {
                      // Reject anything outside scan window
                      // This enforces freshness and prevents old UTXOs
                      Ok(ValidationResult::Reject(
                          "UTXO outside scan window (strict mode)"
                      ))
                  }

                  ValidationMode::Fallback => {
                      // Fall back to Tor API validation
                      // (From earlier research: mempool.space + blockstream.info)
                      info!("📡 Falling back to Tor API validation...");
                      self.validate_via_tor_apis(proposer_utxo).await
                  }
              }
          }
      }
  }

  async fn validate_via_tor_apis(
      &self,
      utxo: OutPoint,
  ) -> Result<ValidationResult> {
      // Query both APIs over Tor for redundancy
      let mempool_url = format!(
          "http://mempoolhqx4isw62xs7abwphsq7ldayuidyx2v2oethdhhj6mlo2r6ad.onion/signet/api/tx/{}/outspend/{}",
          utxo.txid, utxo.vout
      );

      let blockstream_url = format!(
          "http://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion/signet/api/tx/{}/outspend/{}",
          utxo.txid, utxo.vout
      );

      let (mempool_resp, blockstream_resp) = tokio::try_join!(
          self.tor_client.get(&mempool_url),
          self.tor_client.get(&blockstream_url)
      )?;

      // Both must agree on spend status
      let mempool_spent = mempool_resp["spent"].as_bool().unwrap_or(true);
      let blockstream_spent = blockstream_resp["spent"].as_bool().unwrap_or(true);

      if mempool_spent != blockstream_spent {
          warn!("APIs disagree on UTXO status - rejecting for safety");
          return Ok(ValidationResult::Reject("API disagreement"));
      }

      if mempool_spent {
          info!("❌ Proposer UTXO already spent (Tor API)");
          return Ok(ValidationResult::Reject("UTXO spent (API)"));
      }

      info!("✅ Proposer UTXO validated via Tor APIs (fallback)");
      Ok(ValidationResult::Accept)
  }

  Coverage Analysis

  Assuming 1000-block scan window:

  | Proposer UTXO Age | % of Proposals | Validation Method | Latency |
  |-------------------|----------------|-------------------|---------|
  | 0-1000 blocks     | ~90%           | Partial UTXO set  | <10ms   |
  | 1000+ blocks      | ~10%           | Tor API fallback  | ~10s    |

  Most proposals use recent UTXOs, so partial UTXO set handles vast majority with instant, trustless validation.

  ---
  11. Configuration

  config.toml

  [partial_utxo_set]
  # Scan window (number of recent blocks to keep in partial UTXO set)
  scan_window_blocks = 1000  # ~1 week (adjustable: 500-5000)

  # Minimum UTXO amount to track (sats)
  min_utxo_amount_sats = 5000  # Anti-dust/inscription filter

  # Script types to track
  script_types = ["p2tr"]  # Only taproot for SNICKER

  [snicker_protocol]
  # Maximum age difference between proposer and receiver UTXOs
  max_utxo_age_delta_blocks = 1000  # Must <= scan_window_blocks

  # Validation mode when proposer UTXO not in partial set
  validation_mode = "strict"  # "strict" | "fallback"
  # strict = reject if outside scan window (enforces freshness)
  # fallback = use Tor APIs (adds latency, reduces privacy slightly)

  [snicker]
  # Minimum SNICKER output size (must match partial_utxo_set filter)
  min_snicker_output_sats = 5000

  # Dust handling: change below min goes to fee
  drop_change_below_sats = 5000

  ---
  12. Edge Cases

  12.1 Reorg Handling

  Scenario: Block reorganization changes canonical chain.

  Solution:
  // Kyoto/BDK already handles reorgs in wallet chain
  // When reorg detected:
  fn on_reorg(&mut self, old_tip: u32, new_tip: u32, reorg_height: u32) -> Result<()> {
      info!("⚠️  Reorg detected at height {}", reorg_height);

      // Rollback partial UTXO set to reorg point
      self.partial_utxo_set.rollback_to(reorg_height)?;

      // Rescan from reorg point to new tip
      self.scan_block_range(reorg_height, new_tip).await?;

      Ok(())
  }

  12.2 UTXO Below Threshold

  Scenario: Proposer UTXO is 4000 sats (below our 5000 sat filter).

  Result:
  - Not in partial UTXO set
  - Validation mode determines outcome:
    - Strict: Reject (below our minimum)
    - Fallback: Query Tor APIs (might accept)

  This is OK: We don't want to participate in dust-level SNICKER anyway.

  12.3 Database Corruption

  Scenario: Partial UTXO set database corrupted.

  Solution:
  // On startup, verify integrity
  fn verify_database_integrity(&self) -> Result<bool> {
      // Check: can we query the database?
      let test = self.partial_utxo_set.count()?;

      // Check: is last_scanned_height reasonable?
      let last_scanned = self.partial_utxo_set.get_last_scanned_height()?;
      let tip = self.get_tip_height().await?;

      if last_scanned > tip {
          warn!("Database corruption: last_scanned > tip");
          return Ok(false);
      }

      Ok(true)
  }

  // If corrupted, rebuild from scratch
  if !verify_database_integrity()? {
      warn!("🔧 Rebuilding partial UTXO set from scratch");
      self.partial_utxo_set.reset()?;
      self.scan_block_range(tip - SCAN_WINDOW_BLOCKS, tip).await?;
  }

  12.4 First Run (No History)

  Scenario: User starts wallet for first time.

  Solution:
  // On first run (last_scanned_height == 0):
  // 1. Wallet syncs to tip (normal BDK/Kyoto process)
  // 2. Then scan last SCAN_WINDOW_BLOCKS
  // 3. Build initial partial UTXO set

  // This happens once, takes 10-30 minutes depending on bandwidth

  ---
  13. Comparison to Alternatives

  | Approach         | Storage | Bandwidth  | Validation | Privacy | Complexity |
  |------------------|---------|------------|------------|---------|------------|
  | Full UTXO set    | 14 GB   | Same       | Trustless  | Full    | High       |
  | Full node        | 600 GB  | Same       | Trustless  | Full    | Very High  |
  | Partial UTXO set | 60 MB   | 79 GB/year | Trustless* | Better  | Medium     |
  | Tor APIs only    | 0 MB    | Minimal    | Trusted    | Good    | Low        |
  | No validation    | 0 MB    | Minimal    | None       | Full    | Low        |

  *Trustless within scan window; configurable fallback to Tor APIs outside window

  Why Partial UTXO Set Wins

  ✅ Trustless validation (within scan window, covers 90%+ of proposals)
  ✅ Lightweight (60 MB vs 14 GB full UTXO set)
  ✅ Better privacy than selective downloads (looks like full node)
  ✅ Practical bandwidth (79 GB/year is fine for desktop broadband)
  ✅ Self-contained (no external dependencies for recent UTXOs)
  ✅ Enforces freshness (natural benefit of age filtering)

  ---
  Summary

  What We're Building

  A "lobotomized full node" that:
  1. Downloads every block (like full node)
  2. Scans every block in real-time as it arrives
  3. Extracts relevant UTXOs (P2TR, >= 5000 sats, recent)
  4. Maintains 60 MB partial UTXO set
  5. Validates proposals trustlessly (within scan window)
  6. Falls back to Tor APIs for old UTXOs (optional)

  Why It Works

  - Storage: 60 MB is trivial on desktop
  - Bandwidth: 79 GB/year is acceptable
  - Privacy: Better than selective downloads (looks like observer)
  - Validation: Trustless for 90%+ of proposals
  - Implementation: Simple real-time scanning, no timers

  Key Constraints

  1. Script type: P2TR only
  2. Amount: >= 5000 sats only
  3. Age: Last 1000 blocks (~1 week) only
  4. Protocol: Proposer UTXO can't be >1000 blocks older than receiver UTXO

  This Makes SNICKER Viable in a Light Client

  Without compromising:
  - ✅ Security (trustless validation)
  - ✅ Privacy (better than normal light clients)
  - ✅ Practicality (reasonable resource usage)

  ---
  End of Design Document

  This document captures the complete architecture for SNICKER partial UTXO set validation in the Ambient light client wallet.
