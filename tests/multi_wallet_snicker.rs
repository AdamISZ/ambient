use anyhow::Result;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use std::collections::HashMap;

mod common;
use common::BITCOIND;

use ambient::manager::Manager;

/// Sync all wallets to the given height in parallel
async fn sync_all_wallets(
    managers: &[(String, Manager)],
    target_height: u32,
    timeout_secs: u64,
) -> Result<()> {
    // Create futures for all wallet syncs
    let sync_futures: Vec<_> = managers
        .iter()
        .map(|(name, mgr)| {
            let name = name.clone();
            async move {
                mgr.wait_for_height(target_height, timeout_secs).await?;
                Ok::<_, anyhow::Error>(name)
            }
        })
        .collect();

    // Wait for all syncs in parallel
    let results = futures::future::join_all(sync_futures).await;

    // Check results and report
    for result in results {
        match result {
            Ok(name) => println!("   ✅ {} synced to {}", name, target_height),
            Err(e) => return Err(e),
        }
    }

    Ok(())
}

// ============================================================
// TEST CONFIGURATION
// ============================================================

const TEST_SEED: u64 = 0xDEADBEEF;
const NUM_WALLETS: usize = 4;
const UTXOS_PER_WALLET: usize = 4;
const MIN_UTXO_SATS: u64 = 50_000;
const MAX_UTXO_SATS: u64 = 300_000;
const NUM_PROPOSAL_ROUNDS: usize = 3;
const TEST_PASSWORD: &str = "test123";

// Wallet names for clarity
const WALLET_NAMES: [&str; 4] = ["alice", "bob", "carol", "dave"];

// ============================================================
// TEST METRICS
// ============================================================

struct CompletedCoinjoin {
    proposer: String,
    receiver: String,
    txid: String,
}

struct TestMetrics {
    initial_funding: HashMap<String, u64>,
    coinjoins_completed: Vec<CompletedCoinjoin>,
}

impl TestMetrics {
    fn new() -> Self {
        Self {
            initial_funding: HashMap::new(),
            coinjoins_completed: Vec::new(),
        }
    }

    fn record_funding(&mut self, wallet: &str, amount: u64) {
        *self.initial_funding.entry(wallet.to_string()).or_insert(0) += amount;
    }

    fn record_coinjoin(&mut self, proposer: &str, receiver: &str, txid: &str) {
        self.coinjoins_completed.push(CompletedCoinjoin {
            proposer: proposer.to_string(),
            receiver: receiver.to_string(),
            txid: txid.to_string(),
        });
    }
}

// ============================================================
// MULTI-WALLET SNICKER TEST
// ============================================================

#[tokio::test(flavor = "multi_thread")]
async fn test_multi_wallet_snicker() -> Result<()> {
    println!("\n╔═══════════════════════════════════════════════╗");
    println!("║  Multi-Wallet SNICKER Integration Test        ║");
    println!("╚═══════════════════════════════════════════════╝\n");

    // Initialize seeded RNG for reproducibility
    let mut rng = ChaCha8Rng::seed_from_u64(TEST_SEED);
    let mut metrics = TestMetrics::new();

    // Ensure bitcoind is running
    let _ = &*BITCOIND;

    let initial_height = BITCOIND.get_block_count()? as u32;
    println!("📊 Initial blockchain height: {}\n", initial_height);

    // ============================================================
    // PHASE 1: CREATE WALLETS AT STAGGERED HEIGHTS
    // ============================================================
    println!("┌─────────────────────────────────────────────┐");
    println!("│  Phase 1: Create {} Wallets                  │", NUM_WALLETS);
    println!("└─────────────────────────────────────────────┘\n");

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut managers: Vec<(String, Manager)> = Vec::new();

    for (i, name) in WALLET_NAMES.iter().enumerate() {
        // Create wallet at current height
        let current_height = BITCOIND.get_block_count()? as u32;
        let wallet_name = format!("{}_{}", name, timestamp);

        println!("👤 Creating {}'s wallet at height {}...", name, current_height);
        let (mgr, mnemonic) = Manager::generate(&wallet_name, "regtest", current_height, TEST_PASSWORD).await?;
        let mnemonic_str = mnemonic.to_string();
        println!("   ✅ Mnemonic: {}...", &mnemonic_str[..20]);

        // Wait for initial sync (longer timeout for multi-wallet test)
        mgr.wait_for_height(current_height, 60).await?;
        println!("   ✅ Synced to height {}", current_height);

        managers.push((name.to_string(), mgr));

        // Mine some blocks between wallet creations (except after last wallet)
        if i < NUM_WALLETS - 1 {
            let blocks_to_mine = rng.gen_range(5..15);
            println!("   ⛏️  Mining {} blocks...", blocks_to_mine);
            BITCOIND.mine_blocks(blocks_to_mine)?;
        }
    }

    // ============================================================
    // PHASE 2: FUND ALL WALLETS
    // ============================================================
    println!("\n┌─────────────────────────────────────────────┐");
    println!("│  Phase 2: Fund All Wallets                  │");
    println!("└─────────────────────────────────────────────┘\n");

    // Collect all funding transactions first
    for (name, mgr) in &managers {
        println!("💰 Funding {}'s wallet with {} UTXOs...", name, UTXOS_PER_WALLET);

        for j in 0..UTXOS_PER_WALLET {
            let addr = mgr.get_next_address().await?;
            let amount_sats = rng.gen_range(MIN_UTXO_SATS..MAX_UTXO_SATS);
            let amount_btc = amount_sats as f64 / 100_000_000.0;

            let txid = BITCOIND.rpc_call(
                "sendtoaddress",
                &[
                    serde_json::json!(addr.to_string()),
                    serde_json::json!(format!("{:.8}", amount_btc)),
                ],
                Some("testwallet"),
            )?;

            metrics.record_funding(name, amount_sats);
            println!(
                "   [{}] {} sats to {} (txid: {}...)",
                j + 1,
                amount_sats,
                &addr.to_string()[..20],
                &txid.as_str().unwrap_or("?")[..8]
            );
        }
    }

    // Mine blocks to confirm all funding transactions
    println!("\n⛏️  Mining 10 blocks to confirm funding...");
    BITCOIND.mine_blocks(10)?;

    // Wait for all wallets to sync in parallel
    let funding_height = BITCOIND.get_block_count()? as u32;
    println!("⏳ Waiting for all wallets to sync to height {}...", funding_height);
    sync_all_wallets(&managers, funding_height, 90).await?;

    // Print balances
    for (name, mgr) in &managers {
        let balance = mgr.get_balance().await?;
        println!("   {} balance: {}", name, balance);
    }

    // Print initial funding summary
    println!("\n📊 Initial Funding Summary:");
    let mut total_initial = 0u64;
    for (name, amount) in &metrics.initial_funding {
        println!("   {}: {} sats", name, amount);
        total_initial += amount;
    }
    println!("   Total: {} sats", total_initial);

    // ============================================================
    // PHASE 3: PROPOSAL ROUNDS
    // ============================================================
    println!("\n┌─────────────────────────────────────────────┐");
    println!("│  Phase 3: {} Proposal Rounds                 │", NUM_PROPOSAL_ROUNDS);
    println!("└─────────────────────────────────────────────┘\n");

    for round in 0..NUM_PROPOSAL_ROUNDS {
        println!("═══════════════════════════════════════════════");
        println!("  Round {} of {}", round + 1, NUM_PROPOSAL_ROUNDS);
        println!("═══════════════════════════════════════════════\n");

        // Deterministically select proposer
        let proposer_idx = round % NUM_WALLETS;
        let proposer_name = managers[proposer_idx].0.clone();
        let proposer_mgr = &managers[proposer_idx].1;

        println!("🎯 {} creating proposals...", proposer_name);

        // Proposer finds opportunities
        println!("\n🔍 {} scanning for opportunities...", proposer_name);
        let opportunities = proposer_mgr
            .find_snicker_opportunities(
                10_000,  // min candidate size
                250_000, // max candidate size
                0,       // all blocks
            )
            .await?;

        println!("   Found {} opportunities", opportunities.len());

        if opportunities.is_empty() {
            println!("   ⚠️  No opportunities found, skipping round");
            BITCOIND.mine_blocks(1)?;
            continue;
        }

        // Select first opportunity
        let opportunity = &opportunities[0];
        println!(
            "   Selected: Our UTXO {}:{} ({} sats) → Target {} sats",
            &opportunity.our_outpoint.txid.to_string()[..8],
            opportunity.our_outpoint.vout,
            opportunity.our_value.to_sat(),
            opportunity.target_txout.value.to_sat()
        );

        // Create proposal
        println!("\n📝 {} creating proposal...", proposer_name);
        let delta_sats = 1000;

        let result = proposer_mgr
            .create_snicker_proposal(opportunity, delta_sats, ambient::config::MIN_UTXO_SIZE)
            .await;

        let (signed_psbt, encrypted_proposal) = match result {
            Ok(r) => r,
            Err(e) => {
                println!("   ⚠️  Failed to create proposal: {}", e);
                BITCOIND.mine_blocks(1)?;
                continue;
            }
        };

        println!(
            "   ✅ Proposal created, {} inputs, {} outputs",
            signed_psbt.psbt.unsigned_tx.input.len(),
            signed_psbt.psbt.unsigned_tx.output.len()
        );

        // Store proposal in ALL wallets (simulating broadcast)
        // Only the wallet that owns the target UTXO will be able to decrypt it
        println!("\n📤 Broadcasting proposal to all wallets...");
        for (name, mgr) in &managers {
            if *name != proposer_name {
                mgr.store_snicker_proposal(&encrypted_proposal).await?;
            }
        }

        // All non-proposer wallets scan for proposals
        let acceptable_delta = (-2000, 5000);
        let mut found_receiver: Option<(String, ambient::snicker::Proposal)> = None;

        println!("\n🔍 All wallets scanning for proposals...");
        for (name, mgr) in &managers {
            if *name == proposer_name {
                continue;
            }
            let proposals = mgr.scan_for_our_proposals(acceptable_delta).await?;
            if !proposals.is_empty() {
                println!("   ✅ {} found {} proposal(s)", name, proposals.len());
                found_receiver = Some((name.clone(), proposals.into_iter().next().unwrap()));
                break;
            } else {
                println!("   {} found 0 proposals", name);
            }
        }

        let (receiver_name, proposal) = match found_receiver {
            Some(r) => r,
            None => {
                println!("   ⚠️  No wallet could decrypt the proposal, skipping");
                BITCOIND.mine_blocks(1)?;
                continue;
            }
        };

        // Get receiver manager
        let receiver_mgr = &managers.iter().find(|(n, _)| *n == receiver_name).unwrap().1;

        // Accept proposal
        println!("\n✍️  {} accepting proposal...", receiver_name);

        let fully_signed = match receiver_mgr
            .accept_snicker_proposal(&proposal.tag, acceptable_delta)
            .await
        {
            Ok(psbt) => psbt,
            Err(e) => {
                println!("   ⚠️  Failed to accept proposal: {}", e);
                BITCOIND.mine_blocks(1)?;
                continue;
            }
        };

        println!("   ✅ Proposal signed");

        // Finalize and broadcast
        println!("\n🔨 Finalizing transaction...");
        let coinjoin_tx = receiver_mgr.finalize_psbt(fully_signed).await?;
        let txid = coinjoin_tx.compute_txid();

        println!("   Txid: {}", txid);
        println!("   Inputs: {}, Outputs: {}", coinjoin_tx.input.len(), coinjoin_tx.output.len());

        // Broadcast
        println!("\n📡 Broadcasting transaction...");
        use bdk_wallet::bitcoin::consensus::encode::serialize_hex;
        let tx_hex = serialize_hex(&coinjoin_tx);

        match BITCOIND.rpc_call("sendrawtransaction", &[serde_json::json!(tx_hex)], None) {
            Ok(_) => {
                println!("   ✅ Broadcast successful");
                metrics.record_coinjoin(&proposer_name, &receiver_name, &txid.to_string());

                // Store receiver's SNICKER UTXO
                let receiver_utxos = receiver_mgr.wallet_node.get_all_wallet_utxos().await?;
                receiver_mgr
                    .store_accepted_snicker_utxo(&proposal, &coinjoin_tx, &receiver_utxos)
                    .await?;
            }
            Err(e) => {
                println!("   ⚠️  Broadcast failed: {}", e);
            }
        }

        // Mine blocks between rounds
        let blocks_to_mine = rng.gen_range(1..5);
        println!("\n⛏️  Mining {} blocks...", blocks_to_mine);
        BITCOIND.mine_blocks(blocks_to_mine)?;

        // Sync all wallets in parallel
        let new_height = BITCOIND.get_block_count()? as u32;
        sync_all_wallets(&managers, new_height, 90).await?;
    }

    // ============================================================
    // PHASE 4: VERIFICATION
    // ============================================================
    println!("\n┌─────────────────────────────────────────────┐");
    println!("│  Phase 4: Verification                      │");
    println!("└─────────────────────────────────────────────┘\n");

    // Mine final block to ensure all txs confirmed
    BITCOIND.mine_blocks(1)?;
    let final_height = BITCOIND.get_block_count()? as u32;

    // Sync all wallets in parallel
    println!("⏳ Final sync to height {}...", final_height);
    sync_all_wallets(&managers, final_height, 90).await?;

    // Get final balances
    // Note: get_balance() already includes SNICKER balance
    println!("\n📊 Final Balances:");
    let mut total_final = 0u64;
    for (name, mgr) in &managers {
        // get_balance() returns regular + snicker combined
        let total_balance_str = mgr.get_balance().await?;
        let total_balance: u64 = total_balance_str
            .split_whitespace()
            .next()
            .unwrap_or("0")
            .parse()
            .unwrap_or(0);

        let snicker_balance = mgr.get_snicker_balance().await?;
        let wallet_only = total_balance - snicker_balance;

        println!(
            "   {}: {} (wallet) + {} (snicker) = {} sats",
            name, wallet_only, snicker_balance, total_balance
        );
        total_final += total_balance;
    }

    // Verification checks
    println!("\n🔍 Verification Results:");

    // Check 1: Coinjoin count
    // With 3 rounds and 4 wallets, we expect at least 1 successful coinjoin
    // (timing and UTXO availability can cause some rounds to fail)
    let min_expected_coinjoins = 1;
    let actual_coinjoins = metrics.coinjoins_completed.len();
    println!(
        "   Coinjoins completed: {} (minimum expected: {})",
        actual_coinjoins, min_expected_coinjoins
    );

    if actual_coinjoins >= min_expected_coinjoins {
        println!("   ✅ Coinjoin count check PASSED");
    } else {
        println!("   ❌ Coinjoin count check FAILED");
    }

    // Check 2: Fund conservation (with tolerance for fees)
    // Each coinjoin pays some fee, so final should be less than initial
    let max_reasonable_fee_per_tx = 5000u64; // 5000 sats per tx max
    let max_total_fees = max_reasonable_fee_per_tx * actual_coinjoins as u64;

    println!("\n   Fund conservation:");
    println!("     Initial funding: {} sats", total_initial);
    println!("     Final balances:  {} sats", total_final);

    let fees_paid = if total_initial >= total_final {
        total_initial - total_final
    } else {
        println!("     ⚠️  ERROR: Final > Initial by {} sats!", total_final - total_initial);
        0
    };

    println!(
        "     Fees paid: {} sats ({} sats per coinjoin avg)",
        fees_paid,
        if actual_coinjoins > 0 {
            fees_paid / actual_coinjoins as u64
        } else {
            0
        }
    );

    let fund_conservation_ok = total_final <= total_initial && fees_paid <= max_total_fees;
    if fund_conservation_ok {
        println!("   ✅ Fund conservation check PASSED");
    } else {
        println!(
            "   ❌ Fund conservation check FAILED (fees {} > max {} or funds increased)",
            fees_paid, max_total_fees
        );
    }

    // List completed coinjoins
    println!("\n📋 Completed Coinjoins:");
    for (i, cj) in metrics.coinjoins_completed.iter().enumerate() {
        println!(
            "   [{}] {} → {} (txid: {}...)",
            i + 1,
            cj.proposer,
            cj.receiver,
            &cj.txid[..16]
        );
    }

    // Final assertions
    assert!(
        actual_coinjoins >= min_expected_coinjoins,
        "Expected at least {} coinjoins, got {}",
        min_expected_coinjoins,
        actual_coinjoins
    );

    assert!(
        fund_conservation_ok,
        "Fund conservation failed: initial={}, final={}, fees={}",
        total_initial,
        total_final,
        fees_paid
    );

    println!("\n╔═══════════════════════════════════════════════╗");
    println!("║        TEST PASSED SUCCESSFULLY               ║");
    println!("╚═══════════════════════════════════════════════╝\n");

    Ok(())
}
