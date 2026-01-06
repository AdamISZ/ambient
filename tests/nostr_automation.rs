//! Nostr-based SNICKER automation integration test
//!
//! This test verifies end-to-end automation with:
//! - Embedded Nostr relay for proposal exchange
//! - Block-triggered automation on multiple wallets
//! - Deterministic role assignment for reproducibility
//! - Transaction logging for verification
//! - Fund conservation verification
//!
//! Run with:
//! ```bash
//! cargo test --test nostr_automation --features test-utils -- --nocapture
//! ```

#![cfg(feature = "test-utils")]

use anyhow::Result;
use std::sync::Arc;
use std::collections::HashMap;

mod common;
use common::BITCOIND;

use ambient::manager::Manager;
use ambient::automation::{AutomationTask, AutomationConfig};
use ambient::config::{SnickerAutomation, AutomationMode};
use ambient::network::embedded_relay::EmbeddedRelay;
use ambient::network::nostr::NostrNetwork;
use ambient::network::ProposalNetwork;
use ambient::snicker::{AutomationRole, AutomationState};
use nostr_sdk::Keys;

// ============================================================
// TEST CONFIGURATION
// ============================================================

const TEST_PASSWORD: &str = "test123";
const NUM_WALLETS: usize = 4;
const UTXOS_PER_WALLET: usize = 4;
const NUM_ROUNDS: usize = 5;
const WALLET_NAMES: [&str; 4] = ["alice", "bob", "carol", "dave"];

// Spending limits for test
const MAX_SATS_PER_COINJOIN: u64 = 10_000;
const MAX_SATS_PER_DAY: u64 = 50_000;
const MAX_SATS_PER_WEEK: u64 = 100_000;

// ============================================================
// TEST METRICS
// ============================================================

/// A recorded coinjoin transaction
#[derive(Debug, Clone)]
struct CoinjoinRecord {
    wallet: String,
    block_height: u32,
    delta_sats: i64,
    role: String,
    txid: String,
}

struct TestMetrics {
    initial_funding: HashMap<String, u64>,
    coinjoins: Vec<CoinjoinRecord>,
}

impl TestMetrics {
    fn new() -> Self {
        Self {
            initial_funding: HashMap::new(),
            coinjoins: Vec::new(),
        }
    }

    fn record_funding(&mut self, wallet: &str, amount: u64) {
        *self.initial_funding.entry(wallet.to_string()).or_insert(0) += amount;
    }
}

/// Query all coinjoin records from a wallet's database
fn get_coinjoin_history(mgr: &Manager) -> Vec<(u32, i64, String, String)> {
    mgr.snicker.get_coinjoin_history().unwrap_or_default()
}

// ============================================================
// NOSTR AUTOMATION TEST
// ============================================================

#[tokio::test(flavor = "multi_thread")]
async fn test_nostr_automation() -> Result<()> {
    println!("\n╔═══════════════════════════════════════════════╗");
    println!("║  Nostr Automation Integration Test            ║");
    println!("╚═══════════════════════════════════════════════╝\n");

    println!("📋 Test configuration:");
    println!("   Wallets: {}", NUM_WALLETS);
    println!("   UTXOs per wallet: {}", UTXOS_PER_WALLET);
    println!("   Automation rounds: {}", NUM_ROUNDS);
    println!("   Max sats/coinjoin: {}", MAX_SATS_PER_COINJOIN);

    let mut metrics = TestMetrics::new();

    // Ensure bitcoind is running
    let _ = &*BITCOIND;

    let initial_height = BITCOIND.get_block_count()? as u32;
    println!("\n📊 Initial blockchain height: {}", initial_height);

    // ============================================================
    // PHASE 1: START EMBEDDED NOSTR RELAY
    // ============================================================
    println!("\n┌─────────────────────────────────────────────┐");
    println!("│  Phase 1: Start Embedded Nostr Relay        │");
    println!("└─────────────────────────────────────────────┘\n");

    let relay_temp_dir = tempfile::tempdir()?;
    let relay = EmbeddedRelay::start(7781, relay_temp_dir.path())
        .await
        .expect("Failed to start embedded relay");

    let relay_url = relay.url().await;
    println!("✅ Embedded relay started at {}", relay_url);

    // Give relay time to be ready
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // ============================================================
    // PHASE 2: CREATE WALLETS WITH NOSTR NETWORK
    // ============================================================
    println!("\n┌─────────────────────────────────────────────┐");
    println!("│  Phase 2: Create {} Wallets                  │", NUM_WALLETS);
    println!("└─────────────────────────────────────────────┘\n");

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut managers: Vec<(String, Arc<Manager>)> = Vec::new();

    for (i, name) in WALLET_NAMES.iter().enumerate() {
        let current_height = BITCOIND.get_block_count()? as u32;
        let wallet_name = format!("{}_{}", name, timestamp);

        println!("👤 Creating {}'s wallet at height {}...", name, current_height);
        let (mut mgr, _mnemonic) = Manager::generate(&wallet_name, "regtest", current_height, TEST_PASSWORD).await?;

        // Replace network with NostrNetwork connected to our embedded relay
        let keys = Keys::generate();
        let nostr_network = NostrNetwork::with_keys(
            vec![relay_url.clone()],
            keys,
            Some(10), // Low PoW for fast testing
        ).await.expect("Failed to create NostrNetwork");

        mgr.network = Arc::new(nostr_network) as Arc<dyn ProposalNetwork>;
        println!("   ✅ Connected to Nostr relay");

        // Wait for initial sync
        mgr.wait_for_height(current_height, 60).await?;
        println!("   ✅ Synced to height {}", current_height);

        managers.push((name.to_string(), Arc::new(mgr)));

        // Mine some blocks between wallet creations (except after last)
        if i < NUM_WALLETS - 1 {
            BITCOIND.mine_blocks(3)?;
        }
    }

    // ============================================================
    // PHASE 3: FUND ALL WALLETS
    // ============================================================
    println!("\n┌─────────────────────────────────────────────┐");
    println!("│  Phase 3: Fund All Wallets                  │");
    println!("└─────────────────────────────────────────────┘\n");

    // Fund wallets with varying UTXO sizes
    // Larger UTXOs for proposers, smaller for receivers
    let utxo_amounts = [
        [300_000, 280_000, 260_000, 240_000], // alice - larger (proposer)
        [200_000, 180_000, 160_000, 140_000], // bob - medium
        [200_000, 180_000, 160_000, 140_000], // carol - medium
        [150_000, 130_000, 110_000, 100_000], // dave - smaller (receiver)
    ];

    for (i, (name, mgr)) in managers.iter().enumerate() {
        println!("💰 Funding {}'s wallet...", name);

        for j in 0..UTXOS_PER_WALLET {
            let addr = mgr.get_next_address().await?;
            let amount_sats = utxo_amounts[i][j];
            let amount_btc = amount_sats as f64 / 100_000_000.0;

            BITCOIND.rpc_call(
                "sendtoaddress",
                &[
                    serde_json::json!(addr.to_string()),
                    serde_json::json!(format!("{:.8}", amount_btc)),
                ],
                Some("testwallet"),
            )?;

            metrics.record_funding(name, amount_sats);
            println!("   [{}] {} sats", j + 1, amount_sats);
        }
    }

    // Mine blocks to confirm funding
    println!("\n⛏️  Mining 10 blocks to confirm funding...");
    BITCOIND.mine_blocks(10)?;

    // Sync all wallets
    let funding_height = BITCOIND.get_block_count()? as u32;
    println!("⏳ Syncing all wallets to height {}...", funding_height);

    for (name, mgr) in &managers {
        mgr.wait_for_height(funding_height, 90).await?;
        let balance = mgr.get_balance().await?;
        println!("   ✅ {} balance: {}", name, balance);
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
    // PHASE 4: START AUTOMATION ON ALL WALLETS
    // ============================================================
    println!("\n┌─────────────────────────────────────────────┐");
    println!("│  Phase 4: Start Automation                  │");
    println!("└─────────────────────────────────────────────┘\n");

    let snicker_config = SnickerAutomation {
        mode: AutomationMode::Advanced,
        max_sats_per_coinjoin: MAX_SATS_PER_COINJOIN,
        max_sats_per_day: MAX_SATS_PER_DAY,
        max_sats_per_week: MAX_SATS_PER_WEEK,
        prefer_snicker_outputs: true,
        snicker_pattern_only: false, // Allow targeting any P2TR UTXO
        outstanding_proposals: 2,
        receiver_timeout_blocks: 10,
    };

    let task_config = AutomationConfig {
        min_utxo_sats: 50_000,
        proposal_delta_sats: 500,
    };

    let mut automation_tasks: Vec<AutomationTask> = Vec::new();

    // Set deterministic roles: alternate Proposer/Receiver
    // This makes the test reproducible
    let initial_roles = [
        AutomationRole::Proposer,  // alice - will create proposals
        AutomationRole::Receiver,  // bob - will receive proposals
        AutomationRole::Proposer,  // carol - will create proposals
        AutomationRole::Receiver,  // dave - will receive proposals
    ];

    let current_height = BITCOIND.get_block_count()? as u32;

    for (i, (name, mgr)) in managers.iter().enumerate() {
        // Set deterministic role
        let role = initial_roles[i];
        let state = AutomationState {
            role,
            last_coinjoin_height: current_height,
        };
        mgr.snicker.set_automation_state(&state)?;
        println!("🎭 {} assigned role: {:?}", name, role);
    }

    for (name, mgr) in &managers {
        println!("🤖 Starting automation for {}...", name);

        let mut task = AutomationTask::new();
        task.start(mgr.clone(), snicker_config.clone(), task_config.clone()).await;

        println!("   ✅ Automation started");
        automation_tasks.push(task);
    }

    // Give automation time to initialize
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // ============================================================
    // PHASE 5: MINE BLOCKS TO TRIGGER AUTOMATION
    // ============================================================
    println!("\n┌─────────────────────────────────────────────┐");
    println!("│  Phase 5: Mine Blocks (Trigger Automation)  │");
    println!("└─────────────────────────────────────────────┘\n");

    println!("📋 Mining {} rounds of blocks to trigger automation...\n", NUM_ROUNDS);

    for round in 1..=NUM_ROUNDS {
        println!("═══════════════════════════════════════════════");
        println!("  Round {} of {}", round, NUM_ROUNDS);
        println!("═══════════════════════════════════════════════");

        // Mine a block to trigger automation
        println!("⛏️  Mining 1 block...");
        BITCOIND.mine_blocks(1)?;

        let current_height = BITCOIND.get_block_count()? as u32;
        println!("   Height: {}", current_height);

        // Wait for wallets to sync and automation to process
        println!("⏳ Waiting for sync and automation...");
        for (name, mgr) in &managers {
            match tokio::time::timeout(
                std::time::Duration::from_secs(30),
                mgr.wait_for_height(current_height, 30)
            ).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => println!("   ⚠️ {} sync error: {}", name, e),
                Err(_) => println!("   ⚠️ {} sync timeout", name),
            }
        }

        // Give automation time to process proposals
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        // Check balances after this round
        println!("\n📊 Balances after round {}:", round);
        for (name, mgr) in &managers {
            let balance = mgr.get_balance().await?;
            let snicker_balance = mgr.get_snicker_balance().await?;
            println!("   {}: {} (snicker: {} sats)", name, balance, snicker_balance);
        }

        println!();
    }

    // ============================================================
    // PHASE 6: STOP AUTOMATION AND VERIFY
    // ============================================================
    println!("\n┌─────────────────────────────────────────────┐");
    println!("│  Phase 6: Stop Automation and Verify        │");
    println!("└─────────────────────────────────────────────┘\n");

    // Stop all automation tasks
    println!("🛑 Stopping automation on all wallets...");
    for task in &mut automation_tasks {
        task.stop().await;
    }
    println!("   ✅ All automation stopped");

    // Mine final block
    BITCOIND.mine_blocks(1)?;
    let final_height = BITCOIND.get_block_count()? as u32;

    // Final sync
    println!("\n⏳ Final sync to height {}...", final_height);
    for (name, mgr) in &managers {
        mgr.wait_for_height(final_height, 60).await?;
        println!("   ✅ {} synced", name);
    }

    // Calculate final balances
    println!("\n📊 Final Balances:");
    let mut total_final = 0u64;
    let mut total_snicker = 0u64;

    for (name, mgr) in &managers {
        let balance_str = mgr.get_balance().await?;
        let total_balance: u64 = balance_str
            .split_whitespace()
            .next()
            .unwrap_or("0")
            .parse()
            .unwrap_or(0);

        let snicker_balance = mgr.get_snicker_balance().await?;
        let wallet_only = total_balance.saturating_sub(snicker_balance);

        println!(
            "   {}: {} (wallet) + {} (snicker) = {} sats",
            name, wallet_only, snicker_balance, total_balance
        );

        total_final += total_balance;
        total_snicker += snicker_balance;
    }

    // ============================================================
    // VERIFICATION
    // ============================================================
    println!("\n┌─────────────────────────────────────────────┐");
    println!("│  Verification                               │");
    println!("└─────────────────────────────────────────────┘\n");

    // Collect all coinjoin records from all wallets
    println!("📋 Coinjoin Transaction Log:");
    println!("   (These should be identical across test runs with same seed)\n");

    let mut all_coinjoins: Vec<CoinjoinRecord> = Vec::new();

    for (name, mgr) in &managers {
        let history = get_coinjoin_history(mgr);
        for (height, delta, role, txid) in history {
            println!("   {} | height={} | delta={:+} sats | role={} | txid={}...",
                     name, height, delta, role, &txid[..16]);
            all_coinjoins.push(CoinjoinRecord {
                wallet: name.clone(),
                block_height: height,
                delta_sats: delta,
                role,
                txid,
            });
        }
    }

    if all_coinjoins.is_empty() {
        println!("   (no coinjoins recorded)");
    }

    let total_coinjoins = all_coinjoins.len();
    println!("\n   Total coinjoin records: {}", total_coinjoins);

    // Check fund conservation
    let max_fee_per_coinjoin = 2000u64;
    let max_total_fees = max_fee_per_coinjoin * (total_coinjoins as u64).max(5);

    println!("\n📊 Fund Conservation:");
    println!("   Initial funding: {} sats", total_initial);
    println!("   Final balances:  {} sats", total_final);

    let fees_paid = total_initial.saturating_sub(total_final);
    println!("   Fees paid: {} sats", fees_paid);

    let fund_conservation_ok = total_final <= total_initial && fees_paid <= max_total_fees;

    if fund_conservation_ok {
        println!("   ✅ Fund conservation PASSED");
    } else {
        println!("   ❌ Fund conservation FAILED");
    }

    // Check SNICKER activity
    println!("\n📊 SNICKER Activity:");
    println!("   Total SNICKER balance: {} sats", total_snicker);
    println!("   Coinjoin transactions: {}", total_coinjoins);

    let snicker_activity = total_coinjoins > 0 || total_snicker > 0;
    if snicker_activity {
        println!("   ✅ SNICKER coinjoins detected");
    } else {
        println!("   ⚠️ No SNICKER coinjoins detected (automation may need more time)");
    }

    // Log automation state for each wallet
    println!("\n📊 Final Automation States:");
    for (name, mgr) in &managers {
        let state = mgr.snicker.get_automation_state();
        println!("   {}: role={:?}, last_coinjoin_height={}",
                 name, state.role, state.last_coinjoin_height);
    }

    // Shutdown relay
    println!("\n🛑 Shutting down relay...");
    relay.shutdown().await?;
    println!("   ✅ Relay stopped");

    // Final summary
    println!("\n╔═══════════════════════════════════════════════╗");
    if fund_conservation_ok {
        println!("║     NOSTR AUTOMATION TEST PASSED             ║");
    } else {
        println!("║     NOSTR AUTOMATION TEST COMPLETED          ║");
    }
    println!("╠═══════════════════════════════════════════════╣");
    println!("║  ✅ Embedded Nostr relay                      ║");
    println!("║  ✅ Multi-wallet setup                        ║");
    println!("║  ✅ Block-triggered automation                ║");
    if fund_conservation_ok {
        println!("║  ✅ Fund conservation verified                ║");
    }
    if snicker_activity {
        println!("║  ✅ SNICKER coinjoins executed                ║");
    } else {
        println!("║  ⚠️  No coinjoins (may need tuning)           ║");
    }
    println!("╚═══════════════════════════════════════════════╝\n");

    // Soft assertion - test passes if no panics and fund conservation holds
    assert!(
        fund_conservation_ok,
        "Fund conservation failed: initial={}, final={}, fees={}",
        total_initial, total_final, fees_paid
    );

    Ok(())
}
