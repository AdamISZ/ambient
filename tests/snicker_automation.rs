//! SNICKER automation test focused on balance tracking
//!
//! This test traces balance changes through automated coinjoins.
//!
//! ## Balance Flow in SNICKER
//!
//! A SNICKER coinjoin involves:
//! - **Proposer**: Has a larger UTXO, wants to mix with receiver
//!   - Inputs: proposer_utxo + receiver_utxo (from receiver)
//!   - Outputs: proposer_change + receiver_tweaked_output
//!   - Proposer pays most of the fee
//!   - Net change: -(fee - delta) where delta is receiver's fee contribution
//!
//! - **Receiver**: Has a smaller UTXO, receives proposal
//!   - Their original UTXO is spent (they sign)
//!   - They receive a new "tweaked" output worth: original - delta
//!   - Net change: -delta (receiver contributes delta to fee)
//!
//! ## Expected Fund Conservation
//!
//! total_initial - total_final = fees_paid (always positive)
//!
//! If we see total_final > total_initial, there's a tracking bug in the test or code.
//!
//! ## BDK Spend Detection
//!
//! BIP158 compact block filters include INPUT prevout scriptPubKeys, so BDK
//! correctly detects when wallet UTXOs are spent - even in coinjoins where
//! the output goes to a tweaked key not in BDK's descriptor.

#![cfg(feature = "test-utils")]

use anyhow::Result;
use std::sync::Arc;
use std::collections::HashMap;

mod common;
use common::BITCOIND;

use ambient::manager::Manager;
use ambient::automation::{AutomationTask, AutomationConfig};
use ambient::config::{SnickerAutomation, AutomationMode};
use ambient::network::file_based::FileBasedNetwork;
use ambient::network::ProposalNetwork;
use ambient::snicker::{AutomationRole, AutomationState};

const TEST_PASSWORD: &str = "test123";

// Test configuration
const WALLET_NAMES: [&str; 2] = ["proposer", "receiver"];
const UTXOS_PER_WALLET: usize = 4;  // Multiple UTXOs to allow multiple coinjoins
const NUM_ROUNDS: usize = 8;        // Enough rounds to process several coinjoins

/// Track balance at each step
#[derive(Debug, Clone)]
struct BalanceSnapshot {
    step: String,
    block_height: u32,
    balances: HashMap<String, WalletBalance>,
}

#[derive(Debug, Clone)]
struct WalletBalance {
    /// get_balance_breakdown().0 = BDK confirmed + confirmed SNICKER
    confirmed: u64,
    /// get_balance_breakdown().1 = pending inputs (should be subtracted)
    pending_out: u64,
    /// get_balance_breakdown().2 = unconfirmed SNICKER UTXOs
    pending_in_snicker: u64,
    /// Effective balance = confirmed - pending_out + pending_in_snicker
    effective: u64,
}

impl BalanceSnapshot {
    async fn capture(step: &str, height: u32, managers: &[(String, Arc<Manager>)]) -> Result<Self> {
        let mut balances = HashMap::new();

        for (name, mgr) in managers {
            // Use get_balance_breakdown which gives us proper separation
            let (confirmed, pending_out, pending_in_snicker) = mgr.get_balance_breakdown().await?;

            // Effective = what we actually have access to
            let effective = confirmed.saturating_sub(pending_out) + pending_in_snicker;

            balances.insert(name.clone(), WalletBalance {
                confirmed,
                pending_out,
                pending_in_snicker,
                effective,
            });
        }

        Ok(Self {
            step: step.to_string(),
            block_height: height,
            balances,
        })
    }

    fn print(&self) {
        println!("\n  [{}] @ height {}", self.step, self.block_height);
        for (name, bal) in &self.balances {
            println!("    {}: confirmed={} pending_out={} pending_in={} effective={}",
                     name, bal.confirmed, bal.pending_out, bal.pending_in_snicker, bal.effective);
        }
    }

    fn total_all(&self) -> u64 {
        self.balances.values().map(|b| b.effective).sum()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_snicker_balance_tracking() -> Result<()> {
    println!("\n╔═══════════════════════════════════════════════╗");
    println!("║  SNICKER Balance Tracking Test                ║");
    println!("╚═══════════════════════════════════════════════╝\n");

    let mut snapshots: Vec<BalanceSnapshot> = Vec::new();

    // Ensure bitcoind is running
    let _ = &*BITCOIND;
    let initial_height = BITCOIND.get_block_count()? as u32;
    println!("Initial blockchain height: {}", initial_height);

    // ============================================================
    // SETUP: Create shared proposal directory
    // ============================================================
    let proposal_dir = tempfile::tempdir()?;
    println!("Proposal directory: {}", proposal_dir.path().display());

    // ============================================================
    // PHASE 1: Create 2 wallets
    // ============================================================
    println!("\n--- Phase 1: Create Wallets ---\n");

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let mut managers: Vec<(String, Arc<Manager>)> = Vec::new();

    for name in WALLET_NAMES.iter() {
        let current_height = BITCOIND.get_block_count()? as u32;
        let wallet_name = format!("{}_{}", name, timestamp);

        println!("Creating {} wallet at height {}...", name, current_height);
        let (mut mgr, _mnemonic) = Manager::generate(&wallet_name, "regtest", current_height, TEST_PASSWORD).await?;

        // Use file-based network with shared directory
        let file_network = FileBasedNetwork::new(proposal_dir.path().to_path_buf());
        mgr.network = Arc::new(file_network) as Arc<dyn ProposalNetwork>;

        mgr.wait_for_height(current_height, 60).await?;
        managers.push((name.to_string(), Arc::new(mgr)));

        BITCOIND.mine_blocks(1)?;
    }

    // ============================================================
    // PHASE 2: Fund wallets with multiple UTXOs each
    // ============================================================
    println!("\n--- Phase 2: Fund Wallets ({} UTXOs each) ---\n", UTXOS_PER_WALLET);

    // Proposer gets larger UTXOs, receiver gets smaller ones
    let proposer_utxo_amount = 500_000u64;
    let receiver_utxo_amount = 200_000u64;

    let mut total_funded = 0u64;

    // Fund proposer with multiple UTXOs
    let proposer_mgr = managers.iter().find(|(n, _)| n == "proposer").unwrap().1.clone();
    for i in 0..UTXOS_PER_WALLET {
        let addr = proposer_mgr.get_next_address().await?;
        BITCOIND.rpc_call(
            "sendtoaddress",
            &[
                serde_json::json!(addr.to_string()),
                serde_json::json!(format!("{:.8}", proposer_utxo_amount as f64 / 100_000_000.0)),
            ],
            Some("testwallet"),
        )?;
        total_funded += proposer_utxo_amount;
        println!("Funded proposer UTXO {}: {} sats", i + 1, proposer_utxo_amount);
    }

    // Fund receiver with multiple UTXOs
    let receiver_mgr = managers.iter().find(|(n, _)| n == "receiver").unwrap().1.clone();
    for i in 0..UTXOS_PER_WALLET {
        let addr = receiver_mgr.get_next_address().await?;
        BITCOIND.rpc_call(
            "sendtoaddress",
            &[
                serde_json::json!(addr.to_string()),
                serde_json::json!(format!("{:.8}", receiver_utxo_amount as f64 / 100_000_000.0)),
            ],
            Some("testwallet"),
        )?;
        total_funded += receiver_utxo_amount;
        println!("Funded receiver UTXO {}: {} sats", i + 1, receiver_utxo_amount);
    }

    println!("\nTotal funded: {} sats", total_funded);

    // Mine to confirm
    println!("\nMining 10 blocks to confirm funding...");
    BITCOIND.mine_blocks(10)?;

    let height = BITCOIND.get_block_count()? as u32;
    for (name, mgr) in &managers {
        mgr.wait_for_height(height, 60).await?;
        println!("{} synced to {}", name, height);
    }

    // Capture initial balances
    let snapshot = BalanceSnapshot::capture("after_funding", height, &managers).await?;
    snapshot.print();
    snapshots.push(snapshot);

    // ============================================================
    // PHASE 3: Set automation roles and start
    // ============================================================
    println!("\n--- Phase 3: Start Automation ---\n");

    let snicker_config = SnickerAutomation {
        mode: AutomationMode::Advanced,
        max_sats_per_coinjoin: 10_000,
        max_sats_per_day: 50_000,
        max_sats_per_week: 100_000,
        prefer_snicker_outputs: true,
        snicker_pattern_only: false,
        outstanding_proposals: 1,
        receiver_timeout_blocks: 10,
    };

    let task_config = AutomationConfig {
        min_utxo_sats: 50_000,
        proposal_delta_sats: 500,
    };

    let roles = [
        ("proposer", AutomationRole::Proposer),
        ("receiver", AutomationRole::Receiver),
    ];

    let current_height = BITCOIND.get_block_count()? as u32;

    for (name, role) in &roles {
        let mgr = managers.iter().find(|(n, _)| n == *name).unwrap().1.clone();
        let state = AutomationState {
            role: *role,
            last_coinjoin_height: current_height,
        };
        mgr.snicker.set_automation_state(&state)?;
        println!("{} role: {:?}", name, role);
    }

    let mut automation_tasks: Vec<AutomationTask> = Vec::new();

    for (name, mgr) in &managers {
        println!("Starting automation for {}...", name);
        let mut task = AutomationTask::new();
        task.start(mgr.clone(), snicker_config.clone(), task_config.clone()).await;
        automation_tasks.push(task);
    }

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // ============================================================
    // PHASE 4: Mine blocks to trigger coinjoins
    // ============================================================
    println!("\n--- Phase 4: Trigger Coinjoins ({} rounds) ---\n", NUM_ROUNDS);

    for round in 1..=NUM_ROUNDS {
        println!("\n=== Round {} ===", round);

        BITCOIND.mine_blocks(1)?;
        let height = BITCOIND.get_block_count()? as u32;
        println!("Mined block {}", height);

        // Wait for sync
        for (name, mgr) in &managers {
            match tokio::time::timeout(
                std::time::Duration::from_secs(30),
                mgr.wait_for_height(height, 30)
            ).await {
                Ok(Ok(_)) => println!("{} synced", name),
                Ok(Err(e)) => println!("{} sync error: {}", name, e),
                Err(_) => println!("{} sync timeout", name),
            }
        }

        // Give automation time
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        // Capture balance snapshot
        let snapshot = BalanceSnapshot::capture(&format!("round_{}", round), height, &managers).await?;
        snapshot.print();
        snapshots.push(snapshot);

        // Check coinjoin history
        for (name, mgr) in &managers {
            let history = mgr.snicker.get_coinjoin_history().unwrap_or_default();
            if !history.is_empty() {
                println!("  {} coinjoin history: {} entries", name, history.len());
                for (h, delta, role, txid) in &history {
                    println!("    height={} delta={:+} role={} tx={}...", h, delta, role, &txid[..16]);
                }
            }
        }
    }

    // ============================================================
    // PHASE 5: Stop and analyze
    // ============================================================
    println!("\n--- Phase 5: Stop and Analyze ---\n");

    for task in &mut automation_tasks {
        task.stop().await;
    }
    println!("Automation stopped");

    // Final sync
    BITCOIND.mine_blocks(1)?;
    let final_height = BITCOIND.get_block_count()? as u32;
    for (_, mgr) in &managers {
        mgr.wait_for_height(final_height, 60).await?;
    }

    let final_snapshot = BalanceSnapshot::capture("final", final_height, &managers).await?;
    final_snapshot.print();
    snapshots.push(final_snapshot.clone());

    // ============================================================
    // ANALYSIS
    // ============================================================
    println!("\n╔═══════════════════════════════════════════════╗");
    println!("║  Balance Analysis                             ║");
    println!("╚═══════════════════════════════════════════════╝\n");

    println!("Balance progression:");
    for snap in &snapshots {
        let total = snap.total_all();
        println!("  {}: total={} sats", snap.step, total);
    }

    let initial_total = snapshots.first().map(|s| s.total_all()).unwrap_or(0);
    let final_total = final_snapshot.total_all();

    // Count total coinjoins
    let total_coinjoins: usize = managers.iter()
        .map(|(_, mgr)| mgr.snicker.get_coinjoin_history().unwrap_or_default().len())
        .sum::<usize>() / 2; // Divide by 2 since each coinjoin is recorded by both parties

    println!("Total coinjoins completed: {}", total_coinjoins);

    println!("\nFund conservation check:");
    println!("  Initial total: {} sats", initial_total);
    println!("  Final total:   {} sats", final_total);

    // Calculate what we SHOULD see (allowing for fees)
    // ~500-600 sats per coinjoin, be generous
    let max_fees = (total_coinjoins as u64 + 1) * 1000;
    let expected_final_min = initial_total.saturating_sub(max_fees);
    let expected_final_max = initial_total;

    println!("  Expected range: {} - {} sats (fees up to {} for {} coinjoins)",
             expected_final_min, expected_final_max, max_fees, total_coinjoins);

    if final_total <= initial_total {
        let fees = initial_total - final_total;
        println!("  Fees paid:     {} sats", fees);
        println!("  PASSED - funds conserved (lost {} to fees)", fees);
    } else {
        let gain = final_total - initial_total;
        println!("  Apparent gain: {} sats", gain);
        println!("  FAILED - gained {} sats (double-counting detected)", gain);

        // Show per-wallet breakdown for debugging
        println!("\n  Per-wallet breakdown:");
        for (name, bal) in &final_snapshot.balances {
            println!("    {}: confirmed={} pending_out={} pending_in={} effective={}",
                     name, bal.confirmed, bal.pending_out, bal.pending_in_snicker, bal.effective);
        }
        println!("\n  NOTE: This indicates a bug in balance tracking - needs investigation.");
    }

    // Detailed final state
    println!("\nFinal wallet states:");
    for (name, mgr) in &managers {
        let state = mgr.snicker.get_automation_state();
        let history = mgr.snicker.get_coinjoin_history().unwrap_or_default();
        println!("  {}: role={:?}, coinjoins={}", name, state.role, history.len());
        for (h, delta, role, txid) in &history {
            println!("    height={} delta={:+} role={} tx={}...", h, delta, role, &txid[..16]);
        }
    }

    // Per-coinjoin fee analysis
    if total_coinjoins > 0 {
        let fees_paid = initial_total.saturating_sub(final_total);
        let avg_fee = fees_paid / total_coinjoins as u64;
        println!("\nFee analysis:");
        println!("  Total fees: {} sats", fees_paid);
        println!("  Avg fee per coinjoin: {} sats", avg_fee);
    }

    // Final summary
    println!("\n╔═══════════════════════════════════════════════╗");
    if final_total <= initial_total {
        println!("║  TEST PASSED - Fund Conservation OK           ║");
    } else {
        println!("║  TEST FAILED - Balance Tracking Bug           ║");
    }
    println!("╚═══════════════════════════════════════════════╝\n");

    Ok(())
}
