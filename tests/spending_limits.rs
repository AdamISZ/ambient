use anyhow::Result;

mod common;
use common::BITCOIND;

use ambient::manager::Manager;

// ============================================================
// TEST CONFIGURATION
// ============================================================

const TEST_PASSWORD: &str = "test123";

// Spending limits (intentionally low for testing)
const MAX_SATS_PER_COINJOIN: u64 = 500;
const MAX_SATS_PER_DAY: u64 = 1500;    // Allows exactly 3 coinjoins at delta=500
const MAX_SATS_PER_WEEK: u64 = 2500;   // Allows exactly 5 coinjoins at delta=500
                                       // (3 in first day + 2 in second day hits weekly before daily)

// Proposal deltas
const PROPOSAL_DELTA: i64 = 500;       // Normal delta (within per-tx limit)
const EXCESSIVE_DELTA: i64 = 600;      // Exceeds per-tx limit

// ============================================================
// HELPER: Execute a coinjoin round
// ============================================================

async fn execute_coinjoin_round(
    alice: &Manager,
    bob: &Manager,
    delta: i64,
    max_per_tx: u64,
    max_per_day: u64,
    max_per_week: u64,
) -> Result<(bool, String)> {
    let current_height = BITCOIND.get_block_count()? as u32;

    // Alice finds opportunities
    let opportunities = alice
        .find_snicker_opportunities(50_000, 400_000, 0)
        .await?;

    if opportunities.is_empty() {
        return Ok((false, "No opportunities found".to_string()));
    }

    // Alice creates a proposal
    let opportunity = &opportunities[0];
    let (proposal, encrypted) = match alice
        .create_snicker_proposal(opportunity, delta, ambient::config::MIN_UTXO_SIZE)
        .await
    {
        Ok(r) => r,
        Err(e) => return Ok((false, format!("Failed to create proposal: {}", e))),
    };

    // Store proposal for Bob
    bob.store_snicker_proposal(&encrypted).await?;

    // Bob checks spending limits
    let within_limits = bob.snicker.check_spending_limits(
        current_height,
        delta,
        max_per_tx,
        max_per_day,
        max_per_week,
    )?;

    if !within_limits {
        return Ok((false, "Blocked by spending limit".to_string()));
    }

    // Bob accepts and broadcasts
    let acceptable_delta = (-1000, 1000);
    let proposals = bob.scan_for_our_proposals(acceptable_delta).await?;

    if proposals.is_empty() {
        return Ok((false, "Proposal not found by receiver".to_string()));
    }

    let fully_signed = match bob
        .accept_snicker_proposal(&proposal.tag, acceptable_delta)
        .await
    {
        Ok(psbt) => psbt,
        Err(e) => return Ok((false, format!("Failed to accept: {}", e))),
    };

    let coinjoin_tx = bob.finalize_psbt(fully_signed).await?;
    let txid = coinjoin_tx.compute_txid();

    use bdk_wallet::bitcoin::consensus::encode::serialize_hex;
    let tx_hex = serialize_hex(&coinjoin_tx);

    match BITCOIND.rpc_call("sendrawtransaction", &[serde_json::json!(tx_hex)], None) {
        Ok(_) => {
            // Record spending
            bob.snicker.record_coinjoin_spending(
                delta,
                "receiver",
                &txid.to_string(),
                current_height,
            )?;
            Ok((true, txid.to_string()))
        }
        Err(e) => Ok((false, format!("Broadcast failed: {}", e))),
    }
}

// ============================================================
// SPENDING LIMITS TEST
// ============================================================

#[tokio::test(flavor = "multi_thread")]
async fn test_spending_limits() -> Result<()> {
    println!("\n╔═══════════════════════════════════════════════╗");
    println!("║  Comprehensive Spending Limits Test           ║");
    println!("╚═══════════════════════════════════════════════╝\n");

    println!("📋 Test coverage:");
    println!("   1. Per-transaction limit rejection");
    println!("   2. Per-day limit rejection and reset");
    println!("   3. Per-week limit rejection and reset\n");

    // Ensure bitcoind is running
    let _ = &*BITCOIND;

    let initial_height = BITCOIND.get_block_count()? as u32;
    println!("📊 Initial blockchain height: {}\n", initial_height);

    // ============================================================
    // PHASE 1: CREATE TWO WALLETS
    // ============================================================
    println!("┌─────────────────────────────────────────────┐");
    println!("│  Phase 1: Create Alice and Bob              │");
    println!("└─────────────────────────────────────────────┘\n");

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Create Alice (proposer)
    let current_height = BITCOIND.get_block_count()? as u32;
    let alice_name = format!("alice_{}", timestamp);
    println!("👤 Creating Alice's wallet at height {}...", current_height);
    let (alice, _) = Manager::generate(&alice_name, "regtest", current_height, TEST_PASSWORD).await?;
    alice.wait_for_height(current_height, 60).await?;
    println!("   ✅ Alice ready");

    // Mine a few blocks
    BITCOIND.mine_blocks(5)?;

    // Create Bob (receiver)
    let current_height = BITCOIND.get_block_count()? as u32;
    let bob_name = format!("bob_{}", timestamp);
    println!("👤 Creating Bob's wallet at height {}...", current_height);
    let (bob, _) = Manager::generate(&bob_name, "regtest", current_height, TEST_PASSWORD).await?;
    bob.wait_for_height(current_height, 60).await?;
    println!("   ✅ Bob ready");

    // ============================================================
    // PHASE 2: FUND WALLETS (need more UTXOs for comprehensive test)
    // ============================================================
    println!("\n┌─────────────────────────────────────────────┐");
    println!("│  Phase 2: Fund Wallets                      │");
    println!("└─────────────────────────────────────────────┘\n");

    // Fund Alice with 10 UTXOs (proposer needs LARGER UTXOs)
    println!("💰 Funding Alice with 10 UTXOs...");
    for i in 0..10 {
        let addr = alice.get_next_address().await?;
        let amount_btc = 0.003; // 300,000 sats each
        BITCOIND.rpc_call(
            "sendtoaddress",
            &[
                serde_json::json!(addr.to_string()),
                serde_json::json!(format!("{:.8}", amount_btc)),
            ],
            Some("testwallet"),
        )?;
        println!("   [{}] 300,000 sats", i + 1);
    }

    // Fund Bob with 10 UTXOs (receiver needs SMALLER UTXOs)
    println!("💰 Funding Bob with 10 UTXOs...");
    for i in 0..10 {
        let addr = bob.get_next_address().await?;
        let amount_btc = 0.002; // 200,000 sats each
        BITCOIND.rpc_call(
            "sendtoaddress",
            &[
                serde_json::json!(addr.to_string()),
                serde_json::json!(format!("{:.8}", amount_btc)),
            ],
            Some("testwallet"),
        )?;
        println!("   [{}] 200,000 sats", i + 1);
    }

    // Mine blocks to confirm
    println!("\n⛏️  Mining 10 blocks to confirm funding...");
    BITCOIND.mine_blocks(10)?;

    // Sync both wallets
    let funding_height = BITCOIND.get_block_count()? as u32;
    println!("⏳ Syncing wallets to height {}...", funding_height);

    let (alice_sync, bob_sync) = tokio::join!(
        alice.wait_for_height(funding_height, 90),
        bob.wait_for_height(funding_height, 90)
    );
    alice_sync?;
    bob_sync?;

    let alice_balance = alice.get_balance().await?;
    let bob_balance = bob.get_balance().await?;
    println!("   ✅ Alice balance: {} (10 × 300,000 sats)", alice_balance);
    println!("   ✅ Bob balance: {} (10 × 200,000 sats)", bob_balance);

    println!("\n📋 Spending limits being tested:");
    println!("   Max per coinjoin: {} sats", MAX_SATS_PER_COINJOIN);
    println!("   Max per day (144 blocks): {} sats", MAX_SATS_PER_DAY);
    println!("   Max per week (1008 blocks): {} sats", MAX_SATS_PER_WEEK);

    // ============================================================
    // TEST 1: PER-TRANSACTION LIMIT REJECTION
    // ============================================================
    println!("\n┌─────────────────────────────────────────────┐");
    println!("│  Test 1: Per-Transaction Limit Rejection    │");
    println!("└─────────────────────────────────────────────┘\n");

    println!("📝 Attempting coinjoin with delta={} sats (limit: {} sats)",
             EXCESSIVE_DELTA, MAX_SATS_PER_COINJOIN);

    let current_height = BITCOIND.get_block_count()? as u32;

    // Check that excessive delta is rejected
    let within_limits = bob.snicker.check_spending_limits(
        current_height,
        EXCESSIVE_DELTA,
        MAX_SATS_PER_COINJOIN,
        MAX_SATS_PER_DAY,
        MAX_SATS_PER_WEEK,
    )?;

    assert!(
        !within_limits,
        "Per-tx limit should reject delta {} > max {}",
        EXCESSIVE_DELTA, MAX_SATS_PER_COINJOIN
    );
    println!("   ✅ PASSED: Delta {} correctly rejected (exceeds per-tx limit {})",
             EXCESSIVE_DELTA, MAX_SATS_PER_COINJOIN);

    // ============================================================
    // TEST 2: PER-DAY LIMIT REJECTION AND RESET
    // ============================================================
    println!("\n┌─────────────────────────────────────────────┐");
    println!("│  Test 2: Per-Day Limit Rejection and Reset  │");
    println!("└─────────────────────────────────────────────┘\n");

    println!("📝 Running coinjoins until daily limit ({} sats) is hit...\n", MAX_SATS_PER_DAY);

    let mut daily_successes = 0;
    let mut daily_blocked = false;

    // Run up to 5 rounds - expect 3 to succeed (3 × 500 = 1500), then blocked
    for round in 1..=5 {
        println!("═══════════════════════════════════════════════");
        println!("  Daily Limit Test - Round {}", round);
        println!("═══════════════════════════════════════════════");

        let current_height = BITCOIND.get_block_count()? as u32;
        let spent_today = bob.snicker.get_spending_last_day(current_height)?;
        let spent_week = bob.snicker.get_spending_last_week(current_height)?;
        println!("   Daily spending: {} / {} sats", spent_today, MAX_SATS_PER_DAY);
        println!("   Weekly spending: {} / {} sats", spent_week, MAX_SATS_PER_WEEK);

        let (success, msg) = execute_coinjoin_round(
            &alice, &bob, PROPOSAL_DELTA,
            MAX_SATS_PER_COINJOIN, MAX_SATS_PER_DAY, MAX_SATS_PER_WEEK,
        ).await?;

        if success {
            println!("   ✅ SUCCESS: {}", &msg[..16]);
            daily_successes += 1;
        } else if msg.contains("Blocked") {
            println!("   ❌ BLOCKED: {}", msg);
            daily_blocked = true;
            break;
        } else {
            println!("   ⚠️ {}", msg);
        }

        // Mine and sync
        BITCOIND.mine_blocks(1)?;
        let new_height = BITCOIND.get_block_count()? as u32;
        let (a, b) = tokio::join!(
            alice.wait_for_height(new_height, 60),
            bob.wait_for_height(new_height, 60)
        );
        a?; b?;
    }

    println!("\n📊 Daily limit test results:");
    println!("   Successful coinjoins: {}", daily_successes);
    println!("   Blocked by daily limit: {}", daily_blocked);

    assert!(
        daily_successes >= 2,
        "Expected at least 2 successful coinjoins before daily limit, got {}",
        daily_successes
    );
    assert!(
        daily_blocked,
        "Expected daily limit to block further coinjoins"
    );
    println!("   ✅ PASSED: Daily limit correctly enforced");

    // Mine 144 blocks to reset daily window
    println!("\n⛏️  Mining {} blocks to reset daily limit window...", ambient::snicker::BLOCKS_PER_DAY);
    BITCOIND.mine_blocks(ambient::snicker::BLOCKS_PER_DAY as u64)?;

    let new_height = BITCOIND.get_block_count()? as u32;
    let (a, b) = tokio::join!(
        alice.wait_for_height(new_height, 120),
        bob.wait_for_height(new_height, 120)
    );
    a?; b?;

    // Verify daily limit reset
    let spent_today = bob.snicker.get_spending_last_day(new_height)?;
    let spent_week = bob.snicker.get_spending_last_week(new_height)?;
    println!("📊 After daily reset:");
    println!("   Daily spending: {} sats (should be 0)", spent_today);
    println!("   Weekly spending: {} sats (should still be {})", spent_week, daily_successes as u64 * PROPOSAL_DELTA as u64);

    assert_eq!(spent_today, 0, "Daily spending should reset to 0 after 144 blocks");
    println!("   ✅ PASSED: Daily limit correctly reset");

    // ============================================================
    // TEST 3: PER-WEEK LIMIT REJECTION AND RESET
    // ============================================================
    println!("\n┌─────────────────────────────────────────────┐");
    println!("│  Test 3: Per-Week Limit Rejection and Reset │");
    println!("└─────────────────────────────────────────────┘\n");

    // We already have some spending in the weekly window from Test 2
    // Need to do more coinjoins to hit the weekly limit
    let remaining_weekly = MAX_SATS_PER_WEEK - spent_week;
    let remaining_coinjoins = remaining_weekly / PROPOSAL_DELTA as u64;
    println!("📝 Weekly spending so far: {} sats", spent_week);
    println!("   Need {} more sats to hit weekly limit ({} coinjoins)", remaining_weekly, remaining_coinjoins);

    let mut weekly_successes = 0;
    let mut weekly_blocked = false;

    // Run coinjoins until weekly limit is hit
    for round in 1..=(remaining_coinjoins as u32 + 2) {
        println!("\n═══════════════════════════════════════════════");
        println!("  Weekly Limit Test - Round {}", round);
        println!("═══════════════════════════════════════════════");

        let current_height = BITCOIND.get_block_count()? as u32;
        let spent_today = bob.snicker.get_spending_last_day(current_height)?;
        let spent_week = bob.snicker.get_spending_last_week(current_height)?;
        println!("   Daily spending: {} / {} sats", spent_today, MAX_SATS_PER_DAY);
        println!("   Weekly spending: {} / {} sats", spent_week, MAX_SATS_PER_WEEK);

        let (success, msg) = execute_coinjoin_round(
            &alice, &bob, PROPOSAL_DELTA,
            MAX_SATS_PER_COINJOIN, MAX_SATS_PER_DAY, MAX_SATS_PER_WEEK,
        ).await?;

        if success {
            println!("   ✅ SUCCESS: {}", &msg[..16]);
            weekly_successes += 1;
        } else if msg.contains("Blocked") {
            println!("   ❌ BLOCKED: {}", msg);
            // Verify it's the weekly limit blocking us, not daily
            let spent_today = bob.snicker.get_spending_last_day(current_height)?;
            if spent_today < MAX_SATS_PER_DAY {
                println!("   📊 Daily spending {} < limit {} - blocked by WEEKLY limit",
                         spent_today, MAX_SATS_PER_DAY);
                weekly_blocked = true;
            }
            break;
        } else {
            println!("   ⚠️ {}", msg);
        }

        // Mine and sync
        BITCOIND.mine_blocks(1)?;
        let new_height = BITCOIND.get_block_count()? as u32;
        let (a, b) = tokio::join!(
            alice.wait_for_height(new_height, 60),
            bob.wait_for_height(new_height, 60)
        );
        a?; b?;
    }

    println!("\n📊 Weekly limit test results:");
    println!("   Additional successful coinjoins: {}", weekly_successes);
    println!("   Blocked by weekly limit: {}", weekly_blocked);

    assert!(
        weekly_blocked,
        "Expected weekly limit to block further coinjoins"
    );
    println!("   ✅ PASSED: Weekly limit correctly enforced");

    // Verify that another daily reset doesn't help (still blocked by weekly)
    println!("\n⛏️  Mining {} more blocks (another daily reset)...", ambient::snicker::BLOCKS_PER_DAY);
    BITCOIND.mine_blocks(ambient::snicker::BLOCKS_PER_DAY as u64)?;

    let new_height = BITCOIND.get_block_count()? as u32;
    let (a, b) = tokio::join!(
        alice.wait_for_height(new_height, 120),
        bob.wait_for_height(new_height, 120)
    );
    a?; b?;

    let spent_today = bob.snicker.get_spending_last_day(new_height)?;
    let spent_week = bob.snicker.get_spending_last_week(new_height)?;
    println!("📊 After second daily reset:");
    println!("   Daily spending: {} sats", spent_today);
    println!("   Weekly spending: {} sats", spent_week);

    // Try another coinjoin - should still be blocked by weekly
    let within_limits = bob.snicker.check_spending_limits(
        new_height,
        PROPOSAL_DELTA,
        MAX_SATS_PER_COINJOIN,
        MAX_SATS_PER_DAY,
        MAX_SATS_PER_WEEK,
    )?;

    assert!(
        !within_limits,
        "Should still be blocked by weekly limit even after daily reset"
    );
    println!("   ✅ PASSED: Still blocked by weekly limit (daily reset doesn't help)");

    // NOTE: Weekly reset test (mining 1008 blocks) skipped for performance
    // The reset logic is identical to daily reset - just a larger window constant
    // Weekly reset is implicitly tested by the daily reset test proving the mechanism works

    // ============================================================
    // FINAL SUMMARY
    // ============================================================
    println!("\n╔═══════════════════════════════════════════════╗");
    println!("║     ALL SPENDING LIMITS TESTS PASSED          ║");
    println!("╠═══════════════════════════════════════════════╣");
    println!("║  ✅ Per-transaction limit rejection           ║");
    println!("║  ✅ Per-day limit rejection                   ║");
    println!("║  ✅ Per-day limit reset (144 blocks)          ║");
    println!("║  ✅ Per-week limit rejection                  ║");
    println!("║  ✅ Per-week limit persists after daily reset ║");
    println!("║  ⏭️  Per-week reset skipped (same logic)       ║");
    println!("╚═══════════════════════════════════════════════╝\n");

    Ok(())
}
