use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{anyhow, Result};
use once_cell::sync::Lazy;

mod common;
use common::{BITCOIND, TestBitcoind};

// Import Manager from main crate
use ambient::manager::Manager;

// ============================================================
// SNICKER END-TO-END TEST
// ============================================================

#[tokio::test(flavor = "multi_thread")]
async fn test_snicker_end_to_end() -> Result<()> {
    println!("\n╔═══════════════════════════════════════╗");
    println!("║  SNICKER End-to-End Integration Test ║");
    println!("╚═══════════════════════════════════════╝\n");

    // Ensure bitcoind is running
    let _ = &*BITCOIND;

    let current_height = BITCOIND.get_block_count()? as u32;
    println!("📊 Current blockchain height: {}\n", current_height);

    // ============================================================
    // PHASE 1: SETUP - Create and Fund Two Wallets
    // ============================================================
    println!("┌─────────────────────────────────┐");
    println!("│  Phase 1: Setup Two Wallets     │");
    println!("└─────────────────────────────────┘\n");

    // Create Alice's wallet (receiver)
    println!("👤 Creating Alice's wallet (receiver)...");
    let temp_dir = std::env::temp_dir();
    let alice_name = format!("alice_{}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs());

    let test_password = "test123"; // Test password for encrypted wallets

    let (mut alice_mgr, alice_mnemonic) =
        Manager::generate(&alice_name, "regtest", current_height, test_password).await?;
    println!("   ✅ Alice's mnemonic: {}", alice_mnemonic);

    // Create Bob's wallet (proposer)
    println!("\n👤 Creating Bob's wallet (proposer)...");
    let bob_name = format!("bob_{}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs());

    let (mut bob_mgr, bob_mnemonic) =
        Manager::generate(&bob_name, "regtest", current_height, test_password).await?;
    println!("   ✅ Bob's mnemonic: {}", bob_mnemonic);

    // Wait for wallets to do initial sync to current height
    println!("\n⏳ Waiting for wallets to do initial sync to height {}...", current_height);
    alice_mgr.wait_for_height(current_height, 30).await?;
    println!("   ✅ Alice synced to height {}", current_height);
    bob_mgr.wait_for_height(current_height, 30).await?;
    println!("   ✅ Bob synced to height {}", current_height);

    // Get addresses for funding
    println!("\n💰 Getting funding addresses...");
    let alice_addr1 = alice_mgr.get_next_address().await?;
    let alice_addr2 = alice_mgr.get_next_address().await?;
    let alice_addr3 = alice_mgr.get_next_address().await?;
    let bob_addr1 = bob_mgr.get_next_address().await?;
    let bob_addr2 = bob_mgr.get_next_address().await?;

    println!("   Alice addresses:");
    println!("     [1] {}", alice_addr1);
    println!("     [2] {}", alice_addr2);
    println!("     [3] {}", alice_addr3);
    println!("   Bob addresses:");
    println!("     [1] {}", bob_addr1);
    println!("     [2] {}", bob_addr2);

    // Check bitcoind wallet balance first
    println!("\n💰 Checking bitcoind wallet balance...");
    let wallet_balance = BITCOIND.rpc_call("getbalance", &[], Some("testwallet"))?;
    println!("   Bitcoind wallet balance: {} BTC", wallet_balance);

    // Fund Alice with 3 UTXOs: 50k, 80k, 120k sats
    println!("\n💸 Funding Alice's wallet...");
    let txid1 = BITCOIND.rpc_call("sendtoaddress", &[
        serde_json::json!(alice_addr1),
        serde_json::json!("0.0005"), // 50k sats
    ], Some("testwallet"))?;
    println!("   Sent 50k sats to Alice: txid {}", txid1);

    let txid2 = BITCOIND.rpc_call("sendtoaddress", &[
        serde_json::json!(alice_addr2),
        serde_json::json!("0.0008"), // 80k sats
    ], Some("testwallet"))?;
    println!("   Sent 80k sats to Alice: txid {}", txid2);

    let txid3 = BITCOIND.rpc_call("sendtoaddress", &[
        serde_json::json!(alice_addr3),
        serde_json::json!("0.0012"), // 120k sats
    ], Some("testwallet"))?;
    println!("   Sent 120k sats to Alice: txid {}", txid3);

    // Fund Bob with 2 UTXOs: 100k, 200k sats
    println!("\n💸 Funding Bob's wallet...");
    let txid4 = BITCOIND.rpc_call("sendtoaddress", &[
        serde_json::json!(bob_addr1),
        serde_json::json!("0.001"), // 100k sats
    ], Some("testwallet"))?;
    println!("   Sent 100k sats to Bob: txid {}", txid4);

    let txid5 = BITCOIND.rpc_call("sendtoaddress", &[
        serde_json::json!(bob_addr2),
        serde_json::json!("0.002"), // 200k sats
    ], Some("testwallet"))?;
    println!("   Sent 200k sats to Bob: txid {}", txid5);

    // Check mempool
    println!("\n📋 Checking mempool...");
    let mempool = BITCOIND.rpc_call("getrawmempool", &[], None)?;
    println!("   Mempool: {:?}", mempool);

    // Mine blocks to confirm
    println!("\n⛏️  Mining 10 blocks to confirm...");
    BITCOIND.mine_blocks(10)?;
    let new_height = BITCOIND.get_block_count()? as u32;
    println!("   ✅ New height: {}", new_height);

    // Wait for both wallets to sync to new height
    println!("\n⏳ Waiting for wallets to sync to height {}...", new_height);
    alice_mgr.wait_for_height(new_height, 30).await?;
    println!("   ✅ Alice synced");
    bob_mgr.wait_for_height(new_height, 30).await?;
    println!("   ✅ Bob synced");

    // Check balances
    let alice_balance = alice_mgr.get_balance().await?;
    let bob_balance = bob_mgr.get_balance().await?;
    println!("   Alice balance: {}", alice_balance);
    println!("   Bob balance: {}", bob_balance);

    // Verify balances
    assert_eq!(alice_balance, "250000 sats", "Alice should have 250k sats");
    assert_eq!(bob_balance, "300000 sats", "Bob should have 300k sats");

    // ============================================================
    // PHASE 2: CANDIDATE DISCOVERY
    // ============================================================
    println!("\n┌─────────────────────────────────────┐");
    println!("│  Phase 2: Candidate Discovery (Bob)  │");
    println!("└─────────────────────────────────────┘\n");

    println!("🔍 Bob scanning blockchain for SNICKER candidates...");
    let candidates_found = bob_mgr.scan_for_snicker_candidates(
        10,        // last 10 blocks
        10_000,    // min 10k sats
        150_000,   // max 150k sats
    ).await?;
    println!("   ✅ Found {} candidate transactions", candidates_found);
    assert!(candidates_found >= 3, "Should find Alice's 3 UTXOs as candidates");

    println!("\n🎯 Bob finding SNICKER opportunities...");
    let opportunities = bob_mgr.find_snicker_opportunities(75_000).await?;
    println!("   ✅ Found {} opportunities", opportunities.len());

    for (i, opp) in opportunities.iter().enumerate().take(5) {
        println!("      [{}] Our UTXO: {}:{} ({} sats) → Target: {} sats",
                 i,
                 opp.our_outpoint.txid,
                 opp.our_outpoint.vout,
                 opp.our_value.to_sat(),
                 opp.target_value.to_sat());
    }

    assert!(!opportunities.is_empty(), "Should find at least one opportunity");

    // ============================================================
    // PHASE 3: PROPOSAL CREATION (Bob creates proposal)
    // ============================================================
    println!("\n┌─────────────────────────────────────┐");
    println!("│  Phase 3: Proposal Creation (Bob)    │");
    println!("└─────────────────────────────────────┘\n");

    // Select first opportunity: Bob's 100k UTXO + Alice's 80k UTXO
    let opportunity = &opportunities[0];
    println!("📝 Bob creating proposal for opportunity:");
    println!("   Bob's UTXO: {}:{} ({} sats)",
             opportunity.our_outpoint.txid,
             opportunity.our_outpoint.vout,
             opportunity.our_value.to_sat());
    println!("   Alice's UTXO: {} sats", opportunity.target_value.to_sat());

    let delta_sats = 1000; // Alice pays 1000 sats more in fees
    println!("   Delta: {} sats (receiver pays more)", delta_sats);

    println!("\n🔐 Creating and signing proposal...");
    let (signed_psbt, encrypted_proposal) = bob_mgr.create_snicker_proposal(
        opportunity,
        delta_sats,
        ambient::config::DEFAULT_MIN_CHANGE_OUTPUT_SIZE,
    ).await?;

    println!("   ✅ Proposal created and signed by Bob");
    println!("   PSBT inputs: {}", signed_psbt.psbt.unsigned_tx.input.len());
    println!("   PSBT outputs: {}", signed_psbt.psbt.unsigned_tx.output.len());
    println!("   Encrypted proposal size: {} bytes", encrypted_proposal.encrypted_data.len());

    // Store the encrypted proposal (simulating publication)
    println!("\n📤 Storing encrypted proposal (simulating publication)...");
    alice_mgr.store_snicker_proposal(&encrypted_proposal).await?;
    println!("   ✅ Proposal stored");

    // ============================================================
    // PHASE 4: PROPOSAL RECEPTION (Alice receives and validates)
    // ============================================================
    println!("\n┌──────────────────────────────────────────┐");
    println!("│  Phase 4: Proposal Reception (Alice)     │");
    println!("└──────────────────────────────────────────┘\n");

    // Debug: Check how many UTXOs Alice has
    let alice_utxos = alice_mgr.list_unspent().await?;
    println!("   Debug: Alice has {} UTXOs", alice_utxos.len());

    println!("🔍 Alice scanning for proposals meant for her...");
    let acceptable_delta_range = (-2000, 5000); // Accept delta between -2k and +5k
    let proposals = alice_mgr.scan_for_our_proposals(acceptable_delta_range).await?;

    println!("   ✅ Found {} proposals for Alice", proposals.len());
    assert_eq!(proposals.len(), 1, "Should find exactly 1 proposal");

    let proposal = &proposals[0];
    println!("\n📋 Proposal details:");
    println!("   Inputs: {}", proposal.psbt.unsigned_tx.input.len());
    println!("   Outputs: {}", proposal.psbt.unsigned_tx.output.len());

    println!("\n✍️  Alice validating and signing proposal...");
    let fully_signed_psbt = alice_mgr.accept_snicker_proposal(
        &proposal.tag,
        acceptable_delta_range,
    ).await?;

    println!("   ✅ Alice signed the proposal");
    println!("   PSBT now has both signatures");

    // ============================================================
    // PHASE 5: FINALIZATION AND BROADCAST
    // ============================================================
    println!("\n┌────────────────────────────────────────┐");
    println!("│  Phase 5: Finalize and Broadcast       │");
    println!("└────────────────────────────────────────┘\n");

    println!("🔨 Finalizing fully-signed PSBT...");
    let coinjoin_tx = alice_mgr.finalize_psbt(fully_signed_psbt).await?;

    println!("   ✅ Transaction finalized");
    println!("   Txid: {}", coinjoin_tx.compute_txid());
    println!("   Size: {} bytes", coinjoin_tx.total_size());
    println!("   Inputs: {}", coinjoin_tx.input.len());
    println!("   Outputs: {}", coinjoin_tx.output.len());

    // Verify transaction structure
    assert_eq!(coinjoin_tx.input.len(), 2, "Should have 2 inputs");
    assert_eq!(coinjoin_tx.output.len(), 3, "Should have 3 outputs (2 equal + 1 change)");

    // Verify equal-sized outputs exist
    let output_values: Vec<_> = coinjoin_tx.output.iter().map(|o| o.value.to_sat()).collect();
    println!("   Output values: {:?}", output_values);

    // Two outputs should be equal (the coinjoin outputs)
    let mut sorted_values = output_values.clone();
    sorted_values.sort();
    // Check if at least two values are close (equal-sized outputs)
    let equal_output_exists = sorted_values.windows(2).any(|w| w[0] == w[1]);
    assert!(equal_output_exists, "Should have two equal-sized outputs for privacy");

    println!("\n📡 Broadcasting transaction...");
    let txid = coinjoin_tx.compute_txid();

    // Broadcast via bitcoind RPC (for regtest testing)
    use bdk_wallet::bitcoin::consensus::encode::serialize_hex;
    let tx_hex = serialize_hex(&coinjoin_tx);
    let broadcast_result = BITCOIND.rpc_call("sendrawtransaction", &[
        serde_json::json!(tx_hex),
    ], None)?;
    println!("   ✅ Transaction broadcast!");
    println!("   Txid: {}", txid);
    println!("   Broadcast result: {}", broadcast_result);

    // Store Alice's SNICKER UTXO
    println!("\n💾 Storing Alice's SNICKER UTXO...");
    let alice_utxos = alice_mgr.wallet_node.get_all_wallet_utxos().await?;
    alice_mgr.store_accepted_snicker_utxo(&proposal, &coinjoin_tx, &alice_utxos).await?;
    println!("   ✅ SNICKER UTXO stored");

    // Mine a block to confirm
    println!("\n⛏️  Mining 1 block to confirm transaction...");
    BITCOIND.mine_blocks(1)?;
    let final_height = BITCOIND.get_block_count()? as u32;
    println!("   ✅ Block mined, height: {}", final_height);

    // Wait for sync
    println!("\n⏳ Waiting for wallets to sync to height {}...", final_height);
    alice_mgr.wait_for_height(final_height, 30).await?;
    println!("   ✅ Alice synced");
    bob_mgr.wait_for_height(final_height, 30).await?;
    println!("   ✅ Bob synced");

    let alice_wallet_balance = alice_mgr.get_balance().await?;
    let alice_snicker_balance = alice_mgr.get_snicker_balance().await?;
    let bob_final_balance = bob_mgr.get_balance().await?;

    println!("   Alice wallet balance: {}", alice_wallet_balance);
    println!("   Alice SNICKER balance: {} sats", alice_snicker_balance);
    println!("   Alice total balance: {} sats",
             alice_wallet_balance.parse::<String>().unwrap().split_whitespace().next().unwrap().parse::<u64>().unwrap()
             + alice_snicker_balance);
    println!("   Bob final balance: {}", bob_final_balance);

    // List Alice's SNICKER UTXOs
    let alice_snicker_utxos = alice_mgr.list_snicker_utxos().await?;
    println!("\n📋 Alice's SNICKER UTXOs: {}", alice_snicker_utxos.len());
    for utxo in &alice_snicker_utxos {
        println!("   {}:{} - {} sats", utxo.outpoint.txid, utxo.outpoint.vout, utxo.amount);
    }

    // ============================================================
    // VERIFICATION
    // ============================================================
    println!("\n┌────────────────────────────────────────┐");
    println!("│  Verification                           │");
    println!("└────────────────────────────────────────┘\n");

    println!("✅ SNICKER coinjoin completed successfully!");
    println!("   ✅ 2 inputs combined (Bob + Alice)");
    println!("   ✅ 2 equal-sized outputs (privacy achieved)");
    println!("   ✅ 1 change output (proposer's change)");
    println!("   ✅ Transaction confirmed on blockchain");

    println!("\n╔═══════════════════════════════════════╗");
    println!("║        TEST PASSED SUCCESSFULLY       ║");
    println!("╚═══════════════════════════════════════╝\n");

    Ok(())
}
