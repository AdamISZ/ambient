use anyhow::Result;
use std::io::{self, Write};
use std::fs;
use std::sync::Arc;
use tokio::sync::RwLock;
use dialoguer::Password;

use crate::manager::Manager;
use crate::snicker::{ProposalOpportunity, EncryptedProposal};
use crate::automation::{AutomationTask, AutomationConfig};
use crate::config::Config;
use std::str::FromStr;

/// Format an EncryptedProposal for display with hex-encoded data
fn format_encrypted_proposal(proposal: &EncryptedProposal) -> String {
    format!(
        "{{\n  \"ephemeral_pubkey\": \"{}\",\n  \"tag\": \"{}\",\n  \"version\": {},\n  \"encrypted_data\": \"{}\"\n}}",
        proposal.ephemeral_pubkey,
        ::hex::encode(&proposal.tag),
        proposal.version,
        ::hex::encode(&proposal.encrypted_data)
    )
}

/// Parse an EncryptedProposal from hex-encoded format
fn parse_encrypted_proposal(text: &str) -> Result<EncryptedProposal> {
    use bdk_wallet::bitcoin::secp256k1::PublicKey;

    // Simple JSON-like parser for our specific format
    let lines: Vec<&str> = text.lines().collect();

    let mut ephemeral_pubkey_str = None;
    let mut tag_hex = None;
    let mut version = None;
    let mut encrypted_data_hex = None;

    for line in lines {
        let line = line.trim();
        if line.contains("ephemeral_pubkey") {
            if let Some(value) = line.split('"').nth(3) {
                ephemeral_pubkey_str = Some(value);
            }
        } else if line.contains("\"tag\"") {
            if let Some(value) = line.split('"').nth(3) {
                tag_hex = Some(value);
            }
        } else if line.contains("version") {
            // Extract version number (format: "version": 1,)
            if let Some(value_str) = line.split(':').nth(1) {
                let value_str = value_str.trim().trim_end_matches(',');
                if let Ok(v) = value_str.parse::<u8>() {
                    version = Some(v);
                }
            }
        } else if line.contains("encrypted_data") {
            if let Some(value) = line.split('"').nth(3) {
                encrypted_data_hex = Some(value);
            }
        }
    }

    let ephemeral_pubkey = PublicKey::from_str(
        ephemeral_pubkey_str.ok_or_else(|| anyhow::anyhow!("Missing ephemeral_pubkey"))?
    )?;

    let tag_bytes = ::hex::decode(
        tag_hex.ok_or_else(|| anyhow::anyhow!("Missing tag"))?
    )?;
    let mut tag = [0u8; 8];
    tag.copy_from_slice(&tag_bytes);

    let encrypted_data = ::hex::decode(
        encrypted_data_hex.ok_or_else(|| anyhow::anyhow!("Missing encrypted_data"))?
    )?;

    // Version defaults to v1 if not specified (for backward compatibility during transition)
    let version_val = version.unwrap_or(crate::snicker::SNICKER_VERSION_V1);

    Ok(EncryptedProposal {
        ephemeral_pubkey,
        tag,
        version: version_val,
        encrypted_data,
    })
}

pub async fn repl(
    network_str: &str,
    recovery_height: u32,
    rpc_config: Option<(String, String, String)>,
    peer: Option<String>,
) -> Result<()> {
    println!("RustSnicker Wallet 🥷");
    println!("Type 'help' for commands.\n");

    let mut manager_arc: Option<Arc<RwLock<Manager>>> = None;
    let mut opportunities: Vec<ProposalOpportunity> = Vec::new();
    let mut last_scan_delta_range: Option<(i64, i64)> = None;
    let mut last_created_proposal: Option<EncryptedProposal> = None;
    let mut automation_task: Option<AutomationTask> = None;

    loop {
        print!("wallet> ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        if input.is_empty() {
            continue;
        }

        let mut parts = input.split_whitespace();
        let cmd = parts.next().unwrap();
        let args: Vec<&str> = parts.collect();

        match cmd {
            "help" => print_help(),

            "generate" => {
                if args.len() != 1 {
                    println!("Usage: generate <wallet-name>");
                    continue;
                }
                let name = args[0];

                // Prompt for password
                let password = Password::new()
                    .with_prompt("Enter password to encrypt wallet")
                    .interact()?;

                let confirm_password = Password::new()
                    .with_prompt("Confirm password")
                    .interact()?;

                if password != confirm_password {
                    println!("❌ Passwords do not match. Wallet creation cancelled.");
                    continue;
                }

                println!("🪄 Creating wallet '{name}' …");
                let (mut manager, mnemonic) =
                    Manager::generate(name, network_str, recovery_height, &password).await?;
                println!("🔑 New mnemonic (store this safely!):\n{mnemonic}\n");
                println!("⚠️  IMPORTANT: Backup the entire wallet directory!");
                println!("   Location: ~/.local/share/ambient/{}/{}", network_str, name);
                io::stdout().flush()?;

                // Configure RPC if provided
                if let Some((ref url, ref user, ref password)) = rpc_config {
                    if let Err(e) = manager.set_rpc_client(url, (user.clone(), password.clone())) {
                        println!("⚠️  Warning: Failed to connect to Bitcoin Core RPC: {}", e);
                        println!("           Proposer mode disabled. Receiver mode still available.");
                    }
                }

                manager_arc = Some(Arc::new(RwLock::new(manager)));
            }

            "load" => {
                if args.len() != 1 {
                    println!("Usage: load <wallet-name>");
                    continue;
                }
                let name = args[0];

                // Retry loop for password
                loop {
                    // Prompt for password
                    let password = match Password::new()
                        .with_prompt("Enter wallet password")
                        .interact()
                    {
                        Ok(p) => p,
                        Err(_) => {
                            println!("❌ Password input cancelled");
                            break;
                        }
                    };

                    println!("📁 Loading wallet '{name}' …");
                    match Manager::load(name, network_str, recovery_height, &password, peer.clone()).await {
                        Ok(mut manager) => {
                            // Configure RPC if provided
                            if let Some((ref url, ref user, ref password)) = rpc_config {
                                if let Err(e) = manager.set_rpc_client(url, (user.clone(), password.clone())) {
                                    println!("⚠️  Warning: Failed to connect to Bitcoin Core RPC: {}", e);
                                    println!("           Proposer mode disabled. Receiver mode still available.");
                                }
                            }

                            manager_arc = Some(Arc::new(RwLock::new(manager)));
                            break; // Success, exit retry loop
                        }
                        Err(e) => {
                            let err_msg = e.to_string();
                            if err_msg.contains("Wrong password") || err_msg.contains("Encryption") {
                                println!("❌ {}", err_msg);
                                println!("   Please try again...\n");
                                // Continue loop to retry
                            } else {
                                // Other errors (file not found, etc.) - don't retry
                                println!("❌ Error loading wallet: {}", e);
                                break;
                            }
                        }
                    }
                }
            }

            "balance" => {
                if let Some(arc) = manager_arc.as_ref() {
                    let mgr = arc.read().await;
                    println!("{}", mgr.get_balance_with_pending().await?);
                } else {
                    println!("No wallet loaded.");
                }
            }

            "address" => {
                if let Some(arc) = manager_arc.as_ref() {
                    let mut mgr = arc.write().await;
                    let addr = mgr.get_next_address().await?;
                    println!("Next address: {addr}");
                } else {
                    println!("No wallet loaded.");
                }
            }

            "listunspent" => {
                if let Some(arc) = manager_arc.as_ref() {
                    let mgr = arc.read().await;
                    let utxos = mgr.list_unspent_with_status().await?;
                    if utxos.is_empty() {
                        println!("No UTXOs.");
                    } else {
                        for u in utxos {
                            println!("{u}");
                        }
                    }
                } else {
                    println!("No wallet loaded.");
                }
            }

            "summary" => {
                if let Some(arc) = manager_arc.as_ref() {
                    let mgr = arc.read().await;
                    mgr.print_summary().await;
                } else {
                    println!("No wallet loaded.");
                }
            }

            "peek" => {
                if let Some(arc) = manager_arc.as_ref() {
                    let mut mgr = arc.write().await;
                    let addresses = mgr.peek_addresses(10).await?;
                    for addr in addresses {
                        println!("{}", addr);
                    }
                } else {
                    println!("No wallet loaded.");
                }
            }

            "reregister" => {
                if let Some(arc) = manager_arc.as_ref() {
                    let mut mgr = arc.write().await;
                    println!("{}", mgr.reregister_revealed().await?);
                } else {
                    println!("No wallet loaded.");
                }
            }

            "reveal" => {
                if args.len() != 1 {
                    println!("Usage: reveal <index>");
                    continue;
                }
                if let Some(arc) = manager_arc.as_ref() {
                    let mut mgr = arc.write().await;
                    let index: u32 = args[0].parse().unwrap_or(0);
                    println!("{}", mgr.reveal_up_to(index).await?);
                } else {
                    println!("No wallet loaded.");
                }
            }

            "debug" => {
                if let Some(arc) = manager_arc.as_ref() {
                    let mgr = arc.read().await;
                    println!("{}", mgr.debug_transactions().await?);
                } else {
                    println!("No wallet loaded.");
                }
            }

            "send" => {
                if args.len() < 2 || args.len() > 3 {
                    println!("Usage: send <address> <amount_sats> [fee_rate_sat_vb]");
                    println!("Example: send tb1q... 10000           (auto fee estimation)");
                    println!("Example: send tb1q... 10000 1.5       (manual fee rate)");
                    continue;
                }
                if let Some(arc) = manager_arc.as_ref() {
                    let address = args[0];
                    let amount: u64 = match args[1].parse() {
                        Ok(a) => a,
                        Err(_) => {
                            println!("Invalid amount");
                            continue;
                        }
                    };

                    let mut mgr = arc.write().await;

                    // Use auto fee estimation if no fee rate provided
                    if args.len() == 2 {
                        println!("Sending {} sats to {} (auto fee estimation)...", amount, address);
                        match mgr.send_to_address_auto(address, amount).await {
                            Ok(txid) => println!("✅ Transaction broadcast: {}", txid),
                            Err(e) => println!("❌ Error: {}", e),
                        }
                    } else {
                        let fee_rate: f32 = match args[2].parse() {
                            Ok(f) => f,
                            Err(_) => {
                                println!("Invalid fee rate");
                                continue;
                            }
                        };
                        println!("Sending {} sats to {} (fee rate: {} sat/vB)...", amount, address, fee_rate);
                        match mgr.send_to_address(address, amount, fee_rate).await {
                            Ok(txid) => println!("✅ Transaction broadcast: {}", txid),
                            Err(e) => println!("❌ Error: {}", e),
                        }
                    }
                } else {
                    println!("No wallet loaded.");
                }
            }

            "build_snicker_tx" => {
                if args.len() != 3 {
                    println!("Usage: build_snicker_tx <address> <amount_sats> <fee_rate_sat_vb>");
                    println!("Example: build_snicker_tx bcrt1q... 500000 5.0");
                    println!("");
                    println!("Builds a SNICKER spending transaction without broadcasting.");
                    println!("Use this to test transaction validity before broadcasting:");
                    println!("  bitcoin-cli testmempoolaccept '[\"<hex>\"]'");
                    println!("  bitcoin-cli sendrawtransaction \"<hex>\"");
                    continue;
                }
                if let Some(arc) = manager_arc.as_ref() {
                    let address = args[0];
                    let amount: u64 = match args[1].parse() {
                        Ok(a) => a,
                        Err(_) => {
                            println!("Invalid amount");
                            continue;
                        }
                    };
                    let fee_rate: f32 = match args[2].parse() {
                        Ok(f) => f,
                        Err(_) => {
                            println!("Invalid fee rate");
                            continue;
                        }
                    };

                    println!("Building SNICKER transaction: {} sats to {} (fee rate: {} sat/vB)...",
                             amount, address, fee_rate);
                    let mut mgr = arc.write().await;
                    match mgr.build_snicker_tx(address, amount, fee_rate).await {
                        Ok(tx_hex) => {
                            println!("✅ Transaction built successfully!");
                            println!("");
                            println!("Transaction hex:");
                            println!("{}", tx_hex);
                            println!("");
                            println!("Test with:");
                            println!("  bitcoin-cli testmempoolaccept '[\"{}\" ]'", tx_hex);
                            println!("");
                            println!("Broadcast with:");
                            println!("  bitcoin-cli sendrawtransaction \"{}\"", tx_hex);
                        },
                        Err(e) => println!("❌ Error: {}", e),
                    }
                } else {
                    println!("No wallet loaded.");
                }
            }

            // Removed: scan_candidates command
            // Candidates are now queried directly from partial_utxo_set during find_opportunities
            // No separate scanning step is needed

            "test_get_block" => {
                if args.len() != 1 {
                    println!("Usage: test_get_block <block_hash>");
                    println!("Example: test_get_block 0000000000000000000000000000000000000000000000000000000000000000");
                    continue;
                }
                if let Some(arc) = manager_arc.as_ref() {
                    let hash_str = args[0];
                    match hash_str.parse::<bdk_wallet::bitcoin::BlockHash>() {
                        Ok(block_hash) => {
                            println!("🔍 Fetching block {} via Kyoto P2P...", block_hash);
                            let mut mgr = arc.write().await;
                            match mgr.get_block_info(block_hash).await {
                                Ok((version, prev_blockhash, num_txs, p2tr_count)) => {
                                    println!("✅ Successfully fetched block:");
                                    println!("   Hash: {}", block_hash);
                                    println!("   Transactions: {}", num_txs);
                                    println!("   Version: {:?}", version);
                                    println!("   Prev block: {}", prev_blockhash);
                                    println!("   P2TR outputs: {}", p2tr_count);
                                }
                                Err(e) => println!("❌ Failed to fetch block: {}", e),
                            }
                        }
                        Err(_) => println!("❌ Invalid block hash format"),
                    }
                } else {
                    println!("No wallet loaded.");
                }
            }

            "test_headers_db" => {
                if args.len() != 2 {
                    println!("Usage: test_headers_db <start_height> <end_height>");
                    println!("Example: test_headers_db 100 110");
                    continue;
                }
                if let Some(arc) = manager_arc.as_ref() {
                    let start_height: u32 = match args[0].parse() {
                        Ok(h) => h,
                        Err(_) => {
                            println!("Invalid start_height");
                            continue;
                        }
                    };
                    let end_height: u32 = match args[1].parse() {
                        Ok(h) => h,
                        Err(_) => {
                            println!("Invalid end_height");
                            continue;
                        }
                    };

                    println!("🔍 Querying Kyoto headers.db for heights {}-{}...", start_height, end_height);
                    let mgr = arc.read().await;
                    match mgr.get_block_hashes_from_headers_db(start_height, end_height).await {
                        Ok(hashes) => {
                            println!("✅ Retrieved {} block hashes:", hashes.len());
                            for (height, hash) in hashes.iter().take(10) {
                                println!("   Height {}: {}", height, hash);
                            }
                            if hashes.len() > 10 {
                                println!("   ... and {} more", hashes.len() - 10);
                            }
                        }
                        Err(e) => println!("❌ Failed to query headers.db: {}", e),
                    }
                } else {
                    println!("No wallet loaded.");
                }
            }

            "find_opportunities" => {
                if args.len() < 1 || args.len() > 4 {
                    println!("Usage: find_opportunities <min_candidate_sats> [max_candidate_sats] [max_block_age] [snicker_only]");
                    println!("Example: find_opportunities 10000");
                    println!("Example: find_opportunities 10000 100000");
                    println!("Example: find_opportunities 10000 100000 1000");
                    println!("Example: find_opportunities 10000 100000 0 true");
                    println!("  max_block_age: 0 = all blocks, N = last N blocks from tip");
                    continue;
                }
                if let Some(arc) = manager_arc.as_ref() {
                    let min_candidate_sats: u64 = match args[0].parse() {
                        Ok(m) => m,
                        Err(_) => {
                            println!("Invalid min_candidate_sats");
                            continue;
                        }
                    };
                    let max_candidate_sats: u64 = if args.len() > 1 {
                        match args[1].parse() {
                            Ok(m) => m,
                            Err(_) => {
                                println!("Invalid max_candidate_sats");
                                continue;
                            }
                        }
                    } else {
                        u64::MAX
                    };
                    let max_block_age: u32 = if args.len() > 2 {
                        match args[2].parse() {
                            Ok(m) => m,
                            Err(_) => {
                                println!("Invalid max_block_age");
                                continue;
                            }
                        }
                    } else {
                        0  // All blocks
                    };
                    let snicker_only = if args.len() > 3 {
                        args[3].to_lowercase() == "true"
                    } else {
                        false
                    };

                    println!("🔍 Finding SNICKER opportunities (candidates: {}-{} sats, block_age: {}, snicker_only={})...",
                             min_candidate_sats, max_candidate_sats, max_block_age, snicker_only);
                    let mut mgr = arc.write().await;
                    match mgr.find_snicker_opportunities(min_candidate_sats, max_candidate_sats, max_block_age, snicker_only).await {
                        Ok(found) => {
                            if found.is_empty() {
                                println!("No opportunities found.");
                                opportunities.clear();
                            } else {
                                println!("✅ Found {} opportunities:", found.len());
                                for (i, opp) in found.iter().enumerate().take(10) {
                                    println!("  [{}] Our UTXO: {}:{} ({} sats) + Candidate UTXO: {}:{} ({} sats)",
                                             i,
                                             opp.our_outpoint.txid,
                                             opp.our_outpoint.vout,
                                             opp.our_value.to_sat(),
                                             opp.target_outpoint.txid,
                                             opp.target_outpoint.vout,
                                             opp.target_txout.value.to_sat());
                                }
                                if found.len() > 10 {
                                    println!("  ... and {} more", found.len() - 10);
                                }
                                println!("\nUse 'create_proposal <index> <delta_sats>' to create a proposal");
                                opportunities = found;
                            }
                        }
                        Err(e) => println!("❌ Error: {}", e),
                    }
                } else {
                    println!("No wallet loaded.");
                }
            }

            // Removed: list_candidates and clear_candidates commands
            // Candidates are now queried directly from partial_utxo_set on-demand
            // Use 'find_opportunities' to see available candidates

            "clear_proposals" => {
                if let Some(arc) = manager_arc.as_ref() {
                    let mut mgr = arc.write().await;
                    match mgr.clear_snicker_proposals().await {
                        Ok(count) => println!("✅ Cleared {} proposals", count),
                        Err(e) => println!("❌ Error: {}", e),
                    }
                } else {
                    println!("No wallet loaded.");
                }
            }

            "snicker_pattern_check" => {
                if let Some(arc) = manager_arc.as_ref() {
                    let mgr = arc.read().await;
                    // Query candidates with reasonable defaults (10k-100M sats, all blocks, all transaction types)
                    match mgr.get_snicker_candidates(10_000, 100_000_000, 0, false).await {
                        Ok(all_candidates) => {
                            println!("🔍 Listing {} candidate UTXOs...\n", all_candidates.len());

                            // Candidates are now individual UTXOs, not full transactions
                            // Group by block height for display
                            use std::collections::BTreeMap;
                            let mut by_height: BTreeMap<u32, Vec<_>> = BTreeMap::new();

                            for (txid, vout, height, amount, _script_pubkey) in &all_candidates {
                                by_height.entry(*height).or_insert_with(Vec::new).push((txid, vout, amount));
                            }

                            for (height, utxos) in by_height.iter().rev().take(20) {
                                println!("Block {}:", height);
                                for (txid, vout, amount) in utxos {
                                    println!("  {}:{} - {} sats", txid, vout, amount);
                                }
                            }

                            println!("\n📊 Summary:");
                            println!("   Total candidate UTXOs: {}", all_candidates.len());
                            println!("   Note: Candidates are now individual UTXOs, not full transactions");
                        }
                        Err(e) => println!("❌ Error: {}", e),
                    }
                } else {
                    println!("❌ No wallet loaded");
                }
            }

            "create_proposal" => {
                if args.len() != 2 {
                    println!("Usage: create_proposal <index> <delta_sats>");
                    println!("Example: create_proposal 0 5000");
                    continue;
                }
                if let Some(arc) = manager_arc.as_ref() {
                    // Parse index
                    let index: usize = match args[0].parse() {
                        Ok(i) => i,
                        Err(_) => {
                            println!("Invalid index");
                            continue;
                        }
                    };

                    let delta_sats: i64 = match args[1].parse() {
                        Ok(d) => d,
                        Err(_) => {
                            println!("Invalid delta_sats");
                            continue;
                        }
                    };

                    // Look up opportunity by index
                    let opp = match opportunities.get(index) {
                        Some(o) => o,
                        None => {
                            println!("❌ No opportunity at index {}. Run 'find_opportunities' to see available opportunities.", index);
                            continue;
                        }
                    };

                    println!("🔨 Creating proposal for opportunity [{}]...", index);
                    println!("   Our UTXO: {}:{} ({} sats)",
                             opp.our_outpoint.txid,
                             opp.our_outpoint.vout,
                             opp.our_value.to_sat());
                    println!("   Target: {} sats, Delta: {} sats", opp.target_txout.value.to_sat(), delta_sats);

                    let mut mgr = arc.write().await;
                    match mgr.create_snicker_proposal(opp, delta_sats, crate::config::DEFAULT_MIN_CHANGE_OUTPUT_SIZE).await {
                        Ok((proposal, encrypted_proposal)) => {
                            println!("✅ Proposal created!");
                            println!("   Tag: {}", ::hex::encode(&proposal.tag));
                            println!("\n📝 Encrypted proposal (hex-encoded, share this with receiver):");
                            println!("{}", format_encrypted_proposal(&encrypted_proposal));
                            println!("\n💾 Use 'save_proposal <filename>' to save to a file");
                            last_created_proposal = Some(encrypted_proposal);
                        }
                        Err(e) => println!("❌ Error: {}", e),
                    }
                } else {
                    println!("No wallet loaded.");
                }
            }

            "scan_proposals" => {
                if args.len() != 2 {
                    println!("Usage: scan_proposals <min_delta_sats> <max_delta_sats>");
                    println!("Example: scan_proposals -10000 10000");
                    continue;
                }
                if let Some(arc) = manager_arc.as_ref() {
                    let min_delta: i64 = match args[0].parse() {
                        Ok(m) => m,
                        Err(_) => {
                            println!("Invalid min_delta_sats");
                            continue;
                        }
                    };
                    let max_delta: i64 = match args[1].parse() {
                        Ok(m) => m,
                        Err(_) => {
                            println!("Invalid max_delta_sats");
                            continue;
                        }
                    };

                    println!("🔍 Scanning for SNICKER proposals (delta range: {} to {} sats)...",
                             min_delta, max_delta);

                    // Store delta range for later use in accept_proposal
                    last_scan_delta_range = Some((min_delta, max_delta));

                    let mut mgr = arc.write().await;
                    match mgr.scan_for_our_proposals((min_delta, max_delta)).await {
                        Ok(found) => {
                            if found.is_empty() {
                                println!("No proposals found for our UTXOs.");
                            } else {
                                println!("✅ Found {} proposals:", found.len());
                                for proposal in found.iter().take(10) {
                                    // Use Manager's formatting method
                                    let (tag_hex, proposer_input, proposer_value, receiver_output, delta) =
                                        mgr.format_proposal_info(proposal);

                                    println!("  [{}] Proposer: {} ({} sats) → Our output: {} sats (delta: {})",
                                             tag_hex, proposer_input, proposer_value, receiver_output, delta);
                                }
                                if found.len() > 10 {
                                    println!("  ... and {} more", found.len() - 10);
                                }
                                println!("\nUse 'accept_proposal <tag>' to accept and broadcast");
                            }
                        }
                        Err(e) => println!("❌ Error: {}", e),
                    }
                } else {
                    println!("No wallet loaded.");
                }
            }

            "accept_proposal" => {
                if args.len() != 1 {
                    println!("Usage: accept_proposal <tag>");
                    println!("Example: accept_proposal a1b2c3d4e5f6a7b8");
                    continue;
                }
                if let Some(arc) = manager_arc.as_ref() {
                    // Parse hex tag using Manager method
                    let tag_hex = args[0];
                    let tag = match Manager::parse_hex_tag(tag_hex) {
                        Ok(t) => t,
                        Err(e) => {
                            println!("❌ {}", e);
                            continue;
                        }
                    };

                    // Use stored delta range or default wide range
                    let acceptable_range = last_scan_delta_range
                        .unwrap_or((-100_000_000, 100_000_000));

                    println!("✍️  Accepting proposal {}...", tag_hex);

                    // Use the high-level manager method that handles the complete workflow
                    let mut mgr = arc.write().await;
                    match mgr.accept_and_broadcast_snicker_proposal(&tag, acceptable_range).await {
                        Ok(txid) => {
                            println!("✅ SNICKER coinjoin broadcast: {}", txid);
                            println!("🎉 SNICKER coinjoin complete!");
                        }
                        Err(e) => println!("❌ Error: {}", e),
                    }
                } else {
                    println!("No wallet loaded.");
                }
            }

            "save_proposal" => {
                if args.len() != 1 {
                    println!("Usage: save_proposal <filename>");
                    println!("Example: save_proposal proposal.json");
                    continue;
                }
                match &last_created_proposal {
                    Some(proposal) => {
                        let filename = args[0];
                        let formatted = format_encrypted_proposal(proposal);
                        match fs::write(filename, formatted) {
                            Ok(_) => println!("✅ Proposal saved to {}", filename),
                            Err(e) => println!("❌ Error saving file: {}", e),
                        }
                    }
                    None => {
                        println!("❌ No proposal to save. Create a proposal first with 'create_proposal'");
                    }
                }
            }

            "load_proposal" => {
                if args.len() != 1 {
                    println!("Usage: load_proposal <filename>");
                    println!("Example: load_proposal proposal.json");
                    continue;
                }
                if let Some(arc) = manager_arc.as_ref() {
                    let filename = args[0];
                    match fs::read_to_string(filename) {
                        Ok(contents) => {
                            // Parse the hex-encoded format back to EncryptedProposal
                            match parse_encrypted_proposal(&contents) {
                                Ok(proposal) => {
                                    let mut mgr = arc.write().await;
                                    match mgr.store_snicker_proposal(&proposal).await {
                                        Ok(_) => {
                                            println!("✅ Proposal loaded and stored");
                                            println!("   Use 'scan_proposals' to find it among your UTXOs");
                                        }
                                        Err(e) => println!("❌ Error storing proposal: {}", e),
                                    }
                                }
                                Err(e) => println!("❌ Error parsing proposal: {}", e),
                            }
                        }
                        Err(e) => println!("❌ Error reading file: {}", e),
                    }
                } else {
                    println!("No wallet loaded.");
                }
            }

            // Automation commands
            "automation_start" => {
                if let Some(ref arc) = manager_arc {
                    // Stop existing task if running
                    if let Some(mut task) = automation_task.take() {
                        if task.is_running() {
                            println!("⏸️  Stopping existing automation task...");
                            task.stop().await;
                        }
                    }

                    // Load configuration
                    let config = match Config::load() {
                        Ok(c) => c,
                        Err(e) => {
                            println!("❌ Failed to load config: {}", e);
                            continue;
                        }
                    };

                    // Check if automation is enabled
                    if config.snicker_automation.mode == crate::config::AutomationMode::Disabled {
                        println!("⚠️  Automation is disabled in config.");
                        println!("   Edit config file to enable: {:?}", crate::config::get_config_path());
                        continue;
                    }

                    let mut task = AutomationTask::new();
                    let task_config = AutomationConfig::default();

                    println!("🤖 Starting SNICKER automation...");
                    println!("   Mode: {:?}", config.snicker_automation.mode);
                    println!("   Max delta: {} sats", config.snicker_automation.max_delta);
                    println!("   Max proposals/day: {}", config.snicker_automation.max_proposals_per_day);
                    println!("   Interval: {} seconds", task_config.interval_secs);

                    task.start(
                        arc.clone(),
                        config.snicker_automation.clone(),
                        task_config,
                    ).await;

                    automation_task = Some(task);
                    println!("✅ Automation started");
                } else {
                    println!("❌ No wallet loaded");
                }
            }

            "automation_stop" => {
                if let Some(mut task) = automation_task.take() {
                    if task.is_running() {
                        println!("⏸️  Stopping automation task...");
                        task.stop().await;
                        println!("✅ Automation stopped");
                    } else {
                        println!("⚠️  Automation task not running");
                    }
                } else {
                    println!("⚠️  No automation task to stop");
                }
            }

            "automation_status" => {
                match &automation_task {
                    Some(task) => {
                        println!("🤖 Automation Status: {}", task.status());

                        // Load config to show current settings
                        if let Ok(config) = Config::load() {
                            println!("   Mode: {:?}", config.snicker_automation.mode);
                            println!("   Max delta: {} sats", config.snicker_automation.max_delta);
                            println!("   Max proposals/day: {}", config.snicker_automation.max_proposals_per_day);
                            println!("   SNICKER pattern only: {}", config.snicker_automation.snicker_pattern_only);
                            println!("   Prefer SNICKER outputs: {}", config.snicker_automation.prefer_snicker_outputs);
                        }
                    }
                    None => {
                        println!("🤖 Automation Status: Not started");
                        println!("   Use 'automation_start' to begin");
                    }
                }
            }

            "quit" | "exit" => {
                // Stop automation task if running
                if let Some(mut task) = automation_task.take() {
                    if task.is_running() {
                        println!("⏸️  Stopping automation task...");
                        task.stop().await;
                    }
                }

                println!("👋 Goodbye.");
                break;
            }

            other => {
                println!("Unknown command: {other}");
            }
        }
    }

    Ok(())
}

fn print_help() {
    println!("Wallet Commands:");
    println!("  generate <name>                    - create a new wallet");
    println!("  load <name>                        - load an existing wallet");
    println!("  balance                            - show balance");
    println!("  address                            - get next receive address");
    println!("  listunspent                        - show UTXOs");
    println!("  summary                            - show wallet summary");
    println!("  send <addr> <amt> <fee>            - send transaction (addr, sats, sat/vB)");
    println!("  build_snicker_tx <addr> <amt> <f>  - build SNICKER tx without broadcasting (testing)");
    println!();
    println!("SNICKER Commands (Proposer side):");
    println!("  test_get_block <hash>              - test: fetch block by hash via Kyoto P2P");
    println!("  test_headers_db <start> <end>      - test: query headers.db for block hashes");
    println!("  find_opportunities <min> [max] [snicker_only] - find proposal opportunities");
    println!("  create_proposal <index> <delta>    - create proposal (use index from find_opportunities)");
    println!("  save_proposal <file>               - save last proposal to file");
    println!();
    println!("SNICKER Commands (Receiver side):");
    println!("  load_proposal <file>               - load proposal from file");
    println!("  scan_proposals <min> <max>         - scan for proposals (min-max delta in sats)");
    println!("  accept_proposal <tag>              - accept and broadcast coinjoin (16 hex chars)");
    println!();
    println!("SNICKER Automation:");
    println!("  automation_start                   - start background automation task");
    println!("  automation_stop                    - stop background automation task");
    println!("  automation_status                  - show automation status and settings");
    println!();
    println!("SNICKER Maintenance:");
    println!("  clear_proposals                    - clear proposals database");
    println!("  snicker_pattern_check              - analyze candidates for SNICKER pattern");
    println!();
    println!("Other:");
    println!("  help                               - show this help message");
    println!("  quit                               - exit");
}
