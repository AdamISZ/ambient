use anyhow::Result;
use std::io::{self, Write};

use crate::manager::Manager;

pub async fn repl(network_str: &str, recovery_height: u32) -> Result<()> {
    println!("RustSnicker Wallet 🥷");
    println!("Type 'help' for commands.\n");

    let mut current: Option<Manager> = None;

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
                println!("🪄 Creating wallet '{name}' …");
                let (manager, mnemonic) =
                    Manager::generate(name, network_str, recovery_height).await?;
                println!("🔑 New mnemonic (store this safely!):\n{mnemonic}\n");
                io::stdout().flush()?;
                current = Some(manager);
            }

            "load" => {
                if args.len() != 1 {
                    println!("Usage: load <wallet-name>");
                    continue;
                }
                let name = args[0];
                println!("📁 Loading wallet '{name}' …");
                current = Some(Manager::load(name, network_str, recovery_height).await?);
            }

            "balance" => {
                if let Some(mgr) = current.as_mut() {
                    println!("Balance: {}", mgr.get_balance().await?);
                } else {
                    println!("No wallet loaded.");
                }
            }

            "address" => {
                if let Some(mgr) = current.as_mut() {
                    let addr = mgr.get_next_address().await?;
                    println!("Next address: {addr}");
                } else {
                    println!("No wallet loaded.");
                }
            }

            "listunspent" => {
                if let Some(mgr) = current.as_mut() {
                    let utxos = mgr.list_unspent().await?;
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
                if let Some(mgr) = current.as_mut() {
                    mgr.print_summary().await;
                } else {
                    println!("No wallet loaded.");
                }
            }

            "sync" => {
                if let Some(mgr) = current.as_mut() {
                    println!("Syncing (recent blocks)...");
                    mgr.wallet_node.sync_recent().await?;
                    println!("Done.");
                } else {
                    println!("No wallet loaded.");
                }
            }

            "peek" => {
                if let Some(mgr) = current.as_mut() {
                    let addresses = mgr.wallet_node.peek_addresses(10).await?;
                    for addr in addresses {
                        println!("{}", addr);
                    }
                } else {
                    println!("No wallet loaded.");
                }
            }

            "reregister" => {
                if let Some(mgr) = current.as_mut() {
                    println!("{}", mgr.wallet_node.reregister_revealed().await?);
                } else {
                    println!("No wallet loaded.");
                }
            }

            "reveal" => {
                if args.len() != 1 {
                    println!("Usage: reveal <index>");
                    continue;
                }
                if let Some(mgr) = current.as_mut() {
                    let index: u32 = args[0].parse().unwrap_or(0);
                    println!("{}", mgr.wallet_node.reveal_up_to(index).await?);
                } else {
                    println!("No wallet loaded.");
                }
            }

            "debug" => {
                if let Some(mgr) = current.as_mut() {
                    println!("{}", mgr.wallet_node.debug_transactions().await?);
                } else {
                    println!("No wallet loaded.");
                }
            }

            "send" => {
                if args.len() != 3 {
                    println!("Usage: send <address> <amount_sats> <fee_rate_sat_vb>");
                    println!("Example: send tb1q... 10000 1.5");
                    continue;
                }
                if let Some(mgr) = current.as_mut() {
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

                    println!("Sending {} sats to {} (fee rate: {} sat/vB)...", amount, address, fee_rate);
                    match mgr.send_to_address(address, amount, fee_rate).await {
                        Ok(txid) => println!("✅ Transaction broadcast: {}", txid),
                        Err(e) => println!("❌ Error: {}", e),
                    }
                } else {
                    println!("No wallet loaded.");
                }
            }

            // SNICKER commands
            "scan_candidates" => {
                if args.len() != 3 {
                    println!("Usage: scan_candidates <num_blocks> <min_sats> <max_sats>");
                    println!("Example: scan_candidates 10 10000 1000000");
                    continue;
                }
                if let Some(mgr) = current.as_mut() {
                    let num_blocks: u32 = match args[0].parse() {
                        Ok(n) => n,
                        Err(_) => {
                            println!("Invalid num_blocks");
                            continue;
                        }
                    };
                    let min_sats: u64 = match args[1].parse() {
                        Ok(m) => m,
                        Err(_) => {
                            println!("Invalid min_sats");
                            continue;
                        }
                    };
                    let max_sats: u64 = match args[2].parse() {
                        Ok(m) => m,
                        Err(_) => {
                            println!("Invalid max_sats");
                            continue;
                        }
                    };

                    println!("🔍 Scanning {} blocks for SNICKER candidates ({}-{} sats)...",
                             num_blocks, min_sats, max_sats);
                    match mgr.scan_for_snicker_candidates(num_blocks, min_sats, max_sats).await {
                        Ok(count) => println!("✅ Found and stored {} candidates", count),
                        Err(e) => println!("❌ Error: {}", e),
                    }
                } else {
                    println!("No wallet loaded.");
                }
            }

            "find_opportunities" => {
                if args.len() != 1 {
                    println!("Usage: find_opportunities <min_utxo_sats>");
                    println!("Example: find_opportunities 75000");
                    continue;
                }
                if let Some(mgr) = current.as_mut() {
                    let min_utxo_sats: u64 = match args[0].parse() {
                        Ok(m) => m,
                        Err(_) => {
                            println!("Invalid min_utxo_sats");
                            continue;
                        }
                    };

                    println!("🔍 Finding SNICKER opportunities...");
                    match mgr.find_snicker_opportunities(min_utxo_sats).await {
                        Ok(opportunities) => {
                            if opportunities.is_empty() {
                                println!("No opportunities found.");
                            } else {
                                println!("✅ Found {} opportunities:", opportunities.len());
                                for (i, opp) in opportunities.iter().enumerate().take(10) {
                                    println!("  [{}] Our UTXO: {}:{} ({} sats) → Target: {} sats",
                                             i,
                                             opp.our_outpoint.txid,
                                             opp.our_outpoint.vout,
                                             opp.our_value.to_sat(),
                                             opp.target_value.to_sat());
                                }
                                if opportunities.len() > 10 {
                                    println!("  ... and {} more", opportunities.len() - 10);
                                }
                            }
                        }
                        Err(e) => println!("❌ Error: {}", e),
                    }
                } else {
                    println!("No wallet loaded.");
                }
            }

            "list_candidates" => {
                if let Some(mgr) = current.as_mut() {
                    match mgr.get_snicker_candidates().await {
                        Ok(candidates) => {
                            if candidates.is_empty() {
                                println!("No candidates stored.");
                            } else {
                                println!("Stored candidates ({}):", candidates.len());
                                for (height, txid, _tx) in candidates.iter().take(20) {
                                    println!("  Block {}: {}", height, txid);
                                }
                                if candidates.len() > 20 {
                                    println!("  ... and {} more", candidates.len() - 20);
                                }
                            }
                        }
                        Err(e) => println!("❌ Error: {}", e),
                    }
                } else {
                    println!("No wallet loaded.");
                }
            }

            "clear_candidates" => {
                if let Some(mgr) = current.as_mut() {
                    match mgr.clear_snicker_candidates().await {
                        Ok(count) => println!("✅ Cleared {} candidates", count),
                        Err(e) => println!("❌ Error: {}", e),
                    }
                } else {
                    println!("No wallet loaded.");
                }
            }

            "clear_proposals" => {
                if let Some(mgr) = current.as_mut() {
                    match mgr.clear_snicker_proposals().await {
                        Ok(count) => println!("✅ Cleared {} proposals", count),
                        Err(e) => println!("❌ Error: {}", e),
                    }
                } else {
                    println!("No wallet loaded.");
                }
            }

            "quit" | "exit" => {
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
    println!("  sync                               - rescan recent blocks");
    println!();
    println!("SNICKER Commands:");
    println!("  scan_candidates <n> <min> <max>    - scan N blocks for candidates (min-max sats)");
    println!("  list_candidates                    - list stored candidate transactions");
    println!("  find_opportunities <min_utxo>      - find proposal opportunities (min UTXO sats)");
    println!("  clear_candidates                   - clear candidate database");
    println!("  clear_proposals                    - clear proposals database");
    println!();
    println!("Other:");
    println!("  help                               - show this help message");
    println!("  quit                               - exit");
}
