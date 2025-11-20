use anyhow::Result;
use std::io::{self, Write};

use crate::wallet_node::WalletNode;

pub async fn repl(network_str: &str, recovery_height: u32) -> Result<()> {
    println!("RustSnicker Wallet 🥷");
    println!("Type 'help' for commands.\n");

    let mut current: Option<WalletNode> = None;

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
                let (node, mnemonic) =
                    WalletNode::generate(name, network_str, recovery_height).await?;
                println!("🔑 New mnemonic (store this safely!):\n{mnemonic}\n");
                io::stdout().flush()?;
                current = Some(node);
            }

            "load" => {
                if args.len() != 1 {
                    println!("Usage: load <wallet-name>");
                    continue;
                }
                let name = args[0];
                println!("📁 Loading wallet '{name}' …");
                current = Some(WalletNode::load(name, network_str, recovery_height).await?);
            }

            "balance" => {
                if let Some(node) = current.as_mut() {
                    println!("Balance: {}", node.get_balance().await?);
                } else {
                    println!("No wallet loaded.");
                }
            }

            "address" => {
                if let Some(node) = current.as_mut() {
                    let addr = node.get_next_address().await?;
                    println!("Next address: {addr}");
                } else {
                    println!("No wallet loaded.");
                }
            }

            "listunspent" => {
                if let Some(node) = current.as_mut() {
                    let utxos = node.list_unspent().await?;
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
                if let Some(node) = current.as_mut() {
                    node.print_summary().await;
                } else {
                    println!("No wallet loaded.");
                }
            }

            "sync" => {
                if let Some(node) = current.as_mut() {
                    println!("Syncing (recent blocks)...");
                    node.sync_recent().await?;
                    println!("Done.");
                } else {
                    println!("No wallet loaded.");
                }
            }

            "peek" => {
      if let Some(node) = current.as_mut() {
          let addresses = node.peek_addresses(10).await?;
          for addr in addresses {
              println!("{}", addr);
          }
      } else {
          println!("No wallet loaded.");
      }
  }

    "reregister" => {
      if let Some(node) = current.as_mut() {
          println!("{}", node.reregister_revealed().await?);
      } else {
          println!("No wallet loaded.");
      }
  }

  "reveal" => {
      if args.len() != 1 {
          println!("Usage: reveal <index>");
          continue;
      }
      if let Some(node) = current.as_mut() {
          let index: u32 = args[0].parse().unwrap_or(0);
          println!("{}", node.reveal_up_to(index).await?);
      } else {
          println!("No wallet loaded.");
      }
  }

  "debug" => {
      if let Some(node) = current.as_mut() {
          println!("{}", node.debug_transactions().await?);
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
      if let Some(node) = current.as_mut() {
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
          match node.send_to_address(address, amount, fee_rate).await {
              Ok(txid) => println!("✅ Transaction broadcast: {}", txid),
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
    println!("Commands:");
    println!("  generate <name>         - create a new wallet");
    println!("  load <name>             - load an existing wallet");
    println!("  balance                 - show balance");
    println!("  address                 - get next receive address");
    println!("  listunspent             - show UTXOs");
    println!("  summary                 - show wallet summary");
    println!("  send <addr> <amt> <fee> - send transaction (addr, sats, sat/vB)");
    println!("  sync                    - rescan recent blocks for this wallet");
    println!("  help                    - show this help message");
    println!("  quit                    - exit");
}
