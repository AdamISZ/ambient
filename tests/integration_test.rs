use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use bdk_wallet::{
    bitcoin::{Network, Amount, Address},
    keys::{
        bip39::{Language, Mnemonic, WordCount},
        DerivableKey, ExtendedKey, GeneratableKey, GeneratedKey,
    },
    rusqlite::Connection,
    miniscript::Tap,
    KeychainKind, Wallet, PersistedWallet,
};
use bdk_kyoto::builder::{Builder, BuilderExt};
use bdk_kyoto::{LightClient, ScanType};
use once_cell::sync::Lazy;
use tokio::sync::Mutex;

const RECOVERY_LOOKAHEAD: u32 = 50;

// ============================================================
// SHARED REGTEST BITCOIND INSTANCE
// ============================================================

struct TestBitcoind {
    process: Child,
    datadir: PathBuf,
    rpc_port: u16,
    p2p_port: u16,
}

impl TestBitcoind {
    fn start() -> Result<Self> {
        // Find bitcoind binary
        let bitcoind_path = std::env::var("BITCOIND_PATH")
            .or_else(|_| std::env::var("BITCOIN_BIN_DIR").map(|dir| format!("{}/bitcoind", dir)))
            .or_else(|_| which::which("bitcoind").map(|p| p.to_string_lossy().to_string()))
            .map_err(|_| anyhow!(
                "Cannot find bitcoind binary. Set BITCOIND_PATH or BITCOIN_BIN_DIR environment variable, \
                or ensure bitcoind is in PATH"
            ))?;

        let bitcoin_cli_path = std::env::var("BITCOIN_CLI_PATH")
            .or_else(|_| std::env::var("BITCOIN_BIN_DIR").map(|dir| format!("{}/bitcoin-cli", dir)))
            .or_else(|_| which::which("bitcoin-cli").map(|p| p.to_string_lossy().to_string()))
            .map_err(|_| anyhow!(
                "Cannot find bitcoin-cli binary. Set BITCOIN_CLI_PATH or BITCOIN_BIN_DIR environment variable, \
                or ensure bitcoin-cli is in PATH"
            ))?;

        // Clean up any stale bitcoind processes (Drop isn't called for statics in tests)
        let rpc_port = 18443;
        let p2p_port = 18444;

        println!("🔍 Checking for stale bitcoind processes on port {}...", rpc_port);

        // Find and kill any process using our RPC port
        let lsof_output = Command::new("lsof")
            .args(&["-t", "-i", &format!(":{}", rpc_port)])
            .output()
            .ok();

        if let Some(output) = lsof_output {
            if !output.stdout.is_empty() {
                let pids = String::from_utf8_lossy(&output.stdout);
                for pid in pids.lines() {
                    if let Ok(pid_num) = pid.trim().parse::<i32>() {
                        println!("   ⚠️  Found stale bitcoind process (PID: {}), terminating...", pid_num);
                        // Send SIGTERM first (graceful)
                        let _ = Command::new("kill").arg(pid).output();
                        std::thread::sleep(Duration::from_millis(500));

                        // Check if still running, send SIGKILL if needed
                        let still_running = Command::new("kill")
                            .args(&["-0", pid])
                            .output()
                            .map(|o| o.status.success())
                            .unwrap_or(false);

                        if still_running {
                            println!("   ⚠️  Process still running, sending SIGKILL...");
                            let _ = Command::new("kill").args(&["-9", pid]).output();
                            std::thread::sleep(Duration::from_millis(500));
                        }
                    }
                }
            }
        }

        // Verify port is now free
        let port_check = Command::new("lsof")
            .args(&["-i", &format!(":{}", rpc_port)])
            .output()
            .map(|out| out.stdout.is_empty())
            .unwrap_or(true);

        if port_check {
            println!("   ✅ Port {} is free", rpc_port);
        } else {
            return Err(anyhow!("Failed to free port {}", rpc_port));
        }

        // Create temporary datadir and mark it to persist (not auto-delete)
        let datadir = tempfile::tempdir()?.keep();

        println!("🚀 Starting regtest bitcoind...");
        println!("   Datadir: {:?}", datadir);
        println!("   Datadir string: {}", datadir.display());
        println!("   Binary: {}", bitcoind_path);

        // Start bitcoind (no -daemon, we manage the process directly with spawn())
        let datadir_arg = format!("-datadir={}", datadir.display());
        println!("   Datadir arg: {}", datadir_arg);

        println!("   RIGHT BEFORE SPAWN - datadir: {:?}", datadir);
        println!("   RIGHT BEFORE SPAWN - datadir_arg: {}", datadir_arg);

        // Start bitcoind with stdio redirected to null (piping interferes with cleanup)
        let mut process = Command::new(&bitcoind_path)
            .args(&[
                "-regtest",
                "-noconf", // Don't read any bitcoin.conf file
                &datadir_arg,
                "-server=1",
                "-txindex=1",
                "-fallbackfee=0.00001",
                &format!("-rpcport={}", rpc_port),
                &format!("-port={}", p2p_port),
                "-rpcuser=test",
                "-rpcpassword=test",
                "-blockfilterindex=1", // Enable compact block filters (BIP157)
                "-peerblockfilters=1", // Serve compact block filters to peers
                "-printtoconsole=0", // Suppress console output
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| anyhow!("Failed to spawn bitcoind: {}", e))?;

        let pid = process.id();
        println!("   Spawned process PID: {}", pid);

        // Give it a moment and check if it's still running
        std::thread::sleep(Duration::from_millis(500));

        // Check if process already exited (e.g., failed to bind to ports)
        match process.try_wait() {
            Ok(Some(status)) => {
                return Err(anyhow!(
                    "bitcoind exited immediately with status: {}. \
                    This usually means ports are in use or datadir issues. \
                    Check debug.log in {:?}",
                    status, datadir
                ));
            }
            Ok(None) => {
                println!("   ✅ Process still running after 500ms check");
            }
            Err(e) => {
                return Err(anyhow!("Failed to check process status: {}", e));
            }
        }

        let bitcoind = Self {
            process,
            datadir: datadir.clone(),
            rpc_port,
            p2p_port,
        };

        // Wait for bitcoind to be ready
        println!("   Waiting for bitcoind to be ready...");
        for i in 0..30 {
            std::thread::sleep(Duration::from_secs(1));

            let output = Command::new(&bitcoin_cli_path)
                .args(&[
                    "-regtest",
                    &format!("-datadir={}", datadir.display()),
                    "-rpcuser=test",
                    "-rpcpassword=test",
                    "getblockchaininfo",
                ])
                .output();

            if let Ok(out) = output {
                if out.status.success() {
                    println!("   ✅ bitcoind is ready");
                    break;
                } else if i > 5 {
                    // After a few tries, print error for debugging
                    eprintln!("   bitcoin-cli error: {}", String::from_utf8_lossy(&out.stderr));
                }
            }

            if i == 29 {
                return Err(anyhow!("bitcoind failed to start within 30 seconds"));
            }
        }

        // Create wallet
        println!("   Creating wallet...");
        let wallet_output = Command::new(&bitcoin_cli_path)
            .args(&[
                "-regtest",
                &format!("-datadir={}", datadir.display()),
                "-rpcuser=test",
                "-rpcpassword=test",
                "createwallet",
                "testwallet",
            ])
            .output()
            .map_err(|e| anyhow!("Failed to create wallet: {}", e))?;

        if !wallet_output.status.success() {
            eprintln!("   Wallet creation stderr: {}", String::from_utf8_lossy(&wallet_output.stderr));
            return Err(anyhow!("Failed to create wallet"));
        }
        println!("   ✅ Wallet created");

        // Generate initial blocks (101 for coinbase maturity)
        println!("   Generating 101 initial blocks...");
        let addr_output = Command::new(&bitcoin_cli_path)
            .args(&[
                "-regtest",
                &format!("-datadir={}", datadir.display()),
                "-rpcuser=test",
                "-rpcpassword=test",
                "-rpcwallet=testwallet",
                "getnewaddress",
            ])
            .output()
            .map_err(|e| anyhow!("Failed to get new address: {}", e))?;

        if !addr_output.status.success() {
            eprintln!("   getnewaddress stderr: {}", String::from_utf8_lossy(&addr_output.stderr));
            return Err(anyhow!("Failed to get new address"));
        }

        let addr = String::from_utf8_lossy(&addr_output.stdout).trim().to_string();
        println!("   Mining to address: {}", addr);

        let gen_output = Command::new(&bitcoin_cli_path)
            .args(&[
                "-regtest",
                &format!("-datadir={}", datadir.display()),
                "-rpcuser=test",
                "-rpcpassword=test",
                "generatetoaddress",
                "101",
                &addr,
            ])
            .output()
            .map_err(|e| anyhow!("Failed to generate blocks: {}", e))?;

        if !gen_output.status.success() {
            eprintln!("   generatetoaddress stderr: {}", String::from_utf8_lossy(&gen_output.stderr));
            return Err(anyhow!("Failed to generate blocks"));
        }

        println!("   ✅ Regtest bitcoind ready!");
        println!("      RPC: localhost:{}", rpc_port);
        println!("      P2P: localhost:{}", p2p_port);

        // Give bitcoind a moment to fully initialize P2P
        std::thread::sleep(Duration::from_secs(2));

        Ok(bitcoind)
    }

    fn rpc_call(&self, method: &str, params: &[serde_json::Value], wallet: Option<&str>) -> Result<serde_json::Value> {
        let url = match wallet {
            Some(w) => format!("http://127.0.0.1:{}/wallet/{}", self.rpc_port, w),
            None => format!("http://127.0.0.1:{}", self.rpc_port),
        };

        let request = serde_json::json!({
            "jsonrpc": "1.0",
            "id": "test",
            "method": method,
            "params": params,
        });

        let response: serde_json::Value = ureq::post(&url)
            .set("Authorization", &format!("Basic {}", base64_encode("test:test")))
            .send_json(&request)?
            .into_json()?;

        if let Some(error) = response.get("error").and_then(|e| e.as_object()) {
            return Err(anyhow!("RPC error: {:?}", error));
        }

        Ok(response["result"].clone())
    }

    fn mine_blocks(&self, count: u64) -> Result<()> {
        let addr = self.rpc_call("getnewaddress", &[], Some("testwallet"))?
            .as_str()
            .ok_or_else(|| anyhow!("Failed to get address"))?
            .to_string();

        self.rpc_call("generatetoaddress", &[
            serde_json::json!(count),
            serde_json::json!(addr),
        ], None)?;

        Ok(())
    }

    fn get_block_count(&self) -> Result<u64> {
        let count = self.rpc_call("getblockcount", &[], None)?
            .as_u64()
            .ok_or_else(|| anyhow!("Invalid block count"))?;
        Ok(count)
    }
}

impl Drop for TestBitcoind {
    fn drop(&mut self) {
        println!("\n🛑 Shutting down regtest bitcoind (PID: {})...", self.process.id());

        // Try to stop gracefully via RPC
        match self.rpc_call("stop", &[], None) {
            Ok(_) => println!("   ✅ RPC stop command sent"),
            Err(e) => eprintln!("   ⚠️  RPC stop failed: {}", e),
        }

        // Wait a bit for graceful shutdown
        std::thread::sleep(Duration::from_secs(3));

        // Check if still running, kill if necessary
        match self.process.try_wait() {
            Ok(Some(status)) => {
                println!("   ✅ Process already exited with status: {}", status);
            }
            Ok(None) => {
                println!("   ⚠️  Process still running, sending SIGKILL...");
                match self.process.kill() {
                    Ok(_) => println!("   ✅ SIGKILL sent"),
                    Err(e) => eprintln!("   ❌ Failed to kill process: {}", e),
                }

                match self.process.wait() {
                    Ok(status) => println!("   ✅ Process exited with status: {}", status),
                    Err(e) => eprintln!("   ❌ Failed to wait for process: {}", e),
                }
            }
            Err(e) => {
                eprintln!("   ❌ Failed to check process status: {}", e);
            }
        }

        // Give extra time for file handles to close
        std::thread::sleep(Duration::from_secs(1));

        // Clean up datadir
        match std::fs::remove_dir_all(&self.datadir) {
            Ok(_) => println!("   ✅ Cleaned up datadir: {:?}", self.datadir),
            Err(e) => eprintln!("   ⚠️  Failed to clean datadir: {} (path: {:?})", e, self.datadir),
        }
    }
}

// Helper for base64 encoding (simple version for Basic auth)
fn base64_encode(s: &str) -> String {
    use std::io::Write;
    let mut buf = Vec::new();
    {
        let mut encoder = base64::write::EncoderWriter::new(&mut buf, &base64::engine::general_purpose::STANDARD);
        encoder.write_all(s.as_bytes()).unwrap();
    }
    String::from_utf8(buf).unwrap()
}

// Global shared bitcoind instance - started once for all tests
static BITCOIND: Lazy<TestBitcoind> = Lazy::new(|| {
    TestBitcoind::start().expect("Failed to start regtest bitcoind")
});

// ============================================================
// TEST WALLET HELPER
// ============================================================

struct TestWallet {
    wallet: Arc<Mutex<PersistedWallet<Connection>>>,
    conn: Arc<Mutex<Connection>>,
    mnemonic: Mnemonic,
    #[allow(dead_code)]
    requester: bdk_kyoto::Requester,
    update_subscriber: Arc<Mutex<bdk_kyoto::UpdateSubscriber>>,
}

impl TestWallet {
    async fn new_regtest(test_name: &str) -> Result<Self> {
        // Ensure bitcoind is started
        let _ = &*BITCOIND;

        let network = Network::Regtest;

        // Generate new mnemonic for this test
        let gen: GeneratedKey<_, Tap> = Mnemonic::generate((WordCount::Words12, Language::English))
            .map_err(|_| anyhow!("Mnemonic generation failed"))?;
        let mnemonic = Mnemonic::parse_in(Language::English, gen.to_string())?;

        // Create descriptors with private keys
        let xkey: ExtendedKey = mnemonic.clone().into_extended_key()?;
        let xprv = xkey
            .into_xprv(network)
            .ok_or_else(|| anyhow!("Unable to derive xprv"))?;

        let coin_type = 1; // Regtest uses coin_type 1
        let external_desc = format!("tr({}/86h/{}h/0h/0/*)", xprv, coin_type);
        let internal_desc = format!("tr({}/86h/{}h/0h/1/*)", xprv, coin_type);

        // Create temporary database for this test
        let db_path = std::env::temp_dir().join(format!("ambient_test_{}_{}.sqlite",
            test_name,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        ));

        let mut conn = Connection::open(&db_path)?;

        // Create wallet
        let mut wallet = Wallet::create(external_desc, internal_desc)
            .network(network)
            .lookahead(RECOVERY_LOOKAHEAD)
            .create_wallet(&mut conn)?;

        // Force derivation of lookahead scripts
        for index in 0..RECOVERY_LOOKAHEAD {
            let _ = wallet.peek_address(KeychainKind::External, index);
            let _ = wallet.peek_address(KeychainKind::Internal, index);
        }
        wallet.persist(&mut conn)?;

        // Connect to the shared regtest bitcoind
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), BITCOIND.p2p_port);

        // Create temporary directory for Kyoto's peer database
        let kyoto_db_path = std::env::temp_dir().join(format!("ambient_kyoto_{}_{}",
            test_name,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        ));

        let LightClient {
            requester,
            info_subscriber: _,
            warning_subscriber: _,
            update_subscriber,
            node,
        } = Builder::new(network)
            .add_peer(peer)
            .required_peers(1)
            .data_dir(kyoto_db_path)
            .build_with_wallet(&wallet, ScanType::Sync)
            .unwrap();

        // Spawn node in background
        tokio::spawn(async move {
            if let Err(e) = node.run().await {
                eprintln!("Kyoto node error: {e:?}");
            }
        });

        let wallet = Arc::new(Mutex::new(wallet));
        let conn = Arc::new(Mutex::new(conn));
        let update_subscriber = Arc::new(Mutex::new(update_subscriber));

        Ok(Self {
            wallet,
            conn,
            mnemonic,
            requester,
            update_subscriber,
        })
    }

    async fn wait_for_sync(&self, expected_min_height: u32) -> Result<()> {
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(30);

        loop {
            // Check if we've reached the expected height
            {
                let wallet = self.wallet.lock().await;
                let current_height = wallet.local_chain().tip().height();
                if current_height >= expected_min_height {
                    println!("  ✅ Synced to height {}", current_height);
                    return Ok(());
                }
            }

            // Try to get next update with timeout
            let mut sub = self.update_subscriber.lock().await;
            let update_result = tokio::time::timeout(Duration::from_secs(5), sub.update()).await;
            drop(sub);

            match update_result {
                Ok(Ok(update)) => {
                    let mut wallet = self.wallet.lock().await;
                    let mut conn = self.conn.lock().await;

                    wallet.apply_update(update)?;
                    wallet.persist(&mut conn)?;

                    let height = wallet.local_chain().tip().height();
                    println!("  Sync update: height {}", height);
                }
                Ok(Err(e)) => return Err(anyhow!("Sync error: {}", e)),
                Err(_) => {
                    // Timeout on this update - check if we've exceeded total timeout
                    if start.elapsed() > timeout {
                        let wallet = self.wallet.lock().await;
                        let current_height = wallet.local_chain().tip().height();
                        return Err(anyhow!(
                            "Sync timeout: only reached height {} (expected >= {})",
                            current_height, expected_min_height
                        ));
                    }
                    // Otherwise continue waiting
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    async fn get_next_address(&self) -> Result<Address> {
        let mut wallet = self.wallet.lock().await;
        let mut conn = self.conn.lock().await;

        let info = wallet.reveal_next_address(KeychainKind::External);
        wallet.persist(&mut conn)?;

        Ok(info.address)
    }

    async fn get_balance(&self) -> Result<Amount> {
        let wallet = self.wallet.lock().await;
        Ok(wallet.balance().total())
    }

    async fn get_height(&self) -> Result<u32> {
        let wallet = self.wallet.lock().await;
        Ok(wallet.local_chain().tip().height())
    }
}

// ============================================================
// TESTS
// ============================================================

#[tokio::test]
async fn test_wallet_creation() -> Result<()> {
    println!("\n=== Test: Wallet Creation ===");

    let wallet = TestWallet::new_regtest("wallet_creation").await?;

    // Verify mnemonic has 12 words
    assert_eq!(wallet.mnemonic.word_count(), 12);

    // Verify we can get an address
    let addr = wallet.get_next_address().await?;
    println!("  Generated address: {}", addr);
    assert!(addr.to_string().starts_with("bcrt1")); // Regtest bech32m

    println!("✅ Wallet creation test passed");
    Ok(())
}

#[tokio::test]
async fn test_connect_to_regtest() -> Result<()> {
    println!("\n=== Test: Connect to Regtest ===");

    let wallet = TestWallet::new_regtest("connect_regtest").await?;

    // Get current blockchain height
    let current_height = BITCOIND.get_block_count()? as u32;
    println!("  Current blockchain height: {}", current_height);

    // Wait for sync to current height
    println!("  Waiting for sync to height {}...", current_height);
    wallet.wait_for_sync(current_height).await?;

    let height = wallet.get_height().await?;
    println!("  Wallet synced to height: {}", height);

    // Should have synced to at least the current blockchain height
    assert!(height >= current_height, "Should sync to at least height {}", current_height);

    println!("✅ Connect to regtest test passed");
    Ok(())
}

#[tokio::test]
async fn test_receive_funds() -> Result<()> {
    println!("\n=== Test: Receive Funds ===");

    let wallet = TestWallet::new_regtest("receive_funds").await?;

    // Get address
    let addr = wallet.get_next_address().await?;
    println!("  Test wallet address: {}", addr);

    // Get current blockchain height
    let current_height = BITCOIND.get_block_count()? as u32;
    println!("  Current blockchain height: {}", current_height);

    // Initial sync to current height
    println!("  Initial sync...");
    wallet.wait_for_sync(current_height).await?;

    let initial_balance = wallet.get_balance().await?;
    println!("  Initial balance: {} sats", initial_balance.to_sat());

    // Send funds to the address using bitcoind's wallet
    println!("  Sending 1.0 BTC to test wallet...");
    BITCOIND.rpc_call("sendtoaddress", &[
        serde_json::json!(addr.to_string()),
        serde_json::json!(1.0),
    ], Some("testwallet"))?;

    // Mine a block to confirm
    println!("  Mining block to confirm...");
    BITCOIND.mine_blocks(1)?;
    let new_height = current_height + 1;
    println!("  Expecting new height: {}", new_height);

    // Sync to the new block
    println!("  Syncing to detect transaction...");
    wallet.wait_for_sync(new_height).await?;

    let balance = wallet.get_balance().await?;
    println!("  New balance: {} sats", balance.to_sat());

    assert_eq!(balance.to_sat(), 100_000_000, "Should have received 1.0 BTC");

    println!("✅ Receive funds test passed");
    Ok(())
}

#[tokio::test]
async fn test_mine_blocks() -> Result<()> {
    println!("\n=== Test: Mine Blocks ===");

    let initial_height = BITCOIND.get_block_count()?;
    println!("  Initial height: {}", initial_height);

    BITCOIND.mine_blocks(6)?;

    let new_height = BITCOIND.get_block_count()?;
    println!("  New height: {}", new_height);

    assert_eq!(new_height, initial_height + 6, "Should have mined 6 blocks");

    println!("✅ Mine blocks test passed");
    Ok(())
}
