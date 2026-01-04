#![allow(dead_code)]
#![allow(deprecated)]

use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

use anyhow::{anyhow, Result};
use once_cell::sync::Lazy;

// ============================================================
// SHARED REGTEST BITCOIND INSTANCE
// ============================================================

pub struct TestBitcoind {
    process: Child,
    datadir: PathBuf,
    pub rpc_port: u16,
    pub p2p_port: u16,
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

        // Clean up any stale bitcoind processes
        let rpc_port = 18443;
        let p2p_port = 18444;

        println!("🔍 Checking for stale bitcoind processes on port {}...", rpc_port);

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
                        let _ = Command::new("kill").arg(pid).output();
                        std::thread::sleep(Duration::from_millis(500));

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

        let datadir = tempfile::tempdir()?.into_path();

        println!("🚀 Starting regtest bitcoind...");
        println!("   Datadir: {:?}", datadir);
        println!("   Binary: {}", bitcoind_path);

        let datadir_arg = format!("-datadir={}", datadir.display());

        let mut process = Command::new(&bitcoind_path)
            .args(&[
                "-regtest",
                "-noconf",
                &datadir_arg,
                "-server=1",
                "-txindex=1",
                "-fallbackfee=0.00001",
                &format!("-rpcport={}", rpc_port),
                &format!("-port={}", p2p_port),
                "-rpcuser=test",
                "-rpcpassword=test",
                "-blockfilterindex=1",
                "-peerblockfilters=1",
                "-printtoconsole=0",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| anyhow!("Failed to spawn bitcoind: {}", e))?;

        println!("   Spawned process PID: {}", process.id());

        std::thread::sleep(Duration::from_millis(500));

        match process.try_wait() {
            Ok(Some(status)) => {
                return Err(anyhow!(
                    "bitcoind exited immediately with status: {}. \
                    Check debug.log in {:?}",
                    status, datadir
                ));
            }
            Ok(None) => {
                println!("   ✅ Process still running");
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
            return Err(anyhow!("Failed to get new address"));
        }

        let addr = String::from_utf8_lossy(&addr_output.stdout).trim().to_string();

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
            return Err(anyhow!("Failed to generate blocks"));
        }

        println!("   ✅ Regtest bitcoind ready!");
        println!("      RPC: localhost:{}", rpc_port);
        println!("      P2P: localhost:{}", p2p_port);

        std::thread::sleep(Duration::from_secs(2));

        Ok(bitcoind)
    }

    pub fn rpc_call(&self, method: &str, params: &[serde_json::Value], wallet: Option<&str>) -> Result<serde_json::Value> {
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

    pub fn mine_blocks(&self, count: u64) -> Result<()> {
        let addr = self.rpc_call("getnewaddress", &[], Some("testwallet"))?
            .as_str()
            .ok_or_else(|| anyhow!("Failed to get address"))?
            .to_string();

        self.rpc_call("generatetoaddress", &[
            serde_json::json!(count),
            serde_json::json!(addr),
        ], None)?;

        // Wait for block filter index to catch up
        self.wait_for_filter_index()?;

        Ok(())
    }

    /// Wait for the block filter index to catch up with the chain tip
    fn wait_for_filter_index(&self) -> Result<()> {
        let target_height = self.get_block_count()?;

        for i in 0..50 {
            std::thread::sleep(Duration::from_millis(200));

            let info = self.rpc_call("getblockfilter", &[
                serde_json::json!(self.get_block_hash(target_height)?),
            ], None);

            if info.is_ok() {
                // Filters are indexed, but add extra delay to ensure bitcoind is ready to serve blocks
                std::thread::sleep(Duration::from_secs(2));
                return Ok(());
            }

            if i == 49 {
                return Err(anyhow!("Block filter index failed to catch up within 10 seconds"));
            }
        }
        Ok(())
    }

    fn get_block_hash(&self, height: u64) -> Result<String> {
        let hash = self.rpc_call("getblockhash", &[
            serde_json::json!(height),
        ], None)?
            .as_str()
            .ok_or_else(|| anyhow!("Failed to get block hash"))?
            .to_string();
        Ok(hash)
    }

    pub fn get_block_count(&self) -> Result<u64> {
        let count = self.rpc_call("getblockcount", &[], None)?
            .as_u64()
            .ok_or_else(|| anyhow!("Invalid block count"))?;
        Ok(count)
    }
}

impl Drop for TestBitcoind {
    fn drop(&mut self) {
        println!("\n🛑 Shutting down regtest bitcoind (PID: {})...", self.process.id());

        match self.rpc_call("stop", &[], None) {
            Ok(_) => println!("   ✅ RPC stop command sent"),
            Err(e) => eprintln!("   ⚠️  RPC stop failed: {}", e),
        }

        std::thread::sleep(Duration::from_secs(3));

        match self.process.try_wait() {
            Ok(Some(status)) => {
                println!("   ✅ Process exited with status: {}", status);
            }
            Ok(None) => {
                println!("   ⚠️  Process still running, sending SIGKILL...");
                let _ = self.process.kill();
                let _ = self.process.wait();
            }
            Err(e) => {
                eprintln!("   ❌ Failed to check process status: {}", e);
            }
        }

        std::thread::sleep(Duration::from_secs(1));

        match std::fs::remove_dir_all(&self.datadir) {
            Ok(_) => println!("   ✅ Cleaned up datadir: {:?}", self.datadir),
            Err(e) => eprintln!("   ⚠️  Failed to clean datadir: {}", e),
        }
    }
}

fn base64_encode(s: &str) -> String {
    use std::io::Write;
    let mut buf = Vec::new();
    {
        let mut encoder = base64::write::EncoderWriter::new(&mut buf, &base64::engine::general_purpose::STANDARD);
        encoder.write_all(s.as_bytes()).unwrap();
    }
    String::from_utf8(buf).unwrap()
}

// Global shared bitcoind instance
pub static BITCOIND: Lazy<TestBitcoind> = Lazy::new(|| {
    TestBitcoind::start().expect("Failed to start regtest bitcoind")
});
