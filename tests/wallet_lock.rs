//! Tests for wallet locking mechanism (Issue #2)
//!
//! Verifies that:
//! 1. A wallet can be locked successfully
//! 2. Attempting to lock an already-locked wallet fails with appropriate error
//! 3. Lock is released when file handle is dropped

use std::fs;
use std::path::Path;
use fs2::FileExt;
use tempfile::tempdir;

/// Helper function that mimics WalletNode::acquire_wallet_lock
fn acquire_lock(wallet_dir: &Path, name: &str) -> Result<std::fs::File, String> {
    let lock_path = wallet_dir.join(".lock");
    let lock_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| format!("Failed to open lock file: {}", e))?;

    match lock_file.try_lock_exclusive() {
        Ok(()) => Ok(lock_file),
        Err(e) => Err(format!(
            "Wallet '{}' is already open in another instance: {}",
            name, e
        )),
    }
}

#[test]
fn test_wallet_lock_basic() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let wallet_dir = temp_dir.path().join("test_wallet");
    fs::create_dir_all(&wallet_dir).expect("Failed to create wallet dir");

    // First lock should succeed
    let lock1 = acquire_lock(&wallet_dir, "test_wallet");
    assert!(lock1.is_ok(), "First lock should succeed");
    let _lock_handle = lock1.unwrap();

    // Second lock attempt should fail (same wallet, different file descriptor)
    let lock2 = acquire_lock(&wallet_dir, "test_wallet");
    assert!(lock2.is_err(), "Second lock should fail");

    let err_msg = lock2.unwrap_err();
    assert!(
        err_msg.contains("already open"),
        "Error message should mention wallet is already open: {}",
        err_msg
    );
}

#[test]
fn test_wallet_lock_released_on_drop() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let wallet_dir = temp_dir.path().join("test_wallet_drop");
    fs::create_dir_all(&wallet_dir).expect("Failed to create wallet dir");

    // Acquire lock in inner scope
    {
        let lock = acquire_lock(&wallet_dir, "test_wallet_drop");
        assert!(lock.is_ok(), "First lock should succeed");
        // lock is dropped here
    }

    // After drop, we should be able to acquire the lock again
    let lock2 = acquire_lock(&wallet_dir, "test_wallet_drop");
    assert!(
        lock2.is_ok(),
        "Should be able to acquire lock after previous holder dropped: {:?}",
        lock2.err()
    );
}

#[test]
fn test_different_wallets_can_lock_simultaneously() {
    let temp_dir = tempdir().expect("Failed to create temp dir");

    let wallet_dir_a = temp_dir.path().join("wallet_a");
    let wallet_dir_b = temp_dir.path().join("wallet_b");
    fs::create_dir_all(&wallet_dir_a).expect("Failed to create wallet_a dir");
    fs::create_dir_all(&wallet_dir_b).expect("Failed to create wallet_b dir");

    // Both wallets should be lockable simultaneously
    let lock_a = acquire_lock(&wallet_dir_a, "wallet_a");
    let lock_b = acquire_lock(&wallet_dir_b, "wallet_b");

    assert!(lock_a.is_ok(), "wallet_a lock should succeed");
    assert!(lock_b.is_ok(), "wallet_b lock should succeed");

    // Keep both locks alive
    let _handle_a = lock_a.unwrap();
    let _handle_b = lock_b.unwrap();

    // Verify wallet_a is still locked
    let lock_a2 = acquire_lock(&wallet_dir_a, "wallet_a");
    assert!(lock_a2.is_err(), "wallet_a should still be locked");
}

#[test]
fn test_lock_file_created() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let wallet_dir = temp_dir.path().join("test_wallet_file");
    fs::create_dir_all(&wallet_dir).expect("Failed to create wallet dir");

    let lock_path = wallet_dir.join(".lock");
    assert!(!lock_path.exists(), "Lock file should not exist before locking");

    let lock = acquire_lock(&wallet_dir, "test_wallet_file");
    assert!(lock.is_ok(), "Lock should succeed");
    let _handle = lock.unwrap();

    assert!(lock_path.exists(), "Lock file should exist after locking");
}
