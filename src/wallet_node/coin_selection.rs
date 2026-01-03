//! Coin selection algorithms for UTXO spending
//!
//! Implements hybrid UTXO selection that prioritizes SNICKER UTXOs while
//! preserving privacy by preferring single-UTXO spends.

use anyhow::{anyhow, Result};
use tracing::info;
use zeroize::Zeroizing;

use super::WalletNode;

/// Selected UTXOs for spending (hybrid selection result)
pub(crate) struct SelectedUtxos {
    /// (txid, vout, amount, script_pubkey, tweaked_privkey)
    /// tweaked_privkey is wrapped in Zeroizing to ensure it's zeroed on drop
    pub snicker_utxos: Vec<(String, u32, u64, Vec<u8>, Zeroizing<Vec<u8>>)>,
    pub regular_utxos: Vec<bdk_wallet::LocalOutput>,
    pub total_snicker: u64,
    pub total_regular: u64,
}

impl WalletNode {
    /// Select UTXOs using hybrid approach: SNICKER first, then regular as needed
    ///
    /// This implements the core selection algorithm: to spend X, use SNICKER UTXOs up to Y,
    /// then add regular UTXOs to cover X-Y+fee.
    ///
    /// # Privacy Considerations
    /// - Prefers using a SINGLE SNICKER UTXO to preserve coinjoin privacy
    /// - Co-spending multiple SNICKER UTXOs defeats the privacy purpose
    /// - Falls back to regular UTXOs if no single SNICKER UTXO is sufficient
    pub(crate) async fn select_utxos_hybrid(
        &self,
        amount_sats: u64,
        fee_rate_sat_vb: f32,
    ) -> Result<SelectedUtxos> {
        // Get available SNICKER UTXOs
        // Note: tweaked_privkey is wrapped in Zeroizing to ensure it's zeroed on drop
        let snicker_utxos: Vec<(String, u32, u64, Vec<u8>, Zeroizing<Vec<u8>>)> = {
            let conn = self.snicker_conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT txid, vout, amount, script_pubkey, tweaked_privkey FROM snicker_utxos WHERE block_height IS NOT NULL AND status = 'unspent'"
            )?;
            let mut rows = stmt.query([])?;
            let mut result = Vec::new();
            while let Some(row) = rows.next()? {
                result.push((
                    row.get(0)?, row.get(1)?, row.get(2)?,
                    row.get(3)?, Zeroizing::new(row.get(4)?),
                ));
            }
            result
        };

        let total_snicker_available: u64 = snicker_utxos.iter().map(|u| u.2).sum();
        info!("💰 SNICKER UTXOs available: {} sats in {} UTXOs", total_snicker_available, snicker_utxos.len());

        // Rough estimate for fee calculation
        let estimated_fee_per_input = (150.0 * fee_rate_sat_vb) as u64;
        let total_needed = amount_sats + estimated_fee_per_input;

        // IMPROVED SELECTION LOGIC: Prefer using only ONE SNICKER UTXO
        // Co-spending multiple SNICKER UTXOs defeats the privacy purpose of SNICKER coinjoins
        // Strategy:
        // 1. Try to find ONE SNICKER UTXO that can cover the payment
        // 2. If no single SNICKER UTXO is enough, use regular UTXOs only
        // 3. Only use multiple SNICKER UTXOs as a last resort (user must confirm separately)

        let (selected_snicker, snicker_contribution) = if !snicker_utxos.is_empty() {
            // Sort SNICKER UTXOs by amount descending (prefer largest)
            let mut sorted_snicker = snicker_utxos;
            sorted_snicker.sort_by(|a, b| b.2.cmp(&a.2));

            // Try to find ONE SNICKER UTXO that can cover the payment + fee
            if let Some(largest) = sorted_snicker.first() {
                if largest.2 >= total_needed {
                    info!("✅ Using ONE SNICKER UTXO ({} sats) to preserve privacy", largest.2);
                    (vec![largest.clone()], largest.2)
                } else {
                    info!("💡 No single SNICKER UTXO large enough, will use regular UTXOs instead");
                    (Vec::new(), 0)
                }
            } else {
                (Vec::new(), 0)
            }
        } else {
            (Vec::new(), 0)
        };

        // Determine if we need regular UTXOs
        let (regular_utxos, regular_contribution) = if snicker_contribution < total_needed {
            let shortage = total_needed - snicker_contribution;
            info!("💰 SNICKER UTXOs cover {} sats, need {} more from regular UTXOs",
                  snicker_contribution, shortage);

            // Get regular UTXOs from BDK
            let wallet = self.wallet.lock().await;
            let all_regular: Vec<_> = wallet.list_unspent().collect();
            drop(wallet);

            // Sort by value descending (prefer larger UTXOs)
            let mut sorted_regular = all_regular;
            sorted_regular.sort_by(|a, b| b.txout.value.cmp(&a.txout.value));

            // Select regular UTXOs until we have enough
            let mut selected_regular = Vec::new();
            let mut regular_total = 0u64;

            for utxo in sorted_regular {
                selected_regular.push(utxo);
                regular_total += selected_regular.last().unwrap().txout.value.to_sat();

                // Recalculate fee with current input count
                let total_inputs = selected_snicker.len() + selected_regular.len();
                let estimated_fee = estimated_fee_per_input * total_inputs as u64;

                if snicker_contribution + regular_total >= amount_sats + estimated_fee {
                    break;
                }
            }

            if snicker_contribution + regular_total < amount_sats {
                return Err(anyhow!("Insufficient funds: have {} sats (SNICKER: {}, regular: {}), need {} + fees",
                    snicker_contribution + regular_total, snicker_contribution, regular_total, amount_sats));
            }

            info!("✅ Selected {} regular UTXOs contributing {} sats",
                  selected_regular.len(), regular_total);

            (selected_regular, regular_total)
        } else {
            info!("✅ SNICKER UTXOs alone cover the payment");
            (Vec::new(), 0)
        };

        Ok(SelectedUtxos {
            snicker_utxos: selected_snicker,
            regular_utxos,
            total_snicker: snicker_contribution,
            total_regular: regular_contribution,
        })
    }
}
