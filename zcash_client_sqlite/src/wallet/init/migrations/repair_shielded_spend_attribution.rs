//! Repairs the funding attribution of transactions whose spends are shielded.
//!
//! The two repairs before this one selected the transactions to visit by transparent spend
//! evidence alone: a row in `transparent_received_output_spends`. A transaction funded from a
//! shielded note has no such row, so a wallet that stored one before the nullifier revealing its
//! funding note was linked kept the same defect, unrepaired and unreachable — its outputs
//! reported as receipts from an unknown sender, a transfer between two of the wallet's own
//! accounts among them.
//!
//! The selection here is pool-complete: every stored transaction the wallet records as spending
//! anything it received, in any of the four pools. Over-selection costs nothing, because the
//! replay writes only what is missing and settles an already-attributed transaction with two
//! counts.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_protocol::consensus;

use super::{ironwood_received_notes, repair_shielded_funding_attribution};
use crate::wallet::{
    attribution::{self, RepairScope},
    init::WalletMigrationError,
};

/// Records the account that funded each output of a stored transaction whose spend of a wallet
/// note or output was linked after that transaction was stored, whatever pool the spend is in.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0xa0d729d4_5e5d_4aae_8ac9_1fcbeeec3618);

/// `repair_shielded_funding_attribution` is the pass this widens, and is frozen: wallets have
/// recorded it as applied, so the wider selection has to be a migration of its own.
///
/// `ironwood_received_notes` supplies the last of the four spend tables the pool-complete
/// selection reads; the passes before this one sit below it and cannot name that table.
pub(super) const DEPENDENCIES: &[Uuid] = &[
    repair_shielded_funding_attribution::MIGRATION_ID,
    ironwood_received_notes::MIGRATION_ID,
];

pub(super) struct Migration<P> {
    pub(super) params: P,
}

impl<P> schemerz::Migration<Uuid> for Migration<P> {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Attributes the outputs of stored transactions whose spends of any pool were linked late."
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    /// Unlike the two passes before it, this one carries no `transparent-inputs` gate. Those
    /// gates were exact for what they repaired: only a wallet that records transparent outputs
    /// can link a spend of one, so a build without the feature had nothing to select. That
    /// reasoning does not extend here. Shielded notes are received, spent, and linked late
    /// whatever a build's transparent support, and the replay reads those spends and decrypts
    /// under the wallet's viewing keys, neither of which needs the feature. A gate would leave a
    /// build without the feature unable to repair anything at all, and the defect is not confined
    /// to the wallets such a build opens: a transparent-capable wallet reaches it through a
    /// shielded spend just the same.
    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        attribution::repair_funding_attribution(transaction, &self.params, RepairScope::AnySpend)?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use crate::wallet::init::migrations::tests::test_migrate;

    #[test]
    fn migrate() {
        test_migrate(&[super::MIGRATION_ID]);
    }
}
