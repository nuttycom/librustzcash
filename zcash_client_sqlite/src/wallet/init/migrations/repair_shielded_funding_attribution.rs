//! Extends the funding-attribution repair to the shielded outputs of a spend-linked transaction.
//!
//! The repair that `fix_transparent_funding_attribution` applied covered only what a
//! transaction's transparent bundle names. A transaction that shields a transparent output the
//! wallet did not yet recognize carries the same defect in its shielded bundles, and there it is
//! the principal output rather than the change: the wallet keeps a shielded output with no
//! recorded sender, so a transfer into another of its own accounts reads as a payment from
//! nobody.
//!
//! The repair now recovers those outputs by decrypting each stored transaction under the viewing
//! keys the wallet holds. It cannot be folded into the earlier migration, which existing wallets
//! have already recorded as applied, so it is applied again here over the same set of
//! transactions. Both passes are additive, so the transparent half is a no-op the second time.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_protocol::consensus;

use super::fix_transparent_funding_attribution;
use crate::wallet::init::WalletMigrationError;

#[cfg(feature = "transparent-inputs")]
use crate::wallet::attribution::{self, RepairScope};

/// Records the account that funded each shielded output of a stored transaction whose spend of a
/// wallet transparent output was linked after that transaction was stored.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x4a1c6d02_8f37_4e55_9b71_c0d3a5e28f64);

/// `fix_transparent_funding_attribution` is the pass this extends, and is frozen: wallets have
/// recorded it as applied, so the extension has to be a migration of its own that runs after it.
pub(super) const DEPENDENCIES: &[Uuid] = &[fix_transparent_funding_attribution::MIGRATION_ID];

pub(super) struct Migration<P> {
    pub(super) _params: P,
}

impl<P> schemerz::Migration<Uuid> for Migration<P> {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Attributes the shielded outputs of stored transactions whose spends were linked late."
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    /// Decryption needs no transparent support, but the state being repaired does: only a wallet
    /// that records transparent outputs can link a spend of one, and the linkage is what selects
    /// the transactions to repair. A build without the feature creates no such linkage, and the
    /// gate keeps the migration graph identical across configurations.
    ///
    /// It does not follow that nothing is ever left unrepaired. A wallet created by a build that
    /// has the feature, and then opened by one that does not, records this migration as applied
    /// while it does nothing; a later build that has the feature will not run it again, and the
    /// attribution stays missing. Repairing that needs a further migration, this one being
    /// already recorded. The same holds of the pass this extends.
    fn up(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        #[cfg(feature = "transparent-inputs")]
        attribution::repair_funding_attribution(
            _transaction,
            &self._params,
            RepairScope::TransparentSpends,
        )?;

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

    /// The repair heals a wallet in the state the transparent repair alone leaves: the shielding
    /// transaction's transparent outputs carry the account that funded them, and its shielded
    /// output — the principal one — does not.
    ///
    /// The fixture is built through the wallet's own writers and then stripped of its shielded
    /// attribution, because the writers no longer produce that state: a wallet reaches it only by
    /// having been upgraded while the replay covered the transparent half alone.
    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn repairs_a_shielded_output_of_a_linked_spend() {
        use schemerz_rusqlite::RusqliteMigration as _;
        use zcash_client_backend::data_api::{
            Account as _, AccountPurpose, WalletWrite,
            testing::{TestBuilder, TestState},
        };
        use zcash_primitives::block::BlockHash;
        use zcash_protocol::{PoolType, ShieldedPool};

        use crate::{
            testing::db::TestDbFactory,
            wallet::{
                encoding::pool_code,
                transparent::observations::tests::{
                    ShieldedPayment, external_address, pool_output_parties, sapling_receiver,
                    store_shielding_spend_before_its_prevout, tx_output_accounts,
                    unattributed_shielded_receipts,
                },
            },
        };

        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let network = *st.network();
        let host = st.test_account().unwrap();
        let host_uuid = host.account().id().expose_uuid();
        let birthday = host.birthday().clone();
        let host_ufvk = host.usk().to_unified_full_viewing_key();
        let host_address = external_address(&host_ufvk, 0);
        let (host_sapling, _) = sapling_receiver(&host_ufvk);

        let (spend_tx, _, guest_ufvk) = store_shielding_spend_before_its_prevout(
            &mut st,
            host_address,
            &ShieldedPayment::Sapling(None, host_sapling, 300_000),
        );
        let spend_txid = spend_tx.txid();

        let guest_uuid = st
            .wallet_mut()
            .import_account_ufvk(
                "guest",
                &guest_ufvk,
                &birthday,
                AccountPurpose::ViewOnly,
                None,
            )
            .unwrap()
            .id()
            .expose_uuid();

        // Strip the shielded attribution alone, leaving the transparent half in place: the state
        // of a wallet on which only the transparent repair has run.
        {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            conn.execute(
                "DELETE FROM sent_notes
                 WHERE output_pool != :transparent
                 AND transaction_id = (SELECT id_tx FROM transactions WHERE txid = :txid)",
                rusqlite::named_params! {
                    ":transparent": pool_code(PoolType::TRANSPARENT),
                    ":txid": spend_txid.as_ref(),
                },
            )
            .unwrap();
            conn.commit().unwrap();
        }

        let sapling = PoolType::Shielded(ShieldedPool::Sapling);
        let transparent_attribution = vec![
            (0, Some(guest_uuid), Some(host_uuid)),
            (1, Some(guest_uuid), Some(guest_uuid)),
        ];
        assert_eq!(
            tx_output_accounts(&st.wallet().db().conn, spend_txid),
            transparent_attribution,
            "the transparent half of the fixture is already repaired",
        );
        assert_eq!(
            pool_output_parties(&st.wallet().db().conn, spend_txid, sapling),
            vec![(None, Some(host_uuid))],
            "the shielded half of the fixture is not",
        );
        assert!(
            unattributed_shielded_receipts(&st.wallet().db().conn)
                .iter()
                .any(|(txid, _)| txid == spend_txid.as_ref()),
        );

        let migration = super::Migration { _params: network };
        let repair = |st: &TestState<_, crate::testing::db::TestDb, _>| {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            migration.up(&conn).unwrap();
            conn.commit().unwrap();
        };

        repair(&st);

        let repaired = vec![(Some(guest_uuid), Some(host_uuid))];
        assert_eq!(
            pool_output_parties(&st.wallet().db().conn, spend_txid, sapling),
            repaired,
        );
        assert_eq!(
            tx_output_accounts(&st.wallet().db().conn, spend_txid),
            transparent_attribution,
            "the transparent half is unchanged",
        );
        assert!(
            unattributed_shielded_receipts(&st.wallet().db().conn)
                .iter()
                .all(|(txid, _)| txid != spend_txid.as_ref()),
        );

        // Running the repair again records nothing further.
        repair(&st);
        assert_eq!(
            pool_output_parties(&st.wallet().db().conn, spend_txid, sapling),
            repaired,
        );
    }
}
