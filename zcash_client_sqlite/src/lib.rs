//! *An SQLite-based Zcash light client.*
//!
//! `zcash_client_backend` contains a set of APIs that collectively implement an
//! SQLite-based light client for the Zcash network.
//!
//! # Design
//!
//! The light client is built around two SQLite databases:
//!
//! - A cache database, used to inform the light client about new [`CompactBlock`]s. It is
//!   read-only within all light client APIs *except* for [`init_cache_database`] which
//!   can be used to initialize the database.
//!
//! - A data database, where the light client's state is stored. It is read-write within
//!   the light client APIs, and **assumed to be read-only outside these APIs**. Callers
//!   **MUST NOT** write to the database without using these APIs. Callers **MAY** read
//!   the database directly in order to extract information for display to users.
//!
//! # Features
//!
//! The `mainnet` feature configures the light client for use with the Zcash mainnet. By
//! default, the light client is configured for use with the Zcash testnet.
//!
//! [`CompactBlock`]: zcash_client_backend::proto::compact_formats::CompactBlock
//! [`init_cache_database`]: crate::init::init_cache_database

use std::collections::HashMap;
use std::fmt;
use std::path::Path;

use rusqlite::{Connection, Statement, NO_PARAMS};

use zcash_primitives::{
    block::BlockHash,
    consensus::{self, BlockHeight},
    merkle_tree::{CommitmentTree, IncrementalWitness},
    note_encryption::Memo,
    primitives::{Nullifier, PaymentAddress},
    sapling::Node,
    transaction::{components::Amount, Transaction, TxId},
    zip32::ExtendedFullViewingKey,
};

use zcash_client_backend::{
    address::RecipientAddress,
    data_api::{BlockSource, ShieldedOutput, WalletRead, WalletWrite},
    encoding::encode_payment_address,
    proto::compact_formats::CompactBlock,
    wallet::{AccountId, SpendableNote, WalletTx},
    DecryptedOutput,
};

use crate::error::SqliteClientError;

pub mod chain;
pub mod error;
pub mod wallet;

/// A newtype wrapper for sqlite primary key values for the notes
/// table.
#[derive(Debug, Copy, Clone)]
pub enum NoteId {
    SentNoteId(i64),
    ReceivedNoteId(i64),
}

impl fmt::Display for NoteId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NoteId::SentNoteId(id) => write!(f, "Sent Note {}", id),
            NoteId::ReceivedNoteId(id) => write!(f, "Received Note {}", id),
        }
    }
}

/// A wrapper for the sqlite connection to the wallet database.
pub struct WalletDB<P> {
    conn: Connection,
    params: P,
}

impl<P: consensus::Parameters> WalletDB<P> {
    /// Construct a connection to the wallet database stored at the specified path.
    pub fn for_path<F: AsRef<Path>>(path: F, params: P) -> Result<Self, rusqlite::Error> {
        Connection::open(path).map(move |conn| WalletDB { conn, params })
    }

    /// Given a wallet database connection, obtain a handle for the write operations
    /// for that database. This operation may eagerly initialize and cache sqlite
    /// prepared statements that are used in write operations.
    pub fn get_update_ops<'a>(&'a self) -> Result<DataConnStmtCache<'a, P>, SqliteClientError> {
        Ok(
            DataConnStmtCache {
                wallet_db: self,
                stmt_insert_block: self.conn.prepare(
                    "INSERT INTO blocks (height, hash, time, sapling_tree)
                    VALUES (?, ?, ?, ?)",
                )?,
                stmt_insert_tx_meta: self.conn.prepare(
                    "INSERT INTO transactions (txid, block, tx_index)
                    VALUES (?, ?, ?)",
                )?,
                stmt_update_tx_meta: self.conn.prepare(
                    "UPDATE transactions
                    SET block = ?, tx_index = ? WHERE txid = ?",
                )?,
                stmt_insert_tx_data: self.conn.prepare(
                    "INSERT INTO transactions (txid, created, expiry_height, raw)
                    VALUES (?, ?, ?, ?)",
                )?,
                stmt_update_tx_data: self.conn.prepare(
                    "UPDATE transactions
                    SET expiry_height = ?, raw = ? WHERE txid = ?",
                )?,
                stmt_select_tx_ref: self.conn.prepare(
                    "SELECT id_tx FROM transactions WHERE txid = ?",
                )?,
                stmt_mark_recived_note_spent: self.conn.prepare(
                    "UPDATE received_notes SET spent = ? WHERE nf = ?"
                )?,
                stmt_insert_received_note: self.conn.prepare(
                    "INSERT INTO received_notes (tx, output_index, account, diversifier, value, rcm, memo, nf, is_change)
                    VALUES (:tx, :output_index, :account, :diversifier, :value, :rcm, :memo, :nf, :is_change)",
                )?,
                stmt_update_received_note: self.conn.prepare(
                    "UPDATE received_notes
                    SET account = :account,
                        diversifier = :diversifier,
                        value = :value,
                        rcm = :rcm,
                        nf = IFNULL(:nf, nf),
                        memo = IFNULL(:memo, memo),
                        is_change = IFNULL(:is_change, is_change)
                    WHERE tx = :tx AND output_index = :output_index",
                )?,
                stmt_select_received_note: self.conn.prepare(
                    "SELECT id_note FROM received_notes WHERE tx = ? AND output_index = ?"
                )?,
                stmt_update_sent_note: self.conn.prepare(
                    "UPDATE sent_notes
                    SET from_account = ?, address = ?, value = ?, memo = ?
                    WHERE tx = ? AND output_index = ?",
                )?,
                stmt_insert_sent_note: self.conn.prepare(
                    "INSERT INTO sent_notes (tx, output_index, from_account, address, value, memo)
                    VALUES (?, ?, ?, ?, ?, ?)",
                )?,
                stmt_insert_witness: self.conn.prepare(
                    "INSERT INTO sapling_witnesses (note, block, witness)
                    VALUES (?, ?, ?)",
                )?,
                stmt_prune_witnesses: self.conn.prepare(
                    "DELETE FROM sapling_witnesses WHERE block < ?"
                )?,
                stmt_update_expired: self.conn.prepare(
                    "UPDATE received_notes SET spent = NULL WHERE EXISTS (
                        SELECT id_tx FROM transactions
                        WHERE id_tx = received_notes.spent AND block IS NULL AND expiry_height < ?
                    )",
                )?,
            }
        )
    }
}

impl<P: consensus::Parameters> WalletRead for WalletDB<P> {
    type Error = SqliteClientError;
    type NoteRef = NoteId;
    type TxRef = i64;

    fn block_height_extrema(&self) -> Result<Option<(BlockHeight, BlockHeight)>, Self::Error> {
        wallet::block_height_extrema(self).map_err(SqliteClientError::from)
    }

    fn get_block_hash(&self, block_height: BlockHeight) -> Result<Option<BlockHash>, Self::Error> {
        wallet::get_block_hash(self, block_height).map_err(SqliteClientError::from)
    }

    fn get_tx_height(&self, txid: TxId) -> Result<Option<BlockHeight>, Self::Error> {
        wallet::get_tx_height(self, txid).map_err(SqliteClientError::from)
    }

    fn get_extended_full_viewing_keys(
        &self,
    ) -> Result<HashMap<AccountId, ExtendedFullViewingKey>, Self::Error> {
        wallet::get_extended_full_viewing_keys(self)
    }

    fn get_address(&self, account: AccountId) -> Result<Option<PaymentAddress>, Self::Error> {
        wallet::get_address(self, account)
    }

    fn is_valid_account_extfvk(
        &self,
        account: AccountId,
        extfvk: &ExtendedFullViewingKey,
    ) -> Result<bool, Self::Error> {
        wallet::is_valid_account_extfvk(self, account, extfvk)
    }

    fn get_balance_at(
        &self,
        account: AccountId,
        anchor_height: BlockHeight,
    ) -> Result<Amount, Self::Error> {
        wallet::get_balance_at(self, account, anchor_height)
    }

    fn get_memo_as_utf8(&self, id_note: Self::NoteRef) -> Result<Option<String>, Self::Error> {
        match id_note {
            NoteId::SentNoteId(id_note) => wallet::get_sent_memo_as_utf8(self, id_note),
            NoteId::ReceivedNoteId(id_note) => wallet::get_received_memo_as_utf8(self, id_note),
        }
    }

    fn get_commitment_tree(
        &self,
        block_height: BlockHeight,
    ) -> Result<Option<CommitmentTree<Node>>, Self::Error> {
        wallet::get_commitment_tree(self, block_height)
    }

    fn get_witnesses(
        &self,
        block_height: BlockHeight,
    ) -> Result<Vec<(Self::NoteRef, IncrementalWitness<Node>)>, Self::Error> {
        wallet::get_witnesses(self, block_height)
    }

    fn get_nullifiers(&self) -> Result<Vec<(AccountId, Nullifier)>, Self::Error> {
        wallet::get_nullifiers(self)
    }

    fn get_spendable_notes(
        &self,
        account: AccountId,
        anchor_height: BlockHeight,
    ) -> Result<Vec<SpendableNote>, Self::Error> {
        wallet::transact::get_spendable_notes(self, account, anchor_height)
    }

    fn select_spendable_notes(
        &self,
        account: AccountId,
        target_value: Amount,
        anchor_height: BlockHeight,
    ) -> Result<Vec<SpendableNote>, Self::Error> {
        wallet::transact::select_spendable_notes(self, account, target_value, anchor_height)
    }
}

pub struct DataConnStmtCache<'a, P> {
    wallet_db: &'a WalletDB<P>,
    stmt_insert_block: Statement<'a>,

    stmt_insert_tx_meta: Statement<'a>,
    stmt_update_tx_meta: Statement<'a>,

    stmt_insert_tx_data: Statement<'a>,
    stmt_update_tx_data: Statement<'a>,
    stmt_select_tx_ref: Statement<'a>,

    stmt_mark_recived_note_spent: Statement<'a>,

    stmt_insert_received_note: Statement<'a>,
    stmt_update_received_note: Statement<'a>,
    stmt_select_received_note: Statement<'a>,

    stmt_insert_sent_note: Statement<'a>,
    stmt_update_sent_note: Statement<'a>,

    stmt_insert_witness: Statement<'a>,
    stmt_prune_witnesses: Statement<'a>,
    stmt_update_expired: Statement<'a>,
}

impl<'a, P: consensus::Parameters> WalletRead for DataConnStmtCache<'a, P> {
    type Error = SqliteClientError;
    type NoteRef = NoteId;
    type TxRef = i64;

    fn block_height_extrema(&self) -> Result<Option<(BlockHeight, BlockHeight)>, Self::Error> {
        self.wallet_db.block_height_extrema()
    }

    fn get_block_hash(&self, block_height: BlockHeight) -> Result<Option<BlockHash>, Self::Error> {
        self.wallet_db.get_block_hash(block_height)
    }

    fn get_tx_height(&self, txid: TxId) -> Result<Option<BlockHeight>, Self::Error> {
        self.wallet_db.get_tx_height(txid)
    }

    fn get_extended_full_viewing_keys(
        &self,
    ) -> Result<HashMap<AccountId, ExtendedFullViewingKey>, Self::Error> {
        self.wallet_db.get_extended_full_viewing_keys()
    }

    fn get_address(&self, account: AccountId) -> Result<Option<PaymentAddress>, Self::Error> {
        self.wallet_db.get_address(account)
    }

    fn is_valid_account_extfvk(
        &self,
        account: AccountId,
        extfvk: &ExtendedFullViewingKey,
    ) -> Result<bool, Self::Error> {
        self.wallet_db.is_valid_account_extfvk(account, extfvk)
    }

    fn get_balance_at(
        &self,
        account: AccountId,
        anchor_height: BlockHeight,
    ) -> Result<Amount, Self::Error> {
        self.wallet_db.get_balance_at(account, anchor_height)
    }

    fn get_memo_as_utf8(
        &self,
        id_note: Self::NoteRef,
    ) -> Result<Option<String>, Self::Error> {
        self.wallet_db.get_memo_as_utf8(id_note)
    }

    fn get_commitment_tree(
        &self,
        block_height: BlockHeight,
    ) -> Result<Option<CommitmentTree<Node>>, Self::Error> {
        self.wallet_db.get_commitment_tree(block_height)
    }

    fn get_witnesses(
        &self,
        block_height: BlockHeight,
    ) -> Result<Vec<(Self::NoteRef, IncrementalWitness<Node>)>, Self::Error> {
        self.wallet_db.get_witnesses(block_height)
    }

    fn get_nullifiers(&self) -> Result<Vec<(AccountId, Nullifier)>, Self::Error> {
        self.wallet_db.get_nullifiers()
    }

    fn get_spendable_notes(
        &self,
        account: AccountId,
        anchor_height: BlockHeight,
    ) -> Result<Vec<SpendableNote>, Self::Error> {
        self.wallet_db.get_spendable_notes(account, anchor_height)
    }

    fn select_spendable_notes(
        &self,
        account: AccountId,
        target_value: Amount,
        anchor_height: BlockHeight,
    ) -> Result<Vec<SpendableNote>, Self::Error> {
        self.wallet_db
            .select_spendable_notes(account, target_value, anchor_height)
    }
}

impl<'a, P: consensus::Parameters> WalletWrite for DataConnStmtCache<'a, P> {
    fn transactionally<F, A>(&mut self, f: F) -> Result<A, Self::Error>
    where
        F: FnOnce(&mut Self) -> Result<A, Self::Error>,
    {
        self.wallet_db.conn.execute("BEGIN IMMEDIATE", NO_PARAMS)?;
        match f(self) {
            Ok(result) => {
                self.wallet_db.conn.execute("COMMIT", NO_PARAMS)?;
                Ok(result)
            }
            Err(error) => {
                match self.wallet_db.conn.execute("ROLLBACK", NO_PARAMS) {
                    Ok(_) => Err(error),
                    Err(e) =>
                        // Panicking here is probably the right thing to do, because it
                        // means the database is corrupt.
                        panic!(
                            "Rollback failed with error {} while attempting to recover from error {}; database is likely corrupt.",
                            e,
                            error
                        )
                }
            }
        }
    }

    fn insert_block(
        &mut self,
        block_height: BlockHeight,
        block_hash: BlockHash,
        block_time: u32,
        commitment_tree: &CommitmentTree<Node>,
    ) -> Result<(), Self::Error> {
        wallet::insert_block(self, block_height, block_hash, block_time, commitment_tree)
    }

    fn rewind_to_height(&mut self, block_height: BlockHeight) -> Result<(), Self::Error> {
        wallet::rewind_to_height(self.wallet_db, block_height)
    }

    fn put_tx_meta(
        &mut self,
        tx: &WalletTx,
        height: BlockHeight,
    ) -> Result<Self::TxRef, Self::Error> {
        wallet::put_tx_meta(self, tx, height)
    }

    fn put_tx_data(
        &mut self,
        tx: &Transaction,
        created_at: Option<time::OffsetDateTime>,
    ) -> Result<Self::TxRef, Self::Error> {
        wallet::put_tx_data(self, tx, created_at)
    }

    fn mark_spent(&mut self, tx_ref: Self::TxRef, nf: &Nullifier) -> Result<(), Self::Error> {
        wallet::mark_spent(self, tx_ref, nf)
    }

    // Assumptions:
    // - A transaction will not contain more than 2^63 shielded outputs.
    // - A note value will never exceed 2^63 zatoshis.
    fn put_received_note<T: ShieldedOutput>(
        &mut self,
        output: &T,
        nf_opt: &Option<Nullifier>,
        tx_ref: Self::TxRef,
    ) -> Result<Self::NoteRef, Self::Error> {
        wallet::put_received_note(self, output, nf_opt, tx_ref)
    }

    fn insert_witness(
        &mut self,
        note_id: Self::NoteRef,
        witness: &IncrementalWitness<Node>,
        height: BlockHeight,
    ) -> Result<(), Self::Error> {
        if let NoteId::ReceivedNoteId(rnid) = note_id {
            wallet::insert_witness(self, rnid, witness, height)
        } else {
            Err(SqliteClientError::InvalidNoteId)
        }
    }

    fn prune_witnesses(&mut self, below_height: BlockHeight) -> Result<(), Self::Error> {
        wallet::prune_witnesses(self, below_height)
    }

    fn update_expired_notes(&mut self, height: BlockHeight) -> Result<(), Self::Error> {
        wallet::update_expired_notes(self, height)
    }

    fn put_sent_note(
        &mut self,
        output: &DecryptedOutput,
        tx_ref: Self::TxRef,
    ) -> Result<(), Self::Error> {
        wallet::put_sent_note(self, output, tx_ref)
    }

    fn insert_sent_note(
        &mut self,
        tx_ref: Self::TxRef,
        output_index: usize,
        account: AccountId,
        to: &RecipientAddress,
        value: Amount,
        memo: Option<Memo>,
    ) -> Result<(), Self::Error> {
        wallet::insert_sent_note(self, tx_ref, output_index, account, to, value, memo)
    }
}

pub struct BlockDB(Connection);

impl BlockDB {
    pub fn for_path<P: AsRef<Path>>(path: P) -> Result<Self, rusqlite::Error> {
        Connection::open(path).map(BlockDB)
    }
}

impl BlockSource for BlockDB {
    type Error = SqliteClientError;

    fn with_blocks<F>(
        &self,
        from_height: BlockHeight,
        limit: Option<u32>,
        with_row: F,
    ) -> Result<(), Self::Error>
    where
        F: FnMut(CompactBlock) -> Result<(), Self::Error>,
    {
        chain::with_blocks(self, from_height, limit, with_row)
    }
}

fn address_from_extfvk<P: consensus::Parameters>(
    params: &P,
    extfvk: &ExtendedFullViewingKey,
) -> String {
    let addr = extfvk.default_address().unwrap().1;
    encode_payment_address(params.hrp_sapling_payment_address(), &addr)
}

#[cfg(test)]
mod tests {
    use ff::PrimeField;
    use group::GroupEncoding;
    use protobuf::Message;
    use rand_core::{OsRng, RngCore};
    use rusqlite::params;

    use zcash_client_backend::proto::compact_formats::{
        CompactBlock, CompactOutput, CompactSpend, CompactTx,
    };

    use zcash_primitives::{
        block::BlockHash,
        consensus::{BlockHeight, Network, NetworkUpgrade, Parameters},
        note_encryption::{Memo, SaplingNoteEncryption},
        primitives::{Note, Nullifier, PaymentAddress},
        transaction::components::Amount,
        util::generate_random_rseed,
        zip32::ExtendedFullViewingKey,
    };

    use super::BlockDB;

    #[cfg(feature = "mainnet")]
    pub(crate) fn network() -> Network {
        Network::MainNetwork
    }

    #[cfg(not(feature = "mainnet"))]
    pub(crate) fn network() -> Network {
        Network::TestNetwork
    }

    #[cfg(feature = "mainnet")]
    pub(crate) fn sapling_activation_height() -> BlockHeight {
        Network::MainNetwork
            .activation_height(NetworkUpgrade::Sapling)
            .unwrap()
    }

    #[cfg(not(feature = "mainnet"))]
    pub(crate) fn sapling_activation_height() -> BlockHeight {
        Network::TestNetwork
            .activation_height(NetworkUpgrade::Sapling)
            .unwrap()
    }

    /// Create a fake CompactBlock at the given height, containing a single output paying
    /// the given address. Returns the CompactBlock and the nullifier for the new note.
    pub(crate) fn fake_compact_block(
        height: BlockHeight,
        prev_hash: BlockHash,
        extfvk: ExtendedFullViewingKey,
        value: Amount,
    ) -> (CompactBlock, Nullifier) {
        let to = extfvk.default_address().unwrap().1;

        // Create a fake Note for the account
        let mut rng = OsRng;
        let rseed = generate_random_rseed(&network(), height, &mut rng);
        let note = Note {
            g_d: to.diversifier().g_d().unwrap(),
            pk_d: to.pk_d().clone(),
            value: value.into(),
            rseed,
        };
        let encryptor = SaplingNoteEncryption::new(
            Some(extfvk.fvk.ovk),
            note.clone(),
            to.clone(),
            Memo::default(),
            &mut rng,
        );
        let cmu = note.cmu().to_repr().as_ref().to_vec();
        let epk = encryptor.epk().to_bytes().to_vec();
        let enc_ciphertext = encryptor.encrypt_note_plaintext();

        // Create a fake CompactBlock containing the note
        let mut cout = CompactOutput::new();
        cout.set_cmu(cmu);
        cout.set_epk(epk);
        cout.set_ciphertext(enc_ciphertext[..52].to_vec());
        let mut ctx = CompactTx::new();
        let mut txid = vec![0; 32];
        rng.fill_bytes(&mut txid);
        ctx.set_hash(txid);
        ctx.outputs.push(cout);
        let mut cb = CompactBlock::new();
        cb.set_height(u64::from(height));
        cb.hash.resize(32, 0);
        rng.fill_bytes(&mut cb.hash);
        cb.prevHash.extend_from_slice(&prev_hash.0);
        cb.vtx.push(ctx);
        (cb, note.nf(&extfvk.fvk.vk, 0))
    }

    /// Create a fake CompactBlock at the given height, spending a single note from the
    /// given address.
    pub(crate) fn fake_compact_block_spending(
        height: BlockHeight,
        prev_hash: BlockHash,
        (nf, in_value): (Nullifier, Amount),
        extfvk: ExtendedFullViewingKey,
        to: PaymentAddress,
        value: Amount,
    ) -> CompactBlock {
        let mut rng = OsRng;
        let rseed = generate_random_rseed(&network(), height, &mut rng);

        // Create a fake CompactBlock containing the note
        let mut cspend = CompactSpend::new();
        cspend.set_nf(nf.to_vec());
        let mut ctx = CompactTx::new();
        let mut txid = vec![0; 32];
        rng.fill_bytes(&mut txid);
        ctx.set_hash(txid);
        ctx.spends.push(cspend);

        // Create a fake Note for the payment
        ctx.outputs.push({
            let note = Note {
                g_d: to.diversifier().g_d().unwrap(),
                pk_d: to.pk_d().clone(),
                value: value.into(),
                rseed,
            };
            let encryptor = SaplingNoteEncryption::new(
                Some(extfvk.fvk.ovk),
                note.clone(),
                to,
                Memo::default(),
                &mut rng,
            );
            let cmu = note.cmu().to_repr().as_ref().to_vec();
            let epk = encryptor.epk().to_bytes().to_vec();
            let enc_ciphertext = encryptor.encrypt_note_plaintext();

            let mut cout = CompactOutput::new();
            cout.set_cmu(cmu);
            cout.set_epk(epk);
            cout.set_ciphertext(enc_ciphertext[..52].to_vec());
            cout
        });

        // Create a fake Note for the change
        ctx.outputs.push({
            let change_addr = extfvk.default_address().unwrap().1;
            let rseed = generate_random_rseed(&network(), height, &mut rng);
            let note = Note {
                g_d: change_addr.diversifier().g_d().unwrap(),
                pk_d: change_addr.pk_d().clone(),
                value: (in_value - value).into(),
                rseed,
            };
            let encryptor = SaplingNoteEncryption::new(
                Some(extfvk.fvk.ovk),
                note.clone(),
                change_addr,
                Memo::default(),
                &mut rng,
            );
            let cmu = note.cmu().to_repr().as_ref().to_vec();
            let epk = encryptor.epk().to_bytes().to_vec();
            let enc_ciphertext = encryptor.encrypt_note_plaintext();

            let mut cout = CompactOutput::new();
            cout.set_cmu(cmu);
            cout.set_epk(epk);
            cout.set_ciphertext(enc_ciphertext[..52].to_vec());
            cout
        });

        let mut cb = CompactBlock::new();
        cb.set_height(u64::from(height));
        cb.hash.resize(32, 0);
        rng.fill_bytes(&mut cb.hash);
        cb.prevHash.extend_from_slice(&prev_hash.0);
        cb.vtx.push(ctx);
        cb
    }

    /// Insert a fake CompactBlock into the cache DB.
    pub(crate) fn insert_into_cache(db_cache: &BlockDB, cb: &CompactBlock) {
        let cb_bytes = cb.write_to_bytes().unwrap();
        db_cache
            .0
            .prepare("INSERT INTO compactblocks (height, data) VALUES (?, ?)")
            .unwrap()
            .execute(params![u32::from(cb.height()), cb_bytes,])
            .unwrap();
    }
}
