//! Interfaces for wallet data persistence & low-level wallet utilities.

use std::cmp;
use std::collections::HashMap;
use std::fmt::Debug;

use zcash_primitives::{
    block::BlockHash,
    consensus::BlockHeight,
    memo::{Memo, MemoBytes},
    merkle_tree::{CommitmentTree, IncrementalWitness},
    sapling::{Node, Nullifier, PaymentAddress},
    transaction::{components::Amount, Transaction, TxId},
    zip32::ExtendedFullViewingKey,
};

use crate::{
    address::RecipientAddress,
    data_api::wallet::ANCHOR_OFFSET,
    decrypt::DecryptedOutput,
    proto::compact_formats::CompactBlock,
    wallet::{AccountId, SpendableNote, WalletTx},
};

pub mod chain;
pub mod error;
pub mod wallet;

/// Read-only operations required for light wallet functions.
///
/// This trait defines the read-only portion of the storage
/// interface atop which higher-level wallet operations are
/// implemented. It serves to allow wallet functions to be
/// abstracted away from any particular data storage substrate.
pub trait WalletRead {
    /// The type of errors produced by a wallet backend.
    type Error;

    /// Backend-specific note identifier.
    ///
    /// For example, this might be a database identifier type
    /// or a UUID.
    type NoteRef: Copy + Debug;

    /// Backend-specific transaction identifier.
    ///
    /// For example, this might be a database identifier type
    /// or a TxId if the backend is able to support that type
    /// directly.
    type TxRef: Copy + Debug;

    /// Returns the minimum and maximum block heights for stored blocks.
    ///
    /// This will return `Ok(None)` if no block data is present in the database.
    fn block_height_extrema(&self) -> Result<Option<(BlockHeight, BlockHeight)>, Self::Error>;

    /// Returns the default target height (for the block in which a new
    /// transaction would be mined) and anchor height (to use for a new
    /// transaction), given the range of block heights that the backend
    /// knows about.
    ///
    /// This will return `Ok(None)` if no block data is present in the database.
    fn get_target_and_anchor_heights(
        &self,
    ) -> Result<Option<(BlockHeight, BlockHeight)>, Self::Error> {
        self.block_height_extrema().map(|heights| {
            heights.map(|(min_height, max_height)| {
                let target_height = max_height + 1;

                // Select an anchor ANCHOR_OFFSET back from the target block,
                // unless that would be before the earliest block we have.
                let anchor_height = BlockHeight::from(cmp::max(
                    u32::from(target_height).saturating_sub(ANCHOR_OFFSET),
                    u32::from(min_height),
                ));

                (target_height, anchor_height)
            })
        })
    }

    /// Returns the block hash for the block at the given height, if the
    /// associated block data is available. Returns `Ok(None)` if the hash
    /// is not found in the database.
    fn get_block_hash(&self, block_height: BlockHeight) -> Result<Option<BlockHash>, Self::Error>;

    /// Returns the block hash for the block at the maximum height known
    /// in stored data.
    ///
    /// This will return `Ok(None)` if no block data is present in the database.
    fn get_max_height_hash(&self) -> Result<Option<(BlockHeight, BlockHash)>, Self::Error> {
        self.block_height_extrema()
            .and_then(|extrema_opt| {
                extrema_opt
                    .map(|(_, max_height)| {
                        self.get_block_hash(max_height)
                            .map(|hash_opt| hash_opt.map(move |hash| (max_height, hash)))
                    })
                    .transpose()
            })
            .map(|oo| oo.flatten())
    }

    /// Returns the block height in which the specified transaction was mined,
    /// or `Ok(None)` if the transaction is not mined in the main chain.
    fn get_tx_height(&self, txid: TxId) -> Result<Option<BlockHeight>, Self::Error>;

    /// Returns the payment address for the specified account, if the account
    /// identifier specified refers to a valid account for this wallet.
    ///
    /// This will return `Ok(None)` if the account identifier does not correspond
    /// to a known account.
    fn get_address(&self, account: AccountId) -> Result<Option<PaymentAddress>, Self::Error>;

    /// Returns all extended full viewing keys known about by this wallet.
    fn get_extended_full_viewing_keys(
        &self,
    ) -> Result<HashMap<AccountId, ExtendedFullViewingKey>, Self::Error>;

    /// Checks whether the specified extended full viewing key is
    /// associated with the account.
    fn is_valid_account_extfvk(
        &self,
        account: AccountId,
        extfvk: &ExtendedFullViewingKey,
    ) -> Result<bool, Self::Error>;

    /// Returns the wallet balance for an account as of the specified block
    /// height.
    ///
    /// This may be used to obtain a balance that ignores notes that have been
    /// received so recently that they are not yet deemed spendable.
    fn get_balance_at(
        &self,
        account: AccountId,
        anchor_height: BlockHeight,
    ) -> Result<Amount, Self::Error>;

    /// Returns the memo for a note.
    ///
    /// Implementations of this method must return an error if the note identifier
    /// does not appear in the backing data store.
    fn get_memo(&self, id_note: Self::NoteRef) -> Result<Memo, Self::Error>;

    /// Returns the note commitment tree at the specified block height.
    fn get_commitment_tree(
        &self,
        block_height: BlockHeight,
    ) -> Result<Option<CommitmentTree<Node>>, Self::Error>;

    /// Returns the incremental witnesses as of the specified block height.
    #[allow(clippy::type_complexity)]
    fn get_witnesses(
        &self,
        block_height: BlockHeight,
    ) -> Result<Vec<(Self::NoteRef, IncrementalWitness<Node>)>, Self::Error>;

    /// Returns the unspent nullifiers, along with the account identifiers
    /// with which they are associated.
    fn get_nullifiers(&self) -> Result<Vec<(AccountId, Nullifier)>, Self::Error>;

    /// Return all spendable notes.
    fn get_spendable_notes(
        &self,
        account: AccountId,
        anchor_height: BlockHeight,
    ) -> Result<Vec<SpendableNote>, Self::Error>;

    /// Returns a list of spendable notes sufficient to cover the specified
    /// target value, if possible.
    fn select_spendable_notes(
        &self,
        account: AccountId,
        target_value: Amount,
        anchor_height: BlockHeight,
    ) -> Result<Vec<SpendableNote>, Self::Error>;
}

/// The subset of information that is relevant to this wallet that has been
/// decrypted and extracted from a [CompactBlock].
pub struct PrunedBlock<'a> {
    pub block_height: BlockHeight,
    pub block_hash: BlockHash,
    pub block_time: u32,
    pub commitment_tree: &'a CommitmentTree<Node>,
    pub transactions: &'a Vec<WalletTx<Nullifier>>,
}

/// A transaction that was detected during scanning of the blockchain,
/// including its decrypted Sapling outputs.
///
/// The purpose of this struct is to permit atomic updates of the
/// wallet database when transactions are successfully decrypted.
pub struct ReceivedTransaction<'a> {
    pub tx: &'a Transaction,
    pub outputs: &'a Vec<DecryptedOutput>,
}

/// A transaction that was constructed and sent by the wallet.
///
/// The purpose of this struct is to permit atomic updates of the
/// wallet database when transactions are created and submitted
/// to the network.
pub struct SentTransaction<'a> {
    pub tx: &'a Transaction,
    pub created: time::OffsetDateTime,
    /// The index within the transaction that contains the recipient output.
    ///
    /// - If `recipient_address` is a Sapling address, this is an index into the Sapling
    ///   outputs of the transaction.
    /// - If `recipient_address` is a transparent address, this is an index into the
    ///   transparent outputs of the transaction.
    pub output_index: usize,
    pub account: AccountId,
    pub recipient_address: &'a RecipientAddress,
    pub value: Amount,
    pub memo: Option<MemoBytes>,
}

/// This trait encapsulates the write capabilities required to update stored
/// wallet data.
pub trait WalletWrite: WalletRead {
    #[allow(clippy::type_complexity)]
    fn advance_by_block(
        &mut self,
        block: &PrunedBlock,
        updated_witnesses: &[(Self::NoteRef, IncrementalWitness<Node>)],
    ) -> Result<Vec<(Self::NoteRef, IncrementalWitness<Node>)>, Self::Error>;

    fn store_received_tx(
        &mut self,
        received_tx: &ReceivedTransaction,
    ) -> Result<Self::TxRef, Self::Error>;

    fn store_sent_tx(&mut self, sent_tx: &SentTransaction) -> Result<Self::TxRef, Self::Error>;

    /// Rewinds the wallet database to the specified height.
    ///
    /// This method assumes that the state of the underlying data store is
    /// consistent up to a particular block height. Since it is possible that
    /// a chain reorg might invalidate some stored state, this method must be
    /// implemented in order to allow users of this API to "reset" the data store
    /// to correctly represent chainstate as of a specified block height.
    ///
    /// After calling this method, the block at the given height will be the
    /// most recent block and all other operations will treat this block
    /// as the chain tip for balance determination purposes.
    ///
    /// There may be restrictions on how far it is possible to rewind.
    fn rewind_to_height(&mut self, block_height: BlockHeight) -> Result<(), Self::Error>;
}

/// This trait provides sequential access to raw blockchain data via a callback-oriented
/// API.
pub trait BlockSource {
    type Error;

    /// Scan the specified `limit` number of blocks from the blockchain, starting at
    /// `from_height`, applying the provided callback to each block.
    fn with_blocks<F>(
        &self,
        from_height: BlockHeight,
        limit: Option<u32>,
        with_row: F,
    ) -> Result<(), Self::Error>
    where
        F: FnMut(CompactBlock) -> Result<(), Self::Error>;
}

#[cfg(feature = "test-dependencies")]
pub mod testing {
    use sorted_vec::SortedVec;
    use std::cmp::Ordering;
    use std::collections::HashMap;

    use zcash_primitives::{
        block::BlockHash,
        consensus::BlockHeight,
        memo::Memo,
        merkle_tree::{CommitmentTree, IncrementalWitness},
        sapling::{Node, Nullifier, PaymentAddress},
        transaction::{components::Amount, TxId},
        zip32::ExtendedFullViewingKey,
    };

    use crate::{
        proto::compact_formats::CompactBlock,
        wallet::{AccountId, SpendableNote},
    };

    use super::{
        error::Error, BlockSource, PrunedBlock, ReceivedTransaction, SentTransaction, WalletRead,
        WalletWrite,
    };

    struct MemoryWalletBlock {
        height: BlockHeight,
        hash: BlockHash,
        block_time: u32,
        commitment_tree: CommitmentTree<Node>,
        // Just the transactions that map to an account in this wallet
        transactions: HashMap<TxId, WalletTx>,
    }

    impl PartialEq for MemoryWalletBlock {
        fn eq(&self, other: &Self) -> bool {
            (self.height, self.block_time) == (other.height, other.block_time)
        }
    }

    impl Eq for MemoryWalletBlock {}

    impl PartialOrd for MemoryWalletBlock {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some((self.height, self.block_time).cmp(&(other.height, other.block_time)))
        }
    }

    impl Ord for MemoryWalletBlock {
        fn cmp(&self, other: &Self) -> Ordering {
            (self.height, self.block_time).cmp(&(other.height, other.block_time))
        }
    }

    pub struct MemoryWalletDb {
        // A sorted vector of CompactBlock values
        blocks: SortedVec<MemoryWalletBlock>,
        tx_idx: HashMap<TxId, BlockHeight>,
        accounts: HashMap<AccountId, ExtendedFullViewingKey>,
        spentness: HashMap<Nullifier, (TxId, bool)>,
    }

    pub enum MemoryWalletError {
        DataApiError(Error<u32>),
        MemoDecryptionError(std::str::Utf8Error),
    }

    impl WalletRead for MemoryWalletDb {
        type Error = MemoryWalletError;
        type NoteRef = (TxId, usize);
        type TxRef = TxId;

        fn block_height_extrema(&self) -> Result<Option<(BlockHeight, BlockHeight)>, Self::Error> {
            Ok(if self.blocks.len() == 0 {
                None
            } else {
                Some((
                    self.blocks[0].height,
                    self.blocks[self.blocks.len() - 1].height,
                ))
            })
        }

        fn get_block_hash(
            &self,
            block_height: BlockHeight,
        ) -> Result<Option<BlockHash>, Self::Error> {
            Ok(self.blocks.iter().find_map(|b| {
                if b.height == block_height {
                    Some(b.hash)
                } else {
                    None
                }
            }))
        }

        fn get_tx_height(&self, txid: TxId) -> Result<Option<BlockHeight>, Self::Error> {
            Ok(self.tx_idx.get(&txid).map(|h| h.clone()))
        }

        fn get_address(&self, account: AccountId) -> Result<Option<PaymentAddress>, Self::Error> {
            self.accounts
                .get(&account)
                .map(|extfvk| {
                    extfvk
                        .default_address()
                        .map(|(_, a)| a)
                        .map_err(|_| Error::InvalidExtSK(account))
                })
                .transpose()
                .map_err(MemoryWalletError::DataApiError)
        }

        fn get_extended_full_viewing_keys(
            &self,
        ) -> Result<HashMap<AccountId, ExtendedFullViewingKey>, Self::Error> {
            Ok(self.accounts.clone())
        }

        fn is_valid_account_extfvk(
            &self,
            account: AccountId,
            extfvk: &ExtendedFullViewingKey,
        ) -> Result<bool, Self::Error> {
            Ok(self
                .accounts
                .get(&account)
                .filter(|extfvk0| extfvk0 == &extfvk)
                .is_some())
        }

        fn get_balance_at(
            &self,
            account: AccountId,
            height: BlockHeight,
        ) -> Result<Amount, Self::Error> {
            let mut received_amounts: HashMap<Nullifier, Amount> = HashMap::new();
            Ok(self.blocks.iter().filter(|b| b.height <= height).fold(
                Amount::zero(),
                |acc, block| {
                    block.transactions.values().fold(acc, |acc, wallet_tx| {
                        // add to our balance when we receive an output
                        let total_received = wallet_tx
                            .shielded_outputs
                            .iter()
                            .filter(|s| s.account == account)
                            .fold(acc, |acc, o| {
                                let nf = o.note.nf(
                                    &self.accounts.get(&account).unwrap().fvk.vk,
                                    o.witness.position() as u64,
                                );
                                let amount = Amount::from_u64(o.note.value).unwrap();

                                // cache received amounts
                                received_amounts.insert(nf, amount);
                                acc + amount
                            });

                        // subtract the previously cached received amount when we observe
                        // a spend of its nullifier
                        wallet_tx
                            .shielded_spends
                            .iter()
                            .filter(|s| {
                                self.spentness
                                    .get(&s.nf)
                                    .filter(|(_, spent)| *spent)
                                    .is_some()
                            })
                            .fold(total_received, |acc, s| {
                                received_amounts.get(&s.nf).map_or(acc, |amt| acc - *amt)
                            })
                    })
                },
            ))
        }

        fn get_memo(&self, _id_note: Self::NoteRef) -> Result<Memo, Self::Error> {
            self.blocks
                .iter()
                .find_map(|b| {
                    b.transactions.iter().find_map(|(txid, tx)| {
                        if *txid == id_note.0 {
                            tx.shielded_outputs.iter().find_map(|wso| {
                                if wso.index == id_note.1 {
                                    wso.memo.clone().and_then(|m| m.to_utf8())
                                } else {
                                    None
                                }
                            })
                        } else {
                            None
                        }
                    })
                })
                .transpose()
                .map_err(MemoryWalletError::MemoDecryptionError)
        }

        fn get_commitment_tree(
            &self,
            block_height: BlockHeight,
        ) -> Result<Option<CommitmentTree<Node>>, Self::Error> {
            Ok(self.blocks.iter().find_map(|b| {
                if b.height == block_height {
                    Some(b.commitment_tree.clone())
                } else {
                    None
                }
            }))
        }

        #[allow(clippy::type_complexity)]
        fn get_witnesses(
            &self,
            block_height: BlockHeight,
        ) -> Result<Vec<(Self::NoteRef, IncrementalWitness<Node>)>, Self::Error> {
            Ok(self
                .blocks
                .iter()
                .filter(|b| b.height == block_height)
                .flat_map(|b| {
                    b.transactions.iter().flat_map(|(txid, tx)| {
                        tx.shielded_outputs
                            .iter()
                            .map(move |wso| ((txid.clone(), wso.index), wso.witness.clone()))
                    })
                })
                .collect())
        }

        fn get_nullifiers(&self) -> Result<Vec<(AccountId, Nullifier)>, Self::Error> {
            Ok(Vec::new())
        }

        fn get_spendable_notes(
            &self,
            _account: AccountId,
            _anchor_height: BlockHeight,
        ) -> Result<Vec<SpendableNote>, Self::Error> {
            Ok(Vec::new())
        }

        fn select_spendable_notes(
            &self,
            _account: AccountId,
            _target_value: Amount,
            _anchor_height: BlockHeight,
        ) -> Result<Vec<SpendableNote>, Self::Error> {
            Ok(Vec::new())
        }
    }

    impl WalletWrite for MockWalletDb {
        #[allow(clippy::type_complexity)]
        fn advance_by_block(
            &mut self,
            _block: &PrunedBlock,
            _updated_witnesses: &[(Self::NoteRef, IncrementalWitness<Node>)],
        ) -> Result<Vec<(Self::NoteRef, IncrementalWitness<Node>)>, Self::Error> {
            self.blocks.insert(MemoryWalletBlock {
                height: block_height,
                hash: block_hash,
                block_time,
                commitment_tree: commitment_tree.clone(),
                transactions: HashMap::new(), //FIXME
            });

            Ok(())
        }

        fn store_received_tx(
            &mut self,
            _received_tx: &ReceivedTransaction,
        ) -> Result<Self::TxRef, Self::Error> {
            Ok(TxId::from_bytes([0u8; 32]))
        }

        fn store_sent_tx(
            &mut self,
            _sent_tx: &SentTransaction,
        ) -> Result<Self::TxRef, Self::Error> {
            Ok(TxId::from_bytes([0u8; 32]))
        }

        fn rewind_to_height(&mut self, _block_height: BlockHeight) -> Result<(), Self::Error> {
            Ok(())
        }
    }
}
