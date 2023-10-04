use rusqlite::{self, named_params, types::Value, OptionalExtension};
use shardtree::error::ShardTreeError;
use std::cmp::{max, min};
use std::collections::BTreeSet;
use std::ops::Range;
use std::rc::Rc;
use tracing::{debug, trace};

use incrementalmerkletree::{Address, Position};
use zcash_primitives::consensus::{self, BlockHeight, NetworkUpgrade};

use zcash_client_backend::data_api::{
    scanning::{spanning_tree::SpanningTree, ScanPriority, ScanRange},
    SAPLING_SHARD_HEIGHT,
};

use crate::{
    error::SqliteClientError,
    wallet::{block_height_extrema, commitment_tree, init::WalletMigrationError},
    PRUNING_DEPTH, VERIFY_LOOKAHEAD,
};

use super::{scan_queue_extrema, wallet_birthday};

pub(crate) fn priority_code(priority: &ScanPriority) -> i64 {
    use ScanPriority::*;
    match priority {
        Ignored => 0,
        Scanned => 10,
        Historic => 20,
        OpenAdjacent => 30,
        FoundNote => 40,
        ChainTip => 50,
        Verify => 60,
    }
}

pub(crate) fn parse_priority_code(code: i64) -> Option<ScanPriority> {
    use ScanPriority::*;
    match code {
        0 => Some(Ignored),
        10 => Some(Scanned),
        20 => Some(Historic),
        30 => Some(OpenAdjacent),
        40 => Some(FoundNote),
        50 => Some(ChainTip),
        60 => Some(Verify),
        _ => None,
    }
}

pub(crate) fn suggest_scan_ranges(
    conn: &rusqlite::Connection,
    min_priority: ScanPriority,
) -> Result<Vec<ScanRange>, SqliteClientError> {
    let mut stmt_scan_ranges = conn.prepare_cached(
        "SELECT block_range_start, block_range_end, priority
         FROM scan_queue
         WHERE priority >= :min_priority
         ORDER BY priority DESC, block_range_end DESC",
    )?;

    let mut rows =
        stmt_scan_ranges.query(named_params![":min_priority": priority_code(&min_priority)])?;

    let mut result = vec![];
    while let Some(row) = rows.next()? {
        let range = Range {
            start: row.get::<_, u32>(0).map(BlockHeight::from)?,
            end: row.get::<_, u32>(1).map(BlockHeight::from)?,
        };
        let code = row.get::<_, i64>(2)?;
        let priority = parse_priority_code(code).ok_or_else(|| {
            SqliteClientError::CorruptedData(format!("scan priority not recognized: {}", code))
        })?;

        result.push(ScanRange::from_parts(range, priority));
    }

    Ok(result)
}

pub(crate) fn insert_queue_entries<'a>(
    conn: &rusqlite::Connection,
    entries: impl Iterator<Item = &'a ScanRange>,
) -> Result<(), rusqlite::Error> {
    let mut stmt = conn.prepare_cached(
        "INSERT INTO scan_queue (block_range_start, block_range_end, priority)
        VALUES (:block_range_start, :block_range_end, :priority)",
    )?;

    for entry in entries {
        trace!("Inserting queue entry {}", entry);
        if !entry.is_empty() {
            stmt.execute(named_params![
                ":block_range_start": u32::from(entry.block_range().start),
                ":block_range_end": u32::from(entry.block_range().end),
                ":priority": priority_code(&entry.priority())
            ])?;
        }
    }

    Ok(())
}

/// A trait that abstracts over the construction of wallet errors.
///
/// In order to make it possible to use [`replace_queue_entries`] in database migrations as well as
/// in code that returns `SqliteClientError`, it is necessary for that method to be polymorphic in
/// the error type.
pub(crate) trait WalletError {
    fn db_error(err: rusqlite::Error) -> Self;
    fn corrupt(message: String) -> Self;
    fn chain_height_unknown() -> Self;
    fn commitment_tree(err: ShardTreeError<commitment_tree::Error>) -> Self;
}

impl WalletError for SqliteClientError {
    fn db_error(err: rusqlite::Error) -> Self {
        SqliteClientError::DbError(err)
    }

    fn corrupt(message: String) -> Self {
        SqliteClientError::CorruptedData(message)
    }

    fn chain_height_unknown() -> Self {
        SqliteClientError::ChainHeightUnknown
    }

    fn commitment_tree(err: ShardTreeError<commitment_tree::Error>) -> Self {
        SqliteClientError::CommitmentTree(err)
    }
}

impl WalletError for WalletMigrationError {
    fn db_error(err: rusqlite::Error) -> Self {
        WalletMigrationError::DbError(err)
    }

    fn corrupt(message: String) -> Self {
        WalletMigrationError::CorruptedData(message)
    }

    fn chain_height_unknown() -> Self {
        WalletMigrationError::CorruptedData(
            "Wallet migration requires a valid account birthday.".to_owned(),
        )
    }

    fn commitment_tree(err: ShardTreeError<commitment_tree::Error>) -> Self {
        WalletMigrationError::CommitmentTree(err)
    }
}

pub(crate) fn replace_queue_entries<E: WalletError>(
    conn: &rusqlite::Transaction<'_>,
    query_range: &Range<BlockHeight>,
    entries: impl Iterator<Item = ScanRange>,
    force_rescans: bool,
) -> Result<(), E> {
    let (to_create, to_delete_ends) = {
        let mut suggested_stmt = conn
            .prepare_cached(
                "SELECT block_range_start, block_range_end, priority
                 FROM scan_queue
                 -- Ignore ranges that do not overlap and are not adjacent to the query range.
                 WHERE NOT (block_range_start > :end OR :start > block_range_end)
                 ORDER BY block_range_end",
            )
            .map_err(E::db_error)?;

        let mut rows = suggested_stmt
            .query(named_params![
                ":start": u32::from(query_range.start),
                ":end": u32::from(query_range.end),
            ])
            .map_err(E::db_error)?;

        // Iterate over the ranges in the scan queue that overlap the range that we have
        // identified as needing to be fully scanned. For each such range add it to the
        // spanning tree (these should all be nonoverlapping ranges, but we might coalesce
        // some in the process).
        let mut to_create: Option<SpanningTree> = None;
        let mut to_delete_ends: Vec<Value> = vec![];
        while let Some(row) = rows.next().map_err(E::db_error)? {
            let entry = ScanRange::from_parts(
                Range {
                    start: BlockHeight::from(row.get::<_, u32>(0).map_err(E::db_error)?),
                    end: BlockHeight::from(row.get::<_, u32>(1).map_err(E::db_error)?),
                },
                {
                    let code = row.get::<_, i64>(2).map_err(E::db_error)?;
                    parse_priority_code(code).ok_or_else(|| {
                        E::corrupt(format!("scan priority not recognized: {}", code))
                    })?
                },
            );
            to_delete_ends.push(Value::from(u32::from(entry.block_range().end)));
            to_create = if let Some(cur) = to_create {
                Some(cur.insert(entry, force_rescans))
            } else {
                Some(SpanningTree::Leaf(entry))
            };
        }

        // Update the tree that we read from the database, or if we didn't find any ranges
        // start with the scanned range.
        for entry in entries {
            to_create = if let Some(cur) = to_create {
                Some(cur.insert(entry, force_rescans))
            } else {
                Some(SpanningTree::Leaf(entry))
            };
        }

        (to_create, to_delete_ends)
    };

    if let Some(tree) = to_create {
        let ends_ptr = Rc::new(to_delete_ends);
        conn.execute(
            "DELETE FROM scan_queue WHERE block_range_end IN rarray(:ends)",
            named_params![":ends": ends_ptr],
        )
        .map_err(E::db_error)?;

        let scan_ranges = tree.into_vec();
        insert_queue_entries(conn, scan_ranges.iter()).map_err(E::db_error)?;
    }

    Ok(())
}

pub(crate) fn scan_complete<P: consensus::Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    range: Range<BlockHeight>,
    wallet_note_positions: &[Position],
) -> Result<(), SqliteClientError> {
    // Read the wallet birthday (if known).
    let wallet_birthday = wallet_birthday(conn)?;

    // Determine the range of block heights for which we will be updating the scan queue.
    let extended_range = {
        // If notes have been detected in the scan, we need to extend any adjacent un-scanned
        // ranges starting from the wallet birthday to include the blocks needed to complete
        // the note commitment tree subtrees containing the positions of the discovered notes.
        // We will query by subtree index to find these bounds.
        let required_subtrees = wallet_note_positions
            .iter()
            .map(|p| Address::above_position(SAPLING_SHARD_HEIGHT.into(), *p).index())
            .collect::<BTreeSet<_>>();

        // we'll either have both min and max bounds, or we'll have neither
        let subtree_bounds = required_subtrees
            .iter()
            .min()
            .zip(required_subtrees.iter().max());

        let mut sapling_shard_end_stmt = conn.prepare_cached(
            "SELECT subtree_end_height
            FROM sapling_tree_shards
            WHERE shard_index = :shard_index",
        )?;

        let mut sapling_shard_end = |index: u64| -> Result<Option<BlockHeight>, rusqlite::Error> {
            Ok(sapling_shard_end_stmt
                .query_row(named_params![":shard_index": index], |row| {
                    row.get::<_, Option<u32>>(0)
                        .map(|opt| opt.map(BlockHeight::from))
                })
                .optional()?
                .flatten())
        };

        // If no notes belonging to the wallet were found, we don't need to extend the scanning
        // range suggestions to include the associated subtrees, and our bounds are just the
        // scanned range. Otherwise, ensure that all shard ranges starting from the wallet
        // birthday are included.
        subtree_bounds
            .map(|(min_idx, max_idx)| {
                let range_min = if *min_idx > 0 {
                    // get the block height of the end of the previous shard
                    sapling_shard_end(*min_idx - 1)?
                } else {
                    // our lower bound is going to be the Sapling activation height
                    params.activation_height(NetworkUpgrade::Sapling)
                };

                // bound the minimum to the wallet birthday
                let range_min =
                    range_min.map(|h| wallet_birthday.map_or(h, |b| std::cmp::max(b, h)));

                // Get the block height for the end of the current shard, and make it an
                // exclusive end bound.
                let range_max = sapling_shard_end(*max_idx)?.map(|end| end + 1);

                Ok::<Range<BlockHeight>, rusqlite::Error>(Range {
                    start: range.start.min(range_min.unwrap_or(range.start)),
                    end: range.end.max(range_max.unwrap_or(range.end)),
                })
            })
            .transpose()
            .map_err(SqliteClientError::from)
    }?;

    let query_range = extended_range.clone().unwrap_or_else(|| range.clone());

    let scanned = ScanRange::from_parts(range.clone(), ScanPriority::Scanned);

    // If any of the extended range actually extends beyond the scanned range, we need to
    // scan that extension in order to make the found note(s) spendable. We need to avoid
    // creating empty ranges here, as that acts as an optimization barrier preventing
    // `SpanningTree` from merging non-empty scanned ranges on either side.
    let extended_before = extended_range
        .as_ref()
        .map(|extended| ScanRange::from_parts(extended.start..range.start, ScanPriority::FoundNote))
        .filter(|range| !range.is_empty());
    let extended_after = extended_range
        .map(|extended| ScanRange::from_parts(range.end..extended.end, ScanPriority::FoundNote))
        .filter(|range| !range.is_empty());

    replace_queue_entries::<SqliteClientError>(
        conn,
        &query_range,
        Some(scanned)
            .into_iter()
            .chain(extended_before)
            .chain(extended_after),
        false,
    )?;

    Ok(())
}

pub(crate) fn update_chain_tip<P: consensus::Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    new_tip: BlockHeight,
) -> Result<(), SqliteClientError> {
    // If the caller provided a chain tip that is before Sapling activation, do nothing.
    let sapling_activation = match params.activation_height(NetworkUpgrade::Sapling) {
        Some(h) if h <= new_tip => h,
        _ => return Ok(()),
    };

    // Read the previous max scanned height from the blocks table
    let max_scanned = block_height_extrema(conn)?.map(|range| *range.end());

    // Read the wallet birthday (if known).
    let wallet_birthday = wallet_birthday(conn)?;

    // If the chain tip is below the prior max scanned height, then the caller has caught
    // the chain in the middle of a reorg. Do nothing; the caller will continue using the
    // old scan ranges and either:
    // - encounter an error trying to fetch the blocks (and thus trigger the same handling
    //   logic as if this happened with the old linear scanning code); or
    // - encounter a discontinuity error in `scan_cached_blocks`, at which point they will
    //   call `WalletDb::truncate_to_height` as part of their reorg handling which will
    //   resolve the problem.
    //
    // We don't check the shard height, as normal usage would have the caller update the
    // shard state prior to this call, so it is possible and expected to be in a situation
    // where we should update the tip-related scan ranges but not the shard-related ones.
    match max_scanned {
        Some(h) if new_tip < h => return Ok(()),
        _ => (),
    };

    // `ScanRange` uses an exclusive upper bound.
    let chain_end = new_tip + 1;

    // Read the maximum height from the shards table.
    let shard_start_height = conn.query_row(
        "SELECT MAX(subtree_end_height)
        FROM sapling_tree_shards",
        [],
        |row| Ok(row.get::<_, Option<u32>>(0)?.map(BlockHeight::from)),
    )?;

    // Create a scanning range for the fragment of the last shard leading up to new tip.
    // We set a lower bound at the wallet birthday (if known), because account creation
    // requires specifying a tree frontier that ensures we don't need tree information
    // prior to the birthday.
    let tip_shard_entry = shard_start_height.filter(|h| h < &chain_end).map(|h| {
        let min_to_scan = wallet_birthday.filter(|b| b > &h).unwrap_or(h);
        ScanRange::from_parts(min_to_scan..chain_end, ScanPriority::ChainTip)
    });

    // Create scan ranges to either validate potentially invalid blocks at the wallet's
    // view of the chain tip, or connect the prior tip to the new tip.
    let tip_entry = max_scanned.map_or_else(
        || {
            // No blocks have been scanned, so we need to anchor the start of the new scan
            // range to something else.
            wallet_birthday.map_or_else(
                // We don't have a wallet birthday, which means we have no accounts yet.
                // We can therefore ignore all blocks up to the chain tip.
                || ScanRange::from_parts(sapling_activation..chain_end, ScanPriority::Ignored),
                // We have a wallet birthday, so mark all blocks between that and the
                // chain tip as `Historic` (performing wallet recovery).
                |wallet_birthday| {
                    ScanRange::from_parts(wallet_birthday..chain_end, ScanPriority::Historic)
                },
            )
        },
        |max_scanned| {
            // The scan range starts at the block after the max scanned height. Since
            // `scan_cached_blocks` retrieves the metadata for the block being connected to
            // (if it exists), the connectivity of the scan range to the max scanned block
            // will always be checked if relevant.
            let min_unscanned = max_scanned + 1;

            // If we don't have shard metadata, this means we're doing linear scanning, so
            // create a scan range from the prior tip to the current tip with `Historic`
            // priority.
            if tip_shard_entry.is_none() {
                ScanRange::from_parts(min_unscanned..chain_end, ScanPriority::Historic)
            } else {
                // Determine the height to which we expect new blocks retrieved from the
                // block source to be stable and not subject to being reorg'ed.
                let stable_height = new_tip.saturating_sub(PRUNING_DEPTH);

                // If the wallet's max scanned height is above the stable height,
                // prioritize the range between it and the new tip as `ChainTip`.
                if max_scanned > stable_height {
                    // We are in the steady-state case, where a wallet is close to the
                    // chain tip and just needs to catch up.
                    //
                    // This overlaps the `tip_shard_entry` range and so will be coalesced
                    // with it.
                    ScanRange::from_parts(min_unscanned..chain_end, ScanPriority::ChainTip)
                } else {
                    // In this case, the max scanned height is considered stable relative
                    // to the chain tip. However, it may be stable or unstable relative to
                    // the prior chain tip, which we could determine by looking up the
                    // prior chain tip height from the scan queue. For simplicity we merge
                    // these two cases together, and proceed as though the max scanned
                    // block is unstable relative to the prior chain tip.
                    //
                    // To confirm its stability, prioritize the `VERIFY_LOOKAHEAD` blocks
                    // above the max scanned height as `Verify`:
                    //
                    // - We use `Verify` to ensure that a connectivity check is performed,
                    //   along with any required rewinds, before any `ChainTip` ranges
                    //   (from this or any prior `update_chain_tip` call) are scanned.
                    //
                    // - We prioritize `VERIFY_LOOKAHEAD` blocks because this is expected
                    //   to be 12.5 minutes, within which it is reasonable for a user to
                    //   have potentially received a transaction (if they opened their
                    //   wallet to provide an address to someone else, or spent their own
                    //   funds creating a change output), without necessarily having left
                    //   their wallet open long enough for the transaction to be mined and
                    //   the corresponding block to be scanned.
                    //
                    // - We limit the range to at most the stable region, to prevent any
                    //   `Verify` ranges from being susceptible to reorgs, and potentially
                    //   interfering with subsequent `Verify` ranges defined by future
                    //   calls to `update_chain_tip`. Any gap between `stable_height` and
                    //   `shard_start_height` will be filled by the scan range merging
                    //   logic with a `Historic` range.
                    //
                    // If `max_scanned == stable_height` then this is a zero-length range.
                    // In this case, any non-empty `(stable_height+1)..shard_start_height`
                    // will be marked `Historic`, minimising the prioritised blocks at the
                    // chain tip and allowing for other ranges (for example, `FoundNote`)
                    // to take priority.
                    ScanRange::from_parts(
                        min_unscanned..min(stable_height + 1, min_unscanned + VERIFY_LOOKAHEAD),
                        ScanPriority::Verify,
                    )
                }
            }
        },
    );
    if let Some(entry) = &tip_shard_entry {
        debug!("{} will update latest shard", entry);
    }
    debug!("{} will connect prior scanned state to new tip", tip_entry);

    let query_range = match tip_shard_entry.as_ref() {
        Some(se) => Range {
            start: min(se.block_range().start, tip_entry.block_range().start),
            end: max(se.block_range().end, tip_entry.block_range().end),
        },
        None => tip_entry.block_range().clone(),
    };

    replace_queue_entries::<SqliteClientError>(
        conn,
        &query_range,
        tip_shard_entry.into_iter().chain(Some(tip_entry)),
        false,
    )?;

    Ok(())
}

pub(crate) fn frontier_inserted(
    conn: &rusqlite::Transaction<'_>,
    frontier_block: BlockHeight,
) -> Result<(), rusqlite::Error> {
    // If `block_height` is greater than or equal to `stable_height`, we can rewrite any
    // `ChainTip` ranges below `stable_height` to `OpenAdjacent` priority. This may cause some
    // ranges within which a note has been previously found, but which existed within a `ChainTip`
    // range to be deprioritized relative to other found notes.
    match scan_queue_extrema(conn)?.map(|r| *r.end()) {
        Some(chain_tip) if frontier_block + PRUNING_DEPTH > chain_tip => {
            conn.execute(
                "UPDATE scan_queue 
                 SET priority = :open_adjacent_priority
                 WHERE block_range_end < :block_height
                 AND priority = :chain_tip_priority",
                named_params! {
                    ":open_adjacent_priority": priority_code(&ScanPriority::OpenAdjacent),
                    ":chain_tip_priority": priority_code(&ScanPriority::ChainTip),
                    ":block_height": u32::from(frontier_block)
                },
            )?;

            // select all the ranges where end_height > frontier_height & rewrite them to make only
            // `ChainTip` ranges
            let existing_chain_tip_range_start = conn
                .query_row(
                    "SELECT MIN(block_range_start)
                 FROM scan_queue
                 WHERE block_range_end >= :block_height
                 AND priority = :chain_tip_priority",
                    named_params! {
                        ":chain_tip_priority": priority_code(&ScanPriority::ChainTip),
                        ":block_height": u32::from(frontier_block)
                    },
                    |row| row.get::<_, u32>(0).map(BlockHeight::from),
                )
                .optional()?;

            // Even if we have a frontier, we require at a minimum `VERIFY_LOOKAHEAD` blocks
            // to be scanned at `ChainTip` priority at the tip
            let rewrite_max = chain_tip.saturating_sub(VERIFY_LOOKAHEAD);

            let ranges: Vec<ScanRange> = existing_chain_tip_range_start
                .filter(|start| start < &frontier_block)
                .map(|start| {
                    ScanRange::from_parts(
                        start..min(frontier_block, rewrite_max),
                        ScanPriority::OpenAdjacent,
                    )
                })
                .into_iter()
                .chain(
                    Some(ScanRange::from_parts(
                        min(frontier_block, rewrite_max)..chain_tip,
                        ScanPriority::ChainTip,
                    ))
                    .into_iter(),
                )
                .collect();

            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use incrementalmerkletree::{frontier::Frontier, Hashable, Level, Position};

    use secrecy::SecretVec;
    use zcash_client_backend::data_api::{
        chain::CommitmentTreeRoot,
        scanning::{spanning_tree::testing::scan_range, ScanPriority},
        AccountBirthday, Ratio, WalletCommitmentTrees, WalletRead, WalletWrite,
        SAPLING_SHARD_HEIGHT,
    };
    use zcash_primitives::{
        block::BlockHash,
        consensus::{BlockHeight, NetworkUpgrade, Parameters},
        sapling::Node,
        transaction::components::Amount,
        zip32::DiversifiableFullViewingKey,
    };

    use crate::{
        error::SqliteClientError,
        testing::{AddressType, BlockCache, TestBuilder, TestState},
        wallet::scanning::{insert_queue_entries, replace_queue_entries, suggest_scan_ranges},
        VERIFY_LOOKAHEAD,
    };

    #[test]
    fn scan_complete() {
        use ScanPriority::*;

        let mut st = TestBuilder::new()
            .with_block_cache()
            .with_test_account(AccountBirthday::from_sapling_activation)
            .build();

        let dfvk = st.test_account_sapling().unwrap();
        let sapling_activation_height = st.sapling_activation_height();

        assert_matches!(
            // In the following, we don't care what the root hashes are, they just need to be
            // distinct.
            st.wallet_mut().put_sapling_subtree_roots(
                0,
                &[
                    CommitmentTreeRoot::from_parts(
                        sapling_activation_height + 100,
                        Node::empty_root(Level::from(0))
                    ),
                    CommitmentTreeRoot::from_parts(
                        sapling_activation_height + 200,
                        Node::empty_root(Level::from(1))
                    ),
                    CommitmentTreeRoot::from_parts(
                        sapling_activation_height + 300,
                        Node::empty_root(Level::from(2))
                    ),
                ]
            ),
            Ok(())
        );

        // We'll start inserting leaf notes 5 notes after the end of the third subtree, with a gap
        // of 10 blocks. After `scan_cached_blocks`, the scan queue should have a requested scan
        // range of 300..310 with `FoundNote` priority, 310..320 with `Scanned` priority.
        let initial_sapling_tree_size = (0x1 << 16) * 3 + 5;
        let initial_height = sapling_activation_height + 310;

        let value = Amount::from_u64(50000).unwrap();
        st.generate_block_at(
            initial_height,
            BlockHash([0; 32]),
            &dfvk,
            AddressType::DefaultExternal,
            value,
            initial_sapling_tree_size,
        );

        for _ in 1..=10 {
            st.generate_next_block(
                &dfvk,
                AddressType::DefaultExternal,
                Amount::from_u64(10000).unwrap(),
            );
        }

        st.scan_cached_blocks(initial_height, 10);

        // Verify the that adjacent range needed to make the note spendable has been prioritized.
        let sap_active = u32::from(sapling_activation_height);
        assert_matches!(
            st.wallet().suggest_scan_ranges(),
            Ok(scan_ranges) if scan_ranges == vec![
                scan_range((sap_active + 300)..(sap_active + 310), FoundNote)
            ]
        );

        // Check that the scanned range has been properly persisted.
        assert_matches!(
            suggest_scan_ranges(&st.wallet().conn, Scanned),
            Ok(scan_ranges) if scan_ranges == vec![
                scan_range((sap_active + 300)..(sap_active + 310), FoundNote),
                scan_range((sap_active + 310)..(sap_active + 320), Scanned)
            ]
        );

        // Simulate the wallet going offline for a bit, update the chain tip to 20 blocks in the
        // future.
        assert_matches!(
            st.wallet_mut()
                .update_chain_tip(sapling_activation_height + 340),
            Ok(())
        );

        // Check the scan range again, we should see a `ChainTip` range for the period we've been
        // offline.
        assert_matches!(
            st.wallet().suggest_scan_ranges(),
            Ok(scan_ranges) if scan_ranges == vec![
                scan_range((sap_active + 320)..(sap_active + 341), ChainTip),
                scan_range((sap_active + 300)..(sap_active + 310), ChainTip)
            ]
        );

        // Now simulate a jump ahead more than 100 blocks.
        assert_matches!(
            st.wallet_mut()
                .update_chain_tip(sapling_activation_height + 450),
            Ok(())
        );

        // Check the scan range again, we should see a `Validate` range for the previous wallet
        // tip, and then a `ChainTip` for the remaining range.
        assert_matches!(
            st.wallet().suggest_scan_ranges(),
            Ok(scan_ranges) if scan_ranges == vec![
                scan_range((sap_active + 320)..(sap_active + 330), Verify),
                scan_range((sap_active + 330)..(sap_active + 451), ChainTip),
                scan_range((sap_active + 300)..(sap_active + 310), ChainTip)
            ]
        );
    }

    pub(crate) fn test_with_canopy_birthday() -> (
        TestState<BlockCache>,
        DiversifiableFullViewingKey,
        AccountBirthday,
        u32,
    ) {
        let st = TestBuilder::new()
            .with_block_cache()
            .with_test_account(|network| {
                // We use Canopy activation as an arbitrary birthday height that's greater than Sapling
                // activation. We set the Canopy frontier to be 1234 notes into the second shard.
                let birthday_height = network.activation_height(NetworkUpgrade::Canopy).unwrap();
                let frontier_position = Position::from((0x1 << 16) + 1234);
                let frontier = Frontier::from_parts(
                    frontier_position,
                    Node::empty_leaf(),
                    vec![Node::empty_leaf(); frontier_position.past_ommer_count().into()],
                )
                .unwrap();
                AccountBirthday::from_parts(birthday_height, frontier, None)
            })
            .build();

        let (_, _, birthday) = st.test_account().unwrap();
        let dfvk = st.test_account_sapling().unwrap();
        let sap_active = st.sapling_activation_height();

        (st, dfvk, birthday, sap_active.into())
    }

    #[test]
    fn create_account_creates_ignored_range() {
        use ScanPriority::*;

        let (st, _, birthday, sap_active) = test_with_canopy_birthday();
        let birthday_height = birthday.height().into();

        let expected = vec![
            // The range up to the wallet's birthday height is ignored.
            scan_range(sap_active..birthday_height, Ignored),
        ];
        let actual = suggest_scan_ranges(&st.wallet().conn, Ignored).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn update_chain_tip_before_create_account() {
        use ScanPriority::*;

        let mut st = TestBuilder::new().with_block_cache().build();
        let sap_active = st.sapling_activation_height();

        // Update the chain tip.
        let new_tip = sap_active + 1000;
        st.wallet_mut().update_chain_tip(new_tip).unwrap();
        let chain_end = u32::from(new_tip + 1);

        let expected = vec![
            // The range up to the chain end is ignored.
            scan_range(sap_active.into()..chain_end, Ignored),
        ];
        let actual = suggest_scan_ranges(&st.wallet().conn, Ignored).unwrap();
        assert_eq!(actual, expected);

        // Now add an account.
        let wallet_birthday = sap_active + 500;
        st.wallet_mut()
            .create_account(
                &SecretVec::new(vec![0; 32]),
                AccountBirthday::from_parts(wallet_birthday, Frontier::empty(), None),
            )
            .unwrap();

        let expected = vec![
            // The account's birthday onward is marked for recovery.
            scan_range(wallet_birthday.into()..chain_end, Historic),
            // The range up to the wallet's birthday height is ignored.
            scan_range(sap_active.into()..wallet_birthday.into(), Ignored),
        ];
        let actual = suggest_scan_ranges(&st.wallet().conn, Ignored).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn update_chain_tip_with_no_subtree_roots() {
        use ScanPriority::*;

        let (mut st, _, birthday, sap_active) = test_with_canopy_birthday();

        // Set up the following situation:
        //
        //   prior_tip      new_tip
        //       |<--- 500 --->|
        // wallet_birthday
        let prior_tip = birthday.height();
        let wallet_birthday = birthday.height().into();

        // Update the chain tip.
        let new_tip = prior_tip + 500;
        st.wallet_mut().update_chain_tip(new_tip).unwrap();
        let chain_end = u32::from(new_tip + 1);

        // Verify that the suggested scan ranges match what is expected.
        let expected = vec![
            // The wallet's birthday onward is marked for recovery.
            scan_range(wallet_birthday..chain_end, Historic),
            // The range below the wallet's birthday height is ignored.
            scan_range(sap_active..wallet_birthday, Ignored),
        ];

        let actual = suggest_scan_ranges(&st.wallet().conn, Ignored).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn update_chain_tip_when_never_scanned() {
        use ScanPriority::*;

        let (mut st, _, birthday, sap_active) = test_with_canopy_birthday();

        // Set up the following situation:
        //
        // last_shard_start      prior_tip      new_tip
        //        |<----- 1000 ----->|<--- 500 --->|
        //                    wallet_birthday
        let prior_tip_height = birthday.height();

        // Set up some shard root history before the wallet birthday.
        let last_shard_start = birthday.height() - 1000;
        st.wallet_mut()
            .put_sapling_subtree_roots(
                0,
                &[CommitmentTreeRoot::from_parts(
                    last_shard_start,
                    // fake a hash, the value doesn't matter
                    Node::empty_leaf(),
                )],
            )
            .unwrap();

        // Update the chain tip.
        let tip_height = prior_tip_height + 500;
        st.wallet_mut().update_chain_tip(tip_height).unwrap();
        let chain_end = u32::from(tip_height + 1);

        // Verify that the suggested scan ranges match what is expected.
        let expected = vec![
            // The last (incomplete) shard's range starting from the wallet birthday is
            // marked for catching up to the chain tip, to ensure that if any notes are
            // discovered after the wallet's birthday, they will be spendable.
            scan_range(birthday.height().into()..chain_end, ChainTip),
            // The range below the birthday height is ignored.
            scan_range(sap_active..birthday.height().into(), Ignored),
        ];

        let actual = suggest_scan_ranges(&st.wallet().conn, Ignored).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn update_chain_tip_unstable_max_scanned() {
        use ScanPriority::*;

        // this birthday is 1234 notes into the second shard
        let (mut st, dfvk, birthday, sap_active) = test_with_canopy_birthday();

        // Set up the following situation:
        //
        //                                                prior_tip           new_tip
        //        |<------ 1000 ------>|<--- 500 --->|<- 40 ->|<-- 70 -->|<- 20 ->|
        // initial_shard_end    wallet_birthday  max_scanned     last_shard_start
        //
        let max_scanned = birthday.height() + 500;

        // Set up some shard root history before the wallet birthday.
        let initial_shard_end = birthday.height() - 1000;
        st.wallet_mut()
            .put_sapling_subtree_roots(
                0,
                &[CommitmentTreeRoot::from_parts(
                    initial_shard_end,
                    // fake a hash, the value doesn't matter
                    Node::empty_leaf(),
                )],
            )
            .unwrap();

        // Set up prior chain state. This simulates us having imported a wallet
        // with a birthday 520 blocks below the chain tip.
        let prior_tip = max_scanned + 40;
        st.wallet_mut().update_chain_tip(prior_tip).unwrap();

        // Verify that the suggested scan ranges match what is expected.
        let expected = vec![
            scan_range(birthday.height().into()..(prior_tip + 1).into(), ChainTip),
            scan_range(sap_active..birthday.height().into(), Ignored),
        ];
        let actual = suggest_scan_ranges(&st.wallet().conn, Ignored).unwrap();
        assert_eq!(actual, expected);

        // Now, scan the max scanned block.
        st.generate_block_at(
            max_scanned,
            BlockHash([0u8; 32]),
            &dfvk,
            AddressType::DefaultExternal,
            Amount::const_from_i64(10000),
            // 1235 notes into into the second shard
            u64::from(birthday.sapling_frontier().value().unwrap().position() + 1)
                .try_into()
                .unwrap(),
        );
        st.scan_cached_blocks(max_scanned, 1);

        // Verify that the suggested scan ranges match what is expected.
        let expected = vec![
            scan_range((max_scanned + 1).into()..(prior_tip + 1).into(), ChainTip),
            scan_range(birthday.height().into()..max_scanned.into(), ChainTip),
            scan_range(max_scanned.into()..(max_scanned + 1).into(), Scanned),
            scan_range(sap_active..birthday.height().into(), Ignored),
        ];

        let actual = suggest_scan_ranges(&st.wallet().conn, Ignored).unwrap();
        assert_eq!(actual, expected);

        // Now simulate shutting down, and then restarting 90 blocks later, after a shard
        // has been completed.
        let last_shard_start = prior_tip + 70;
        st.wallet_mut()
            .put_sapling_subtree_roots(
                0,
                &[CommitmentTreeRoot::from_parts(
                    last_shard_start,
                    // fake a hash, the value doesn't matter
                    Node::empty_leaf(),
                )],
            )
            .unwrap();

        let new_tip = last_shard_start + 20;
        st.wallet_mut().update_chain_tip(new_tip).unwrap();
        let chain_end = u32::from(new_tip + 1);

        // Verify that the suggested scan ranges match what is expected
        let expected = vec![
            // The max scanned block's connectivity is verified by scanning the next 10 blocks.
            scan_range(
                (max_scanned + 1).into()..(max_scanned + 1 + VERIFY_LOOKAHEAD).into(),
                Verify,
            ),
            // The last shard needs to catch up to the chain tip in order to make notes spendable.
            scan_range(last_shard_start.into()..chain_end, ChainTip),
            // The range between the verification blocks and the prior tip is still in the queue.
            scan_range(
                (max_scanned + 1 + VERIFY_LOOKAHEAD).into()..(prior_tip + 1).into(),
                ChainTip,
            ),
            // The remainder of the second-to-last shard's range is still in the queue.
            scan_range(birthday.height().into()..max_scanned.into(), ChainTip),
            // The gap between the prior tip and the last shard is deferred as low priority.
            scan_range((prior_tip + 1).into()..last_shard_start.into(), Historic),
            // The max scanned block itself is left as-is.
            scan_range(max_scanned.into()..(max_scanned + 1).into(), Scanned),
            // The range below the second-to-last shard is ignored.
            scan_range(sap_active..birthday.height().into(), Ignored),
        ];

        let actual = suggest_scan_ranges(&st.wallet().conn, Ignored).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn update_chain_tip_stable_max_scanned() {
        use ScanPriority::*;

        let (mut st, dfvk, birthday, sap_active) = test_with_canopy_birthday();

        // Set up the following situation:
        //
        //                            prior_tip           new_tip
        //        |<--- 500 --->|<- 20 ->|<-- 50 -->|<- 20 ->|
        // wallet_birthday  max_scanned     last_shard_start
        //
        let max_scanned = birthday.height() + 500;
        let prior_tip = max_scanned + 20;

        // Set up some shard root history before the wallet birthday.
        let second_to_last_shard_start = birthday.height() - 1000;
        st.wallet_mut()
            .put_sapling_subtree_roots(
                0,
                &[CommitmentTreeRoot::from_parts(
                    second_to_last_shard_start,
                    // fake a hash, the value doesn't matter
                    Node::empty_leaf(),
                )],
            )
            .unwrap();

        // We have scan ranges and a subtree, but have scanned no blocks.
        let summary = st.get_wallet_summary(1);
        assert_eq!(summary.and_then(|s| s.scan_progress()), None);

        // Set up prior chain state. This simulates us having imported a wallet
        // with a birthday 520 blocks below the chain tip.
        st.wallet_mut().update_chain_tip(prior_tip).unwrap();

        // Verify that the suggested scan ranges match what is expected.
        let expected = vec![
            scan_range(birthday.height().into()..(prior_tip + 1).into(), ChainTip),
            scan_range(sap_active..birthday.height().into(), Ignored),
        ];

        let actual = suggest_scan_ranges(&st.wallet().conn, Ignored).unwrap();
        assert_eq!(actual, expected);

        // Now, scan the max scanned block.
        st.generate_block_at(
            max_scanned,
            BlockHash([0u8; 32]),
            &dfvk,
            AddressType::DefaultExternal,
            Amount::const_from_i64(10000),
            u64::from(birthday.sapling_frontier().value().unwrap().position() + 1)
                .try_into()
                .unwrap(),
        );
        st.scan_cached_blocks(max_scanned, 1);

        // We have scanned a block, so we now have a starting tree position, 500 blocks above the
        // wallet birthday but before the end of the shard.
        let summary = st.get_wallet_summary(1);
        assert_eq!(
            summary.and_then(|s| s.scan_progress()),
            Some(Ratio::new(1, 0x1 << SAPLING_SHARD_HEIGHT))
        );

        // Now simulate shutting down, and then restarting 70 blocks later, after a shard
        // has been completed.
        let last_shard_start = prior_tip + 50;
        st.wallet_mut()
            .put_sapling_subtree_roots(
                0,
                &[CommitmentTreeRoot::from_parts(
                    last_shard_start,
                    // fake a hash, the value doesn't matter
                    Node::empty_leaf(),
                )],
            )
            .unwrap();

        let new_tip = last_shard_start + 20;
        st.wallet_mut().update_chain_tip(new_tip).unwrap();
        let chain_end = u32::from(new_tip + 1);

        // Verify that the suggested scan ranges match what is expected.
        let expected = vec![
            // The blocks after the max scanned block up to the chain tip are prioritised.
            scan_range((max_scanned + 1).into()..chain_end, ChainTip),
            // The remainder of the second-to-last shard's range is still in the queue.
            scan_range(birthday.height().into()..max_scanned.into(), ChainTip),
            // The max scanned block itself is left as-is.
            scan_range(max_scanned.into()..(max_scanned + 1).into(), Scanned),
            // The range below the second-to-last shard is ignored.
            scan_range(sap_active..birthday.height().into(), Ignored),
        ];

        let actual = suggest_scan_ranges(&st.wallet().conn, Ignored).unwrap();
        assert_eq!(actual, expected);

        // We've crossed a subtree boundary, and so still only have one scanned note but have two
        // shards worth of notes to scan.
        let summary = st.get_wallet_summary(1);
        assert_eq!(
            summary.and_then(|s| s.scan_progress()),
            Some(Ratio::new(1, 0x1 << (SAPLING_SHARD_HEIGHT + 1)))
        );
    }

    #[test]
    fn replace_queue_entries_merges_previous_range() {
        use ScanPriority::*;

        let mut st = TestBuilder::new().build();

        let ranges = vec![
            scan_range(150..200, ChainTip),
            scan_range(100..150, Scanned),
            scan_range(0..100, Ignored),
        ];

        {
            let tx = st.wallet_mut().conn.transaction().unwrap();
            insert_queue_entries(&tx, ranges.iter()).unwrap();
            tx.commit().unwrap();
        }

        let actual = suggest_scan_ranges(&st.wallet().conn, Ignored).unwrap();
        assert_eq!(actual, ranges);

        {
            let tx = st.wallet_mut().conn.transaction().unwrap();
            replace_queue_entries::<SqliteClientError>(
                &tx,
                &(BlockHeight::from(150)..BlockHeight::from(160)),
                vec![scan_range(150..160, Scanned)].into_iter(),
                false,
            )
            .unwrap();
            tx.commit().unwrap();
        }

        let expected = vec![
            scan_range(160..200, ChainTip),
            scan_range(100..160, Scanned),
            scan_range(0..100, Ignored),
        ];

        let actual = suggest_scan_ranges(&st.wallet().conn, Ignored).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn replace_queue_entries_merges_subsequent_range() {
        use ScanPriority::*;

        let mut st = TestBuilder::new().build();

        let ranges = vec![
            scan_range(150..200, ChainTip),
            scan_range(100..150, Scanned),
            scan_range(0..100, Ignored),
        ];

        {
            let tx = st.wallet_mut().conn.transaction().unwrap();
            insert_queue_entries(&tx, ranges.iter()).unwrap();
            tx.commit().unwrap();
        }

        let actual = suggest_scan_ranges(&st.wallet().conn, Ignored).unwrap();
        assert_eq!(actual, ranges);

        {
            let tx = st.wallet_mut().conn.transaction().unwrap();
            replace_queue_entries::<SqliteClientError>(
                &tx,
                &(BlockHeight::from(90)..BlockHeight::from(100)),
                vec![scan_range(90..100, Scanned)].into_iter(),
                false,
            )
            .unwrap();
            tx.commit().unwrap();
        }

        let expected = vec![
            scan_range(150..200, ChainTip),
            scan_range(90..150, Scanned),
            scan_range(0..90, Ignored),
        ];

        let actual = suggest_scan_ranges(&st.wallet().conn, Ignored).unwrap();
        assert_eq!(actual, expected);
    }
}
