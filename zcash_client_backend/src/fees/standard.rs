//! Change strategies designed for use with a standard fee.

use std::convert::Infallible;

use zcash_primitives::{
    consensus::{self, BlockHeight},
    memo::MemoBytes,
    transaction::fees::{transparent, zip317::FeeError as Zip317FeeError, StandardFeeRule},
};

use crate::ShieldedProtocol;

use super::{
    sapling as sapling_fees, ChangeError, ChangeStrategy, CommonChangeStrategy, DummyMetaSource,
    EphemeralBalance, TransactionBalance,
};

#[cfg(feature = "orchard")]
use super::orchard as orchard_fees;

/// A change strategy that proposes change as a single output. The output pool is chosen
/// as the most current pool that avoids unnecessary pool-crossing (with a specified
/// fallback when the transaction has no shielded inputs). Fee calculation is delegated
/// to the provided fee rule.
pub struct SingleOutputChangeStrategy(CommonChangeStrategy<DummyMetaSource, StandardFeeRule>);

impl SingleOutputChangeStrategy {
    /// Constructs a new [`SingleOutputChangeStrategy`] with the specified fee rule
    /// and change memo.
    ///
    /// `fallback_change_pool` is used when more than one shielded pool is enabled via
    /// feature flags, and the transaction has no shielded inputs.
    #[deprecated(note = "Use [`CommonChangeStrategy::simple`] instead.")]
    pub fn new(
        fee_rule: StandardFeeRule,
        change_memo: Option<MemoBytes>,
        fallback_change_pool: ShieldedProtocol,
    ) -> Self {
        Self(CommonChangeStrategy::simple(
            fee_rule,
            change_memo,
            fallback_change_pool,
        ))
    }
}

impl ChangeStrategy for SingleOutputChangeStrategy {
    type FeeRule = StandardFeeRule;
    type Error = Zip317FeeError;
    type MetaSource = DummyMetaSource;
    type WalletMeta = Infallible;

    fn fee_rule(&self) -> &Self::FeeRule {
        self.0.fee_rule()
    }

    fn compute_balance<P: consensus::Parameters, NoteRefT: Clone>(
        &self,
        params: &P,
        target_height: BlockHeight,
        transparent_inputs: &[impl transparent::InputView],
        transparent_outputs: &[impl transparent::OutputView],
        sapling: &impl sapling_fees::BundleView<NoteRefT>,
        #[cfg(feature = "orchard")] orchard: &impl orchard_fees::BundleView<NoteRefT>,
        ephemeral_balance: Option<&EphemeralBalance>,
        _wallet_meta: Option<&Self::WalletMeta>,
    ) -> Result<TransactionBalance, ChangeError<Self::Error, NoteRefT>> {
        self.0.compute_balance(
            params,
            target_height,
            transparent_inputs,
            transparent_outputs,
            sapling,
            #[cfg(feature = "orchard")]
            orchard,
            ephemeral_balance,
            None,
        )
    }
}
