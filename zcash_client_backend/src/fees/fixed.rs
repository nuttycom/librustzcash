//! Change strategies designed for use with a fixed fee.

use std::convert::Infallible;

use zcash_primitives::{
    consensus::{self, BlockHeight},
    memo::MemoBytes,
    transaction::{
        components::amount::BalanceError,
        fees::{fixed::FeeRule as FixedFeeRule, transparent},
    },
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
pub struct SingleOutputChangeStrategy(CommonChangeStrategy<DummyMetaSource, FixedFeeRule>);

impl SingleOutputChangeStrategy {
    /// Constructs a new [`SingleOutputChangeStrategy`] with the specified fee rule
    /// and change memo.
    ///
    /// `fallback_change_pool` is used when more than one shielded pool is enabled via
    /// feature flags, and the transaction has no shielded inputs.
    #[deprecated(note = "Use [`CommonChangeStrategy::simple`] instead.")]
    pub fn new(
        fee_rule: FixedFeeRule,
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
    type FeeRule = FixedFeeRule;
    type Error = BalanceError;
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

#[cfg(test)]
mod tests {
    use zcash_primitives::{
        consensus::{Network, NetworkUpgrade, Parameters},
        transaction::{
            components::{amount::NonNegativeAmount, transparent::TxOut},
            fees::{fixed::FeeRule as FixedFeeRule, zip317::MINIMUM_FEE},
        },
    };

    use crate::{
        data_api::{testing::MockWalletDb, wallet::input_selection::SaplingPayment},
        fees::{
            tests::{TestSaplingInput, TestTransparentInput},
            ChangeError, ChangeStrategy, ChangeValue, CommonChangeStrategy,
        },
        ShieldedProtocol,
    };

    #[cfg(feature = "orchard")]
    use crate::fees::orchard as orchard_fees;

    #[test]
    fn change_without_dust() {
        #[allow(deprecated)]
        let fee_rule = FixedFeeRule::non_standard(MINIMUM_FEE);
        let change_strategy = CommonChangeStrategy::<MockWalletDb, _>::simple(
            fee_rule,
            None,
            ShieldedProtocol::Sapling,
        );

        // spend a single Sapling note that is sufficient to pay the fee
        let result = change_strategy.compute_balance(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap(),
            &[] as &[TestTransparentInput],
            &[] as &[TxOut],
            &(
                sapling::builder::BundleType::DEFAULT,
                &[TestSaplingInput {
                    note_id: 0,
                    value: NonNegativeAmount::const_from_u64(60000),
                }][..],
                &[SaplingPayment::new(NonNegativeAmount::const_from_u64(
                    40000,
                ))][..],
            ),
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            None,
            None,
        );

        assert_matches!(
            result,
            Ok(balance) if
                balance.proposed_change() == [ChangeValue::sapling(NonNegativeAmount::const_from_u64(10000), None)] &&
                balance.fee_required() == MINIMUM_FEE
        );
    }

    #[test]
    fn dust_change() {
        #[allow(deprecated)]
        let fee_rule = FixedFeeRule::non_standard(MINIMUM_FEE);
        let change_strategy = CommonChangeStrategy::<MockWalletDb, _>::simple(
            fee_rule,
            None,
            ShieldedProtocol::Sapling,
        );

        // spend a single Sapling note that is sufficient to pay the fee
        let result = change_strategy.compute_balance(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap(),
            &[] as &[TestTransparentInput],
            &[] as &[TxOut],
            &(
                sapling::builder::BundleType::DEFAULT,
                &[
                    TestSaplingInput {
                        note_id: 0,
                        value: NonNegativeAmount::const_from_u64(40000),
                    },
                    // enough to pay a fee, plus dust
                    TestSaplingInput {
                        note_id: 0,
                        value: NonNegativeAmount::const_from_u64(10100),
                    },
                ][..],
                &[SaplingPayment::new(NonNegativeAmount::const_from_u64(
                    40000,
                ))][..],
            ),
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            None,
            None,
        );

        assert_matches!(
            result,
            Err(ChangeError::InsufficientFunds { available, required })
            if available == NonNegativeAmount::const_from_u64(50100) && required == NonNegativeAmount::const_from_u64(60000)
        );
    }
}
