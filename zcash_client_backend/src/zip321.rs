use std::fmt;
use core::fmt::Debug;

use percent_encoding::{
    percent_encode,
    utf8_percent_encode,
    NON_ALPHANUMERIC
};

use zcash_primitives::{
    consensus,
    legacy,
    primitives,
    transaction::components::Amount,
    transaction::components::amount::COIN
};

use crate::{
    encoding::{encode_payment_address, encode_transparent_address}
};

#[derive(Debug)]
pub enum Address {
    TransparentAddress(legacy::TransparentAddress),
    SaplingAddress(primitives::PaymentAddress),
}

pub struct Zip321Payment {
    recipient_address: Address,
    amount: Amount,
    memo: Option<[u8; 512]>,
    message: Option<String>,
}

impl Debug for Zip321Payment {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("Zip321Payment")
            .field("recipient_address", &self.recipient_address)
            .field("amount", &self.amount)
            .field("memo", &self.memo.map(|b| format!("{:?}...", &b[0..17])))
            .field("message", &self.message)
            .finish()
    }
}

#[derive(Debug)]
pub struct Zip321Request {
    payments: Vec<Zip321Payment>
}

impl Zip321Request {
    pub fn to_uri<P: consensus::Parameters>(&self, params: &P) -> Option<String> {
        fn param_index(idx: Option<usize>) -> String {
            match idx {
                Some(i) if i > 0 => format!(".{}", i),
                _otherwise => "".to_string()
            }
        }

        let addr_str = |addr: &Address| {
            match addr {
                Address::TransparentAddress(t) => encode_transparent_address(
                    &params.b58_pubkey_address_prefix(),
                    &params.b58_script_address_prefix(),
                    &t
                ),
                Address::SaplingAddress(s) => encode_payment_address(
                    &params.hrp_sapling_payment_address(),
                    &s
                )
            }
        };

        let addr_param = |addr: &Address, idx: Option<usize>| {
            format!(
                "address{}={}",
                param_index(idx),
                addr_str(addr),
            )
        };

        let amount_param = |amount: Amount, idx: Option<usize>| {
            if amount.is_positive() {
                let z_coins = u64::from(amount) / (COIN as u64);
                let z_cents = u64::from(amount) % (COIN as u64);
                Some(format!("amount{}={}.{}", param_index(idx), z_coins, z_cents))
            } else {
                None
            }
        };

        let memo_param = |value: &[u8], idx: Option<usize>| {
            // strip trailing zero bytes. 
            let value0: &[u8] = {
                let mut last_nonzero = -1;
                for i in (0..(value.len())).rev() {
                    if value[i] != 0x0 {
                        last_nonzero = i as i64;
                        break;
                    }
                }

                &value[..((last_nonzero + 1) as usize)]
            }; 

            format!(
                "{}{}={}",
                "memo",
                param_index(idx),
                percent_encode(value0, NON_ALPHANUMERIC)
            )
        };

        let str_param = |label: &str, value: &str, idx: Option<usize>| {
            format!(
                "{}{}={}",
                label,
                param_index(idx),
                utf8_percent_encode(value, NON_ALPHANUMERIC)
            )
        };

        if self.payments.len() == 1 {
            self.payments.get(0).map(|payment| {
                let mut params = vec![];
                if let Some(amt_param) = amount_param(payment.amount, None) {
                    params.push(amt_param);
                }

                format!("zcash:{}?{}", addr_str(&payment.recipient_address), params.join("&"))
            })
        } else {
            let mut params = vec![];
            for (i, payment) in (&self.payments).into_iter().enumerate() {
                params.push(addr_param(&payment.recipient_address, Some(i)));
                if let Some(amt_param) = amount_param(payment.amount, Some(i)) {
                    params.push(amt_param);
                }

                if let Some(m_param) = payment.memo.map(|m| memo_param(&m, Some(i))) {
                    params.push(m_param);
                }

                if let Some(msg_param) = payment.message.as_ref().map(|m| str_param("message", &m, Some(i))) {
                    params.push(msg_param);
                }
            }

            Some(format!("zcash:?{}", params.join("&")))
        }
    }
}

#[cfg(feature = "test-dependencies")]
pub mod testing {
    use proptest::collection::vec;
    use proptest::prelude::*;
    use proptest::strategy::Strategy;

    use zcash_primitives::{
        legacy::testing::arb_transparent_addr,
        keys::testing::arb_shielded_addr,
        transaction::components::amount::testing::arb_amount,
    };

    use super::{Address, Zip321Payment, Zip321Request};

    pub fn arb_addr() -> impl Strategy<Value = Address> {
        prop_oneof![
            arb_shielded_addr().prop_map(Address::SaplingAddress),
            arb_transparent_addr().prop_map(Address::TransparentAddress),
        ]
    }

    prop_compose! {
        pub fn arb_zip321_payment()(
            recipient_address in arb_addr(), 
            amount in arb_amount(), 
            memo_vec_opt in proptest::option::of(vec(any::<u8>(), 0..512)),
            message in proptest::option::of(any::<String>()),
            ) -> Zip321Payment {
            let memo_opt = memo_vec_opt.map(|memo_vec| {
                let mut memo: [u8; 512] = [0; 512];
                memo[..memo_vec.len()].copy_from_slice(&memo_vec);
                memo
            });

            Zip321Payment {
                recipient_address,
                amount,
                memo: memo_opt,
                message
            }
        }
    }

    prop_compose! {
        pub fn arb_zip321_request()(payments in vec(arb_zip321_payment(), 1..10)) -> Zip321Request {
            Zip321Request { payments }
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use zcash_primitives::{
        consensus::Network,
    };

    use super::{
        testing::{arb_zip321_request},
    };

    proptest!{
        #[test]
        fn test_zip321_uri_roundtrip(req in arb_zip321_request()) {
            if let Some(req_uri) = req.to_uri(&Network::TestNetwork) {
                println!("{}", req_uri);
            } else {
                panic!("Generated invalid payment request: {:?}", req);
            }
        }
    }
}
