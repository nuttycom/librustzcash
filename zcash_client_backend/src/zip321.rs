use core::fmt::Debug;
use std::convert::TryFrom;
use std::fmt;

use nom::{
    branch::alt,
    bytes::complete::{tag, take_until},
    character::complete::{alpha1, alphanumeric0, digit0, digit1, one_of, char},
    combinator::{map, map_res, opt, recognize},
    error::ParseError,
    multi::{many0, separated_list},
    sequence::{preceded, separated_pair, tuple},
    AsChar, IResult, InputTakeAtPosition,
};

use percent_encoding::{percent_encode, utf8_percent_encode, AsciiSet, CONTROLS};

use zcash_primitives::{
    consensus, legacy, legacy::TransparentAddress, primitives,
    transaction::components::amount::COIN, 
    transaction::components::Amount,
};

use crate::encoding::{
    decode_payment_address, decode_transparent_address, encode_payment_address,
    encode_transparent_address,
};

// The set of ASCII characters which must be percent-encoded according
// to the definition of ZIP-0321. This is the complement of the subset of
// ASCII characters defined by `qchar`
//
//       unreserved      = ALPHA / DIGIT / "-" / "." / "_" / "~"
//       allowed-delims  = "!" / "$" / "'" / "(" / ")" / "*" / "+" / "," / ";"
//       qchar           = unreserved / pct-encoded / allowed-delims / ":" / "@"
pub const QCHAR_ENCODE: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'&')
    .add(b'\\')
    .add(b'/')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'[')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

#[derive(Debug, PartialEq)]
pub enum Address {
    TransparentAddress(legacy::TransparentAddress),
    SaplingAddress(primitives::PaymentAddress),
}

pub struct Memo([u8; 512]);

impl Debug for Memo {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("Zip321Payment")
            .field("memo", &format!("{:?}...", &self.0[0..17]))
            .finish()
    }
}

impl PartialEq for Memo {
    fn eq(&self, other: &Self) -> bool {
        let mut res = true;
        for i in 0..512 {
            if self.0[i] != other.0[i] {
                res = false;
                break;
            }
        }
        res
    }
}
pub enum AddrParseError {
    TAddrError(bs58::decode::Error),
    SAddrError(bech32::Error),
}

#[derive(Debug, PartialEq)]
pub struct Zip321Payment {
    recipient_address: Address,
    amount: Amount,
    memo: Option<Memo>,
    message: Option<String>,
}

#[derive(Debug, PartialEq)]
pub struct Zip321Request {
    payments: Vec<Zip321Payment>,
}

impl Zip321Request {
    pub fn to_uri<P: consensus::Parameters + Clone>(&self, params: &P) -> Option<String> {
        fn param_index(idx: Option<usize>) -> String {
            match idx {
                Some(i) if i > 0 => format!(".{}", i),
                _otherwise => "".to_string(),
            }
        }

        let addr_str = |addr: &Address| match addr {
            Address::TransparentAddress(t) => encode_transparent_address(
                &params.b58_pubkey_address_prefix(),
                &params.b58_script_address_prefix(),
                &t,
            ),
            Address::SaplingAddress(s) => {
                encode_payment_address(&params.hrp_sapling_payment_address(), &s)
            }
        };

        let addr_param = |addr: &Address, idx: Option<usize>| {
            format!("address{}={}", param_index(idx), addr_str(addr),)
        };

        let amount_param = |amount: Amount, idx: Option<usize>| {
            if amount.is_positive() {
                let z_coins = u64::from(amount) / (COIN as u64);
                let z_cents = u64::from(amount) % (COIN as u64);
                Some(format!(
                    "amount{}={}.{}",
                    param_index(idx),
                    z_coins,
                    z_cents
                ))
            } else {
                None
            }
        };

        let memo_param = |value: &Memo, idx: Option<usize>| {
            // strip trailing zero bytes.
            let value0: &[u8] = {
                let mut last_nonzero = -1;
                for i in (0..(value.0.len())).rev() {
                    if value.0[i] != 0x0 {
                        last_nonzero = i as i64;
                        break;
                    }
                }

                &value.0[..((last_nonzero + 1) as usize)]
            };

            format!(
                "{}{}={}",
                "memo",
                param_index(idx),
                percent_encode(value0, QCHAR_ENCODE)
            )
        };

        let str_param = |label: &str, value: &str, idx: Option<usize>| {
            format!(
                "{}{}={}",
                label,
                param_index(idx),
                utf8_percent_encode(value, QCHAR_ENCODE)
            )
        };

        if self.payments.len() == 1 {
            self.payments.get(0).map(|payment| {
                let mut params = vec![];
                if let Some(amt_param) = amount_param(payment.amount, None) {
                    params.push(amt_param);
                }

                format!(
                    "zcash:{}?{}",
                    addr_str(&payment.recipient_address),
                    params.join("&")
                )
            })
        } else {
            let mut params = vec![];
            for (i, payment) in (&self.payments).into_iter().enumerate() {
                params.push(addr_param(&payment.recipient_address, Some(i)));
                if let Some(amt_param) = amount_param(payment.amount, Some(i)) {
                    params.push(amt_param);
                }

                if let Some(m_param) = payment.memo.as_ref().map(|m| memo_param(&m, Some(i))) {
                    params.push(m_param);
                }

                if let Some(msg_param) = payment
                    .message
                    .as_ref()
                    .map(|m| str_param("message", &m, Some(i)))
                {
                    params.push(msg_param);
                }
            }

            Some(format!("zcash:?{}", params.join("&")))
        }
    }

    pub fn from_uri<'a, P: consensus::Parameters + Clone>(
        params: &P,
        uri: &'a str,
    ) -> IResult<&'a str, Zip321Request> {
        // For purposes of parsing
        #[derive(Debug)]
        enum Param<'a> {
            Addr(Address),
            Amount(Amount),
            Message(&'a str),
            Memo(Memo),
            Req(&'a str, &'a str),
            Other(&'a str, &'a str),
        };

        #[derive(Debug)]
        struct IndexedParam<'a> {
            param: Param<'a>,
            payment_index: usize,
        }

        let parse_address = |input: &str| {
            let t_res = decode_transparent_address(
                &params.b58_pubkey_address_prefix(),
                &params.b58_script_address_prefix(),
                input,
            )
            .map(|t| t.map(Address::TransparentAddress))
            .map_err(AddrParseError::TAddrError);

            let s_res = decode_payment_address(&params.hrp_sapling_payment_address(), input)
                .map(|s| s.map(Address::SaplingAddress))
                .map_err(AddrParseError::SAddrError);

            match t_res {
                Err(_) | Ok(None) => s_res,
                t_addr => t_addr,
            }
        };

        let lead_addr = |input: &'a str| -> IResult<&'a str, Option<Address>> {
            let (input, _) = tag("zcash:")(input)?;
            map_res(take_until("?"), parse_address)(input)
        };

        fn alphanum_or<'a>(allowed: String) -> impl (Fn(&'a str) -> IResult<&'a str, &'a str>) { 
            move |input| {
                input.split_at_position_complete(|item| {
                    let c = item.as_char();
                    !(c.is_alphanum() || allowed.contains(c))
                })
            }
        }

        fn qchars(input: &str) -> IResult<&str, &str> {
            alphanum_or("-._~!$'()*+,;:@%".to_string())(input)
        }

        fn namechars(input: &str) -> IResult<&str, &str> {
            alphanum_or("+-".to_string())(input)
        }


        fn indexed_name<'a>(input: &'a str) -> IResult<&'a str, (&'a str, Option<&'a str>)> {
            let paramname = recognize(tuple((alpha1, namechars)));

            tuple((
                paramname,
                opt(preceded(char('.'), recognize(tuple((one_of("123456789"), digit0)))))
            ))(input)
        }

        fn amount<'a>(input: &'a str) -> IResult<&'a str, Amount> {
            map_res(
                separated_pair(digit1, char('.'), digit0),
                |(whole_s, decimal_s): (&str, &str)| {
                    let coins: i64 = whole_s.to_string().parse::<i64>().map_err(|e| e.to_string())?;
                    let zats: i64 = decimal_s.to_string().parse::<i64>().map_err(|e| e.to_string())?;
                    let amt = coins * COIN + zats;

                    Amount::from_i64(amt).map_err(|_| format!("Not a valid zat amount: {}", amt))
                }
            )(input)
        }

        fn to_indexed_param<'a, P: consensus::Parameters>(params: &P) ->
            impl Fn(((&'a str, Option<&'a str>), &'a str)) -> Result<IndexedParam<'a>, String> {

            |((name, iopt), value)| {
                let param = match name {
                    //"address" =>
                    "amount" => map(amount, |a| Param::Amount(a))(value).map(|a| a.1).map_err(|e| e.to_string()),
                    //"label" =>
                    //"memo" =>
                    //"message" =>
                    other if other.starts_with("req-") =>
                        Err(format!("Required parameter {} not recognized", other)),
                    other =>
                        Ok(Param::Other(other, value))
                }?;

                let payment_index = match iopt {
                    Some(istr) => istr.to_string().parse::<usize>().map(Some).map_err(|e| e.to_string()),
                    None => Ok(None)
                }?;

                Ok(IndexedParam { param, payment_index: payment_index.unwrap_or(0) })
            }
        }

        fn zcashparam<'a, P: consensus::Parameters + Clone>(params: &P) ->
            impl Fn(&'a str) -> IResult<&str, IndexedParam<'a>>
        {
            let params0 = params.clone();
            move |input: &str| {
                map_res(
                    separated_pair(indexed_name, char('='), recognize(qchars)),
                    to_indexed_param(&params0)
                )(input)
            }
        }

        let (rest, addr) = lead_addr(uri)?;
        let primary_addr_param = addr.map(|a| IndexedParam { param: Param::Addr(a), payment_index: 0 });
        println!("{:?}: {:?}", rest, primary_addr_param);

        let (rest, _) = char('?')(rest)?;
        let (rest, xs) = separated_list(char('&'), zcashparam(params))(rest)?;
        println!("{:?}: {:?}", rest, xs);

        Ok((uri, Zip321Request { payments: vec![] }))
    }
}

#[cfg(feature = "test-dependencies")]
pub mod testing {
    use proptest::collection::vec;
    use proptest::prelude::*;
    use proptest::strategy::Strategy;

    use zcash_primitives::{
        keys::testing::arb_shielded_addr, legacy::testing::arb_transparent_addr,
        legacy::TransparentAddress, transaction::components::amount::testing::arb_amount,
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
    #[cfg(all(test, feature = "test-dependencies"))]
    use proptest::prelude::*;

    use zcash_primitives::consensus::Network;

    use super::Zip321Request;

    #[cfg(all(test, feature = "test-dependencies"))]
    use super::testing::arb_zip321_request;

    #[test]
    fn parse_simple() {
        let uri = "zcash:ztestsapling1n65uaftvs2g7075q2x2a04shfk066u3lldzxsrprfrqtzxnhc9ps73v4lhx4l9yfxj46sl0q90k?amount=3768769.2796286";
        let (_, parse_result) = Zip321Request::from_uri(&Network::TestNetwork, &uri).unwrap();

        assert_eq!(parse_result, Zip321Request { payments: vec![] });
    }

    #[cfg(all(test, feature = "test-dependencies"))]
    proptest! {
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
