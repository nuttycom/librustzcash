//! Helper functions for managing light client key material.

use zcash_primitives::zip32::{ChildIndex, ExtendedSpendingKey};

#[cfg(feature = "transparent-inputs")]
use {
    crate::wallet::AccountId,
    bs58::{self, decode::Error as Bs58Error},
    hdwallet::{ExtendedPrivKey, KeyIndex},
    secp256k1::{key::PublicKey, key::SecretKey, Secp256k1},
    sha2::{Digest, Sha256},
    std::convert::TryInto,
    zcash_primitives::{consensus, legacy::TransparentAddress},
};

/// Derives the ZIP 32 [`ExtendedSpendingKey`] for a given coin type and account from the
/// given seed.
///
/// # Panics
///
/// Panics if `seed` is shorter than 32 bytes.
///
/// # Examples
///
/// ```
/// use zcash_primitives::{constants::testnet::COIN_TYPE};
/// use zcash_client_backend::{keys::spending_key};
///
/// let extsk = spending_key(&[0; 32][..], COIN_TYPE, 0);
/// ```
pub fn spending_key(seed: &[u8], coin_type: u32, account: u32) -> ExtendedSpendingKey {
    if seed.len() < 32 {
        panic!("ZIP 32 seeds MUST be at least 32 bytes");
    }

    ExtendedSpendingKey::from_path(
        &ExtendedSpendingKey::master(&seed),
        &[
            ChildIndex::Hardened(32),
            ChildIndex::Hardened(coin_type),
            ChildIndex::Hardened(account),
        ],
    )
}

#[cfg(feature = "transparent-inputs")]
pub fn derive_transparent_address_from_secret_key(
    secret_key: secp256k1::key::SecretKey,
) -> TransparentAddress {
    let secp = Secp256k1::new();
    let pk = PublicKey::from_secret_key(&secp, &secret_key);
    let mut hash160 = ripemd160::Ripemd160::new();
    hash160.update(Sha256::digest(&pk.serialize()[..].to_vec()));
    TransparentAddress::PublicKey(*hash160.finalize().as_ref())
}

#[cfg(feature = "transparent-inputs")]
pub fn derive_secret_key_from_seed<P: consensus::Parameters>(
    params: &P,
    seed: &[u8],
    account: AccountId,
    index: u32,
) -> Result<SecretKey, hdwallet::error::Error> {
    let ext_t_key = ExtendedPrivKey::with_seed(&seed)?;
    let private_key = ext_t_key
        .derive_private_key(KeyIndex::hardened_from_normalize_index(44)?)?
        .derive_private_key(KeyIndex::hardened_from_normalize_index(params.coin_type())?)?
        .derive_private_key(KeyIndex::hardened_from_normalize_index(account.0)?)?
        .derive_private_key(KeyIndex::Normal(0))?
        .derive_private_key(KeyIndex::Normal(index))?
        .private_key;

    Ok(private_key)
}

pub struct Wif(pub String);

impl Wif {
    pub fn from_secret_key(sk: &SecretKey, compressed: bool) -> Self {
        let secret_key = sk.as_ref();
        let mut wif = [0u8; 34];
        wif[0] = 0x80;
        wif[1..33].copy_from_slice(secret_key);
        if compressed {
            wif[33] = 0x01;
            Wif(bs58::encode(&wif[..]).with_check().into_string())
        } else {
            Wif(bs58::encode(&wif[..]).with_check().into_string())
        }
    }
}

impl TryInto<SecretKey> for Wif {
    type Error = Bs58Error;

    fn try_into(self) -> Result<SecretKey, Self::Error> {
        bs58::decode(&self.0)
            .with_check(None)
            .into_vec()
            .map(|decoded| SecretKey::from_slice(&decoded[1..33]).expect("wrong size key"))
    }
}

#[cfg(test)]
mod tests {
    use super::spending_key;

    #[cfg(feature = "transparent-inputs")]
    use {
        super::{derive_secret_key_from_seed, derive_transparent_address_from_secret_key, Wif},
        crate::{encoding::AddressCodec, wallet::AccountId},
        secp256k1::key::SecretKey,
        std::convert::TryInto,
        zcash_primitives::consensus::MAIN_NETWORK,
    };

    #[test]
    #[should_panic]
    fn spending_key_panics_on_short_seed() {
        let _ = spending_key(&[0; 31][..], 0, 0);
    }

    #[cfg(feature = "transparent-inputs")]
    #[test]
    fn sk_to_wif() {
        let seed_hex = "6ef5f84def6f4b9d38f466586a8380a38593bd47c8cda77f091856176da47f26b5bd1c8d097486e5635df5a66e820d28e1d73346f499801c86228d43f390304f";
        let seed = hex::decode(&seed_hex).unwrap();
        let sk = derive_secret_key_from_seed(&MAIN_NETWORK, &seed, AccountId(0), 0).unwrap();
        assert_eq!(
            Wif::from_secret_key(&sk, true).0,
            "L4BvDC33yLjMRxipZvdiUmdYeRfZmR8viziwsVwe72zJdGbiJPv2".to_string()
        );
    }

    #[cfg(feature = "transparent-inputs")]
    #[test]
    fn sk_to_taddr() {
        let seed_hex = "6ef5f84def6f4b9d38f466586a8380a38593bd47c8cda77f091856176da47f26b5bd1c8d097486e5635df5a66e820d28e1d73346f499801c86228d43f390304f";
        let seed = hex::decode(&seed_hex).unwrap();
        let sk = derive_secret_key_from_seed(&MAIN_NETWORK, &seed, AccountId(0), 0).unwrap();
        let taddr = derive_transparent_address_from_secret_key(sk);
        assert_eq!(
            taddr.encode(&MAIN_NETWORK),
            "t1PKtYdJJHhc3Pxowmznkg7vdTwnhEsCvR4".to_string()
        );
    }

    #[cfg(feature = "transparent-inputs")]
    #[test]
    fn sk_wif_to_taddr() {
        let sk_wif = Wif("L4BvDC33yLjMRxipZvdiUmdYeRfZmR8viziwsVwe72zJdGbiJPv2".to_string());
        let sk: SecretKey = sk_wif.try_into().expect("invalid wif");
        let taddr = derive_transparent_address_from_secret_key(sk);
        assert_eq!(
            taddr.encode(&MAIN_NETWORK),
            "t1PKtYdJJHhc3Pxowmznkg7vdTwnhEsCvR4".to_string()
        );
    }
}
