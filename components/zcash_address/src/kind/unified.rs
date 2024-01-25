//! Implementation of [ZIP 316](https://zips.z.cash/zip-0316) Unified Addresses and Viewing Keys.

use bech32::{self, FromBase32, ToBase32, Variant};
use std::cmp;
use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::fmt;
use std::num::TryFromIntError;

use crate::Network;

pub(crate) mod address;
pub(crate) mod fvk;
pub(crate) mod ivk;

pub use address::{Address, Receiver};
pub use fvk::{Fvk, Ufvk};
pub use ivk::{Ivk, Uivk};

const PADDING_LEN: usize = 16;

/// The known Receiver and Viewing Key types.
///
/// The typecodes `0xFFFA..=0xFFFF` reserved for experiments are currently not
/// distinguished from unknown values, and will be parsed as [`Typecode::Unknown`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DataTypecode {
    /// A transparent P2PKH address, FVK, or IVK encoding as specified in [ZIP 316](https://zips.z.cash/zip-0316).
    P2pkh,
    /// A transparent P2SH address.
    ///
    /// This typecode cannot occur in a [`Ufvk`] or [`Uivk`].
    P2sh,
    /// A Sapling raw address, FVK, or IVK encoding as specified in [ZIP 316](https://zips.z.cash/zip-0316).
    Sapling,
    /// An Orchard raw address, FVK, or IVK encoding as specified in [ZIP 316](https://zips.z.cash/zip-0316).
    Orchard,
    /// An unknown or experimental typecode.
    Unknown(u32),
}

impl TryFrom<u32> for DataTypecode {
    type Error = ();

    fn try_from(typecode: u32) -> Result<Self, Self::Error> {
        match typecode {
            0x00 => Ok(DataTypecode::P2pkh),
            0x01 => Ok(DataTypecode::P2sh),
            0x02 => Ok(DataTypecode::Sapling),
            0x03 => Ok(DataTypecode::Orchard),
            0x04..=0xDF | 0xFD..=0x02000000 => Ok(DataTypecode::Unknown(typecode)),
            _ => Err(()),
        }
    }
}

impl From<DataTypecode> for u32 {
    fn from(t: DataTypecode) -> Self {
        match t {
            DataTypecode::P2pkh => 0x00,
            DataTypecode::P2sh => 0x01,
            DataTypecode::Sapling => 0x02,
            DataTypecode::Orchard => 0x03,
            DataTypecode::Unknown(typecode) => typecode,
        }
    }
}

impl DataTypecode {
    pub fn preference_order(a: &Self, b: &Self) -> cmp::Ordering {
        match (a, b) {
            // Trivial equality checks.
            (Self::Orchard, Self::Orchard)
            | (Self::Sapling, Self::Sapling)
            | (Self::P2sh, Self::P2sh)
            | (Self::P2pkh, Self::P2pkh) => cmp::Ordering::Equal,

            // We don't know for certain the preference order of unknown items, but it
            // is likely that the higher typecode has higher preference. The exact order
            // doesn't really matter, as unknown items have lower preference than
            // known items.
            (Self::Unknown(a), Self::Unknown(b)) => b.cmp(a),

            // For the remaining cases, we rely on `match` always choosing the first arm
            // with a matching pattern. Patterns below are listed in priority order:
            (Self::Orchard, _) => cmp::Ordering::Less,
            (_, Self::Orchard) => cmp::Ordering::Greater,

            (Self::Sapling, _) => cmp::Ordering::Less,
            (_, Self::Sapling) => cmp::Ordering::Greater,

            (Self::P2sh, _) => cmp::Ordering::Less,
            (_, Self::P2sh) => cmp::Ordering::Greater,

            (Self::P2pkh, _) => cmp::Ordering::Less,
            (_, Self::P2pkh) => cmp::Ordering::Greater,
        }
    }
}

/// The known Metadata Typecodes
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MetadataTypecode {
    /// Expiration height metadata as specified in [ZIP 316, Revision 1](https://zips.z.cash/zip-0316)
    ExpiryHeight,
    /// Expiration height metadata as specified in [ZIP 316, Revision 1](https://zips.z.cash/zip-0316)
    ExpiryTime,
    /// An unknown MUST-underatand metadata item as specified in [ZIP 316, Revision 1](https://zips.z.cash/zip-0316)
    /// A parser encountering this typecode must halt with an error.
    MustUnderstand(u32),
    /// An unknown metadata item as specified in [ZIP 316, Revision 1](https://zips.z.cash/zip-0316)
    Unknown(u32),
}

impl TryFrom<u32> for MetadataTypecode {
    type Error = ();

    fn try_from(typecode: u32) -> Result<Self, Self::Error> {
        match typecode {
            0xE0 => Ok(MetadataTypecode::ExpiryHeight),
            0xE1 => Ok(MetadataTypecode::ExpiryTime),
            0xE2..=0xEF => Ok(MetadataTypecode::MustUnderstand(typecode)),
            0xF0..=0xFC => Ok(MetadataTypecode::Unknown(typecode)),
            _ => Err(()),
        }
    }
}

impl From<MetadataTypecode> for u32 {
    fn from(t: MetadataTypecode) -> Self {
        match t {
            MetadataTypecode::ExpiryHeight => 0xE0,
            MetadataTypecode::ExpiryTime => 0xE1,
            MetadataTypecode::MustUnderstand(value) => value,
            MetadataTypecode::Unknown(value) => value,
        }
    }
}

/// An enumeration of the Unified Address Item Typecodes.
///
/// Unified Address Items are partitioned into two sets: key-type items, which include
/// receivers and viewing keys, and metadata items
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Typecode {
    Data(DataTypecode),
    Metadata(MetadataTypecode),
}

impl Typecode {
    pub const P2PKH: Typecode = Typecode::Data(DataTypecode::P2pkh);
    pub const P2SH: Typecode = Typecode::Data(DataTypecode::P2sh);
    pub const SAPLING: Typecode = Typecode::Data(DataTypecode::Sapling);
    pub const ORCHARD: Typecode = Typecode::Data(DataTypecode::Orchard);

    pub fn encoding_order(a: &Self, b: &Self) -> cmp::Ordering {
        u32::from(*a).cmp(&u32::from(*b))
    }

    pub fn is_transparent_data_item(&self) -> bool {
        *self == Self::P2PKH || *self == Self::P2SH
    }
}

impl TryFrom<u32> for Typecode {
    type Error = ParseError;

    fn try_from(typecode: u32) -> Result<Self, Self::Error> {
        DataTypecode::try_from(typecode)
            .map_or_else(
                |()| MetadataTypecode::try_from(typecode).map(Typecode::Metadata),
                |t| Ok(Typecode::Data(t)),
            )
            .map_err(|()| ParseError::InvalidTypecodeValue(typecode as u64))
    }
}

impl From<Typecode> for u32 {
    fn from(t: Typecode) -> Self {
        match t {
            Typecode::Data(tc) => tc.into(),
            Typecode::Metadata(tc) => tc.into(),
        }
    }
}

impl TryFrom<Typecode> for usize {
    type Error = TryFromIntError;

    fn try_from(t: Typecode) -> Result<Self, Self::Error> {
        u32::from(t).try_into()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum MetadataItem {
    ExpiryHeight(u32),
    ExpiryTime(u64),
    Unknown { typecode: u32, data: Vec<u8> },
}

impl MetadataItem {
    pub fn parse(typecode: MetadataTypecode, data: &[u8]) -> Result<Self, ParseError> {
        match typecode {
            MetadataTypecode::ExpiryHeight => data
                .try_into()
                .map(u32::from_le_bytes)
                .map(MetadataItem::ExpiryHeight)
                .map_err(|_| {
                    ParseError::InvalidEncoding(
                        "Expiry height must be a 32-bit little-endian value.".to_string(),
                    )
                }),
            MetadataTypecode::ExpiryTime => data
                .try_into()
                .map(u64::from_le_bytes)
                .map(MetadataItem::ExpiryTime)
                .map_err(|_| {
                    ParseError::InvalidEncoding(
                        "Expiry time must be a 64-bit little-endian value.".to_string(),
                    )
                }),
            MetadataTypecode::MustUnderstand(tc) => Err(ParseError::NotUnderstood(tc)),
            MetadataTypecode::Unknown(typecode) => Ok(MetadataItem::Unknown {
                typecode,
                data: data.to_vec(),
            }),
        }
    }

    pub fn typecode(&self) -> MetadataTypecode {
        match self {
            MetadataItem::ExpiryHeight(_) => MetadataTypecode::ExpiryHeight,
            MetadataItem::ExpiryTime(_) => MetadataTypecode::ExpiryTime,
            MetadataItem::Unknown { typecode, .. } => MetadataTypecode::Unknown(*typecode),
        }
    }

    pub fn data(&self) -> Vec<u8> {
        match self {
            MetadataItem::ExpiryHeight(h) => h.to_le_bytes().to_vec(),
            MetadataItem::ExpiryTime(t) => t.to_le_bytes().to_vec(),
            MetadataItem::Unknown { data, .. } => data.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Item<T> {
    Data(T),
    Metadata(MetadataItem),
}

impl<T: private::SealedDataItem> Item<T> {
    pub fn typecode(&self) -> Typecode {
        match self {
            Item::Data(d) => Typecode::Data(d.typecode()),
            Item::Metadata(m) => Typecode::Metadata(m.typecode()),
        }
    }

    pub fn encoding_order(a: &Self, b: &Self) -> cmp::Ordering {
        Typecode::encoding_order(&a.typecode(), &b.typecode())
    }

    pub fn data(&self) -> Vec<u8> {
        match self {
            Item::Data(d) => d.data().to_vec(),
            Item::Metadata(m) => m.data(),
        }
    }
}

/// An error while attempting to parse a string as a Zcash address.
#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The unified container contains both P2PKH and P2SH items.
    BothP2phkAndP2sh,
    /// The unified container contains a duplicated typecode.
    DuplicateTypecode(Typecode),
    /// The parsed typecode exceeds the maximum allowed CompactSize value.
    InvalidTypecodeValue(u64),
    /// The string is an invalid encoding.
    InvalidEncoding(String),
    /// The items in the unified container are not in typecode order.
    InvalidTypecodeOrder,
    /// The unified container only contains transparent items.
    OnlyTransparent,
    /// The string is not Bech32m encoded, and so cannot be a unified address.
    NotUnified,
    /// The Bech32m string has an unrecognized human-readable prefix.
    UnknownPrefix(String),
    /// A `MUST-understand` metadata item was not recognized.
    NotUnderstood(u32),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::BothP2phkAndP2sh => write!(f, "UA contains both P2PKH and P2SH items"),
            ParseError::DuplicateTypecode(c) => write!(f, "Duplicate typecode {}", u32::from(*c)),
            ParseError::InvalidTypecodeValue(v) => write!(f, "Typecode value out of range {}", v),
            ParseError::InvalidEncoding(msg) => write!(f, "Invalid encoding: {}", msg),
            ParseError::InvalidTypecodeOrder => write!(f, "Items are out of order."),
            ParseError::OnlyTransparent => write!(f, "UA only contains transparent items"),
            ParseError::NotUnified => write!(f, "Address is not Bech32m encoded"),
            ParseError::UnknownPrefix(s) => {
                write!(f, "Unrecognized Bech32m human-readable prefix: {}", s)
            }
            ParseError::NotUnderstood(tc) => {
                write!(
                    f,
                    "MUST-understand metadata item with typecode {} was not recognized; please upgrade.",
                    tc
                )
            }
        }
    }
}

impl Error for ParseError {}

pub(crate) mod private {
    use super::{DataTypecode, ParseError, Typecode, PADDING_LEN};
    use crate::{
        unified::{Item, MetadataItem},
        Network,
    };
    use std::{
        convert::{TryFrom, TryInto},
        io::Write,
    };
    use zcash_encoding::CompactSize;

    /// A raw address or viewing key.
    pub trait SealedDataItem: Clone {
        fn parse(tc: DataTypecode, value: &[u8]) -> Result<Self, ParseError>;
        fn typecode(&self) -> DataTypecode;
        fn data(&self) -> &[u8];
    }

    /// A Unified Container containing addresses or viewing keys.
    pub trait SealedContainer: super::Container + std::marker::Sized {
        const MAINNET: &'static str;
        const TESTNET: &'static str;
        const REGTEST: &'static str;

        /// Implementations of this method should act as unchecked constructors
        /// of the container type; the caller is guaranteed to check the
        /// general invariants that apply to all unified containers.
        fn from_inner(items: Vec<Item<Self::DataItem>>) -> Self;

        fn network_hrp(network: &Network) -> &'static str {
            match network {
                Network::Main => Self::MAINNET,
                Network::Test => Self::TESTNET,
                Network::Regtest => Self::REGTEST,
            }
        }

        fn hrp_network(hrp: &str) -> Option<Network> {
            if hrp == Self::MAINNET {
                Some(Network::Main)
            } else if hrp == Self::TESTNET {
                Some(Network::Test)
            } else if hrp == Self::REGTEST {
                Some(Network::Regtest)
            } else {
                None
            }
        }

        fn write_raw_encoding<W: Write>(&self, mut writer: W) {
            for item in self.items_as_parsed() {
                let data = item.data();
                CompactSize::write(
                    &mut writer,
                    <u32>::from(item.typecode()).try_into().unwrap(),
                )
                .unwrap();
                CompactSize::write(&mut writer, data.len()).unwrap();
                writer.write_all(&data).unwrap();
            }
        }

        /// Returns the jumbled padded raw encoding of this Unified Address or viewing key.
        fn to_jumbled_bytes(&self, hrp: &str) -> Vec<u8> {
            assert!(hrp.len() <= PADDING_LEN);

            let mut writer = std::io::Cursor::new(Vec::new());
            self.write_raw_encoding(&mut writer);

            let mut padding = [0u8; PADDING_LEN];
            padding[0..hrp.len()].copy_from_slice(hrp.as_bytes());
            writer.write_all(&padding).unwrap();

            let padded = writer.into_inner();
            f4jumble::f4jumble(&padded)
                .unwrap_or_else(|e| panic!("f4jumble failed on {:?}: {}", padded, e))
        }

        /// Parse the items of the unified container.
        fn parse_items<T: Into<Vec<u8>>>(
            hrp: &str,
            buf: T,
        ) -> Result<Vec<Item<Self::DataItem>>, ParseError> {
            fn read_receiver<R: SealedDataItem>(
                mut cursor: &mut std::io::Cursor<&[u8]>,
            ) -> Result<Item<R>, ParseError> {
                let typecode = CompactSize::read(&mut cursor)
                    .map(|v| u32::try_from(v).expect("CompactSize::read enforces MAX_SIZE limit"))
                    .map_err(|e| {
                        ParseError::InvalidEncoding(format!(
                            "Failed to deserialize CompactSize-encoded typecode {}",
                            e
                        ))
                    })?;
                let length = CompactSize::read(&mut cursor).map_err(|e| {
                    ParseError::InvalidEncoding(format!(
                        "Failed to deserialize CompactSize-encoded length {}",
                        e
                    ))
                })?;
                let addr_end = cursor.position().checked_add(length).ok_or_else(|| {
                    ParseError::InvalidEncoding(format!(
                        "Length value {} caused an overflow error",
                        length
                    ))
                })?;
                let buf = cursor.get_ref();
                if (buf.len() as u64) < addr_end {
                    return Err(ParseError::InvalidEncoding(format!(
                        "Truncated: unable to read {} bytes of item data",
                        length
                    )));
                }
                let data = &buf[cursor.position() as usize..addr_end as usize];
                let result = match Typecode::try_from(typecode)? {
                    Typecode::Data(tc) => Item::Data(R::parse(tc, data)?),
                    Typecode::Metadata(tc) => Item::Metadata(MetadataItem::parse(tc, data)?),
                };
                cursor.set_position(addr_end);
                Ok(result)
            }

            // Here we allocate if necessary to get a mutable Vec<u8> to unjumble.
            let mut encoded = buf.into();
            f4jumble::f4jumble_inv_mut(&mut encoded[..]).map_err(|e| {
                ParseError::InvalidEncoding(format!("F4Jumble decoding failed: {}", e))
            })?;

            // Validate and strip trailing padding bytes.
            if hrp.len() > 16 {
                return Err(ParseError::InvalidEncoding(
                    "Invalid human-readable part".to_owned(),
                ));
            }
            let mut expected_padding = [0; PADDING_LEN];
            expected_padding[0..hrp.len()].copy_from_slice(hrp.as_bytes());
            let encoded = match encoded.split_at(encoded.len() - PADDING_LEN) {
                (encoded, tail) if tail == expected_padding => Ok(encoded),
                _ => Err(ParseError::InvalidEncoding(
                    "Invalid padding bytes".to_owned(),
                )),
            }?;

            let mut cursor = std::io::Cursor::new(encoded);
            let mut result = vec![];
            while cursor.position() < encoded.len().try_into().unwrap() {
                result.push(read_receiver(&mut cursor)?);
            }
            assert_eq!(cursor.position(), encoded.len().try_into().unwrap());

            Ok(result)
        }

        /// A private function that constructs a unified container with the
        /// specified items, which must be in ascending typecode order.
        fn try_from_items_internal(items: Vec<Item<Self::DataItem>>) -> Result<Self, ParseError> {
            assert!(u32::from(Typecode::P2SH) == u32::from(Typecode::P2PKH) + 1);

            let mut only_transparent = true;
            let mut prev_code = None; // less than any Some
            for item in &items {
                let t = item.typecode();
                let t_code = Some(u32::from(t));
                if t_code < prev_code {
                    return Err(ParseError::InvalidTypecodeOrder);
                } else if t_code == prev_code {
                    return Err(ParseError::DuplicateTypecode(t));
                } else if t == Typecode::Data(DataTypecode::P2sh)
                    && prev_code == Some(u32::from(DataTypecode::P2pkh))
                {
                    // P2pkh and P2sh can only be in that order and next to each other,
                    // otherwise we would detect an out-of-order or duplicate typecode.
                    return Err(ParseError::BothP2phkAndP2sh);
                } else {
                    prev_code = t_code;
                    only_transparent = only_transparent && t.is_transparent_data_item();
                }
            }

            if only_transparent {
                Err(ParseError::OnlyTransparent)
            } else {
                // All checks pass!
                Ok(Self::from_inner(items))
            }
        }

        fn parse_internal<T: Into<Vec<u8>>>(hrp: &str, buf: T) -> Result<Self, ParseError> {
            Self::parse_items(hrp, buf).and_then(Self::try_from_items_internal)
        }
    }
}

use private::SealedDataItem;

/// Trait providing common encoding and decoding logic for Unified containers.
pub trait Encoding: private::SealedContainer {
    /// Constructs a value of a unified container type from a vector
    /// of container items, sorted according to typecode as specified
    /// in ZIP 316.
    ///
    /// This function will return an error in the case that the following ZIP 316
    /// invariants concerning the composition of a unified container are
    /// violated:
    /// * the item list may not contain two items having the same typecode
    /// * the item list may not contain only transparent items (or no items)
    /// * the item list may not contain both P2PKH and P2SH items.
    fn try_from_items(mut items: Vec<Item<Self::DataItem>>) -> Result<Self, ParseError> {
        items.sort_unstable_by(Item::encoding_order);
        Self::try_from_items_internal(items)
    }

    /// Decodes a unified container from its string representation, preserving
    /// the order of its components so that it correctly obeys round-trip
    /// serialization invariants.
    fn decode(s: &str) -> Result<(Network, Self), ParseError> {
        if let Ok((hrp, data, Variant::Bech32m)) = bech32::decode(s) {
            let hrp = hrp.as_str();
            // validate that the HRP corresponds to a known network.
            let net =
                Self::hrp_network(hrp).ok_or_else(|| ParseError::UnknownPrefix(hrp.to_string()))?;

            let data = Vec::<u8>::from_base32(&data)
                .map_err(|e| ParseError::InvalidEncoding(e.to_string()))?;

            Self::parse_internal(hrp, data).map(|value| (net, value))
        } else {
            Err(ParseError::NotUnified)
        }
    }

    /// Encodes the contents of the unified container to its string representation
    /// using the correct constants for the specified network, preserving the
    /// ordering of the contained items such that it correctly obeys round-trip
    /// serialization invariants.
    fn encode(&self, network: &Network) -> String {
        let hrp = Self::network_hrp(network);
        bech32::encode(
            hrp,
            self.to_jumbled_bytes(hrp).to_base32(),
            Variant::Bech32m,
        )
        .expect("hrp is invalid")
    }
}

/// Trait for for Unified containers, that exposes the items within them.
pub trait Container {
    /// The type of item in this unified container.
    type DataItem: SealedDataItem;

    /// Returns the items in the order they were parsed from the string encoding.
    ///
    /// This API is for advanced usage; in most cases you should use `Self::items`.
    fn items_as_parsed(&self) -> &[Item<Self::DataItem>];
}
