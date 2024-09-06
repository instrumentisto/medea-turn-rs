//! [TURN ChannelData Message][1] implementation.
//!
//! [1]: https://tools.ietf.org/html/rfc5766#section-11.4

use derive_more::{Display, Error};

use crate::attr::ChannelNumber;

/// [`ChannelData`] message MUST be padded to a multiple of four bytes in order
/// to ensure the alignment of subsequent messages.
const PADDING: usize = 4;

/// [Channel Number] field size.
///
/// [Channel Number]: https://tools.ietf.org/html/rfc5766#section-11.4
const NUMBER_SIZE: usize = 2;

/// [Length] field size.
///
/// [Length]: https://tools.ietf.org/html/rfc5766#section-11.4
const LENGTH_SIZE: usize = 2;

/// [ChannelData Message][1] header size.
///
/// [1]: https://tools.ietf.org/html/rfc5766#section-11.4
const HEADER_SIZE: usize = LENGTH_SIZE + NUMBER_SIZE;

/// Representation of [TURN ChannelData Message][1] defined in [RFC 5766].
///
/// [1]: https://tools.ietf.org/html/rfc5766#section-11.4
/// [RFC 5766]: https://tools.ietf.org/html/rfc5766
#[derive(Debug)]
pub struct ChannelData {
    /// Parsed [Channel Number][1].
    ///
    /// [1]: https://tools.ietf.org/html/rfc5766#section-11.4
    number: u16,

    /// Parsed payload.
    data: Vec<u8>,
}

impl ChannelData {
    /// Checks whether the provided `data` represents a [`ChannelData`] message.
    #[expect( // false positive
        clippy::missing_asserts_for_indexing,
        reason = "length is checked with the first `if` expression",
    )]
    pub(crate) fn is_channel_data(data: &[u8]) -> bool {
        if data.len() < HEADER_SIZE {
            return false;
        }
        let len = usize::from(u16::from_be_bytes([
            data[NUMBER_SIZE],
            data[NUMBER_SIZE + 1],
        ]));

        if len > data[HEADER_SIZE..].len() {
            return false;
        }

        ChannelNumber::new(u16::from_be_bytes([data[0], data[1]])).is_ok()
    }

    /// Decodes the provided `raw` message as a [`ChannelData`] message.
    ///
    /// # Errors
    ///
    /// See the [`FormatError`] for details.
    pub(crate) fn decode(mut raw: Vec<u8>) -> Result<Self, FormatError> {
        if raw.len() < HEADER_SIZE {
            return Err(FormatError::BadChannelDataLength);
        }

        let number = u16::from_be_bytes([raw[0], raw[1]]);
        if ChannelNumber::new(number).is_err() {
            return Err(FormatError::InvalidChannelNumber);
        }

        let l = usize::from(u16::from_be_bytes([
            raw[NUMBER_SIZE],
            raw[NUMBER_SIZE + 1],
        ]));

        if l > raw[HEADER_SIZE..].len() {
            return Err(FormatError::BadChannelDataLength);
        }

        // Discard header and padding.
        drop(raw.drain(0..HEADER_SIZE));
        if l != raw.len() {
            raw.truncate(l);
        }

        Ok(Self { data: raw, number })
    }

    /// Returns payload of this [`ChannelData`] message.
    pub(crate) fn data(self) -> Vec<u8> {
        self.data
    }

    /// Returns [Channel Number][1] of this [`ChannelData`] message.
    ///
    /// [1]: https://tools.ietf.org/html/rfc5766#section-11.4
    pub(crate) const fn num(&self) -> u16 {
        self.number
    }

    /// Encodes the provided `payload` and [Channel Number][1] as
    /// [`ChannelData`] message bytes.
    ///
    /// [1]: https://tools.ietf.org/html/rfc5766#section-11.4
    pub(crate) fn encode(
        payload: &[u8],
        chan_num: u16,
    ) -> Result<Vec<u8>, FormatError> {
        let length = HEADER_SIZE + payload.len();
        let padded_length = nearest_padded_value_length(length);

        #[expect(clippy::map_err_ignore, reason = "useless")]
        let len = u16::try_from(payload.len())
            .map_err(|_| FormatError::BadChannelDataLength)?;

        let mut encoded = vec![0u8; padded_length];

        encoded[..NUMBER_SIZE].copy_from_slice(&chan_num.to_be_bytes());
        encoded[NUMBER_SIZE..HEADER_SIZE].copy_from_slice(&len.to_be_bytes());
        encoded[HEADER_SIZE..length].copy_from_slice(payload);

        Ok(encoded)
    }
}

/// Calculates a nearest padded length for a [`ChannelData`] message.
pub(crate) const fn nearest_padded_value_length(l: usize) -> usize {
    let mut n = PADDING * (l / PADDING);
    if n < l {
        n += PADDING;
    }
    n
}

/// Possible errors of a [`ChannelData`] message format.
#[derive(Clone, Copy, Debug, Display, Error, Eq, PartialEq)]
pub enum FormatError {
    /// [Channel Number][1] is incorrect.
    ///
    /// [1]: https://tools.ietf.org/html/rfc5766#section-11.4
    #[display("Channel Number not in [0x4000, 0x7FFF]")]
    InvalidChannelNumber,

    /// Incorrect message length.
    #[display("Invalid `ChannelData` length")]
    BadChannelDataLength,
}

#[cfg(test)]
mod spec {
    use crate::attr::ChannelNumber;

    use super::{ChannelData, FormatError};

    #[test]
    fn encodes() {
        let encoded =
            ChannelData::encode(&[1, 2, 3, 4], ChannelNumber::MIN + 1).unwrap();
        let decoded = ChannelData::decode(encoded.clone()).unwrap();

        assert!(
            ChannelData::is_channel_data(&encoded),
            "wrong `is_channel_data`",
        );
        assert_eq!(vec![1, 2, 3, 4], decoded.data, "wrong decoded data");
        assert_eq!(ChannelNumber::MIN + 1, decoded.number, "wrong number");
    }

    #[test]
    fn encoded_equality() {
        let tests = [
            (
                "equal",
                ChannelData { number: ChannelNumber::MIN, data: vec![1, 2, 3] },
                ChannelData { number: ChannelNumber::MIN, data: vec![1, 2, 3] },
                true,
            ),
            (
                "number",
                ChannelData {
                    number: ChannelNumber::MIN + 1,
                    data: vec![1, 2, 3],
                },
                ChannelData { number: ChannelNumber::MIN, data: vec![1, 2, 3] },
                false,
            ),
            (
                "length",
                ChannelData {
                    number: ChannelNumber::MIN,
                    data: vec![1, 2, 3, 4],
                },
                ChannelData { number: ChannelNumber::MIN, data: vec![1, 2, 3] },
                false,
            ),
            (
                "data",
                ChannelData { number: ChannelNumber::MIN, data: vec![1, 2, 2] },
                ChannelData { number: ChannelNumber::MIN, data: vec![1, 2, 3] },
                false,
            ),
        ];

        for (name, a, b, r) in tests {
            let v = ChannelData::encode(&a.data, a.number)
                == ChannelData::encode(&b.data, b.number);

            assert_eq!(v, r, "wrong equality of {name}");
        }
    }

    #[test]
    fn fails_decoding_correctly() {
        let tests = [
            ("small", vec![1, 2, 3], FormatError::BadChannelDataLength),
            (
                "zeroes",
                vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                FormatError::InvalidChannelNumber,
            ),
            (
                "bad chan number",
                vec![63, 255, 0, 0, 0, 4, 0, 0, 1, 2, 3, 4],
                FormatError::InvalidChannelNumber,
            ),
            (
                "bad length",
                vec![0x40, 0x40, 0x02, 0x23, 0x16, 0, 0, 0, 0, 0, 0, 0],
                FormatError::BadChannelDataLength,
            ),
        ];
        for (name, buf, want_err) in tests {
            if let Err(e) = ChannelData::decode(buf) {
                assert_eq!(want_err, e, "wrong error of {name}");
            } else {
                panic!("expected `Err`, but got `Ok` in {name}");
            }
        }
    }

    #[test]
    fn is_channel_data_detects_correctly() {
        let tests = [
            ("small", vec![1, 2, 3, 4], false),
            ("zeroes", vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], false),
        ];
        for (name, buf, r) in tests {
            let v = ChannelData::is_channel_data(&buf);

            assert_eq!(v, r, "wrong result in {name}");
        }
    }

    const CHANDATA_TEST_HEX: [&str; 2] = [
        "40000064000100502112a442453731722f2b322b6e4e7a5800060009443758343a3377\
         6c59000000c0570004000003e7802a00081d5136dab65b169300250000002400046e00\
         1eff0008001465d11a330e104a9f5f598af4abc6a805f26003cf802800046b334442",
        "4000022316fefd0000000000000011012c0b000120000100000000012000011d00011a\
         308201163081bda003020102020900afe52871340bd13e300a06082a8648ce3d040302\
         3011310f300d06035504030c06576562525443301e170d313830383131303335323030\
         5a170d3138303931313033353230305a3011310f300d06035504030c06576562525443\
         3059301306072a8648ce3d020106082a8648ce3d030107034200048080e348bd41469c\
         fb7a7df316676fd72a06211765a50a0f0b07526c872dcf80093ed5caa3f5a40a725dd7\
         4b41b79bdd19ee630c5313c8601d6983286c8722c1300a06082a8648ce3d0403020348\
         003045022100d13a0a131bc2a9f27abd3d4c547f7ef172996a0c0755c707b6a3e048d8\
         762ded0220055fc8182818a644a3d3b5b157304cc3f1421fadb06263bfb451cd28be4b\
         c9ee16fefd0000000000000012002d10000021000200000000002120f7e23c97df45a9\
         6e13cb3e76b37eff5e73e2aee0b6415d29443d0bd24f578b7e16fefd00000000000000\
         1300580f00004c000300000000004c040300483046022100fdbb74eab1aca1532e6ac0\
         ab267d5b83a24bb4d5d7d504936e2785e6e388b2bd022100f6a457b9edd9ead52a9d0e\
         9a19240b3a68b95699546c044f863cf8349bc8046214fefd0000000000000014000101\
         16fefd0001000000000004003000010000000000040aae2421e7d549632a7def8ed068\
         98c3c5b53f5b812a963a39ab6cdd303b79bdb237f3314c1da21b",
    ];

    #[test]
    fn chrome_channel_data() {
        let mut data = vec![];
        let mut messages = vec![];

        // Decoding HEX data into binary.
        for h in &CHANDATA_TEST_HEX {
            let b = match hex::decode(h) {
                Ok(b) => b,
                Err(_) => panic!("hex decode error"),
            };
            data.push(b);
        }

        // All HEX streams decoded to raw binary format and stored in the `data`
        // slice. Decoding packets to messages.
        for packet in data {
            let m = ChannelData::decode(packet.clone()).unwrap();

            let encoded = ChannelData::encode(&m.data, m.number).unwrap();
            let decoded = ChannelData::decode(encoded.clone()).unwrap();

            assert_eq!(m.data, decoded.data, "wrong payload");
            assert_eq!(m.number, decoded.number, "wrong number");

            messages.push(m);
        }

        assert_eq!(messages.len(), 2, "wrong number of messages");
    }
}
