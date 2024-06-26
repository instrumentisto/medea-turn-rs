//! [`ChannelData`] message implementation.

use crate::{attr::ChannelNumber, Error};

/// [`ChannelData`] message MUST be padded to a multiple of four bytes in order
/// to ensure the alignment of subsequent messages.
const PADDING: usize = 4;

/// [Channel Number] field size.
///
/// [Channel Number]: https://datatracker.ietf.org/doc/html/rfc5766#section-11.4
const CHANNEL_DATA_NUMBER_SIZE: usize = 2;

/// [Length] field size.
///
/// [Length]: https://datatracker.ietf.org/doc/html/rfc5766#section-11.4
const CHANNEL_DATA_LENGTH_SIZE: usize = 2;

/// [ChannelData] message header size.
///
/// [ChannelData]: https://datatracker.ietf.org/doc/html/rfc5766#section-11.4
const CHANNEL_DATA_HEADER_SIZE: usize =
    CHANNEL_DATA_LENGTH_SIZE + CHANNEL_DATA_NUMBER_SIZE;

/// [`ChannelData`] represents the `ChannelData` Message defined in
/// [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766#section-11.4).
#[derive(Debug)]
pub(crate) struct ChannelData {
    /// Parsed [`ChannelData`] [Channel Number][1].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc5766#section-11.4
    number: u16,

    /// Parsed [`ChannelData`] payload.
    data: Vec<u8>,
}

impl ChannelData {
    /// Returns `true` if `buf` looks like the `ChannelData` Message.
    #[allow(clippy::missing_asserts_for_indexing)] // Length is checked
    pub(crate) fn is_channel_data(buf: &[u8]) -> bool {
        if buf.len() < CHANNEL_DATA_HEADER_SIZE {
            return false;
        }
        let len = usize::from(u16::from_be_bytes([
            buf[CHANNEL_DATA_NUMBER_SIZE],
            buf[CHANNEL_DATA_NUMBER_SIZE + 1],
        ]));

        if len > buf[CHANNEL_DATA_HEADER_SIZE..].len() {
            return false;
        }

        ChannelNumber::new(u16::from_be_bytes([buf[0], buf[1]])).is_ok()
    }

    /// Decodes the given raw message as [`ChannelData`].
    pub(crate) fn decode(mut raw: Vec<u8>) -> Result<Self, Error> {
        if raw.len() < CHANNEL_DATA_HEADER_SIZE {
            return Err(Error::UnexpectedEof);
        }

        let number = u16::from_be_bytes([raw[0], raw[1]]);
        if ChannelNumber::new(number).is_err() {
            return Err(Error::InvalidChannelNumber);
        }

        let l = usize::from(u16::from_be_bytes([
            raw[CHANNEL_DATA_NUMBER_SIZE],
            raw[CHANNEL_DATA_NUMBER_SIZE + 1],
        ]));

        if l > raw[CHANNEL_DATA_HEADER_SIZE..].len() {
            return Err(Error::BadChannelDataLength);
        }

        // Discard header and padding.
        drop(raw.drain(0..CHANNEL_DATA_HEADER_SIZE));
        if l != raw.len() {
            raw.truncate(l);
        }

        Ok(Self { data: raw, number })
    }

    /// Returns [`ChannelData`] [Channel Number][1].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc5766#section-11.4
    pub(crate) const fn num(&self) -> u16 {
        self.number
    }

    /// Encodes the provided [`ChannelData`] payload and channel number to
    /// bytes.
    pub(crate) fn encode(
        mut data: Vec<u8>,
        chan_num: u16,
    ) -> Result<Vec<u8>, Error> {
        #[allow(clippy::map_err_ignore)]
        let len = u16::try_from(data.len())
            .map_err(|_| Error::BadChannelDataLength)?;
        for i in len.to_be_bytes().into_iter().rev() {
            data.insert(0, i);
        }
        for i in chan_num.to_be_bytes().into_iter().rev() {
            data.insert(0, i);
        }

        let padded = nearest_padded_value_length(data.len());
        let bytes_to_add = padded - data.len();
        if bytes_to_add > 0 {
            data.extend_from_slice(&vec![0; bytes_to_add]);
        }

        Ok(data)
    }

    /// Returns [`ChannelData`] payload.
    pub(crate) fn data(self) -> Vec<u8> {
        self.data
    }
}

/// Calculates nearest padded length for the [`ChannelData`].
pub(crate) const fn nearest_padded_value_length(l: usize) -> usize {
    let mut n = PADDING * (l / PADDING);
    if n < l {
        n += PADDING;
    }
    n
}

#[cfg(test)]
mod chandata_test {
    use super::*;

    #[test]
    fn test_channel_data_encode() {
        let encoded =
            ChannelData::encode(vec![1, 2, 3, 4], ChannelNumber::MIN + 1)
                .unwrap();
        let decoded = ChannelData::decode(encoded.clone()).unwrap();

        assert!(
            ChannelData::is_channel_data(&encoded),
            "unexpected IsChannelData"
        );

        assert_eq!(vec![1, 2, 3, 4], decoded.data, "not equal");
        assert_eq!(ChannelNumber::MIN + 1, decoded.number, "not equal");
    }

    #[test]
    fn test_channel_data_equal() {
        let tests = vec![
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
            let v = ChannelData::encode(a.data.clone(), a.number)
                == ChannelData::encode(b.data.clone(), b.number);
            assert_eq!(v, r, "unexpected: ({name}) {r} != {r}");
        }
    }

    #[test]
    fn test_channel_data_decode() {
        let tests = vec![
            ("small", vec![1, 2, 3], Error::UnexpectedEof),
            (
                "zeroes",
                vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                Error::InvalidChannelNumber,
            ),
            (
                "bad chan number",
                vec![63, 255, 0, 0, 0, 4, 0, 0, 1, 2, 3, 4],
                Error::InvalidChannelNumber,
            ),
            (
                "bad length",
                vec![0x40, 0x40, 0x02, 0x23, 0x16, 0, 0, 0, 0, 0, 0, 0],
                Error::BadChannelDataLength,
            ),
        ];

        for (name, buf, want_err) in tests {
            if let Err(err) = ChannelData::decode(buf) {
                assert_eq!(
                    want_err, err,
                    "unexpected: ({name}) {want_err} != {err}"
                );
            } else {
                panic!("expected error, but got ok");
            }
        }
    }

    #[test]
    fn test_is_channel_data() {
        let tests = vec![
            ("small", vec![1, 2, 3, 4], false),
            ("zeroes", vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], false),
        ];

        for (name, buf, r) in tests {
            let v = ChannelData::is_channel_data(&buf);
            assert_eq!(v, r, "unexpected: ({name}) {r} != {v}");
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
    fn test_chrome_channel_data() {
        let mut data = vec![];
        let mut messages = vec![];

        // Decoding hex data into binary.
        for h in &CHANDATA_TEST_HEX {
            let b = match hex::decode(h) {
                Ok(b) => b,
                Err(_) => panic!("hex decode error"),
            };
            data.push(b);
        }

        // All hex streams decoded to raw binary format and stored in data
        // slice. Decoding packets to messages.
        for packet in data {
            let m = ChannelData::decode(packet.clone()).unwrap();

            let encoded =
                ChannelData::encode(m.data.clone(), m.number).unwrap();
            let decoded = ChannelData::decode(encoded.clone()).unwrap();

            assert_eq!(m.data, decoded.data, "should be equal");
            assert_eq!(m.number, decoded.number, "should be equal");

            messages.push(m);
        }

        assert_eq!(messages.len(), 2, "unexpected message slice list");
    }
}
