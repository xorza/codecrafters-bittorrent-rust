use std::fmt::Display;

use serde::{Deserialize, Serialize};
use sha1::digest::Output;
use sha1::{Digest, Sha1};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Sha1Hash([u8; 20]);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorrentInfo {
    pub length: u32,
    pub name: String,
    #[serde(rename = "piece length")]
    pub piece_length: u32,
    #[serde(
        deserialize_with = "list_of_hashes::deserialize",
        serialize_with = "list_of_hashes::serialize"
    )]
    pub pieces: Vec<Sha1Hash>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorrentFile {
    pub announce: String,
    #[serde(rename = "created by")]
    pub created_by: String,
    pub info: TorrentInfo,
}

impl TorrentFile {
    pub fn from_file(filename: &str) -> Result<TorrentFile, Box<dyn std::error::Error>> {
        let bytes = std::fs::read(filename)?;
        let torrent_file: TorrentFile = serde_bencode::from_bytes(&bytes)?;

        Ok(torrent_file)
    }
}

impl TorrentInfo {
    pub fn get_sha1(&self) -> Sha1Hash {
        let bytes = serde_bencode::to_bytes(self).unwrap();

        let mut hasher = Sha1::new();
        hasher.update(bytes);
        hasher.finalize().into()
    }
}

impl From<[u8; 20]> for Sha1Hash {
    fn from(value: [u8; 20]) -> Self {
        Sha1Hash(value)
    }
}

impl From<Output<Sha1>> for Sha1Hash {
    fn from(value: Output<Sha1>) -> Self {
        let mut array = [0; 20];
        array.copy_from_slice(&value[..]);
        Sha1Hash(array)
    }
}

impl Display for Sha1Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl Sha1Hash {
    pub fn iter(&self) -> std::slice::Iter<'_, u8> {
        self.0.iter()
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

mod list_of_hashes {
    use std::fmt;

    use serde::de::Visitor;
    use serde::Deserializer;

    use crate::torrent_data::Sha1Hash;

    struct ListOfArraysVisitor;

    impl<'de> Visitor<'de> for ListOfArraysVisitor {
        type Value = Vec<Sha1Hash>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("sdfgsdfg")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            let result: Self::Value = v
                .chunks(20)
                .map(|chunk| {
                    let mut array = [0; 20];
                    array.copy_from_slice(chunk);
                    Sha1Hash(array)
                })
                .collect();

            Ok(result)
        }
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Sha1Hash>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(ListOfArraysVisitor)
    }

    pub(crate) fn serialize<S>(value: &Vec<Sha1Hash>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes: Vec<u8> = Vec::new();
        for hash in value {
            bytes.extend_from_slice(&hash.0);
        }

        serializer.serialize_bytes(&bytes)
    }
}
