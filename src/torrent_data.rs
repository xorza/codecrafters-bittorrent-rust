
use serde::{Deserialize, Serialize};
use crate::utils::get_bytes_sha1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorrentInfo {
    pub length: u32,
    pub name: String,
    #[serde(rename = "piece length")]
    pub piece_length: u32,
    #[serde(deserialize_with = "hash_array::deserialize_hash_array", serialize_with = "hash_array::serialize_hash_array")]
    pub pieces: Vec<[u8; 20]>,
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
    pub fn get_sha1(&self) -> [u8; 20] {
        let bytes = serde_bencode::to_bytes(self).unwrap();

        get_bytes_sha1(&bytes)
    }
}


mod hash_array {
    use std::fmt;
    use serde::de::Visitor;
    use serde::Deserializer;

    struct HashArrayVisitor;

    impl<'de> Visitor<'de> for HashArrayVisitor {
        type Value = Vec<[u8; 20]>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("sdfgsdfg")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
        {
            let result: Self::Value = v.chunks(20)
                .map(|chunk| {
                    let mut array = [0; 20];
                    array.copy_from_slice(chunk);
                    array
                })
                .collect();

            Ok(result)
        }
    }

    pub(crate) fn deserialize_hash_array<'de, D>(deserializer: D) -> Result<Vec<[u8; 20]>, D::Error>
        where
            D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(HashArrayVisitor)
    }

    pub(crate) fn serialize_hash_array<S>(value: &Vec<[u8; 20]>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
    {
        let mut bytes: Vec<u8> = Vec::new();
        for hash in value {
            bytes.extend_from_slice(hash);
        }

        serializer.serialize_bytes(&bytes)
    }
}