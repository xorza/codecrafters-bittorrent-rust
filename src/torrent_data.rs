use std::fmt::Display;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha1::digest::Output;
use sha1::{Digest, Sha1};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sha1Hash([u8; 20]);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorrentInfo {
    pub length: usize,
    pub name: String,
    #[serde(rename = "piece length")]
    pub piece_size: usize,
    #[serde(
        deserialize_with = "list_of_hashes::deserialize",
        serialize_with = "list_of_hashes::serialize"
    )]
    pub pieces: Vec<Sha1Hash>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorrentFile {
    pub announce: String,
    #[serde(rename = "created by", default = "String::new")]
    pub created_by: String,
    pub info: TorrentInfo,
}

impl TorrentFile {
    pub fn from_file(filename: &str) -> Result<TorrentFile, Box<dyn std::error::Error>> {
        let bytes = std::fs::read(filename)?;
        let torrent_file: TorrentFile = serde_bencode::from_bytes(&bytes)?;

        Ok(torrent_file)
    }

    pub fn to_pretty_string(&self) -> String {
        serde_json::to_string_pretty(&list_of_hashes::TorrentFileWrap(self)).unwrap()
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

impl From<&[u8]> for Sha1Hash {
    fn from(value: &[u8]) -> Self {
        let mut array = [0; 20];
        array.copy_from_slice(value);
        Sha1Hash(array)
    }
}

impl From<Output<Sha1>> for Sha1Hash {
    fn from(value: Output<Sha1>) -> Self {
        let mut array = [0; 20];
        array.copy_from_slice(&value[..]);

        Sha1Hash(array)
    }
}

impl FromStr for Sha1Hash {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)?;
        let mut array = [0; 20];
        array.copy_from_slice(&bytes);

        Ok(Sha1Hash(array))
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
    pub fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

mod list_of_hashes {
    use std::fmt;

    use serde::de::{Error, SeqAccess, Visitor};
    use serde::ser::SerializeStruct;
    use serde::{Deserializer, Serialize};

    use super::*;

    struct ListOfHashesVisitor;

    impl<'de> Visitor<'de> for ListOfHashesVisitor {
        type Value = Vec<Sha1Hash>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("sdfgsdfg")
        }

        fn visit_str<E>(self, _v: &str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            panic!("visit_str")
        }
        fn visit_string<E>(self, _v: String) -> Result<Self::Value, E>
        where
            E: Error,
        {
            panic!("visit_string")
        }
        fn visit_bytes<E>(self, v: &[u8]) -> Result<Vec<Sha1Hash>, E>
        where
            E: serde::de::Error,
        {
            let result: Vec<Sha1Hash> = v
                .chunks(20)
                .map(|chunk| {
                    let mut array = [0; 20];
                    array.copy_from_slice(chunk);
                    Sha1Hash(array)
                })
                .collect();

            Ok(result)
        }
        fn visit_seq<A>(self, mut seq: A) -> Result<Vec<Sha1Hash>, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut hashes = Vec::new();
            while let Some(hash) = seq.next_element::<String>()? {
                hashes.push(Sha1Hash::from_str(&hash).map_err(A::Error::custom)?);
            }

            Ok(hashes)
        }
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Sha1Hash>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(ListOfHashesVisitor)
    }

    pub(crate) fn serialize<S>(value: &Vec<Sha1Hash>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // let string = value.iter()
        //     .map(|hash| hash.to_string())
        //     .collect::<Vec<String>>()
        //     .join(" ");
        //
        // serializer.serialize_str(string.as_str())

        let mut bytes: Vec<u8> = Vec::new();
        for hash in value {
            bytes.extend_from_slice(&hash.0);
        }

        serializer.serialize_bytes(&bytes)
    }

    pub(super) struct TorrentFileWrap<'a>(pub &'a TorrentFile);

    pub(super) struct TorrentInfoWrap<'a>(&'a TorrentInfo);

    pub(super) struct HashVecWrap<'a>(&'a Vec<Sha1Hash>);

    impl<'a> Serialize for TorrentFileWrap<'a> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut state = serializer.serialize_struct("TorrentFile", 3)?;
            state.serialize_field("announce", &self.0.announce)?;
            state.serialize_field("created by", &self.0.created_by)?;
            state.serialize_field("info", &TorrentInfoWrap(&self.0.info))?;
            state.end()
        }
    }

    impl<'a> Serialize for TorrentInfoWrap<'a> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut state = serializer.serialize_struct("TorrentInfo", 4)?;
            state.serialize_field("length", &self.0.length)?;
            state.serialize_field("name", &self.0.name)?;
            state.serialize_field("piece length", &self.0.piece_size)?;
            state.serialize_field("pieces", &HashVecWrap(&self.0.pieces))?;
            state.end()
        }
    }

    impl<'a> Serialize for HashVecWrap<'a> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.collect_seq(self.0.iter().map(|hash| hash.to_string()))
        }
    }
}
