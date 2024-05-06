use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::torrent_data::{Sha1Hash, TorrentFile};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackerResponse {
    pub interval: u32,
    #[serde(
        deserialize_with = "list_of_ip_addr::deserialize",
        serialize_with = "list_of_ip_addr::serialize"
    )]
    pub peers: Vec<(Ipv4Addr, u16)>,
}

pub struct TrackerRequest {
    pub info_hash: Sha1Hash,
    pub peer_id: Sha1Hash,
    pub port: u16,
    pub uploaded: u64,
    pub downloaded: u64,
    pub left: u64,
}

impl From<TorrentFile> for TrackerRequest {
    fn from(value: TorrentFile) -> Self {
        let info_hash = value.info.get_sha1();
        let peer_id = Sha1Hash::default();
        let port = 6881;
        let uploaded = 0;
        let downloaded = 0;
        let left = value.info.length as u64;

        TrackerRequest {
            info_hash,
            peer_id,
            port,
            uploaded,
            downloaded,
            left,
        }
    }
}

pub async fn send_request(
    request: TrackerRequest,
    announce: &str,
) -> Result<TrackerResponse, Box<dyn std::error::Error>> {
    let info_hash_url = request
        .info_hash
        .iter()
        .map(|b| format!("%{:02x}", b))
        .collect::<String>();

    let request_url = format!(
        "{}?info_hash={}&{}",
        announce,
        info_hash_url,
        serde_urlencoded::to_string(&[
            ("peer_id", request.peer_id.to_string().as_str()),
            ("port", request.port.to_string().as_str()),
            ("uploaded", request.uploaded.to_string().as_str()),
            ("downloaded", request.downloaded.to_string().as_str()),
            ("left", request.left.to_string().as_str()),
            ("compact", "1"),
        ])?
    );

    let client = reqwest::Client::new();
    let response = client.get(request_url).send().await?;

    let response_bytes = response.bytes().await?;
    let response: TrackerResponse = serde_bencode::from_bytes(&response_bytes)?;

    Ok(response)
}

mod list_of_ip_addr {
    use std::fmt;
    use std::net::Ipv4Addr;

    use serde::de::Visitor;
    use serde::Deserializer;

    struct ListOfAddrVisitor;

    impl<'de> Visitor<'de> for ListOfAddrVisitor {
        type Value = Vec<(Ipv4Addr, u16)>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("sdfgsdfg")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            let result: Self::Value = v
                .chunks(6)
                .map(|chunk| {
                    let mut ip_bytes = [0u8; 4];
                    ip_bytes.copy_from_slice(&chunk[0..4]);

                    let port = u16::from_be_bytes([chunk[4], chunk[5]]);

                    (Ipv4Addr::from(ip_bytes), port)
                })
                .collect();

            Ok(result)
        }
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<(Ipv4Addr, u16)>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(ListOfAddrVisitor)
    }

    pub(crate) fn serialize<S>(
        value: &Vec<(Ipv4Addr, u16)>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes: Vec<u8> = Vec::new();
        for arr in value {
            let ip_bytes = arr.0.octets();
            bytes.extend_from_slice(&ip_bytes);
            bytes.extend_from_slice(&arr.1.to_be_bytes());
        }

        serializer.serialize_bytes(&bytes)
    }
}
