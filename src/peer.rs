use anyhow::anyhow;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::torrent_data::Sha1Hash;

#[derive(Debug, Clone, Default)]
pub struct HandShake {
    pub protocol: String,
    pub reserved: [u8; 8],
    pub info_hash: Sha1Hash,
    pub peer_id: Sha1Hash,
}

impl HandShake {
    pub fn new(info_hash: Sha1Hash, peer_id: Sha1Hash) -> Self {
        Self {
            protocol: "BitTorrent protocol".to_string(),
            reserved: [0; 8],
            info_hash,
            peer_id,
        }
    }

    pub async fn to_stream<S: AsyncWrite + Unpin>(&self, stream: &mut S) -> anyhow::Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        stream.write_u8(self.protocol.len() as u8).await?;
        stream.write_all(self.protocol.as_bytes()).await?;
        stream.write_all(&self.reserved).await?;
        stream.write_all(self.info_hash.as_slice()).await?;
        stream.write_all(self.peer_id.as_slice()).await?;

        Ok(())
    }

    pub async fn from_stream<S>(stream: &mut S) -> anyhow::Result<HandShake>
    where
        S: AsyncRead + Unpin,
    {
        let proto_str_len = stream.read_u8().await? as usize;
        let protocol = {
            let mut buf = vec![0; proto_str_len];
            stream.read_exact(&mut buf).await?;

            String::from_utf8(buf)?
        };

        if protocol != "BitTorrent protocol" {
            return Err(anyhow!("Invalid protocol name"));
        }

        let mut result = HandShake::default();
        result.protocol = protocol;
        stream.read_exact(&mut result.reserved).await?;
        stream.read_exact(result.info_hash.as_mut()).await?;
        stream.read_exact(result.peer_id.as_mut()).await?;

        Ok(result)
    }
}
