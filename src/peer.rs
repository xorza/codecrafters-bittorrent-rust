use std::mem::size_of;

use anyhow::anyhow;
use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

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

    pub fn write<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(self.protocol.len() as u8);
        buf.put_slice(self.protocol.as_bytes());
        buf.put_slice(&self.reserved);
        buf.put_slice(self.info_hash.as_slice());
        buf.put_slice(self.peer_id.as_slice());
    }

    pub async fn read_async<S>(stream: &mut S, buf: &mut BytesMut) -> anyhow::Result<HandShake>
    where
        S: AsyncRead + Unpin,
    {
        let proto_str_len = stream.read_u8().await? as usize;

        let total_size = proto_str_len
            + 8 //reserved
            + size_of::<Sha1Hash>() //info_hash
            + size_of::<Sha1Hash>(); //peer_id
        buf.resize(total_size, 0u8);
        stream.read_exact(buf.as_mut()).await?;

        let proto_name_str = String::from_utf8(buf.copy_to_bytes(proto_str_len).to_vec())?;
        if proto_name_str != "BitTorrent protocol" {
            return Err(anyhow!("Invalid protocol name"));
        }

        let mut result = HandShake::default();
        result.protocol = proto_name_str;
        buf.copy_to_slice(&mut result.reserved);
        buf.copy_to_slice(result.info_hash.as_mut());
        buf.copy_to_slice(result.peer_id.as_mut());

        Ok(result)
    }
}
