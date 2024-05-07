use std::net::SocketAddr;

use anyhow::anyhow;
use bytes::{Buf, BufMut, BytesMut};
use sha1::Digest;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufStream};
use tokio::net::TcpStream;

use crate::download::PieceState;
use crate::torrent_data::Sha1Hash;
use crate::BLOCK_SIZE;

pub struct Peer {
    pub addr: SocketAddr,
    pub connection: Option<Connection>,
}

pub struct Connection {
    pub peer_id: Sha1Hash,
    pub stream: BufStream<TcpStream>,
}

impl Peer {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            connection: None,
        }
    }
    pub async fn connect(&mut self, handshake: &HandShake) -> anyhow::Result<()> {
        let stream = TcpStream::connect(self.addr).await?;
        let mut stream = BufStream::new(stream);
        handshake.to_stream(&mut stream).await?;
        stream.flush().await?;

        let handshake_reply = HandShake::from_stream(&mut stream).await?;

        self.connection = Some(Connection {
            peer_id: handshake_reply.peer_id,
            stream,
        });

        Ok(())
    }

    pub async fn receive(&mut self, buf: &mut BytesMut) -> anyhow::Result<Message> {
        assert!(self.connection.is_some());
        let connection = self.connection.as_mut().unwrap();

        let message_length = connection.stream.read_u32().await? as usize;
        let message_id = connection.stream.read_u8().await?;

        buf.resize(message_length - 1, 0);
        connection.stream.read_exact(buf).await?;

        Ok(Message { id: message_id })
    }
    pub async fn send(&mut self, message: &Message, buf: &[u8]) -> anyhow::Result<()> {
        assert!(self.connection.is_some());
        let connection = self.connection.as_mut().unwrap();

        connection.stream.write_u32(buf.len() as u32 + 1).await?;
        connection.stream.write_u8(message.id).await?;
        connection.stream.write_all(&buf).await?;
        connection.stream.flush().await?;

        Ok(())
    }

    pub async fn prepare_download(&mut self, buf: &mut BytesMut) -> anyhow::Result<()> {
        let message = self.receive(buf).await?;
        if message.id != 5 {
            return Err(anyhow!("Expected bitfield message"));
        }
        println!(
            "Bitfield message received from: {}",
            self.connection.as_ref().unwrap().peer_id
        );

        let interested_message = Message::new(2);
        self.send(&interested_message, &[]).await?;
        let unchoke_message = self.receive(buf).await?;
        if unchoke_message.id != 1 {
            return Err(anyhow!("Expected unchoke message"));
        }
        println!(
            "Unchoke message received from {}",
            self.connection.as_ref().unwrap().peer_id
        );

        Ok(())
    }

    pub async fn download_piece(
        &mut self,
        piece: &PieceState,
        buf: &mut BytesMut,
    ) -> anyhow::Result<Vec<u8>> {
        assert!(self.connection.is_some());

        let mut piece_data = vec![0u8; piece.size];
        let mut downloaded = 0usize;

        while downloaded < piece.size {
            let offset = downloaded;
            let size = if offset + BLOCK_SIZE > piece.size {
                piece.size - offset
            } else {
                BLOCK_SIZE
            };

            buf.clear();
            buf.put_u32(piece.index as u32);
            buf.put_u32(offset as u32);
            buf.put_u32(size as u32);

            let request_msg = Message::new(6);
            self.send(&request_msg, &buf).await?;

            let piece_msg = self.receive(buf).await?;
            if piece_msg.id != 7 {
                return Err(anyhow!("Expected piece message"));
            }

            let received_piece_index = buf.get_u32() as usize;
            let received_offset = buf.get_u32() as usize;
            let received_size = buf.len();

            assert_eq!(received_piece_index, piece.index);
            assert_eq!(received_offset, offset);

            downloaded += received_size;
            piece_data[received_offset..received_offset + received_size].copy_from_slice(&buf[..]);

            println!(
                "Received piece: {} offset: {} bytes: {}",
                piece.index, offset, size,
            )
        }

        let calculated_hash: Sha1Hash = {
            let mut hasher = sha1::Sha1::new();
            hasher.update(&piece_data);
            hasher.finalize().into()
        };
        if piece.hash != calculated_hash {
            return Err(anyhow!("Piece hash mismatch"));
        }

        Ok(piece_data)
    }
}

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

pub struct Message {
    pub id: u8,
}

impl Message {
    pub fn new(id: u8) -> Self {
        Self { id }
    }
}
