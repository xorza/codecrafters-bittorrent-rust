use std::io::SeekFrom;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::anyhow;
use bytes::BytesMut;
use sha1::Digest;
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt, BufStream};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::torrent_data::{Sha1Hash, TorrentFile};

pub struct Peer {
    pub peer_id: Sha1Hash,
    pub addr: SocketAddr,
    pub stream: BufStream<TcpStream>,
}

impl Peer {
    pub async fn connect(addr: &SocketAddr, handshake: &HandShake) -> anyhow::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        let mut stream = BufStream::new(stream);

        handshake.to_stream(&mut stream).await?;
        stream.flush().await?;
        let handshake_reply = HandShake::from_stream(&mut stream).await?;

        Ok(Self {
            peer_id: handshake_reply.peer_id,
            addr: addr.clone(),
            stream,
        })
    }
    pub async fn receive(&mut self, buf: &mut BytesMut) -> anyhow::Result<Message> {
        let message_length = self.stream.read_u32().await? as usize;
        let message_id = self.stream.read_u8().await?;

        buf.resize(message_length - 1, 0);
        self.stream.read_exact(buf).await?;

        Ok(Message { id: message_id })
    }
    pub async fn send(&mut self, message: &Message, buf: &[u8]) -> anyhow::Result<()> {
        self.stream.write_u32(buf.len() as u32 + 1).await?;
        self.stream.write_u8(message.id).await?;
        self.stream.write_all(&buf).await?;
        self.stream.flush().await?;

        Ok(())
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

#[derive(Debug)]
pub struct PieceState {
    pub hash: Sha1Hash,
    pub done: bool,
    pub blocks: Vec<bool>,
    pub size: usize,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct DownloadState {
    pub block_size: usize,
    pub piece_size: usize,
    pub pieces: Vec<PieceState>,
    pub done: bool,

    pub output_filename: String,
    pub output_file: Option<File>,
}

#[derive(Clone)]
pub struct SharedDownloadState(Arc<Mutex<DownloadState>>);

impl SharedDownloadState {
    pub fn new(torrent_file: TorrentFile, output_filename: String, block_size: usize) -> Self {
        let block_count = {
            let count = torrent_file.info.piece_size / block_size;
            if torrent_file.info.piece_size % block_size != 0 {
                count + 1
            } else {
                count
            }
        };

        let pieces = torrent_file
            .info
            .pieces
            .iter()
            .enumerate()
            .map(|(index, hash)| {
                let size = if index == torrent_file.info.pieces.len() - 1 {
                    torrent_file.info.length % torrent_file.info.piece_size
                } else {
                    torrent_file.info.piece_size
                };
                PieceState {
                    hash: hash.clone(),
                    done: false,
                    blocks: vec![false; block_count],
                    size,
                    data: Vec::new(),
                }
            })
            .collect();

        Self(Arc::new(Mutex::new(DownloadState {
            block_size,
            piece_size: torrent_file.info.piece_size,
            pieces,
            done: false,
            output_filename,
            output_file: None,
        })))
    }

    pub async fn next_block(&self, piece_index: usize) -> Option<BlockInfo> {
        self.0.lock().await.next_block(piece_index)
    }

    pub async fn block_done(
        &mut self,
        piece_index: usize,
        block_index: usize,
        offset: usize,
        data: Vec<u8>,
    ) -> anyhow::Result<()> {
        let mut state = self.0.lock().await;

        debug_assert_eq!(state.done, false);
        debug_assert!(offset + data.len() <= state.piece_size);
        debug_assert!(piece_index < state.pieces.len());
        debug_assert!(data.len() <= state.block_size);
        debug_assert!(state.pieces[piece_index].blocks.len() >= block_index);
        debug_assert_eq!(state.pieces[piece_index].blocks[block_index], false);

        let piece_done = {
            let piece = &mut state.pieces[piece_index];

            piece.blocks[block_index] = true;
            if piece.data.is_empty() {
                piece.data.resize(piece.size, 0);
            }

            piece.data.splice(offset..offset + data.len(), data);

            if piece.blocks.iter().all(|&b| b) {
                let mut hasher = sha1::Sha1::new();
                hasher.update(&piece.data);
                let hash = hasher.finalize();
                if hash.as_slice() != piece.hash.as_slice() {
                    piece.blocks.fill(false);
                } else {
                    piece.done = true;
                    piece.blocks = Vec::new();
                }
            }

            piece.done
        };

        if piece_done {
            if state.pieces.iter().all(|p| p.done) {
                state.pieces = Vec::new();
                state.done = true;
            }

            let file_offset = piece_index * state.pieces[piece_index].size + offset;
            let data = std::mem::take(&mut state.pieces[piece_index].data);
            let all_done = state.done;

            {
                let output_file = {
                    if state.output_file.is_none() {
                        let output_file = File::options()
                            .write(true)
                            .create(true)
                            .open(&state.output_filename)
                            .await?;
                        state.output_file = Some(output_file);
                    }

                    state.output_file.as_mut().unwrap()
                };
                output_file
                    .seek(SeekFrom::Start(file_offset as u64))
                    .await?;
                output_file.write_all(&data).await?;
            }

            if all_done {
                state.output_file.as_mut().unwrap().sync_all().await?;
                state.output_file = None;
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct BlockInfo {
    pub piece_index: usize,
    pub index: usize,
    pub offset: usize,
    pub length: usize,
}

impl DownloadState {
    fn next_block(&mut self, piece_index: usize) -> Option<BlockInfo> {
        if self.pieces[piece_index].done {
            return None;
        }

        let piece = &self.pieces[piece_index];
        let block_index = piece.blocks.iter().position(|&b| !b);
        if block_index.is_none() {
            panic!("Piece is not done");
        }

        let block_index = block_index.unwrap();
        let offset = block_index * self.block_size;
        let length = if offset + self.block_size > piece.size {
            self.piece_size % self.block_size
        } else {
            self.block_size
        };

        Some(BlockInfo {
            piece_index,
            index: block_index,
            offset,
            length,
        })
    }
    fn block_done(&mut self, piece_index: usize, block_index: usize) {
        self.pieces[piece_index].blocks[block_index] = true;
    }
}

impl DownloadState {}
