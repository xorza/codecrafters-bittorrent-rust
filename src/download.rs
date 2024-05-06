use std::sync::Arc;

use sha1::Digest;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::torrent_data::{Sha1Hash, TorrentFile};

#[derive(Debug)]
pub struct BlockInfo {
    pub piece_index: usize,
    pub index: usize,
    pub offset: usize,
    pub size: usize,
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
        assert_ne!(block_size, 0);

        let pieces = torrent_file
            .info
            .pieces
            .iter()
            .enumerate()
            .map(|(index, hash)| {
                let piece_size = if index == torrent_file.info.pieces.len() - 1 {
                    torrent_file.info.length % torrent_file.info.piece_size
                } else {
                    torrent_file.info.piece_size
                };
                let block_count = {
                    let count = piece_size / block_size;
                    if piece_size % block_size != 0 {
                        count + 1
                    } else {
                        count
                    }
                };

                assert_ne!(block_count, 0);
                assert_ne!(piece_size, 0);

                PieceState {
                    hash: hash.clone(),
                    done: false,
                    blocks: vec![false; block_count],
                    size: piece_size,
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
        let this = self.0.lock().await;

        if this.pieces[piece_index].done {
            return None;
        }

        let piece = &this.pieces[piece_index];
        let block_index = piece.blocks.iter().position(|&b| !b);
        if block_index.is_none() {
            panic!("Piece is not done");
        }

        let block_index = block_index.unwrap();
        let offset = block_index * this.block_size;
        let size = if offset + this.block_size > piece.size {
            piece.size % this.block_size
        } else {
            this.block_size
        };

        assert_ne!(size, 0);
        assert!(offset <= piece.size);
        assert!(offset + size <= piece.size);

        Some(BlockInfo {
            piece_index,
            index: block_index,
            offset,
            size,
        })
    }

    pub async fn block_done(
        &mut self,
        piece_index: usize,
        block_index: usize,
        offset: usize,
        data: Vec<u8>,
    ) -> anyhow::Result<()> {
        let mut state = self.0.lock().await;

        assert_eq!(state.done, false);
        assert!(offset + data.len() <= state.piece_size);
        assert!(piece_index < state.pieces.len());
        assert!(data.len() <= state.block_size);
        assert!(state.pieces[piece_index].blocks.len() >= block_index);
        assert_eq!(state.pieces[piece_index].blocks[block_index], false);

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
                let hash: Sha1Hash = hasher.finalize().into();
                if hash != piece.hash {
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

            let data = std::mem::take(&mut state.pieces[piece_index].data);
            let all_done = state.done;

            {
                let output_file = {
                    if state.output_file.is_none() {
                        let output_file = File::options()
                            .create(true)
                            .write(true)
                            .truncate(true)
                            .open(&state.output_filename)
                            .await?;
                        state.output_file = Some(output_file);
                    }

                    state.output_file.as_mut().unwrap()
                };

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
