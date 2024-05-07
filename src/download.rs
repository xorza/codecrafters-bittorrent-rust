use std::sync::Arc;

use sha1::Digest;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::peer::HandShake;
use crate::torrent_data::{Sha1Hash, TorrentFile, TorrentInfo};

#[derive(Debug)]
pub struct BlockInfo {
    pub piece_index: usize,
    pub index: usize,
    pub offset: usize,
    pub size: usize,
}

#[derive(Debug, Clone)]
pub struct PieceState {
    pub index: usize,
    pub hash: Sha1Hash,
    pub size: usize,

    pub done: bool,
    pub in_progress: bool,
}

#[derive(Debug)]
pub struct DownloadState {
    pub handshake: HandShake,

    pub block_size: usize,
    pub piece_size: usize,
    pub pieces: Vec<PieceState>,
    pub done: bool,

    pub output_file: Option<File>,
}

#[derive(Clone)]
pub struct SharedDownloadState(Arc<Mutex<DownloadState>>);

impl PieceState {
    pub fn new(torrent_info: &TorrentInfo, index: usize) -> Self {
        assert!(index < torrent_info.pieces.len());

        let size = if index == torrent_info.pieces.len() - 1 {
            torrent_info.length % torrent_info.piece_size
        } else {
            torrent_info.piece_size
        };

        assert_ne!(size, 0);
        assert!(size <= torrent_info.piece_size);

        Self {
            index,
            hash: torrent_info.pieces[index].clone(),
            done: false,
            size,
            in_progress: false,
        }
    }
}

impl SharedDownloadState {
    pub fn new(
        torrent_file: TorrentFile,
        handshake: HandShake,
        output_file: File,
        block_size: usize,
    ) -> Self {
        assert_ne!(block_size, 0);

        let pieces = (0..torrent_file.info.pieces.len())
            .map(|piece_index| PieceState::new(&torrent_file.info, piece_index))
            .collect();

        Self(Arc::new(Mutex::new(DownloadState {
            handshake,
            block_size,
            piece_size: torrent_file.info.piece_size,
            pieces,
            done: false,
            output_file: Some(output_file),
        })))
    }

    pub async fn next_piece(&mut self) -> Option<PieceState> {
        let mut this = self.0.lock().await;

        if this.done {
            return None;
        }

        let piece = this
            .pieces
            .iter_mut()
            .find(|p| !p.done && !p.in_progress)
            .expect("No pieces available");
        piece.in_progress = true;

        Some(piece.clone())
    }

    pub async fn piece_done(&mut self, piece: &PieceState, data: Vec<u8>) -> anyhow::Result<()> {
        let mut state = self.0.lock().await;

        assert!(!state.done);
        assert!(data.len() <= piece.size);

        {
            let piece_ref = &mut state.pieces[piece.index];
            assert!(piece_ref.in_progress);
            assert!(!piece_ref.done);

            piece_ref.in_progress = false;
            let data_hash = Sha1Hash::from(sha1::Sha1::digest(&data));

            if piece.hash != data_hash {
                return Err(anyhow::format_err!("Piece hash mismatch"));
            }

            piece_ref.done = true;
        }

        if state.pieces.iter().all(|p| p.done) {
            state.pieces = Vec::new();
            state.done = true;
        }

        state
            .output_file
            .as_mut()
            .expect("File not available")
            .write_all(&data)
            .await?;

        if state.done {
            state
                .output_file
                .as_mut()
                .expect("File not available")
                .sync_all()
                .await?;
            state.output_file = None;
        }

        Ok(())
    }

    pub async fn handshake(&self) -> HandShake {
        self.0.lock().await.handshake.clone()
    }
}
