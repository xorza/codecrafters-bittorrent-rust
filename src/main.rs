#![allow(dead_code)]

use std::net::SocketAddr;

use bytes::BytesMut;
use clap::{Arg, ArgMatches, Command};
use serde_json;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::task::JoinHandle;

use crate::download::{PieceState, SharedDownloadState};
use crate::peer::{HandShake, Peer};
use crate::torrent_data::TorrentFile;
use crate::tracker::{send_request, TrackerRequest};

mod bencode;
mod download;
mod peer;
mod torrent_data;
mod tracker;
mod utils;

const PEER_ID: &str = "01234567890123456789";
const BLOCK_SIZE: usize = 16 * 1024;
const RETRY_COUNT: usize = 10;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let matches = get_arg_matches();

    match matches.subcommand() {
        Some(("decode", decode_matches)) => {
            let encoded_value = decode_matches
                .get_one::<String>("encoded_value")
                .expect("encoded_value is required");
            let decoded_value: bencode::Value =
                serde_bencode::from_bytes(encoded_value.as_bytes())?;
            println!("{}", serde_json::to_string(&decoded_value)?);
        }
        Some(("info", info_matches)) => {
            let torrent_filename = info_matches
                .get_one::<String>("torrent_filename")
                .expect("torrent_filename is required");
            let torrent_file = TorrentFile::from_file(torrent_filename)?;
            let info_sha1 = torrent_file.info.get_sha1();

            println!("Tracker URL: {}", torrent_file.announce);
            println!("Length: {}", torrent_file.info.length);
            println!("Info Hash: {}", info_sha1);
            println!("Piece Length: {}", torrent_file.info.piece_size);

            println!("Piece Hashes:");
            for piece in torrent_file.info.pieces {
                println!("  {}", piece);
            }
        }
        Some(("peers", peers_matches)) => {
            let torrent_filename = peers_matches
                .get_one::<String>("torrent_filename")
                .expect("torrent_filename is required");
            let torrent_file = TorrentFile::from_file(torrent_filename)?;
            let tracker_request = TrackerRequest {
                info_hash: torrent_file.info.get_sha1(),
                peer_id: PEER_ID.to_string(),
                port: 6881,
                uploaded: 0,
                downloaded: 0,
                left: torrent_file.info.length as u64,
            };
            let tracker_response =
                send_request(tracker_request, torrent_file.announce.as_str()).await?;

            println!("Interval: {}", tracker_response.interval);
            println!("Peers:");
            for addr in tracker_response.peers {
                println!("  {}", addr);
            }
        }
        Some(("handshake", handshake_matches)) => {
            let torrent_filename = handshake_matches
                .get_one::<String>("torrent_filename")
                .expect("torrent_filename is required");
            let peer_address = handshake_matches
                .get_one::<String>("peer_address")
                .expect("peer_address is required");

            let peer_address = peer_address.parse::<std::net::SocketAddr>()?;
            let torrent_file = TorrentFile::from_file(torrent_filename)?;
            let handshake = HandShake::new(torrent_file.info.get_sha1(), PEER_ID.as_bytes().into());

            let mut peer = Peer::new(peer_address);
            peer.connect(&handshake).await?;
            let peer_id = peer.connection.as_ref().unwrap().peer_id.to_string();
            println!("Peer ID: {}", peer_id);
        }
        Some(("download_piece", download_piece_matches)) => {
            let output_filename = download_piece_matches
                .get_one::<String>("output")
                .expect("output is required");
            let torrent_filename = download_piece_matches
                .get_one::<String>("torrent_file")
                .expect("torrent_file is required");
            let piece_index: usize = download_piece_matches
                .get_one::<String>("piece_index")
                .expect("piece_index is required")
                .parse()?;

            let torrent_file = TorrentFile::from_file(torrent_filename)?;
            let json = torrent_file.to_pretty_string();
            println!("{}", json);

            let tracker_request = TrackerRequest {
                info_hash: torrent_file.info.get_sha1(),
                peer_id: PEER_ID.to_string(),
                port: 6881,
                uploaded: 0,
                downloaded: 0,
                left: torrent_file.info.length as u64,
            };
            let tracker_response =
                send_request(tracker_request, torrent_file.announce.as_str()).await?;
            let handshake = HandShake::new(torrent_file.info.get_sha1(), PEER_ID.as_bytes().into());

            let peer_addr = tracker_response.peers[1];

            let mut data: Option<Vec<u8>> = None;
            for i in 0..RETRY_COUNT {
                let result =
                    peer_download_piece(piece_index, &torrent_file, &handshake, peer_addr).await;
                match result {
                    Ok(received_data) => {
                        data = Some(received_data);
                        break;
                    }
                    Err(err) => {
                        if i < RETRY_COUNT - 1 {
                            eprintln!("Retrying download from peer: {}", err);
                        }
                    }
                }
            }
            let data = data.ok_or(anyhow::format_err!("Failed to download piece"))?;

            {
                let mut output_file = File::options()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&output_filename)
                    .await?;
                output_file.write_all(&data).await?;
                output_file.sync_all().await?;
            }

            println!(
                "Downloaded piece: {} to file: {}",
                piece_index, output_filename
            );
        }
        Some(("download", download_matches)) => {
            let output_filename = download_matches
                .get_one::<String>("output")
                .expect("output is required");
            let torrent_filename = download_matches
                .get_one::<String>("torrent_file")
                .expect("torrent_file is required");

            let torrent_file = TorrentFile::from_file(torrent_filename)?;
            let tracker_request = TrackerRequest {
                info_hash: torrent_file.info.get_sha1(),
                peer_id: PEER_ID.to_string(),
                port: 6881,
                uploaded: 0,
                downloaded: 0,
                left: torrent_file.info.length as u64,
            };
            let tracker_response =
                send_request(tracker_request, torrent_file.announce.as_str()).await?;
            let handshake = HandShake::new(torrent_file.info.get_sha1(), PEER_ID.as_bytes().into());

            let output_file = File::options()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&output_filename)
                .await?;

            let download_state =
                SharedDownloadState::new(torrent_file, handshake, output_file, BLOCK_SIZE);

            let tasks: Vec<JoinHandle<()>> = tracker_response
                .peers
                .iter()
                .map(|peer_addr| {
                    let peer_addr = peer_addr.clone();
                    let download_state = download_state.clone();

                    tokio::spawn(async move {
                        for i in 0..RETRY_COUNT {
                            let result =
                                peer_thread(download_state.clone(), peer_addr.clone()).await;
                            match result {
                                Ok(_) => break,
                                Err(err) => {
                                    if i == RETRY_COUNT - 1 {
                                        eprintln!("Error downloading from peer: {}", err);
                                    } else {
                                        eprintln!("Retrying download from peer: {}", err);
                                    }
                                }
                            }
                        }
                    })
                })
                .collect();
            for task in tasks {
                task.await?;
            }

            println!("Downloaded {} to {}.", torrent_filename, output_filename);
        }
        _ => {
            println!("No subcommand was used, use --help to see available subcommands");
        }
    }

    Ok(())
}

async fn peer_download_piece(
    piece_index: usize,
    torrent_file: &TorrentFile,
    handshake: &HandShake,
    peer_addr: SocketAddr,
) -> anyhow::Result<Vec<u8>> {
    let mut peer = Peer::new(peer_addr);
    peer.connect(&handshake).await?;
    let peer_id = peer.connection.as_ref().unwrap().peer_id.to_string();
    println!("Connected to peer: {}", peer_id);

    let mut buf = BytesMut::with_capacity(BLOCK_SIZE + 128);
    peer.prepare_download(&mut buf).await?;

    let piece = PieceState {
        index: piece_index,
        hash: torrent_file.info.pieces[piece_index].clone(),
        done: false,
        size: torrent_file.info.piece_size,
        in_progress: false,
    };
    let data = peer.download_piece(&piece, &mut buf).await?;
    Ok(data)
}

async fn peer_thread(
    mut download_state: SharedDownloadState,
    peer_addr: SocketAddr,
) -> anyhow::Result<()> {
    let mut peer = Peer::new(peer_addr);
    peer.connect(&download_state.handshake().await).await?;

    let peer_id = peer.connection.as_ref().unwrap().peer_id.to_string();
    println!("Connected to peer: {}", peer_id);

    let mut buf = BytesMut::with_capacity(BLOCK_SIZE + 128);
    peer.prepare_download(&mut buf).await?;

    loop {
        let piece = download_state.next_piece().await;
        if piece.is_none() {
            break;
        }
        let piece = piece.unwrap();
        let data = peer.download_piece(&piece, &mut buf).await?;

        download_state.piece_done(&piece, data).await?;
        println!("Downloaded piece: {}", piece.index);
    }

    println!("Downloaded all pieces from peer: {}", peer_id);
    Ok(())
}

fn get_arg_matches() -> ArgMatches {
    let matches = Command::new("codecrafters-bittorrent-rust")
        .version("0.1")
        .about("CodeCrafters BitTorrent Rust Challenge")
        .subcommand_required(true)
        .subcommand(
            Command::new("decode")
                .about("Decodes a bencoded value")
                .arg(Arg::new("encoded_value").required(true)),
        )
        .subcommand(
            Command::new("info")
                .about("Prints information about a torrent file")
                .arg(Arg::new("torrent_filename").required(true)),
        )
        .subcommand(
            Command::new("peers")
                .about("Prints peers from a tracker")
                .arg(Arg::new("torrent_filename").required(true)),
        )
        .subcommand(
            Command::new("handshake")
                .about("Performs a handshake with a peer and prints the peer ID")
                .arg(Arg::new("torrent_filename").required(true))
                .arg(Arg::new("peer_address").required(true)),
        )
        .subcommand(
            Command::new("download_piece")
                .arg(
                    Arg::new("output")
                        .short('o')
                        .long("output")
                        .required(true)
                        .value_name("FILE")
                        .help("Sets the output file path"),
                )
                .arg(
                    Arg::new("torrent_file")
                        .help("The torrent file")
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::new("piece_index")
                        .help("The index of the piece to download")
                        .required(true)
                        .index(2),
                ),
        )
        .subcommand(
            Command::new("download")
                .arg(
                    Arg::new("output")
                        .short('o')
                        .long("output")
                        .required(true)
                        .value_name("FILE")
                        .help("Sets the output file path"),
                )
                .arg(
                    Arg::new("torrent_file")
                        .help("The torrent file")
                        .required(true)
                        .index(1),
                ),
        )
        .get_matches();
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_info_hash() {
        let torrent_filename = "sample.torrent";
        let torrent_file = TorrentFile::from_file(torrent_filename).unwrap();
        let info_sha1_str = torrent_file.info.get_sha1().to_string();

        assert_eq!(info_sha1_str, "d69f91e6b2ae4c542468d1073a71d4ea13879a7f");
    }

    #[test]
    fn test_decode_torrent_file() {
        let torrent_filename = "sample.torrent";
        let mut torrent_file = TorrentFile::from_file(torrent_filename).unwrap();
        torrent_file.info.pieces.clear();

        let json_decoded_value = serde_json::to_value(&torrent_file).unwrap();

        assert_eq!(
            json_decoded_value,
            serde_json::json!({
                "announce": "http://bittorrent-test-tracker.codecrafters.io/announce",
                "created by": "mktorrent 1.1",
                "info": {
                    "length": 92063,
                    "name": "sample.txt",
                    "piece length": 32768,
                    "pieces": []
                }
            })
        );

        assert_eq!(
            torrent_file.announce,
            "http://bittorrent-test-tracker.codecrafters.io/announce"
        );
        assert_eq!(torrent_file.info.length, 92063);
    }

    #[test]
    fn test_torrent_file_from_json() {
        let torrent_json = serde_json::json!({
            "announce": "http://bittorrent-test-tracker.codecrafters.io/announce",
            "created by": "mktorrent 1.1",
            "info": {
                "length": 92063,
                "name": "sample.txt",
                "piece length": 32768,
                "pieces": [
                  "e876f67a2a8886e8f36b136726c30fa29703022d",
                  "6e2275e604a0766656736e81ff10b55204ad8d35",
                  "f00d937a0213df1982bc8d097227ad9e909acc17"
                ]
            }
        });
        let torrent_file: TorrentFile = serde_json::from_value(torrent_json).unwrap();
        assert_eq!(torrent_file.info.pieces.len(), 3);
        assert_eq!(
            torrent_file.info.pieces[0].to_string(),
            "e876f67a2a8886e8f36b136726c30fa29703022d"
        );
    }

    #[test]
    fn test_bencode_to_json() {
        assert_eq!(bencode_to_json("4:spam"), serde_json::json!("spam"));

        assert_eq!(bencode_to_json("i52e"), serde_json::json!(52));

        assert_eq!(
            bencode_to_json("l5:helloi52ee"),
            serde_json::json!(["hello", 52])
        );

        assert_eq!(
            bencode_to_json("d4:spaml1:a1:bee"),
            serde_json::json!({
                "spam": ["a", "b"]
            })
        );

        assert_eq!(
            bencode_to_json("d3:foo9:blueberry5:helloi52ee"),
            serde_json::json!({
                "foo": "blueberry",
                "hello": 52
            })
        );
    }

    fn bencode_to_json(encoded_value: &str) -> serde_json::Value {
        let decoded_value: bencode::Value = serde_bencode::from_str(encoded_value).unwrap();
        serde_json::to_value(&decoded_value).unwrap()
    }

    //#[test]
    fn test() {
        let json = serde_json::json!(
            {
              "announce": "http://bittorrent-test-tracker.codecrafters.io/announce",
              "created by": "mktorrent 1.1",
              "info": {
                "length": 2994120,
                "name": "codercat.gif",
                "piece length": 262144,
                "pieces": [
                  "3c34309faebf01e49c0f63c90b7edcc2259b6ad0",
                  "b8519b2ea9bb373ff567f644428156c98a1d00fc",
                  "9dc81366587536f48c2098a1d79692f2590fd9a6",
                  "033c61e717f8c0d1e55850680eb451e3543b6203",
                  "6f54e746ec369f65f32d45f77b1f1c37621fb965",
                  "c656704b78107ed553bd0813f92fef780267c07b",
                  "7431b8683137d20ff594b1f1bf3f8835165d68fb",
                  "0432bd8e779608d27782b779c7738062e9b50ab5",
                  "d6bc0409a0f3a9503857669d47fe752d4577ea00",
                  "a86ee6abbc30cddb800a0b62d7a296111166d839",
                  "783f52b70f0c902d56196bd3ee7f379b5db57e3b",
                  "3d8db9e34db63b4ba1be27930911aa37b3f997dd"
                ]
              }
            }

        );
        let torrent_file: TorrentFile = serde_json::from_value(json).unwrap();
        let bencode = serde_bencode::to_bytes(&torrent_file).unwrap();
        std::fs::write("sample2.torrent", &bencode).unwrap();
    }
}
