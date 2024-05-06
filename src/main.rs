#![allow(dead_code)]

use std::error::Error;
use std::net::SocketAddr;

use bytes::{Buf, BufMut, BytesMut};
use clap::{Arg, ArgMatches, Command};
use serde_json;
use tokio::task::JoinHandle;

use crate::download::SharedDownloadState;
use crate::peer::{HandShake, Message, Peer};
use crate::torrent_data::TorrentFile;
use crate::tracker::{send_request, TrackerRequest};

mod bencode_serialization;
mod download;
mod peer;
mod torrent_data;
mod tracker;
mod utils;

const PEER_ID: &str = "01234567890123456789";
const BLOCK_SIZE: usize = 16 * 1024;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let matches = get_arg_matches();

    match matches.subcommand() {
        Some(("decode", decode_matches)) => {
            let encoded_value = decode_matches
                .get_one::<String>("encoded_value")
                .expect("encoded_value is required");
            let decoded_value: bencode_serialization::Value =
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

            let peer = Peer::connect(&peer_address, &handshake).await?;
            println!("Peer ID: {}", peer.peer_id);
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

            let download_state =
                SharedDownloadState::new(torrent_file, output_filename.clone(), BLOCK_SIZE);

            let tasks: Vec<JoinHandle<()>> = tracker_response.peers[1..2]
                .iter()
                .map(|peer_addr| {
                    let peer_addr = peer_addr.clone();
                    let handshake = handshake.clone();
                    let download_state = download_state.clone();

                    tokio::spawn(async move {
                        download_piece(peer_addr, handshake.clone(), download_state, piece_index)
                            .await
                            .unwrap_or_else(|e| eprintln!("Error: {}", e));
                    })
                })
                .collect();
            for task in tasks {
                task.await?;
            }
        }
        _ => {
            println!("No subcommand was used, use --help to see available subcommands");
        }
    }

    Ok(())
}

async fn download_piece(
    peer_addr: SocketAddr,
    handshake: HandShake,
    mut download_state: SharedDownloadState,
    piece_index: usize,
) -> Result<(), Box<dyn Error>> {
    let mut buf = BytesMut::with_capacity(BLOCK_SIZE + 128);
    let mut peer = Peer::connect(&peer_addr, &handshake).await?;

    println!("Connected to peer: {}", peer.peer_id);

    let message = peer.receive(&mut buf).await?;
    if message.id != 5 {
        return Err("Expected bitfield message".into());
    }
    println!("Bitfield message received from: {}", peer.peer_id);

    let interested_message = Message::new(2);
    peer.send(&interested_message, &[]).await?;
    let unchoke_message = peer.receive(&mut buf).await?;
    if unchoke_message.id != 1 {
        return Err("Expected unchoke message".into());
    }
    println!("Unchoke message received from {}", peer.peer_id);

    loop {
        let block = download_state.next_block(piece_index).await;
        if block.is_none() {
            break;
        }
        let block = block.unwrap();

        buf.clear();
        buf.put_u32(block.piece_index as u32);
        buf.put_u32(block.offset as u32);
        buf.put_u32(block.size as u32);

        let request_msg = Message::new(6);
        peer.send(&request_msg, &buf).await?;

        let piece_msg = peer.receive(&mut buf).await?;
        if piece_msg.id != 7 {
            return Err("Expected piece message".into());
        }

        let piece_index = buf.get_u32() as usize;
        let offset = buf.get_u32() as usize;
        let size = buf.len();

        if piece_index != block.piece_index {
            panic!("Received piece with wrong index: {}", piece_index);
        }

        download_state
            .block_done(piece_index, block.index, offset, buf.to_vec())
            .await?;
        println!(
            "Received block: {} offset: {} bytes: {} piece: {}",
            piece_index, offset, size, piece_index,
        );
    }

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
        let decoded_value: bencode_serialization::Value =
            serde_bencode::from_str(encoded_value).unwrap();
        serde_json::to_value(&decoded_value).unwrap()
    }
}
