#![allow(dead_code)]

use std::error::Error;

use clap::{Arg, ArgMatches, Command};
use serde_json;
use tokio::io::{AsyncWriteExt, BufStream};

use crate::peer::HandShake;
use crate::torrent_data::TorrentFile;
use crate::tracker::{send_request, TrackerRequest};

mod bencode_serialization;
mod peer;
mod torrent_data;
mod tracker;
mod utils;

const PEER_ID: &str = "01234567890123456789";

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
            println!("Piece Length: {}", torrent_file.info.piece_length);

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
            for (ip, port) in tracker_response.peers {
                println!("  {}:{}", ip, port);
            }
        }
        Some(("handshake", handshake_matches)) => {
            let torrent_filename = handshake_matches
                .get_one::<String>("torrent_filename")
                .expect("torrent_filename is required");
            let peer_address = handshake_matches
                .get_one::<String>("peer_address")
                .expect("peer_address is required");

            let torrent_file = TorrentFile::from_file(torrent_filename)?;

            let request = HandShake::new(torrent_file.info.get_sha1(), PEER_ID.as_bytes().into());
            let mut stream = tokio::net::TcpStream::connect(peer_address).await?;
            let mut bufstream = BufStream::new(&mut stream);

            request.to_stream(&mut bufstream).await?;
            bufstream.flush().await?;

            let response = HandShake::from_stream(&mut stream).await?;
            println!("Peer ID: {}", response.peer_id);
        }
        Some(("download_piece", download_piece_matches)) => {
            let output = download_piece_matches
                .get_one::<String>("output")
                .expect("output is required");
            let torrent_filename = download_piece_matches
                .get_one::<String>("torrent_file")
                .expect("torrent_file is required");
            let piece_index = download_piece_matches
                .get_one::<usize>("piece_index")
                .expect("piece_index is required");

            let torrent_file = TorrentFile::from_file(torrent_filename)?;
        }
        _ => {
            println!("No subcommand was used, use --help to see available subcommands");
        }
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
    fn test_decode_bencoded_value_string() {
        let encoded_value = "4:spam";
        let decoded_value: String = serde_bencode::from_bytes(encoded_value.as_bytes()).unwrap();
        let json_decoded_value = serde_json::to_value(&decoded_value).unwrap();
        assert_eq!(json_decoded_value, serde_json::json!("spam"));
    }

    #[test]
    fn test_decode_bencoded_value_integer() {
        let encoded_value = "i52e";
        let decoded_value: i64 = serde_bencode::from_bytes(encoded_value.as_bytes()).unwrap();
        let json_decoded_value = serde_json::to_value(&decoded_value).unwrap();
        assert_eq!(json_decoded_value, serde_json::json!(52));
    }

    #[test]
    fn test_decode_bencoded_list() {
        let encoded_value = "l5:helloi52ee";
        let decoded_value: bencode_serialization::Value =
            serde_bencode::from_str(encoded_value).unwrap();
        let json_decoded_value = serde_json::to_value(&decoded_value).unwrap();
        assert_eq!(json_decoded_value, serde_json::json!(["hello", 52]));
    }

    #[test]
    fn test_decode_bencoded_list_in_dict() {
        let encoded_value = "d4:spaml1:a1:bee";
        let decoded_value: bencode_serialization::Value =
            serde_bencode::from_str(encoded_value).unwrap();
        let json_decoded_value = serde_json::to_value(&decoded_value).unwrap();
        assert_eq!(
            json_decoded_value,
            serde_json::json!({
                "spam": ["a", "b"]
            })
        );
    }
}
