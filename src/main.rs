use serde_json;
use sha1::{Digest, Sha1};
use std::{
    env, fs,
    io::{Read, Write},
    net::TcpStream,
};

use serde::{Deserialize, Serialize};
use serde_bencode::value::Value as BencodeValue;
use serde_bytes::ByteBuf;

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
struct Node(String, i64);

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
struct File {
    path: Vec<String>,
    length: i64,
    #[serde(default)]
    md5sum: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
struct Info {
    pub name: String,
    pub pieces: ByteBuf,
    #[serde(rename = "piece length")]
    pub piece_length: i64,
    #[serde(default)]
    pub md5sum: Option<String>,
    #[serde(default)]
    pub length: Option<i64>,
    #[serde(default)]
    pub files: Option<Vec<File>>,
    #[serde(default)]
    pub private: Option<u8>,
    #[serde(default)]
    pub path: Option<Vec<String>>,
    #[serde(default)]
    #[serde(rename = "root hash")]
    pub root_hash: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Torrent {
    info: Info,
    #[serde(default)]
    announce: Option<String>,
    #[serde(default)]
    nodes: Option<Vec<Node>>,
    #[serde(default)]
    encoding: Option<String>,
    #[serde(default)]
    httpseeds: Option<Vec<String>>,
    #[serde(default)]
    #[serde(rename = "announce-list")]
    announce_list: Option<Vec<Vec<String>>>,
    #[serde(default)]
    #[serde(rename = "creation date")]
    creation_date: Option<i64>,
    #[serde(rename = "comment")]
    comment: Option<String>,
    #[serde(default)]
    #[serde(rename = "created by")]
    created_by: Option<String>,
}

fn convert_to_json_value(val: &BencodeValue) -> serde_json::Value {
    match val {
        BencodeValue::Bytes(b) => {
            let s = String::from_utf8_lossy(&b).to_string();
            serde_json::json!(s)
        }
        BencodeValue::Int(i) => serde_json::json!(i),
        BencodeValue::List(l) => {
            let mut arr: Vec<serde_json::Value> = vec![];
            for i in l {
                arr.push(convert_to_json_value(i));
            }
            serde_json::Value::Array(arr)
        }
        BencodeValue::Dict(dict) => {
            let mut map = serde_json::Map::new();
            for (k, v) in dict {
                let key = String::from_utf8_lossy(k).to_string();
                let val = convert_to_json_value(v);
                map.insert(key, val);
            }
            serde_json::Value::Object(map)
        }
    }
}

#[allow(dead_code)]
fn decode_bencoded_value(encoded_value: &str) -> serde_json::Value {
    let value: BencodeValue = serde_bencode::from_str(encoded_value).unwrap();
    convert_to_json_value(&value)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let command = &args[1];

    if command == "decode" {
        let encoded_value = &args[2];
        let decoded_value = decode_bencoded_value(encoded_value);
        println!("{}", decoded_value.to_string());
    } else if command == "info" || command == "peers" {
        let file_name = &args[2];
        let mut file = fs::File::open(file_name).unwrap();
        let length = file.metadata().unwrap().len();
        let mut data = Vec::with_capacity(length as usize);
        file.read_to_end(&mut data).unwrap();
        let data: Torrent = serde_bencode::from_bytes(&data).unwrap();
        let info = serde_bencode::to_bytes(&data.info).unwrap();
        let tracker_url = data.announce.unwrap();
        let piece_length = data.info.piece_length;
        let pieces = data.info.pieces.as_slice();
        if command == "info" {
            println!("Tracker URL: {}", &tracker_url);
            println!("Length: {}", data.info.length.unwrap());
            println!("Info Hash: {}", get_hash(&info));
            println!("Piece Length: {}", piece_length);
            println!("Piece Hashes:");
            pieces
                .chunks(20)
                .for_each(|d| println!("{}", hex::encode(d)));
        }
        if command == "peers" {
            make_request(&tracker_url, &info, piece_length);
        }
    } else if command == "handshake" {
        let file_name = &args[2];
        let addr = &args[3];
        handshake(file_name, addr);
    } else if command == "download_piece" {
        download_piece(args.as_slice());
    } else {
        println!("unknown command: {}", args[1])
    }
}

fn get_hash(data: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(&data);
    let hash = hasher.finalize();
    hex::encode(hash)
}

fn make_request(url: &str, info: &[u8], piece_length: i64) -> Vec<String> {
    let mut hasher = Sha1::new();
    hasher.update(&info);
    let info_hash = hasher.finalize();
    let mut info_hash_encoded = String::with_capacity(60);
    for byte in info_hash {
        info_hash_encoded.push('%');
        info_hash_encoded.push_str(&hex::encode(&[byte]));
    }
    let url = format!(
        "{}?info_hash={}&peer_id=00112233445566778899&port=6881&uploaded=0&downloaded=0&left={}&compact=1",
        url, &info_hash_encoded, piece_length
    );

    #[allow(dead_code)]
    #[derive(Deserialize)]
    struct Response {
        interval: i64,
        peers: ByteBuf,
    }

    let resp = reqwest::blocking::get(url).unwrap().bytes().unwrap();
    let resp: Response = serde_bencode::from_bytes(&resp).unwrap();
    let mut peers = vec![];
    resp.peers.as_slice().chunks(6).for_each(|d| {
        let port = u16::from_be_bytes([d[4], d[5]]);
        let addr = format!("{}.{}.{}.{}:{}", d[0], d[1], d[2], d[3], port);
        println!("{}", addr);
        peers.push(addr);
    });
    peers
}

fn info_hash_encoded(torrent: &Torrent) -> String {
    let hash = info_hash(torrent);
    let mut encoded = String::with_capacity(hash.len() * 3);
    for byte in hash {
        encoded.push('%');
        encoded.push_str(&hex::encode(&[byte]));
    }
    encoded
}

fn get_peers_list(torrent: &Torrent) -> Vec<String> {
    let tracker_url = torrent.announce.as_ref().unwrap();
    let piece_length = torrent.info.piece_length.to_string();
    let params = [
        ("peer_id", "00112233445566778899"),
        ("port", "6881"),
        ("uploaded", "0"),
        ("downloaded", "0"),
        ("left", piece_length.as_str()),
        ("compact", "1"),
    ];
    let params = serde_urlencoded::to_string(&params).unwrap();
    let url = format!(
        "{}?{}&info_hash={}",
        tracker_url,
        params,
        info_hash_encoded(torrent)
    );
    #[derive(Deserialize)]
    struct Response {
        peers: ByteBuf,
    }
    let resp = reqwest::blocking::get(url).unwrap().bytes().unwrap();
    let resp: Response = serde_bencode::from_bytes(&resp).unwrap();
    let mut peers = vec![];
    resp.peers.as_slice().chunks(6).for_each(|d| {
        let port = u16::from_be_bytes([d[4], d[5]]);
        let addr = format!("{}.{}.{}.{}:{}", d[0], d[1], d[2], d[3], port);
        peers.push(addr);
    });
    peers
}

fn parse_torrent_file(file_name: &str) -> Torrent {
    let mut file = fs::File::open(file_name).unwrap();
    let length = file.metadata().unwrap().len();
    let mut data = Vec::with_capacity(length as usize);
    file.read_to_end(&mut data).unwrap();
    serde_bencode::from_bytes(&data).unwrap()
}

fn info_hash(torrent: &Torrent) -> [u8; 20] {
    let info = serde_bencode::to_bytes(&torrent.info).unwrap();
    let mut hasher = Sha1::new();
    hasher.update(&info);
    hasher.finalize().into()
}

fn handshake(file_name: &str, addr: &str) {
    let data = parse_torrent_file(file_name);
    let info_hash = info_hash(&data);
    let mut body: [u8; 68] = [0; 68];
    body[0] = 19;
    "BitTorrent protocol"
        .as_bytes()
        .iter()
        .enumerate()
        .for_each(|(i, &b)| {
            body[i + 1] = b;
        });
    info_hash.iter().enumerate().for_each(|(i, &b)| {
        body[i + 28] = b;
    });
    "00112233445566778899"
        .as_bytes()
        .iter()
        .enumerate()
        .for_each(|(i, &b)| {
            body[i + 48] = b;
        });
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.write_all(&body).unwrap();
    let mut response = [0u8; 68];
    stream.read_exact(&mut response).unwrap();
    println!("Peer ID: {}", hex::encode(&response[48..]));
}

fn download_piece(args: &[String]) {
    if args.len() != 6 {
        panic!("incorrect arguments");
    }
    let output_path = &args[3];
    let file_name = &args[4];
    let piece_index = args[5].parse::<usize>().unwrap();
    let torrent = parse_torrent_file(file_name);
    let total_length = torrent.info.length.unwrap();
    let piece_length = torrent.info.piece_length;
    let (num_piece, remainder_piece_len) = if total_length % piece_length > 0 {
        (
            (total_length / piece_length) + 1,
            total_length % piece_length,
        )
    } else {
        (total_length / piece_length, 0)
    };
    if piece_index >= num_piece as usize {
        panic!("invalid index");
    }
    let piece_length = if piece_index < num_piece as usize - 1 {
        piece_length
    } else {
        if remainder_piece_len == 0 {
            piece_length
        } else {
            remainder_piece_len
        }
    };
    let peers = get_peers_list(&torrent);
    let addr = peers[0].as_str();
    let info_hash = info_hash(&torrent);
    let mut body: [u8; 68] = [0; 68];
    body[0] = 19;
    "BitTorrent protocol"
        .as_bytes()
        .iter()
        .enumerate()
        .for_each(|(i, &b)| {
            body[i + 1] = b;
        });
    info_hash.iter().enumerate().for_each(|(i, &b)| {
        body[i + 28] = b;
    });
    "00112233445566778899"
        .as_bytes()
        .iter()
        .enumerate()
        .for_each(|(i, &b)| {
            body[i + 48] = b;
        });
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.write_all(&body).unwrap();
    let mut response = [0u8; 68];
    stream.read_exact(&mut response).unwrap();
    let mut buffer = [0u8; 4];
    stream.read_exact(&mut buffer).unwrap();
    let message_length = u32::from_be_bytes(buffer);
    let mut buffer = vec![0; message_length as usize];
    stream.read_exact(&mut buffer).unwrap();

    // send interested message
    let mut message = [0u8; 5];
    message[3] = 1;
    message[4] = 2;
    stream.write_all(&message).unwrap();
    let mut buffer = [0u8; 4];
    stream.read_exact(&mut buffer).unwrap();
    let message_length = u32::from_be_bytes(buffer);
    let mut buffer = vec![0u8; message_length as usize];
    stream.read_exact(&mut buffer).unwrap();

    let block_size = 16 * 1024;
    let (num_blocks, remainder_block_size) = if piece_length % block_size > 0 {
        ((piece_length / block_size) + 1, piece_length % block_size)
    } else {
        (piece_length / block_size, 0)
    };
    let mut output_bytes = Vec::with_capacity(piece_length as usize);
    for idx in 0..num_blocks {
        let begin = idx * block_size;
        let length = if idx < num_blocks - 1 {
            block_size
        } else {
            if remainder_block_size == 0 {
                block_size
            } else {
                remainder_block_size
            }
        };
        let payload = [
            13u32.to_be_bytes().as_slice(),
            6u8.to_be_bytes().as_slice(),
            (piece_index as u32).to_be_bytes().as_slice(),
            (begin as u32).to_be_bytes().as_slice(),
            (length as u32).to_be_bytes().as_slice(),
        ]
        .concat();
        stream.write_all(&payload).unwrap();
        loop {
            let mut buffer = [0u8; 4];
            stream.read_exact(&mut buffer).unwrap();
            let message_length = u32::from_be_bytes(buffer);
            if message_length == 0 {
                continue;
            }
            let mut buffer = vec![0u8; message_length as usize];
            stream.read_exact(&mut buffer).unwrap();
            if buffer[0] != 7 {
                continue;
            }
            let data = &buffer[9..];
            output_bytes.extend(data);
            break;
        }
    }
    let mut hasher = Sha1::new();
    hasher.update(&output_bytes);
    let output_hash: [u8; 20] = hasher.finalize().into();
    let output_hash = hex::encode(&output_hash);
    let actual_hash = torrent.info.pieces.chunks(20).skip(piece_index).next().unwrap();
    let actual_hash = hex::encode(&actual_hash);
    assert_eq!(output_hash, actual_hash);
    // write to output path
    let mut f = fs::File::create(output_path).unwrap();
    f.write_all(&output_bytes).unwrap();
    f.flush().unwrap();
    println!("Piece {} downloaded to {}", piece_index, output_path);
}
