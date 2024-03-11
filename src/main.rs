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

const BIT_TORRENT_PROTO: &str = "BitTorrent protocol";

#[derive(Debug, Deserialize, Serialize)]
struct Info {
    pub name: String,
    pub pieces: ByteBuf,
    #[serde(rename = "piece length")]
    pub piece_length: i64,
    pub length: i64,
}

#[derive(Debug, Deserialize)]
struct Torrent {
    info: Info,
    announce: String,
}

fn main() {
    let args = env::args().collect::<Vec<_>>();
    if args.len() < 2 {
        panic!("expected args");
    }
    match args[1].as_str() {
        "decode" => decode_bencoded_value(&args),
        "info" => print_info(&args),
        "peers" => make_peer_request(&args),
        "handshake" => handshake_with_peer(&args),
        "download_piece" => download_piece(&args),
        _ => panic!("unknown command: {}", args[1]),
    };
}

fn decode_bencoded_value(args: &[String]) {
    let encoded_value = args[2].as_str();
    let value: BencodeValue = serde_bencode::from_str(encoded_value).unwrap();
    let decoded_value = convert_to_json_value(&value);
    println!("{}", decoded_value.to_string());
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

fn print_info(args: &[String]) {
    let file_name = &args[2];
    let torrent = parse_torrent_file(file_name);
    println!("Tracker URL: {}", torrent.announce);
    println!("Length: {}", torrent.info.length);
    println!("Info Hash: {}", hex::encode(info_hash(&torrent)));
    println!("Piece Length: {}", torrent.info.piece_length);
    println!("Piece Hashes:");
    torrent
        .info
        .pieces
        .chunks(20)
        .for_each(|d| println!("{}", hex::encode(d)));
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

fn make_peer_request(args: &[String]) {
    let file_name = &args[2];
    let torrent = parse_torrent_file(file_name);
    let peers = get_peers_list(&torrent);
    for peer in peers {
        println!("{}", peer);
    }
}

fn get_peers_list(torrent: &Torrent) -> Vec<String> {
    let tracker_url = torrent.announce.as_str();
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

fn info_hash_encoded(torrent: &Torrent) -> String {
    let hash = info_hash(torrent);
    let mut encoded = String::with_capacity(hash.len() * 3);
    for byte in hash {
        encoded.push('%');
        encoded.push_str(&hex::encode(&[byte]));
    }
    encoded
}

fn handshake_with_peer(args: &[String]) {
    let file_name = &args[2];
    let addr = &args[3];
    let torrent = parse_torrent_file(file_name);
    let mut stream = TcpStream::connect(addr).unwrap();
    println!("Peer ID: {}", handshake(&mut stream, &torrent));
}

fn handshake(stream: &mut TcpStream, torrent: &Torrent) -> String {
    let peer_id = "00112233445566778899";
    let info_hash = info_hash(&torrent);
    let mut body = Vec::with_capacity(68);
    body.push(19u8);
    body.extend(BIT_TORRENT_PROTO.as_bytes());
    body.extend([0u8; 8]);
    body.extend(info_hash);
    body.extend(peer_id.as_bytes());
    assert_eq!(body.len(), 68);
    stream.write_all(&body).unwrap();
    let mut response = [0u8; 68];
    stream.read_exact(&mut response).unwrap();
    hex::encode(&response[48..])
}

fn download_piece(args: &[String]) {
    if args.len() != 6 {
        panic!("incorrect arguments");
    }
    let output_path = &args[3];
    let file_name = &args[4];
    let piece_index = args[5].parse::<usize>().unwrap();
    let torrent = parse_torrent_file(file_name);
    let total_length = torrent.info.length;
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
    let mut stream = TcpStream::connect(addr).unwrap();
    let _peer_id = handshake(&mut stream, &torrent);
    {
        // bitfield
        let message = read_message(&mut stream);
        assert_eq!(message[0], 5);
    }
    {
        // interested
        let message = [0u8, 0, 0, 1, 2];
        stream.write_all(&message).unwrap();
        // unchoke
        let message = read_message(&mut stream);
        assert_eq!(message[0], 1); 
    }
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
            let message = read_message(&mut stream);
            if message.is_empty() {
                continue;
            }
            if message[0] != 7 {
                continue;
            }
            let data = &message[9..];
            output_bytes.extend(data);
            break;
        }
    }
    let mut hasher = Sha1::new();
    hasher.update(&output_bytes);
    let output_hash: [u8; 20] = hasher.finalize().into();
    let output_hash = hex::encode(&output_hash);
    let actual_hash = torrent
        .info
        .pieces
        .chunks(20)
        .skip(piece_index)
        .next()
        .unwrap();
    let actual_hash = hex::encode(&actual_hash);
    assert_eq!(output_hash, actual_hash);
    // write to output path
    let mut f = fs::File::create(output_path).unwrap();
    f.write_all(&output_bytes).unwrap();
    f.flush().unwrap();
    println!("Piece {} downloaded to {}", piece_index, output_path);
}

fn get_message_length(stream: &mut TcpStream) -> u32 {
    let mut buffer = [0u8; 4];
    stream.read_exact(&mut buffer).unwrap();
    u32::from_be_bytes(buffer)
}

fn read_message(stream: &mut TcpStream) -> Vec<u8> {
    let length = get_message_length(stream);
    let mut buffer = vec![0u8; length as usize];
    stream.read_exact(&mut buffer).unwrap();
    buffer
}


