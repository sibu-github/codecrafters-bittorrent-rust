use serde_json;
use sha1::{Digest, Sha1};
use std::{env, fs, io::{Read, Write}, net::TcpStream};

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

fn make_request(url: &str, info: &[u8], piece_length: i64) {
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
    resp.peers.as_slice().chunks(6).for_each(|d| {
        let port = u16::from_be_bytes([d[4], d[5]]);
        let addr = format!("{}.{}.{}.{}:{}", d[0], d[1], d[2], d[3], port);
        println!("{}", addr);
    });
}

fn handshake(file_name: &str, addr: &str) {
    let mut file = fs::File::open(file_name).unwrap();
    let length = file.metadata().unwrap().len();
    let mut data = Vec::with_capacity(length as usize);
    file.read_to_end(&mut data).unwrap();
    let data: Torrent = serde_bencode::from_bytes(&data).unwrap();
    let info = serde_bencode::to_bytes(&data.info).unwrap();
    let mut hasher = Sha1::new();
    hasher.update(&info);
    let info_hash = hasher.finalize();
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
    println!("{}", get_hash(&response[48..]));
}
