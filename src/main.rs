use serde_json;
use std::{env, fs, io::Read};
use sha1::{Sha1, Digest};

use serde::{Serialize, Deserialize};
use serde_bytes::ByteBuf;
use serde_bencode::value::Value as BencodeValue;

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
    } else if command == "info" {
        let file_name = &args[2];
        let mut file = fs::File::open(file_name).unwrap();
        let length = file.metadata().unwrap().len();
        let mut data = Vec::with_capacity(length as usize);
        file.read_to_end(&mut data).unwrap();
        let data: Torrent = serde_bencode::from_bytes(&data).unwrap();
        let info = serde_bencode::to_bytes(&data.info).unwrap();
        println!("Tracker URL: {}", data.announce.unwrap());
        println!("Length: {}", data.info.length.unwrap());
        println!("Info Hash: {}", get_hash(&info));
        let piece_length = data.info.piece_length as usize;
        println!("Piece Length: {}", piece_length);
        println!("Piece Hashes:");
        let pieces = data.info.pieces.as_slice();
        pieces.chunks(20).for_each(|d| println!("{}", hex::encode(d)));
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
