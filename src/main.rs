use serde_json;
use std::env;

// Available if you need it!
use serde_bencode::value::Value as BencodeValue;

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

// Usage: your_bittorrent.sh decode "<encoded_value>"
fn main() {
    let args: Vec<String> = env::args().collect();
    let command = &args[1];

    if command == "decode" {
        let encoded_value = &args[2];
        let decoded_value = decode_bencoded_value(encoded_value);
        println!("{}", decoded_value.to_string());
    } else {
        println!("unknown command: {}", args[1])
    }
}
