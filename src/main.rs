use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek};
use flate2::read::GzDecoder;
use zstd::stream::read::Decoder as ZstdDecoder;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use base64::{Engine as _, engine::general_purpose};
use json::JsonValue;

fn csv_header(json_obj: &json::JsonValue) -> String {
    let mut header = String::new();
    for (key, _) in json_obj.entries() {
        if key == "Samples" {
            for i in 0..3 {
                header.push_str(&format!("Samples_{},", i));
            }
            continue;
        } else {
            header.push_str(&format!("{},", key));
        }
    }
    header.push_str("SYN,ACK,FIN,RST,PSH,URG,EventType");
    header
}

fn conv_to_csv(json_obj: JsonValue) -> String {
    let mut csv = String::new();
    for (name, value) in json_obj.entries() {
        if value.is_array() {
            if name == "Samples" {
                for value in value.members() {
                    csv.push_str(&format!("\"{}\",", value));
                }

                if value.len() < 3 {
                    for _ in value.len()..3 {
                        csv.push_str(&"\"\",".to_string());
                    }
                }
            } else if name == "RDNS" {
                if value.len() >= 1 {
                    csv.push_str(&format!("\"{}\",", value[0]));
                } else if value.len() == 0 {
                    csv.push_str(&"\"\",");
                } else {
                    // This will never happen
                    eprintln!("Unexpected number of elements in RDNS field.");
                    eprintln!("{:?}", json_obj);
                }
            } else {
                eprintln!("Unknown array: {}", name);
            }
        } else {
            csv.push_str(&format!("\"{}\",", value));
        };
    }

    csv.pop();
    csv
}

fn determine_scanner_or_backscatter(obj: &JsonValue) -> String {
    let traffic = obj["Traffic"].as_i32().unwrap();
    if ((obj["SYN"].as_bool().unwrap() || obj["FIN"].as_bool().unwrap())
        && (! obj["ACK"].as_bool().unwrap())) ||
        (traffic == 0) ||
        (traffic == 15 &&
            ! obj["SYN"].as_bool().unwrap() &&
            ! obj["ACK"].as_bool().unwrap() &&
            ! obj["FIN"].as_bool().unwrap() &&
            ! obj["PSH"].as_bool().unwrap() &&
            ! obj["URG"].as_bool().unwrap()){
        "Scanner".to_string()
    } else if (traffic > 0 && traffic < 11) ||
        (traffic > 11 && traffic < 16) {
        "Backscatter".to_string()
    } else {
        "Unknown".to_string()
    }
}

fn extract_tcp_flags(sample: &str) -> (bool, bool, bool, bool, bool, bool) {
    let decoded_sample: Vec<u8> = general_purpose::STANDARD.decode(sample).unwrap();

    if let Some(eth) = EthernetPacket::new(&decoded_sample) {
        if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
            if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                let syn = tcp.get_flags() & 0b0000_0010 != 0;
                let ack = tcp.get_flags() & 0b0001_0000 != 0;
                let fin = tcp.get_flags() & 0b0000_0001 != 0;
                let rst = tcp.get_flags() & 0b0000_0100 != 0;
                let psh = tcp.get_flags() & 0b0000_1000 != 0;
                let urg = tcp.get_flags() & 0b0010_0000 != 0;
                return (syn, ack, fin, rst, psh, urg);
            }
        }
    }

    (false, false, false, false, false, false)
}

fn main() -> io::Result<()>{
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <file> ...", args[0]);
        std::process::exit(1);
    }

    for x in 1..args.len() {
        let file_path = &args[x];

        let mut file = File::open(file_path)?;

        let mut buffer = [0; 4];
        file.read_exact(&mut buffer)?;
        file.seek(io::SeekFrom::Start(0))?;

        let reader: Box<dyn BufRead> = if buffer == [0x28, 0xb5, 0x2f, 0xfd] {
            Box::new(BufReader::new(ZstdDecoder::new(file)?))
        } else if buffer[0] == 0x1f && buffer[1] == 0x8b {
            Box::new(BufReader::new(GzDecoder::new(file)))
        } else {
            Box::new(BufReader::new(file))
        };

        let mut header_written = false;

        let mut counter = 0;

        for line in reader.lines() {
            if counter <= 2000 {
                counter += 1;
                continue;
            }
            counter = 0;
            let mut obj = json::parse(&line?).unwrap();

            if !header_written {
                println!("{}", csv_header(&obj));
                header_written = true;
            }

            if let Some(x) = &obj["Traffic"].as_i32() {
                match x {
                    11..=15 => {
                        if let Some(x) = &obj["Samples"][0].as_str() {
                            let (syn, ack, fin, rst, psh, urg) = extract_tcp_flags(x);
                            obj["SYN"] = JsonValue::Boolean(syn);
                            obj["ACK"] = JsonValue::Boolean(ack);
                            obj["FIN"] = JsonValue::Boolean(fin);
                            obj["RST"] = JsonValue::Boolean(rst);
                            obj["PSH"] = JsonValue::Boolean(psh);
                            obj["URG"] = JsonValue::Boolean(urg);
                        } else {
                            obj["SYN"] = JsonValue::Boolean(false);
                            obj["ACK"] = JsonValue::Boolean(false);
                            obj["FIN"] = JsonValue::Boolean(false);
                            obj["RST"] = JsonValue::Boolean(false);
                            obj["PSH"] = JsonValue::Boolean(false);
                            obj["URG"] = JsonValue::Boolean(false);
                        }
                    }
                    _ => {
                        obj["SYN"] = JsonValue::Boolean(false);
                        obj["ACK"] = JsonValue::Boolean(false);
                        obj["FIN"] = JsonValue::Boolean(false);
                        obj["RST"] = JsonValue::Boolean(false);
                        obj["PSH"] = JsonValue::Boolean(false);
                        obj["URG"] = JsonValue::Boolean(false);
                    }
                }
            }

            obj["EventType"] = JsonValue::String(determine_scanner_or_backscatter(&obj));

            println!("{}", conv_to_csv(obj));
        }
    }

    Ok(())
}
