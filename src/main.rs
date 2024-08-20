use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek};
use flate2::read::GzDecoder;
use zstd::stream::read::Decoder as ZstdDecoder;

fn csv_header(json_obj: &json::JsonValue) -> String {
    let mut header = String::new();
    for (key, _) in json_obj.entries() {
        header.push_str(&format!("{},", key));
    }
    header.pop();
    header
}

fn conv_to_csv(json_obj: json::JsonValue) -> String {
    let mut csv = String::new();
    for (_, value) in json_obj.entries() {
        if value.is_array() {
            let mut array_str = format!("{}", value);
            array_str = array_str.replace("\"", "\\\"");
            csv.push_str(&format!("\"{}\",", array_str));
        } else {
            csv.push_str(&format!("\"{}\",", value));
        };
    }
    csv.pop();
    csv
}

fn determine_scanner_or_backscatter(traffic_type: i32) -> String {
    match traffic_type {
        0 | 11 => "Scanner".to_string(),
        16 | 17 => "Unknown".to_string(),
        _ => "Backscatter".to_string(),
    }
}

fn main() -> io::Result<()>{
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <file>", args[0]);
        std::process::exit(1);
    }
    let file_path = &args[1];

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

    for line in reader.lines() {
        let mut obj = json::parse(&line?).unwrap();

        if !header_written {
            println!("{}", csv_header(&obj));
            header_written = true;
        }

        obj["EventType"] = json::JsonValue::String(determine_scanner_or_backscatter(obj["Traffic"].as_i32().unwrap()));

        println!("{}", conv_to_csv(obj));
    }

    Ok(())
}
