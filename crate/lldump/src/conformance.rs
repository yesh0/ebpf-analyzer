use std::{io, fs};

/// Wrapper for bpf_conformance debug output
pub struct ConformanceData {
    pub name: String,
    pub memory: Vec<u8>,
    pub returns: u64,
    pub code: Vec<u64>,
    pub error: String,
}

fn parse_bytes(s: &str) -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    for byte in s.split_ascii_whitespace() {
        v.push(u8::from_str_radix(byte, 16).ok().unwrap());
    }
    v
}

/// Decodes [bpf_conformance](https://github.com/Alan-Jowett/bpf_conformance) debug output
pub fn get_conformance_data(path: &str) -> Result<ConformanceData, io::Error> {
    let content = fs::read_to_string(path)?;
    println!("Full content:\n{}\n", &content);
    let mut data = ConformanceData {
        name: path.into(),
        memory: Vec::new(),
        returns: 0,
        code: Vec::new(),
        error: String::new(),
    };
    for line in content.split('\n') {
        if let Some(info) = line.strip_prefix("Test file: ") {
            data.name = info.into();
        } else if let Some(info) = line.strip_prefix("Input memory: ") {
            data.memory = parse_bytes(info);
        } else if let Some(info) = line.strip_prefix("Expected return value: ") {
            data.returns = info.parse().unwrap();
        } else if let Some(info) = line.strip_prefix("Expected error string: ") {
            data.error = info.into();
        } else if let Some(info) = line.strip_prefix("Byte code: ") {
            assert_eq!(info.len() % 8, 0);
            data.code.clear();
            data.code.reserve(info.len() / 8);
            for dw in parse_bytes(info).chunks(8) {
                let mut array: [u8; 8] = Default::default();
                array.copy_from_slice(dw);
                data.code.push(u64::from_ne_bytes(array));
            }
        }
    }
    Ok(data)
}