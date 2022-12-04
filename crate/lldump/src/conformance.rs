use std::{
    collections::hash_map::DefaultHasher,
    env, fs,
    hash::{Hash, Hasher},
    io,
    path::Path,
    process::{self, Stdio}, str::from_utf8,
};

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
            let bytes = parse_bytes(info);
            assert_eq!(bytes.len() % 8, 0);
            data.code.clear();
            data.code.reserve(bytes.len() / 8);
            for dw in bytes.chunks(8) {
                let mut array: [u8; 8] = Default::default();
                array.copy_from_slice(dw);
                data.code.push(u64::from_ne_bytes(array));
            }
        }
    }
    Ok(data)
}

pub const BPF_CONF_PLUGIN: &str = "BPF_CONF_PLUGIN";
pub const BPF_CONF_RUNNER: &str = "BPF_CONF_RUNNER";
pub const BPF_CONF_TEMP: &str = "BPF_CONF_TEMP";

/// Compiles the eBPF assembly using bpf_conformance
///
/// This requires correctly configuring the testing environment:
/// 1. Compile bpf_conformance;
/// 2. Point the environment variable `BPF_CONF_RUNNER` to the runner;
/// 3. Provide the env var `BPF_CONF_TEMP`, or make sure that `/tmp` is writable;
/// 4. Set the env var `BPF_CONF_PLUGIN` to some random binary (defaulting to `/bin/true`).
///
/// It panics otherwise.
pub fn assemble(asm: &str) -> ConformanceData {
    let runner = env::var(BPF_CONF_RUNNER).ok().unwrap();
    let temp = env::var(BPF_CONF_TEMP).ok().unwrap_or("/tmp".into());
    let plugin = env::var(BPF_CONF_PLUGIN).ok().unwrap_or("/bin/true".into());

    let dir = format!("{temp}/bpf_asm");
    assert!(fs::create_dir_all(Path::new(&dir)).is_ok());

    let mut hasher = DefaultHasher::new();
    asm.hash(&mut hasher);
    let hash = hasher.finish();
    let output = format!("{dir}/{hash:x}.data");

    assert!(fs::write(
        Path::new(&output),
        format!("-- asm\n{asm}\n-- result\n0x0\n")
    )
    .is_ok());

    let child = process::Command::new(runner)
        .arg("--test_file_path")
        .arg(&output)
        .arg("--plugin_path")
        .arg(plugin)
        .arg("--debug")
        .arg("true")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()
        .unwrap();

    let child_output = child.wait_with_output().ok().unwrap();
    let err_data = from_utf8(&child_output.stderr).ok().unwrap();
    let file = format!("{output}.txt");
    assert!(fs::write(&file, err_data).is_ok());

    get_conformance_data(&file).ok().unwrap()
}
