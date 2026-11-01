use std::path::PathBuf;

use zkm_sdk::ZKMStdin;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out_dir = PathBuf::from(&args[1]);
    for input in &args[2..] {
        let path = PathBuf::from(input);
        let stem = path.file_name().unwrap().to_str().unwrap();
        let hex = stem.strip_suffix("_payload.rlp").expect("expected <hex>_payload.rlp");
        let block = u64::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap();
        let payload = std::fs::read(&path).unwrap();
        let mut stdin = ZKMStdin::new();
        stdin.write(&payload);
        let bytes = bincode::serialize(&stdin).unwrap();
        std::fs::write(out_dir.join(format!("{block}-stdin.bin")), bytes).unwrap();
        println!("{block}");
    }
}
