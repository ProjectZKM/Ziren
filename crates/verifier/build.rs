use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const HISTORY_DIR: &str = "bn254-vk/history";
const PART_STARK_VK_SUFFIX: &str = "_part_stark_vk.bin";

fn main() {
    println!("cargo:rerun-if-changed={HISTORY_DIR}");

    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let history_dir = manifest_dir.join(HISTORY_DIR);
    let mut entries = collect_history_entries(&history_dir);
    if entries.is_empty() {
        panic!("no bundled part_stark_vk files found under {}", history_dir.display());
    }

    entries.sort_by(|left, right| left.0.cmp(&right.0));

    for (_, file_name) in &entries {
        println!("cargo:rerun-if-changed={HISTORY_DIR}/{file_name}");
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let registry = out_dir.join("part_stark_vk_registry.rs");
    let source = render_registry(&entries);
    fs::write(&registry, source).unwrap_or_else(|err| {
        panic!("failed to write registry {}: {err}", registry.display());
    });
}

fn collect_history_entries(history_dir: &Path) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    let read_dir = fs::read_dir(history_dir).unwrap_or_else(|err| {
        panic!("failed to read history dir {}: {err}", history_dir.display());
    });

    for entry in read_dir {
        let entry = entry.unwrap_or_else(|err| panic!("failed to iterate history dir: {err}"));
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if !file_name.ends_with(PART_STARK_VK_SUFFIX) {
            continue;
        }

        let version = file_name.trim_end_matches(PART_STARK_VK_SUFFIX).to_owned();
        entries.push((version, file_name.into_owned()));
    }

    entries
}

fn render_registry(entries: &[(String, String)]) -> String {
    let mut source =
        String::from("pub(crate) static BUNDLED_PART_STARK_VKS: &[(&str, &[u8])] = &[\n");

    for (version, file_name) in entries {
        source.push_str(&format!(
            "    (\"{version}\", include_bytes!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/{HISTORY_DIR}/{file_name}\"))),\n"
        ));
    }

    source.push_str("];\n");
    source
}
