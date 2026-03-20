//! # Ziren Install
//!
//! A library for installing the Ziren circuit artifacts.

use cfg_if::cfg_if;
use std::path::PathBuf;
use zkm_prover::build::zkm_imm_wrap_vk_mode;

#[cfg(any(feature = "network", feature = "network"))]
use {
    crate::utils::block_on,
    futures::StreamExt,
    indicatif::{ProgressBar, ProgressStyle},
    reqwest::Client,
    std::{cmp::min, process::Command},
};

use crate::ZKM_CIRCUIT_VERSION;

/// The base URL for the S3 bucket containing the circuit artifacts.
pub const CIRCUIT_ARTIFACTS_URL_BASE: &str = "https://zkm-toolchain.s3.us-west-2.amazonaws.com";

/// The directory where the groth16 circuit artifacts will be stored.
#[must_use]
pub fn groth16_circuit_artifacts_dir(zkm_circuit_version: &str) -> PathBuf {
    if zkm_imm_wrap_vk_mode() {
        dirs::home_dir().unwrap().join(".zkm").join("circuits/groth16/imm-wrap-vk")
    } else {
        dirs::home_dir().unwrap().join(".zkm").join("circuits/groth16").join(zkm_circuit_version)
    }
}

/// The directory where the plonk circuit artifacts will be stored.
#[must_use]
pub fn plonk_circuit_artifacts_dir() -> PathBuf {
    dirs::home_dir().unwrap().join(".zkm").join("circuits/plonk").join(ZKM_CIRCUIT_VERSION)
}

/// Tries to install the groth16 circuit artifacts if they are not already installed.
/// zkm_circuit_version: The version of the circuit, e.g. "v1.0.0".
#[must_use]
pub fn try_install_circuit_artifacts(artifacts_type: &str, zkm_circuit_version: &str) -> PathBuf {
    let build_dir = if artifacts_type == "groth16" {
        groth16_circuit_artifacts_dir(zkm_circuit_version)
    } else if artifacts_type == "plonk" {
        plonk_circuit_artifacts_dir()
    } else {
        unimplemented!("unsupported artifacts type: {}", artifacts_type);
    };

    if build_dir.exists() {
        println!(
            "[zkm] {} circuit artifacts already seem to exist at {}. if you want to re-download them, delete the directory",
            artifacts_type,
            build_dir.display()
        );
    } else {
        cfg_if! {
            if #[cfg(feature = "network")] {
                println!(
                    "[zkm] {} circuit artifacts for version {} do not exist at {}. downloading...",
                    artifacts_type,
                    zkm_circuit_version,
                    build_dir.display()
                );
                install_circuit_artifacts(build_dir.clone(), artifacts_type, zkm_circuit_version);
            }
        }
    }
    build_dir
}

/// Install the specified version of circuit artifacts.
///
/// This function will download the latest circuit artifacts from the S3 bucket and extract them
/// to the directory specified by the provided `build_dir`.
#[cfg(feature = "network")]
#[allow(clippy::needless_pass_by_value)]
pub fn install_circuit_artifacts(
    build_dir: PathBuf,
    artifacts_type: &str,
    zkm_circuit_version: &str,
) {
    // Create the build directory.
    std::fs::create_dir_all(&build_dir).expect("failed to create build directory");

    // Download the artifacts.
    let download_url = if zkm_prover::build::zkm_imm_wrap_vk_mode() {
        format!("{CIRCUIT_ARTIFACTS_URL_BASE}/{artifacts_type}-imm-wrap-vk.tar.gz")
    } else {
        format!("{CIRCUIT_ARTIFACTS_URL_BASE}/{zkm_circuit_version}-{artifacts_type}.tar.gz")
    };
    let mut artifacts_tar_gz_file =
        tempfile::NamedTempFile::new().expect("failed to create tempfile");
    let client = Client::builder().build().expect("failed to create reqwest client");
    block_on(download_file(&client, &download_url, &mut artifacts_tar_gz_file))
        .expect("failed to download file");

    // Extract the tarball to the build directory.
    let mut res = Command::new("tar")
        .args([
            "-Pxzf",
            artifacts_tar_gz_file.path().to_str().unwrap(),
            "-C",
            build_dir.to_str().unwrap(),
        ])
        .spawn()
        .expect("failed to extract tarball");
    res.wait().unwrap();

    println!("[zkm] downloaded {} to {:?}", download_url, build_dir.to_str().unwrap(),);
}

/// Download the file with a progress bar that indicates the progress.
#[cfg(any(feature = "network", feature = "network"))]
pub async fn download_file(
    client: &Client,
    url: &str,
    file: &mut impl std::io::Write,
) -> std::result::Result<(), String> {
    let res = client.get(url).send().await.or(Err(format!("Failed to GET from '{}'", &url)))?;

    let total_size =
        res.content_length().ok_or(format!("Failed to get content length from '{}'", &url))?;

    let pb = ProgressBar::new(total_size);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})").unwrap()
        .progress_chars("#>-"));

    let mut downloaded: u64 = 0;
    let mut stream = res.bytes_stream();
    while let Some(item) = stream.next().await {
        let chunk = item.or(Err("Error while downloading file"))?;
        file.write_all(&chunk).or(Err("Error while writing to file"))?;
        let new = min(downloaded + (chunk.len() as u64), total_size);
        downloaded = new;
        pb.set_position(new);
    }
    pb.finish();

    Ok(())
}

/// Get the part start vkey for a given version.
/// version: The version of the circuit, e.g. "v1.0.0"
pub fn get_part_start_vk(zkm_circuit_version: &str) -> &'static [u8] {
    let groth16_bn254_artifacts = try_install_circuit_artifacts("groth16", zkm_circuit_version);
    let path = groth16_bn254_artifacts.join("part_stark_vk.bin");
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("failed to read part_stark_vk.bin at {path:?}: {e}"));
    Box::leak(bytes.into_boxed_slice())
}
