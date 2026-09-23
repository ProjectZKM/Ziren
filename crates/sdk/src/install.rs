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
    std::cmp::min,
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

/// The kinds of circuit artifacts that can be installed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CircuitArtifacts {
    Groth16,
    Plonk,
}

impl CircuitArtifacts {
    /// The name the artifact bucket and the install directory use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Groth16 => "groth16",
            Self::Plonk => "plonk",
        }
    }
}

/// Tries to install the circuit artifacts if they are not already installed.
/// zkm_circuit_version: The version of the circuit, e.g. "v1.0.0".
#[must_use]
pub fn try_install_circuit_artifacts(
    artifacts: CircuitArtifacts,
    zkm_circuit_version: &str,
) -> PathBuf {
    let artifacts_type = artifacts.as_str();
    let build_dir = match artifacts {
        CircuitArtifacts::Groth16 => groth16_circuit_artifacts_dir(zkm_circuit_version),
        CircuitArtifacts::Plonk => plonk_circuit_artifacts_dir(),
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

    let staging = build_dir.with_extension(format!("staging-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).expect("failed to create staging directory");

    if let Err(e) = extract_contained(artifacts_tar_gz_file.path(), &staging) {
        let _ = std::fs::remove_dir_all(&staging);
        panic!("failed to extract circuit artifacts from {download_url}: {e}");
    }

    let _ = std::fs::remove_dir_all(&build_dir);
    if let Some(parent) = build_dir.parent() {
        std::fs::create_dir_all(parent).expect("failed to create build directory parent");
    }
    std::fs::rename(&staging, &build_dir).expect("failed to install circuit artifacts");

    println!("[zkm] downloaded {} to {:?}", download_url, build_dir.to_str().unwrap(),);
}

/// Extract a `.tar.gz` into `dest`, refusing any entry that would write outside
/// it.
///
/// The archive is fetched over the network and is not pinned by digest or
/// signature, so it is treated as untrusted input: an absolute path, a `..`
/// component, or a link escaping `dest` aborts the extraction rather than
/// landing anywhere on the host. This replaces `tar -Pxzf`, whose `-P` kept
/// absolute paths and made a compromised archive an arbitrary file overwrite.
#[cfg(feature = "network")]
fn extract_contained(archive: &std::path::Path, dest: &std::path::Path) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    use std::path::{Component, Path};

    let dest_root = dest.canonicalize()?;
    let bad = |msg: String| Error::new(ErrorKind::InvalidData, msg);

    let contained = |p: &Path| -> std::io::Result<()> {
        for c in p.components() {
            match c {
                Component::Normal(_) | Component::CurDir => {}
                Component::ParentDir => {
                    return Err(bad(format!(
                        "entry escapes the install directory: {}",
                        p.display()
                    )))
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Err(bad(format!("entry has an absolute path: {}", p.display())))
                }
            }
        }
        Ok(())
    };

    let file = std::fs::File::open(archive)?;
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(file));
    tar.set_preserve_permissions(false);
    tar.set_unpack_xattrs(false);

    for entry in tar.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        contained(&path)?;

        if let Some(link) = entry.link_name()? {
            contained(&link)?;
            let base = if entry.header().entry_type().is_hard_link() {
                dest_root.clone()
            } else {
                dest_root.join(&path).parent().unwrap_or(&dest_root).to_path_buf()
            };
            if !base.join(&link).starts_with(&dest_root) {
                return Err(bad(format!(
                    "link target escapes the install directory: {}",
                    link.display()
                )));
            }
        }

        let kind = entry.header().entry_type();
        if !(kind.is_file() || kind.is_dir() || kind.is_symlink() || kind.is_hard_link()) {
            return Err(bad(format!("unsupported archive entry type for {}", path.display())));
        }

        entry.unpack_in(&dest_root)?;
    }
    Ok(())
}

/// Download the file with a progress bar that indicates the progress.
#[cfg(any(feature = "network", feature = "network"))]
pub async fn download_file(
    client: &Client,
    url: &str,
    file: &mut impl std::io::Write,
) -> std::result::Result<(), String> {
    let res = client.get(url).send().await.or(Err(format!("Failed to GET from '{}'", url)))?;
    let res = res.error_for_status().map_err(|e| format!("Request for '{}' failed: {}", url, e))?;

    let total_size =
        res.content_length().ok_or(format!("Failed to get content length from '{}'", url))?;

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

#[cfg(all(test, feature = "network"))]
mod tests {
    use super::extract_contained;
    use std::io::Write;
    use std::path::Path;

    /// Build a `.tar.gz` with one entry, writing the name straight into the
    /// header bytes.
    ///
    /// `Builder::append_data` validates the path itself and refuses `..` and
    /// absolute names, so it cannot produce the archives this module has to
    /// test against. `append` writes a caller-built header verbatim, which is
    /// exactly what a hostile packer would do.
    fn archive_with(header: tar::Header, path: &str, body: &[u8]) -> tempfile::NamedTempFile {
        let f = tempfile::NamedTempFile::new().unwrap();
        let enc = flate2::write::GzEncoder::new(f.reopen().unwrap(), flate2::Compression::none());
        let mut b = tar::Builder::new(enc);
        let mut header = header;
        header.set_size(body.len() as u64);
        {
            let raw = header.as_mut_bytes();
            let name = path.as_bytes();
            assert!(name.len() < 100, "test names stay in the short-name field");
            raw[..100].fill(0);
            raw[..name.len()].copy_from_slice(name);
        }
        header.set_cksum();
        b.append(&header, body).unwrap();
        b.into_inner().unwrap().finish().unwrap();
        f
    }

    fn file_header() -> tar::Header {
        let mut h = tar::Header::new_gnu();
        h.set_mode(0o644);
        h.set_cksum();
        h
    }

    fn extract_to_fresh_dir(a: &tempfile::NamedTempFile) -> std::io::Result<tempfile::TempDir> {
        let dest = tempfile::tempdir().unwrap();
        extract_contained(a.path(), dest.path())?;
        Ok(dest)
    }

    #[test]
    fn plain_entry_extracts() {
        let a = archive_with(file_header(), "vk.bin", b"ok");
        let dest = extract_to_fresh_dir(&a).expect("honest archive must extract");
        assert_eq!(std::fs::read(dest.path().join("vk.bin")).unwrap(), b"ok");
    }

    #[test]
    fn parent_traversal_is_rejected() {
        let a = archive_with(file_header(), "../escaped.bin", b"pwn");
        let err = extract_to_fresh_dir(&a).unwrap_err();
        assert!(err.to_string().contains("escapes"), "got: {err}");
    }

    #[test]
    fn absolute_path_is_rejected() {
        let a = archive_with(file_header(), "/tmp/zkm-absolute-escape.bin", b"pwn");
        let err = extract_to_fresh_dir(&a).unwrap_err();
        assert!(
            err.to_string().contains("absolute") || err.to_string().contains("escapes"),
            "got: {err}"
        );
        assert!(!Path::new("/tmp/zkm-absolute-escape.bin").exists(), "wrote outside dest");
    }

    #[test]
    fn symlink_escaping_dest_is_rejected() {
        let mut h = tar::Header::new_gnu();
        h.set_mode(0o777);
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_link_name("/etc").unwrap();
        h.set_cksum();
        let a = archive_with(h, "link", b"");
        let err = extract_to_fresh_dir(&a).unwrap_err();
        assert!(
            err.to_string().contains("escapes") || err.to_string().contains("absolute"),
            "got: {err}"
        );
    }

    #[test]
    fn device_nodes_are_rejected() {
        let mut h = tar::Header::new_gnu();
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Char);
        h.set_cksum();
        let a = archive_with(h, "dev/null", b"");
        let err = extract_to_fresh_dir(&a).unwrap_err();
        assert!(err.to_string().contains("unsupported"), "got: {err}");
    }

    #[test]
    fn truncated_archive_is_an_error_not_a_partial_install() {
        let good = archive_with(file_header(), "vk.bin", b"0123456789");
        let bytes = std::fs::read(good.path()).unwrap();
        let mut t = tempfile::NamedTempFile::new().unwrap();
        t.write_all(&bytes[..bytes.len() / 2]).unwrap();
        t.flush().unwrap();
        assert!(extract_to_fresh_dir(&t).is_err(), "truncated archive must not report success");
    }
}
