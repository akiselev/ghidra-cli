use anyhow::{anyhow, Context, Result};
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Deserialize;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

/// GitHub release asset information
#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
    size: u64,
}

/// GitHub release information
#[derive(Deserialize, Debug)]
struct GithubRelease {
    tag_name: String,
    assets: Vec<GithubAsset>,
}

/// Resolve the download URL for a Ghidra release.
/// If version is None, fetches the latest release.
pub async fn resolve_version_url(version: Option<String>) -> Result<(String, String, String)> {
    let mut headers = reqwest::header::HeaderMap::new();
    // Use GITHUB_TOKEN if available (avoids 60 req/hour unauthenticated rate limit)
    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        headers.insert(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", token).parse()?,
        );
    }

    let client = reqwest::Client::builder()
        .user_agent("ghidra-cli")
        .default_headers(headers)
        .build()?;

    let release: GithubRelease = if let Some(ver) = version {
        // Fetch specific version
        let url = format!(
            "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/tags/Ghidra_{}",
            ver
        );
        println!("Fetching release info for Ghidra {}...", ver);
        client
            .get(&url)
            .send()
            .await?
            .error_for_status()
            .context(format!("Could not find Ghidra version {}", ver))?
            .json()
            .await?
    } else {
        // Fetch latest release
        let url = "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest";
        println!("Fetching latest Ghidra release info...");
        client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?
    };

    println!("Found release: {}", release.tag_name);

    // Find the zip file in assets
    let zip_asset = release
        .assets
        .iter()
        .find(|a| a.name.ends_with(".zip") && !a.name.contains("src"))
        .ok_or_else(|| anyhow!("No zip distribution found in release assets"))?;

    Ok((
        zip_asset.browser_download_url.clone(),
        zip_asset.name.clone(),
        release.tag_name,
    ))
}

/// Download a file with progress bar.
pub async fn download_file(url: &str, path: &Path) -> Result<()> {
    let client = reqwest::Client::builder()
        .user_agent("ghidra-cli")
        .build()?;

    let res = client
        .get(url)
        .send()
        .await?
        .error_for_status()
        .context("Download request failed")?;

    let total_size = res.content_length().unwrap_or(0);

    let pb = ProgressBar::new(total_size);
    pb.set_style(ProgressStyle::default_bar()
        .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})")?
        .progress_chars("#>-"));
    pb.set_message(format!(
        "Downloading {}",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));

    let mut file = File::create(path)?;
    let mut stream = res.bytes_stream();

    while let Some(item) = stream.next().await {
        let chunk = item.context("Error reading download stream")?;
        file.write_all(&chunk)?;
        pb.inc(chunk.len() as u64);
    }

    pb.finish_with_message("Download complete");
    Ok(())
}

/// Extract a zip file to the target directory.
/// Returns the path to the extracted Ghidra directory.
pub fn extract_zip(zip_path: &Path, target_dir: &Path) -> Result<PathBuf> {
    println!("Extracting...");

    let file = File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    let total_files = archive.len();
    let pb = ProgressBar::new(total_files as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len}",
            )?
            .progress_chars("#>-"),
    );
    pb.set_message("Extracting files");

    // Track the root directory from the archive
    let mut root_dir: Option<PathBuf> = None;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = match file.enclosed_name() {
            Some(path) => target_dir.join(path),
            None => continue,
        };

        // Capture the root directory (first path component)
        if root_dir.is_none() {
            if let Some(first_component) = file.enclosed_name().and_then(|p| p.components().next())
            {
                root_dir = Some(target_dir.join(first_component.as_os_str()));
            }
        }

        if file.name().ends_with('/') {
            std::fs::create_dir_all(&outpath)?;
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    std::fs::create_dir_all(p)?;
                }
            }
            let mut outfile = File::create(&outpath)?;
            std::io::copy(&mut file, &mut outfile)?;
        }

        // Set permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some(mode) = file.unix_mode() {
                std::fs::set_permissions(&outpath, std::fs::Permissions::from_mode(mode)).ok();
            }
        }

        pb.inc(1);
    }

    pb.finish_with_message("Extraction complete");

    root_dir.ok_or_else(|| anyhow!("Could not determine extracted directory"))
}

/// Install Ghidra to the specified directory.
/// Returns the path to the installed Ghidra directory.
pub async fn install_ghidra(version: Option<String>, target_dir: PathBuf) -> Result<PathBuf> {
    // Resolve version and get download URL
    let (download_url, filename, tag) = resolve_version_url(version).await?;

    println!("Installing Ghidra {} to: {}", tag, target_dir.display());

    // Download the zip file
    let zip_path = target_dir.join(&filename);
    download_file(&download_url, &zip_path).await?;

    // Extract the zip
    let install_path = extract_zip(&zip_path, &target_dir)?;

    // Cleanup zip file
    if let Err(e) = std::fs::remove_file(&zip_path) {
        println!("⚠ Could not remove zip file: {}", e);
    }

    Ok(install_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ghidra_min_java_defaults() {
        // Unknown install dir falls back to the documented default floor.
        let min = crate::ghidra::java::ghidra_min_java(std::path::Path::new("/nonexistent"));
        assert_eq!(min, crate::ghidra::java::DEFAULT_MIN_JAVA);
    }
}
