use crate::error::{GhidraError, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub ghidra_install_dir: Option<PathBuf>,
    pub ghidra_project_dir: Option<PathBuf>,
    /// Full JDK home for Ghidra to use (must be a JDK, not a JRE). When unset,
    /// ghidra-cli auto-detects a suitable JDK.
    #[serde(default)]
    pub java_home: Option<PathBuf>,
    pub default_program: Option<String>,
    pub default_project: Option<String>,
    pub default_output_format: Option<String>,
    pub default_limit: Option<usize>,
    pub timeout: Option<u64>,
    pub aliases: std::collections::HashMap<String, String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ghidra_install_dir: None,
            ghidra_project_dir: None,
            java_home: None,
            default_program: None,
            default_project: None,
            default_output_format: Some("auto".to_string()),
            default_limit: Some(1000),
            timeout: Some(300),
            aliases: std::collections::HashMap::new(),
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        let config_path = Self::config_path()?;

        if !config_path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(&config_path)?;
        let config: Config = serde_yaml::from_str(&content)?;

        Ok(config)
    }

    pub fn save(&self) -> Result<()> {
        let config_path = Self::config_path()?;

        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = serde_yaml::to_string(self)?;
        fs::write(config_path, content)?;

        Ok(())
    }

    pub fn config_path() -> Result<PathBuf> {
        // Check for override via environment variable
        if let Ok(path) = std::env::var("GHIDRA_CLI_CONFIG") {
            return Ok(PathBuf::from(path));
        }

        let config_dir = dirs::config_dir().ok_or_else(|| {
            GhidraError::ConfigError("Could not determine config directory".to_string())
        })?;

        Ok(config_dir.join("ghidra-cli").join("config.yaml"))
    }

    pub fn get_ghidra_install_dir(&self) -> Result<PathBuf> {
        // Check environment variable first
        if let Ok(dir) = std::env::var("GHIDRA_INSTALL_DIR") {
            return Ok(PathBuf::from(dir));
        }

        // Check config
        if let Some(dir) = &self.ghidra_install_dir {
            return Ok(dir.clone());
        }

        // Try to auto-detect on Windows
        #[cfg(target_os = "windows")]
        {
            if let Some(dir) = Self::detect_ghidra_windows() {
                return Ok(dir);
            }
        }

        Err(GhidraError::GhidraNotFound)
    }

    pub fn get_project_dir(&self) -> Result<PathBuf> {
        // Check environment variable first
        if let Ok(dir) = std::env::var("GHIDRA_PROJECT_DIR") {
            return Ok(PathBuf::from(dir));
        }

        // Check config
        if let Some(dir) = &self.ghidra_project_dir {
            return Ok(dir.clone());
        }

        // Default to cache dir (e.g., ~/.cache/ghidra-cli/projects)
        let cache_dir = dirs::cache_dir().ok_or_else(|| {
            GhidraError::ConfigError("Could not determine cache directory".to_string())
        })?;

        Ok(cache_dir.join("ghidra-cli").join("projects"))
    }

    #[cfg(target_os = "windows")]
    pub fn detect_ghidra_windows() -> Option<PathBuf> {
        // Helper function to check if a path is a valid Ghidra installation
        let is_valid_ghidra =
            |path: &PathBuf| -> bool { path.join("support").join("analyzeHeadless.bat").exists() };

        // Check common installation paths
        let mut common_paths = vec![
            PathBuf::from("C:\\Program Files\\Ghidra"),
            PathBuf::from("C:\\Program Files (x86)\\Ghidra"),
            PathBuf::from("C:\\ghidra"),
        ];

        // Add user's home directory paths
        if let Some(home) = dirs::home_dir() {
            common_paths.push(home.join("ghidra"));
        }

        for path in common_paths {
            if !path.exists() {
                continue;
            }

            // First check if the path itself is a Ghidra installation
            if is_valid_ghidra(&path) {
                return Some(path);
            }

            // Look for ghidra_* subdirectories
            if let Ok(entries) = fs::read_dir(&path) {
                for entry in entries.flatten() {
                    let entry_path = entry.path();
                    if entry_path.is_dir() {
                        let name = entry_path.file_name()?.to_str()?;
                        if name.starts_with("ghidra_") && is_valid_ghidra(&entry_path) {
                            return Some(entry_path);
                        }
                    }
                }
            }
        }

        None
    }

    /// Explicit JDK home override: `GHIDRA_CLI_JAVA_HOME` env (set from the
    /// `--java-home` flag in main) takes precedence over the config value.
    pub fn get_java_home(&self) -> Option<PathBuf> {
        std::env::var("GHIDRA_CLI_JAVA_HOME")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .or_else(|| self.java_home.clone())
    }

    pub fn get_default_program(&self) -> Option<String> {
        std::env::var("GHIDRA_DEFAULT_PROGRAM")
            .ok()
            .or_else(|| self.default_program.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.timeout, Some(300));
        assert_eq!(config.default_limit, Some(1000));
    }
}
