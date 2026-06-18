pub mod bridge;
pub mod java;
pub mod setup;

use crate::config::Config;
use crate::error::{GhidraError, Result};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct GhidraClient {
    install_dir: PathBuf,
    project_dir: PathBuf,
}

impl GhidraClient {
    pub fn new(config: Config) -> Result<Self> {
        let install_dir = config.get_ghidra_install_dir()?;
        let project_dir = config.get_project_dir()?;

        // Create project directory if it doesn't exist
        if !project_dir.exists() {
            std::fs::create_dir_all(&project_dir)?;
        }

        Ok(Self {
            install_dir,
            project_dir,
        })
    }

    pub fn verify_installation(&self) -> Result<()> {
        bridge::find_headless_script(&self.install_dir).map_err(|_| GhidraError::GhidraNotFound)?;
        Ok(())
    }

    pub fn get_project_path(&self, project_name: &str) -> PathBuf {
        self.project_dir.join(project_name)
    }

    pub fn project_exists(&self, project_name: &str) -> bool {
        let project_path = self.get_project_path(project_name);
        project_path.exists() && project_path.join(format!("{}.rep", project_name)).exists()
    }

    pub fn create_project(&self, project_name: &str) -> Result<()> {
        let project_path = self.get_project_path(project_name);

        if self.project_exists(project_name) {
            return Ok(());
        }

        // Ghidra creates the project automatically when you import or process a file
        // Just create the directory structure
        std::fs::create_dir_all(&project_path)?;

        Ok(())
    }

    pub fn get_project_dir(&self) -> &Path {
        &self.project_dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ghidra_client_creation() {
        // This will fail if GHIDRA_INSTALL_DIR is not set, which is expected
        let config = Config::default();
        let result = GhidraClient::new(config);

        // We can't test this properly without a Ghidra installation
        // Just verify the error is what we expect
        if let Err(e) = result {
            assert!(matches!(e, GhidraError::GhidraNotFound));
        }
    }
}
