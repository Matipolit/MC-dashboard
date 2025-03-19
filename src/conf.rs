use std::{env::home_dir, fs, path::PathBuf};

use config::{Config, ConfigError, File};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppConfig {
    pub server_url: String,
    pub password: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        AppConfig {
            server_url: "http://localhost:3000".into(),
            password: "123".into(),
        }
    }
}

impl AppConfig {
    pub fn load() -> Result<Self, ConfigError> {
        let config_path = format!(
            "{}/.config/fabric-dash/Settings.toml",
            home_dir().unwrap().to_str().unwrap()
        );
        let config = Config::builder()
            .add_source(File::with_name(&config_path))
            .build()?;

        config.try_deserialize()
    }

    pub fn save(&self) -> std::io::Result<()> {
        let config_path = PathBuf::from(format!(
            "{}/.config/timely/Settings.toml",
            home_dir().unwrap().to_str().unwrap()
        ));
        let toml_string = toml::to_string(self).unwrap();
        fs::write(config_path, toml_string)
    }
}
