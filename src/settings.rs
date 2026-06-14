// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;
use std::path::PathBuf;

use config::{Config, ConfigError, File};
use serde::Deserialize;

use crate::providers::ProviderConfig;

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub audience: String,
    pub policy_path: PathBuf,
    pub log_directory: Option<String>,
    pub port: Option<u16>,
    pub providers: Vec<ProviderConfig>,
    #[serde(default)]
    pub oxide: Option<SettingsOxide>,
    #[serde(default)]
    pub github: Option<SettingsGitHubApp>,
}

impl Settings {
    pub fn new(config_sources: Option<Vec<String>>) -> Result<Self, ConfigError> {
        let mut config =
            Config::builder().add_source(File::with_name("settings.toml").required(false));

        for source in config_sources.unwrap_or_default() {
            config = config.add_source(File::with_name(&source).required(false));
        }

        config.build()?.try_deserialize()
    }
}

#[derive(Debug, Deserialize)]
pub struct SettingsOxide {
    #[serde(default = "default_max_duration")]
    pub max_duration: u32,
    #[serde(default = "default_allow_tokens_without_expiry")]
    pub allow_tokens_without_expiry: bool,
    #[serde(default)]
    pub silos: HashMap<String, PathBuf>,
}

#[derive(Debug, Deserialize)]
pub struct SettingsGitHubApp {
    pub client_id: String,
    pub private_key_path: PathBuf,
}

fn default_max_duration() -> u32 {
    3600
}

fn default_allow_tokens_without_expiry() -> bool {
    false
}
