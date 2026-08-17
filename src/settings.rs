// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use std::collections::HashMap;
use std::path::PathBuf;

use config::{Config, ConfigError, File};
use serde::Deserialize;
use v_api_param::{JsonParam, StringParam};

use crate::providers::ProviderConfig;

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub audience: StringParam,
    pub policy_path: PathBuf,
    pub log_directory: Option<String>,
    pub port: Option<u16>,
    pub providers: Vec<ProviderConfig>,
    #[serde(default)]
    pub oxide: Option<SettingsOxide>,
    #[serde(default)]
    pub github: Option<SettingsGitHubApp>,
    /// Base directory that file-backed `StringParam`/`SerializedParam` values
    /// are resolved against. Populated once from the `PARAMS_BASE_PATH`
    /// environment variable in [`Settings::new`] rather than from the config
    /// file itself.
    #[serde(skip)]
    pub params_base_path: Option<PathBuf>,
}

impl Settings {
    pub fn new(config_sources: Option<Vec<String>>) -> Result<Self, ConfigError> {
        let mut config =
            Config::builder().add_source(File::with_name("settings.toml").required(false));

        for source in config_sources.unwrap_or_default() {
            config = config.add_source(File::with_name(&source).required(false));
        }

        let mut settings: Settings = config.build()?.try_deserialize()?;
        // Read the params base path a single time here; every file-backed param
        // is resolved against it.
        settings.params_base_path = std::env::var_os("PARAMS_BASE_PATH").map(PathBuf::from);
        Ok(settings)
    }
}

#[derive(Debug, Deserialize)]
pub struct SettingsOxide {
    #[serde(default = "default_max_duration")]
    pub max_duration: u32,
    #[serde(default = "default_allow_tokens_without_expiry")]
    pub allow_tokens_without_expiry: bool,
    /// The silos this environment can issue tokens for.
    ///
    /// The manifest is a JSON object mapping each silo url to the credential
    /// used to mint tokens for it. Each credential is a v-api `StringParam`,
    /// so it may be an inline secret or a `{ "path": "..." }` reference to a
    /// secret file on the volume:
    ///
    /// ```json
    /// {
    ///   "https://oxide.sys.rack2.eng.oxide.computer": { "path": "/params/oxide-token" },
    ///   "https://example.sys.rack2.eng.oxide.computer": { "path": "/params/example-token" }
    /// }
    /// ```
    pub silos: JsonParam<HashMap<String, StringParam>>,
}

#[derive(Debug, Deserialize)]
pub struct SettingsGitHubApp {
    pub client_id: StringParam,
    /// PEM-encoded GitHub App private key. May be provided inline or, more
    /// commonly, as a `{ path = "..." }` reference to a key file on the
    /// parameters volume.
    pub private_key: StringParam,
}

fn default_max_duration() -> u32 {
    3600
}

fn default_allow_tokens_without_expiry() -> bool {
    false
}
