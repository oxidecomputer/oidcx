// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Known remote identity providers and their principal entity builders.

use serde::Deserialize;

use crate::context::PrincipalBuilder;
use crate::policy;

/// Configuration for an OIDC identity provider. Each variant represents a
/// known provider type with its own claim structure and Cedar principal entity
/// type.
///
/// ```toml
/// [[providers]]
/// type = "github_actions"
/// url = "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
/// ```
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProviderConfig {
    GitHubActions { url: String },
}

impl ProviderConfig {
    /// The OIDC discovery URL for this provider.
    pub fn url(&self) -> &str {
        match self {
            ProviderConfig::GitHubActions { url } => url,
        }
    }

    /// The [`PrincipalBuilder`] that converts validated OIDC claims into the
    /// correct Cedar principal entity for this provider type.
    pub fn principal_builder(&self) -> PrincipalBuilder {
        match self {
            ProviderConfig::GitHubActions { .. } => policy::workflow_run_entity,
        }
    }
}
