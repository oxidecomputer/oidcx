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
    #[serde(rename = "github_actions")]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_github_actions_provider() {
        let config: ProviderConfig = serde_json::from_value(serde_json::json!({
            "type": "github_actions",
            "url": "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
        }))
        .unwrap();

        assert!(
            matches!(config, ProviderConfig::GitHubActions { .. }),
            "expected GitHubActions variant, got: {config:?}"
        );
        assert_eq!(
            config.url(),
            "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
        );
    }

    #[test]
    fn deserialize_unknown_type_is_error() {
        let result = serde_json::from_value::<ProviderConfig>(serde_json::json!({
            "type": "unknown_provider",
            "url": "https://example.com"
        }));

        assert!(
            result.is_err(),
            "unknown provider type should fail deserialization"
        );
    }

    #[test]
    fn deserialize_missing_type_is_error() {
        let result = serde_json::from_value::<ProviderConfig>(serde_json::json!({
            "url": "https://example.com"
        }));

        assert!(
            result.is_err(),
            "missing type field should fail deserialization"
        );
    }

    #[test]
    fn principal_builder_produces_correct_entity_type() {
        let config: ProviderConfig = serde_json::from_value(serde_json::json!({
            "type": "github_actions",
            "url": "https://example.com"
        }))
        .unwrap();

        let builder = config.principal_builder();
        let claims = crate::oidc::Claims::from_json(serde_json::json!({
            "jti": "test-id",
            "iss": "https://token.actions.githubusercontent.com",
            "repository": "oxidecomputer/test",
            "repository_owner": "oxidecomputer",
            "repository_visibility": "public",
            "event_name": "push",
        }));
        let entity = builder(&claims).unwrap();
        assert_eq!(entity.uid().type_name().to_string(), "Oidcx::WorkflowRun");
    }
}
