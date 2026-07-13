// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    collections::HashMap,
    error::Error as StdError,
    sync::{Arc, RwLock},
};
use thiserror::Error;

use cedar_policy::{Entity, PolicySet, Schema};

use crate::{
    oidc::{Claims, OidcError, OidcProvider, ResolvedOidcConfig},
    policy::{Policy, PolicyError},
    settings::Settings,
    token::{
        github::{GitHubTokenError, GitHubTokens},
        oxide::{OxideError, OxideTokens},
    },
};

#[derive(Debug, Error)]
pub enum ContextBuildError {
    #[error("Failed to construct client")]
    ClientConstruction(Box<dyn StdError + Send + Sync>),
    #[error("Failed to initialize the Oxide token store")]
    OxideTokens(#[from] OxideError),
    #[error("Failed to initialize the GitHub token store")]
    GitHubTokens(#[from] GitHubTokenError),
    #[error("Encountered an error configuring OIDC providers")]
    Oidc(#[from] OidcError),
    #[error("Failed to initialize the Cedar policy engine")]
    Policy(#[from] PolicyError),
}

/// A function that builds a Cedar principal [`Entity`] from validated OIDC
/// [`Claims`]. Each identity provider has its own builder because different
/// issuers produce tokens with different claim structures and map to different
/// Cedar entity types.
pub type PrincipalBuilder = fn(&Claims) -> Result<Entity, PolicyError>;

#[derive(Debug)]
pub struct ResolvedOidcProvider {
    pub config: ResolvedOidcConfig,
    pub build_principal: PrincipalBuilder,
}

#[derive(Debug)]
pub struct Context {
    pub settings: Settings,
    pub providers: HashMap<String, Arc<RwLock<ResolvedOidcProvider>>>,
    pub oxide_tokens: OxideTokens,
    pub github_tokens: GitHubTokens,
    pub policy: Policy,
}

impl Context {
    pub async fn new(settings: Settings) -> Result<Self, ContextBuildError> {
        let client = reqwest::Client::new();

        let mut providers = HashMap::new();
        for provider_config in &settings.providers {
            let config = OidcProvider::new(provider_config.url().to_string())
                .fetch_config(&client)
                .await?
                .resolve(&client)
                .await?;

            let issuer = config.issuer.clone();
            providers.insert(
                issuer,
                Arc::new(RwLock::new(ResolvedOidcProvider {
                    config,
                    build_principal: provider_config.principal_builder(),
                })),
            );
        }

        let github_tokens = GitHubTokens::new(&settings)?;

        let base = settings.policy_path.with_extension("");

        let schema_path = base.with_extension("cedarschema");
        let schema_src = std::fs::read_to_string(&schema_path)
            .map_err(|err| PolicyError::ReadFile(schema_path, err))?;
        let (schema, _warnings) =
            Schema::from_cedarschema_str(&schema_src).map_err(PolicyError::InitSchema)?;

        let cedar_path = base.with_extension("cedar");
        let policy_src = std::fs::read_to_string(&cedar_path)
            .map_err(|err| PolicyError::ReadFile(cedar_path, err))?;
        let policy_set: PolicySet = policy_src.parse().map_err(PolicyError::InitPolicy)?;

        Ok(Context {
            providers,
            policy: Policy::new(schema, policy_set, github_tokens.clone()),
            oxide_tokens: OxideTokens::new(&settings)?,
            github_tokens,
            settings,
        })
    }
}
