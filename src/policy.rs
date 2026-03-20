// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::endpoints::TokenRequest;
use crate::oidc::Claims;
use crate::token::github::{GitHubTokenError, GitHubTokens};
use chrono::{DateTime, Duration, Utc};
use oso::{Class, Oso, OsoError, PolarClass, ToPolar};
use std::collections::HashMap;
use std::fmt::Display;
use std::path::Path;
use std::sync::{Arc, Mutex};

pub struct Policy {
    oso: Oso,
    github_tokens: GitHubTokens,
    github_visibility_cache: Arc<Mutex<HashMap<String, CachedVisibility>>>,
}

impl Policy {
    pub fn new(path: &Path, github_tokens: GitHubTokens) -> Result<Self, OsoError> {
        let mut oso = Oso::new();
        oso.register_class(GitHubClass::get_polar_class())?;
        oso.register_class(OxideClass::get_polar_class())?;
        oso.register_class(create_utils_class())?;
        oso.load_files(vec![path])?;
        Ok(Self {
            oso,
            github_tokens,
            github_visibility_cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn ensure_allowed(
        &self,
        claims: &Claims,
        request: &TokenRequest,
    ) -> Result<(), PolicyError> {
        match request {
            TokenRequest::Oxide(oxide) => self.ensure_permutation(
                claims,
                OxideClass {
                    silo: oxide.silo.clone(),
                    duration: oxide.duration as _,
                },
            ),
            TokenRequest::GitHub(github) => {
                // We require at least one repository and one permission to be present. If either
                // is empty we would not actually run the `ensure_permutation` check which evaluates
                // the policy against the repositories and permissions provided.
                if github.repositories.is_empty() || github.permissions.is_empty() {
                    return Err(PolicyError::InvalidTokenRequest);
                }
                for repository in &github.repositories {
                    let repository_visibility = self.github_visibility(repository).await?;

                    for permission in &github.permissions {
                        self.ensure_permutation(
                            claims,
                            GitHubClass {
                                repository: repository.clone(),
                                repository_visibility: repository_visibility.clone(),
                                permission: permission.clone(),
                            },
                        )?;
                    }
                }
                Ok(())
            }
        }
    }

    fn ensure_permutation<T: ToPolar + Display>(
        &self,
        claims: &Claims,
        permutation: T,
    ) -> Result<(), PolicyError> {
        let string_repr = permutation.to_string();
        let mut result = self
            .oso
            .query_rule("allow_request", (claims.clone(), permutation))?;
        match result.next() {
            Some(Ok(_)) => Ok(()),
            Some(Err(e)) => Err(e.into()),
            None => Err(PolicyError::NotMatching(string_repr)),
        }
    }

    async fn github_visibility(&self, repo: &str) -> Result<String, PolicyError> {
        // We are not holding the lock across the await point below.
        {
            let cache = self.github_visibility_cache.lock().unwrap();
            if let Some(cached) = cache.get(repo)
                && cached.expires_at >= Utc::now()
            {
                return Ok(cached.visibility.clone());
            }
        }

        let visibility = self
            .github_tokens
            .repository_visibility(repo)
            .await
            .map_err(|e| PolicyError::GetVisibility(repo.into(), e))?;

        self.github_visibility_cache.lock().unwrap().insert(
            repo.into(),
            CachedVisibility {
                visibility: visibility.clone(),
                expires_at: Utc::now() + Duration::hours(1),
            },
        );
        Ok(visibility)
    }
}

impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Policy")
    }
}

#[derive(PolarClass, Clone)]
#[polar(class_name = "Oxide")]
struct OxideClass {
    #[polar(attribute)]
    silo: String,
    #[polar(attribute)]
    duration: i64,
}

impl std::fmt::Display for OxideClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "silo {}", self.silo)
    }
}

#[derive(PolarClass, Clone)]
#[polar(class_name = "GitHub")]
struct GitHubClass {
    #[polar(attribute)]
    repository: String,
    #[polar(attribute)]
    repository_visibility: String,
    #[polar(attribute)]
    permission: String,
}

impl std::fmt::Display for GitHubClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "permission {} on repository {}",
            self.permission, self.repository
        )
    }
}

struct CachedVisibility {
    visibility: String,
    expires_at: DateTime<Utc>,
}

pub(super) fn create_utils_class() -> Class {
    #[derive(Clone, PolarClass)]
    #[polar(class_name = "utils")]
    struct Utils;

    Utils::get_polar_class_builder()
        .add_class_method("concat", |a: String, b: String| format!("{a}{b}"))
        .build()
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("Failed to evaluate the authorization policy")]
    Oso(#[from] OsoError),
    #[error("{0} does not match the authorization policy")]
    NotMatching(String),
    #[error("failed to retrieve the repository visibility for {0}")]
    GetVisibility(String, #[source] GitHubTokenError),
    #[error("invalid token request")]
    InvalidTokenRequest,
}
