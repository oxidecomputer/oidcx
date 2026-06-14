// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::endpoints::TokenRequest;
use crate::oidc::Claims;
use crate::token::github::{GitHubTokenError, GitHubTokens};
use cedar_policy::entities_errors::EntitiesError;
use cedar_policy::{
    Authorizer, CedarSchemaError, Context, Decision, Entities, Entity, EntityAttrEvaluationError,
    EntityId, EntityTypeName, EntityUid, ParseErrors, PolicySet, Request, RequestValidationError,
    RestrictedExpression, Schema,
};
use chrono::{DateTime, Duration, Utc};
use reqwest::Url;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::{Arc, LazyLock, Mutex};

macro_rules! cedar_entity {
    ($static_name:ident, $type_name:literal, $fn_name:ident, $id_type:ty) => {
        static $static_name: LazyLock<EntityTypeName> = LazyLock::new(|| {
            EntityTypeName::from_str($type_name)
                .expect(concat!("invalid entity type name: ", $type_name))
        });

        fn $fn_name(id: $id_type) -> EntityUid {
            EntityUid::from_type_name_and_id($static_name.clone(), EntityId::new(id))
        }
    };
}

cedar_entity!(
    WORKFLOW_RUN_TYPE,
    "Oidcx::WorkflowRun",
    workflow_run_uid,
    &str
);
cedar_entity!(REPOSITORY_TYPE, "Oidcx::Repository", repository_uid, &str);
cedar_entity!(SILO_TARGET_TYPE, "Oidcx::SiloTarget", silo_target_uid, &Url);
cedar_entity!(ACTION_TYPE, "Oidcx::Action", action_uid, &str);

/// Build a Cedar principal entity for a GitHub Actions workflow run.
///
/// The entity type is `Oidcx::WorkflowRun` and its attributes are drawn from
/// the standard OIDC claims issued by GitHub's token service.
pub fn workflow_run_entity(claims: &Claims) -> Result<Entity, PolicyError> {
    let uid = workflow_run_uid(claims.get_str("jti").ok_or(PolicyError::NoPrincipal)?);

    let mut attrs = HashMap::from([
        (
            "repository".into(),
            RestrictedExpression::new_string(claims.get_str("repository").unwrap_or("").into()),
        ),
        (
            "repository_owner".into(),
            RestrictedExpression::new_string(
                claims.get_str("repository_owner").unwrap_or("").into(),
            ),
        ),
        (
            "repository_visibility".into(),
            RestrictedExpression::new_string(
                claims.get_str("repository_visibility").unwrap_or("").into(),
            ),
        ),
        (
            "event_name".into(),
            RestrictedExpression::new_string(claims.get_str("event_name").unwrap_or("").into()),
        ),
        (
            "iss".into(),
            RestrictedExpression::new_string(claims.get_str("iss").unwrap_or("").into()),
        ),
    ]);
    if let Some(env) = claims.get_str("environment") {
        attrs.insert(
            "environment".into(),
            RestrictedExpression::new_string(env.into()),
        );
    }
    Entity::new(uid, attrs, HashSet::new()).map_err(PolicyError::EntityEvaluation)
}

pub struct Policy {
    schema: Schema,
    policy_set: PolicySet,
    authorizer: Authorizer,
    github_tokens: GitHubTokens,
    github_visibility_cache: Arc<Mutex<HashMap<String, CachedVisibility>>>,
}

impl Policy {
    pub fn new(schema: Schema, policy_set: PolicySet, github_tokens: GitHubTokens) -> Self {
        Self {
            schema,
            policy_set,
            authorizer: Authorizer::new(),
            github_tokens,
            github_visibility_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn ensure_allowed(
        &self,
        principal: &Entity,
        request: &TokenRequest,
    ) -> Result<(), PolicyError> {
        match request {
            TokenRequest::Oxide(oxide) => {
                self.authorize(principal, "deploy", Self::silo_target_entity(&oxide.silo)?)?;
                Ok(())
            }
            TokenRequest::GitHub(github) => {
                for repository in &github.repositories {
                    let repository_visibility = self.github_visibility(repository).await?;
                    let resource = Self::repository_entity(repository, &repository_visibility)?;

                    for permission in &github.permissions {
                        self.authorize(principal, permission, resource.clone())?;
                    }
                }
                Ok(())
            }
        }
    }

    fn authorize(
        &self,
        principal: &Entity,
        action: &str,
        resource: Entity,
    ) -> Result<(), PolicyError> {
        let principal_uid = principal.uid().clone();
        let resource_uid = resource.uid().clone();

        let entities = Entities::from_entities([principal.clone(), resource], Some(&self.schema))
            .map_err(PolicyError::Entities)?;

        let request = Request::new(
            principal_uid,
            action_uid(action),
            resource_uid,
            Context::empty(),
            Some(&self.schema),
        )
        .map_err(PolicyError::Request)?;

        let response = self
            .authorizer
            .is_authorized(&request, &self.policy_set, &entities);

        match response.decision() {
            Decision::Allow => Ok(()),
            Decision::Deny => {
                let errors: Vec<_> = response
                    .diagnostics()
                    .errors()
                    .map(|e| e.to_string())
                    .collect();
                if !errors.is_empty() {
                    tracing::warn!(?errors, "policy evaluation errors");
                }
                Err(PolicyError::NotMatching(action.to_string()))
            }
        }
    }

    fn repository_entity(name: &str, visibility: &str) -> Result<Entity, PolicyError> {
        let uid = repository_uid(name);
        let attrs = HashMap::from([
            ("name".into(), RestrictedExpression::new_string(name.into())),
            (
                "visibility".into(),
                RestrictedExpression::new_string(visibility.into()),
            ),
        ]);
        Entity::new(uid, attrs, HashSet::new()).map_err(PolicyError::EntityEvaluation)
    }

    fn silo_target_entity(url: &Url) -> Result<Entity, PolicyError> {
        let uid = silo_target_uid(url);
        let attrs = HashMap::from([(
            "url".into(),
            RestrictedExpression::new_string(url.to_string()),
        )]);
        Entity::new(uid, attrs, HashSet::new()).map_err(PolicyError::EntityEvaluation)
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

struct CachedVisibility {
    visibility: String,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("Failed to read policy file {0}")]
    ReadFile(std::path::PathBuf, #[source] std::io::Error),
    #[error("Failed to parse Cedar schema")]
    InitSchema(#[source] CedarSchemaError),
    #[error("Failed to parse Cedar policy")]
    InitPolicy(#[source] ParseErrors),
    #[error("Failed to construct Cedar entities")]
    Entities(#[source] EntitiesError),
    #[error("Failed to evaluate Cedar entities")]
    EntityEvaluation(#[source] EntityAttrEvaluationError),
    #[error("Failed to construct Cedar authorization request")]
    Request(#[source] RequestValidationError),
    #[error("Does not match the authorization policy")]
    NotMatching(String),
    #[error("Claims do not contain an id to construct a principal from")]
    NoPrincipal,
    #[error("failed to retrieve the repository visibility for {0}")]
    GetVisibility(String, #[source] GitHubTokenError),
}
