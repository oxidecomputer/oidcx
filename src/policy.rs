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
cedar_entity!(SILO_TYPE, "Oidcx::Silo", silo_uid, &Url);
cedar_entity!(ACTION_TYPE, "Oidcx::Action", action_uid, &str);

/// Build a Cedar principal entity for a GitHub Actions workflow run.
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
                self.authorize(principal, "deploy", Self::silo_entity(&oxide.silo)?)?;
                Ok(())
            }
            TokenRequest::GitHub(github) => {
                // Reject requests that wouldn't exercise any authorization
                // check. An empty repository or permission list would pass the
                // loop below vacuously, and GitHub grants a broadly-scoped
                // token when the `permissions` object is empty. Fail closed.
                if github.repositories.is_empty() || github.permissions.is_empty() {
                    return Err(PolicyError::EmptyRequest);
                }
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

    pub(crate) fn authorize(
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

    pub(crate) fn repository_entity(name: &str, visibility: &str) -> Result<Entity, PolicyError> {
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

    pub(crate) fn silo_entity(url: &Url) -> Result<Entity, PolicyError> {
        let uid = silo_uid(url);
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
    #[error("Token request must specify at least one repository and one permission")]
    EmptyRequest,
    #[error("Claims do not contain an id to construct a principal from")]
    NoPrincipal,
    #[error("failed to retrieve the repository visibility for {0}")]
    GetVisibility(String, #[source] GitHubTokenError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::Claims;
    use cedar_policy::EvalResult;

    /// Load the static application schema from the cedarschema file.
    fn load_schema() -> Schema {
        let src = include_str!("../policy.cedarschema");
        let (schema, _warnings) =
            Schema::from_cedarschema_str(src).expect("failed to parse application schema");
        schema
    }

    /// Helper: build a Claims with typical GitHub Actions OIDC fields.
    fn github_actions_claims() -> Claims {
        Claims::from_json(serde_json::json!({
            "jti": "test-run-id",
            "iss": "https://token.actions.githubusercontent.com",
            "repository": "oxidecomputer/hubris",
            "repository_owner": "oxidecomputer",
            "repository_visibility": "public",
            "event_name": "push",
        }))
    }

    #[test]
    fn workflow_run_entity_has_correct_type() {
        let claims = github_actions_claims();
        let entity = workflow_run_entity(&claims).unwrap();
        assert_eq!(entity.uid().type_name().to_string(), "Oidcx::WorkflowRun");
    }

    #[test]
    fn workflow_run_entity_uses_jti_as_id() {
        let claims = github_actions_claims();
        let entity = workflow_run_entity(&claims).unwrap();
        assert!(
            entity.uid().to_string().contains("test-run-id"),
            "entity uid should contain the jti value, got: {}",
            entity.uid()
        );
    }

    #[test]
    fn workflow_run_entity_maps_required_attributes() {
        let claims = github_actions_claims();
        let entity = workflow_run_entity(&claims).unwrap();

        assert_eq!(
            entity.attr("repository").unwrap().unwrap(),
            EvalResult::String("oxidecomputer/hubris".into())
        );
        assert_eq!(
            entity.attr("repository_owner").unwrap().unwrap(),
            EvalResult::String("oxidecomputer".into())
        );
        assert_eq!(
            entity.attr("repository_visibility").unwrap().unwrap(),
            EvalResult::String("public".into())
        );
        assert_eq!(
            entity.attr("event_name").unwrap().unwrap(),
            EvalResult::String("push".into())
        );
        assert_eq!(
            entity.attr("iss").unwrap().unwrap(),
            EvalResult::String("https://token.actions.githubusercontent.com".into())
        );
    }

    #[test]
    fn workflow_run_entity_includes_environment_when_present() {
        let claims = Claims::from_json(serde_json::json!({
            "jti": "test-run-id",
            "iss": "https://token.actions.githubusercontent.com",
            "repository": "oxidecomputer/corp-services",
            "repository_owner": "oxidecomputer",
            "repository_visibility": "private",
            "event_name": "push",
            "environment": "staging",
        }));
        let entity = workflow_run_entity(&claims).unwrap();
        assert_eq!(
            entity.attr("environment").unwrap().unwrap(),
            EvalResult::String("staging".into())
        );
    }

    #[test]
    fn workflow_run_entity_omits_environment_when_absent() {
        let claims = github_actions_claims();
        let entity = workflow_run_entity(&claims).unwrap();
        assert!(
            entity.attr("environment").is_none(),
            "environment attribute should not be present when claim is missing"
        );
    }

    #[test]
    fn workflow_run_entity_requires_jti() {
        let claims = Claims::from_json(serde_json::json!({
            "iss": "https://token.actions.githubusercontent.com",
            "repository": "oxidecomputer/hubris",
        }));
        let err = workflow_run_entity(&claims).unwrap_err();
        assert!(
            matches!(err, PolicyError::NoPrincipal),
            "expected NoPrincipal, got: {err:?}"
        );
    }

    #[test]
    fn workflow_run_entity_defaults_missing_strings_to_empty() {
        // Only jti is present — all other string claims are missing.
        let claims = Claims::from_json(serde_json::json!({
            "jti": "minimal"
        }));
        let entity = workflow_run_entity(&claims).unwrap();
        assert_eq!(
            entity.attr("repository").unwrap().unwrap(),
            EvalResult::String("".into())
        );
        assert_eq!(
            entity.attr("iss").unwrap().unwrap(),
            EvalResult::String("".into())
        );
    }

    #[test]
    fn workflow_run_entity_conforms_to_schema() {
        let schema = load_schema();
        let claims = github_actions_claims();
        let entity = workflow_run_entity(&claims).unwrap();
        Entities::from_entities([entity], Some(&schema))
            .expect("WorkflowRun entity should conform to the schema");
    }

    #[test]
    fn workflow_run_entity_with_environment_conforms_to_schema() {
        let schema = load_schema();
        let claims = Claims::from_json(serde_json::json!({
            "jti": "test-run-id",
            "iss": "https://token.actions.githubusercontent.com",
            "repository": "oxidecomputer/corp-services",
            "repository_owner": "oxidecomputer",
            "repository_visibility": "private",
            "event_name": "push",
            "environment": "production",
        }));
        let entity = workflow_run_entity(&claims).unwrap();
        Entities::from_entities([entity], Some(&schema))
            .expect("WorkflowRun entity with environment should conform to the schema");
    }

    #[test]
    fn repository_entity_has_correct_type() {
        let entity = Policy::repository_entity("oxidecomputer/hubris", "public").unwrap();
        assert_eq!(entity.uid().type_name().to_string(), "Oidcx::Repository");
    }

    #[test]
    fn repository_entity_has_correct_attributes() {
        let entity = Policy::repository_entity("oxidecomputer/hubris", "public").unwrap();
        assert_eq!(
            entity.attr("name").unwrap().unwrap(),
            EvalResult::String("oxidecomputer/hubris".into())
        );
        assert_eq!(
            entity.attr("visibility").unwrap().unwrap(),
            EvalResult::String("public".into())
        );
    }

    #[test]
    fn repository_entity_conforms_to_schema() {
        let schema = load_schema();
        let entity = Policy::repository_entity("oxidecomputer/hubris", "public").unwrap();
        Entities::from_entities([entity], Some(&schema))
            .expect("Repository entity should conform to the schema");
    }

    #[test]
    fn silo_entity_has_correct_attributes() {
        let url: Url = "https://corp-staging.sys.r3.oxide-preview.com"
            .parse()
            .unwrap();
        let entity = Policy::silo_entity(&url).unwrap();
        assert_eq!(
            entity.attr("url").unwrap().unwrap(),
            EvalResult::String("https://corp-staging.sys.r3.oxide-preview.com/".into())
        );
    }

    #[test]
    fn silo_entity_conforms_to_schema() {
        let schema = load_schema();
        let url: Url = "https://corp-staging.sys.r3.oxide-preview.com"
            .parse()
            .unwrap();
        let entity = Policy::silo_entity(&url).unwrap();
        Entities::from_entities([entity], Some(&schema))
            .expect("Silo entity should conform to the schema");
    }

    #[test]
    fn all_entity_types_conform_to_schema_together() {
        let schema = load_schema();
        let claims = github_actions_claims();
        let principal = workflow_run_entity(&claims).unwrap();
        let repository = Policy::repository_entity("oxidecomputer/hubris", "public").unwrap();
        let url: Url = "https://corp-staging.sys.r3.oxide-preview.com"
            .parse()
            .unwrap();
        let silo = Policy::silo_entity(&url).unwrap();

        Entities::from_entities([principal, repository, silo], Some(&schema))
            .expect("all entity types should conform to the schema together");
    }

    /// Helper: build a Policy with the real schema, a given inline policy, and
    /// no GitHub credentials (sufficient for authorize() which doesn't need them).
    fn policy_with(cedar_src: &str) -> Policy {
        let schema = load_schema();
        let policy_set: PolicySet = cedar_src.parse().expect("failed to parse test policy");
        let settings = crate::settings::Settings {
            audience: String::new(),
            policy_path: std::path::PathBuf::new(),
            log_directory: None,
            port: None,
            providers: vec![],
            oxide: None,
            github: None,
        };
        let github_tokens = crate::token::github::GitHubTokens::new(&settings)
            .expect("failed to create dummy GitHubTokens");
        Policy::new(schema, policy_set, github_tokens)
    }

    #[test]
    fn authorize_allows_when_policy_permits() {
        let policy = policy_with(
            r#"
            permit(principal, action, resource);
        "#,
        );
        let claims = github_actions_claims();
        let principal = workflow_run_entity(&claims).unwrap();
        let resource = Policy::repository_entity("oxidecomputer/hubris", "public").unwrap();

        policy
            .authorize(&principal, "contents:read", resource)
            .unwrap();
    }

    #[test]
    fn authorize_denies_when_no_policy_matches() {
        // Empty policy set — default deny.
        let policy = policy_with("");
        let claims = github_actions_claims();
        let principal = workflow_run_entity(&claims).unwrap();
        let resource = Policy::repository_entity("oxidecomputer/hubris", "public").unwrap();

        let err = policy
            .authorize(&principal, "contents:read", resource)
            .unwrap_err();
        assert!(
            matches!(err, PolicyError::NotMatching(_)),
            "expected NotMatching, got: {err:?}"
        );
    }

    #[test]
    fn authorize_denies_when_forbid_overrides_permit() {
        let policy = policy_with(
            r#"
            permit(principal, action, resource);
            forbid(principal, action, resource);
        "#,
        );
        let claims = github_actions_claims();
        let principal = workflow_run_entity(&claims).unwrap();
        let resource = Policy::repository_entity("oxidecomputer/hubris", "public").unwrap();

        let err = policy
            .authorize(&principal, "contents:read", resource)
            .unwrap_err();
        assert!(
            matches!(err, PolicyError::NotMatching(_)),
            "expected NotMatching, got: {err:?}"
        );
    }

    #[test]
    fn authorize_works_with_silo_entity() {
        let policy = policy_with(
            r#"
            permit(principal, action, resource);
        "#,
        );
        let claims = github_actions_claims();
        let principal = workflow_run_entity(&claims).unwrap();
        let url: Url = "https://corp-staging.sys.r3.oxide-preview.com"
            .parse()
            .unwrap();
        let resource = Policy::silo_entity(&url).unwrap();

        policy.authorize(&principal, "deploy", resource).unwrap();
    }

    #[tokio::test]
    async fn ensure_allowed_oxide_permit() {
        let policy = policy_with(
            r#"
            permit(principal, action, resource);
        "#,
        );
        let claims = github_actions_claims();
        let principal = workflow_run_entity(&claims).unwrap();
        let request =
            crate::endpoints::TokenRequest::Oxide(crate::token::oxide::OxideTokenRequest {
                silo: "https://corp-staging.sys.r3.oxide-preview.com"
                    .parse()
                    .unwrap(),
                duration: 3600,
            });

        policy.ensure_allowed(&principal, &request).await.unwrap();
    }

    #[tokio::test]
    async fn ensure_allowed_oxide_deny() {
        let policy = policy_with("");
        let claims = github_actions_claims();
        let principal = workflow_run_entity(&claims).unwrap();
        let request =
            crate::endpoints::TokenRequest::Oxide(crate::token::oxide::OxideTokenRequest {
                silo: "https://corp-staging.sys.r3.oxide-preview.com"
                    .parse()
                    .unwrap(),
                duration: 3600,
            });

        let err = policy
            .ensure_allowed(&principal, &request)
            .await
            .unwrap_err();
        assert!(
            matches!(err, PolicyError::NotMatching(_)),
            "expected NotMatching, got: {err:?}"
        );
    }

    // These tests use a deliberately permissive allow-all policy. The point is
    // that the schema (static application config) must reject type-confused or
    // undefined actions BEFORE policy evaluation, so a catch-all permit can't
    // be tricked into granting an action the resource doesn't support. This
    // guards against a regression where `Request::new` is called without the
    // schema (`None`), which would silently remove this protection.

    #[test]
    fn authorize_rejects_deploy_action_on_repository() {
        // A GitHub request controls the permission string. Smuggling in the
        // Oxide "deploy" action against a Repository resource must be rejected,
        // since the schema says `deploy` applies only to Silo.
        let policy = policy_with("permit(principal, action, resource);");
        let claims = github_actions_claims();
        let principal = workflow_run_entity(&claims).unwrap();
        let resource = Policy::repository_entity("oxidecomputer/hubris", "public").unwrap();

        let err = policy
            .authorize(&principal, "deploy", resource)
            .unwrap_err();
        assert!(
            matches!(err, PolicyError::Request(_)),
            "expected Request validation error, got: {err:?}"
        );
    }

    #[test]
    fn authorize_rejects_github_permission_on_silo() {
        let policy = policy_with("permit(principal, action, resource);");
        let claims = github_actions_claims();
        let principal = workflow_run_entity(&claims).unwrap();
        let url: Url = "https://corp-staging.sys.r3.oxide-preview.com"
            .parse()
            .unwrap();
        let resource = Policy::silo_entity(&url).unwrap();

        let err = policy
            .authorize(&principal, "contents:read", resource)
            .unwrap_err();
        assert!(
            matches!(err, PolicyError::Request(_)),
            "expected Request validation error, got: {err:?}"
        );
    }

    #[test]
    fn authorize_rejects_undefined_action() {
        // An action not declared in the schema must be rejected even under an
        // allow-all policy, so a request can't smuggle in an arbitrary
        // permission string that a catch-all permit might otherwise match.
        let policy = policy_with("permit(principal, action, resource);");
        let claims = github_actions_claims();
        let principal = workflow_run_entity(&claims).unwrap();
        let resource = Policy::repository_entity("oxidecomputer/hubris", "public").unwrap();

        let err = policy
            .authorize(&principal, "admin:write", resource)
            .unwrap_err();
        assert!(
            matches!(err, PolicyError::Request(_)),
            "expected Request validation error, got: {err:?}"
        );
    }

    // An empty repository or permission list would otherwise skip the
    // authorization loop entirely and return Ok, while GitHub grants a
    // broadly-scoped token for an empty `permissions` object.

    #[tokio::test]
    async fn ensure_allowed_rejects_empty_repositories() {
        // Allow-all policy: the request must still be rejected because no
        // repository means no authorization check was performed.
        let policy = policy_with("permit(principal, action, resource);");
        let claims = github_actions_claims();
        let principal = workflow_run_entity(&claims).unwrap();
        let request =
            crate::endpoints::TokenRequest::GitHub(crate::token::github::GitHubTokenRequest {
                repositories: vec![],
                permissions: vec!["contents:read".into()],
            });

        let err = policy
            .ensure_allowed(&principal, &request)
            .await
            .unwrap_err();
        assert!(
            matches!(err, PolicyError::EmptyRequest),
            "expected EmptyRequest, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn ensure_allowed_rejects_empty_permissions() {
        // Allow-all policy and a real repository, but no permissions. This must
        // fail closed BEFORE any GitHub API call (no network in this test),
        // preventing an empty-permissions token request.
        let policy = policy_with("permit(principal, action, resource);");
        let claims = github_actions_claims();
        let principal = workflow_run_entity(&claims).unwrap();
        let request =
            crate::endpoints::TokenRequest::GitHub(crate::token::github::GitHubTokenRequest {
                repositories: vec!["oxidecomputer/hubris".into()],
                permissions: vec![],
            });

        let err = policy
            .ensure_allowed(&principal, &request)
            .await
            .unwrap_err();
        assert!(
            matches!(err, PolicyError::EmptyRequest),
            "expected EmptyRequest, got: {err:?}"
        );
    }
}
