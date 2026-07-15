// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::endpoints::Token;
use crate::settings::Settings;
use jsonwebtoken::{Algorithm, EncodingKey};
use reqwest::{Client, RequestBuilder, StatusCode};
use schemars::JsonSchema;
use secrecy::ExposeSecret;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use v_api_param::ParamResolutionError;

static USER_AGENT: &str = "https://github.com/oxidecomputer/oidcx";

#[derive(Clone, Debug, Deserialize, JsonSchema, Hash, PartialEq, Eq)]
pub struct GitHubTokenRequest {
    pub repositories: Vec<String>,
    pub permissions: Vec<String>,
}

/// A [`GitHubTokenRequest`] whose repository and permission strings have been
/// validated and parsed exactly once.
///
/// The raw request carries free-form strings (`"org/name"`, `"contents:read"`).
/// Several consumers need structured pieces of that data: the org namespace to
/// locate the app installation, the bare repository names for the API call, and
/// the permission name/level pairs. Re-splitting the strings at each use site
/// would risk the parsed scope drifting from what was authorized. Instead we
/// parse once, here, and every consumer reads the already-validated fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedGitHubRequest {
    namespace: String,
    repository_names: Vec<String>,
    permissions: HashMap<String, String>,
}

impl ParsedGitHubRequest {
    /// Validate and parse a raw request. All scope-determining parsing happens
    /// here and nowhere else.
    pub fn parse(request: &GitHubTokenRequest) -> Result<Self, GitHubTokenError> {
        // Every repository must be `namespace/name` (no extra slashes) and all
        // repositories must share a single namespace, since the token is scoped
        // to one app installation.
        let mut namespace: Option<&str> = None;
        let mut repository_names = Vec::new();
        for repo in &request.repositories {
            match repo.split_once('/') {
                Some((ns, name)) if !name.contains('/') => {
                    if let Some(existing) = namespace
                        && existing != ns
                    {
                        return Err(GitHubTokenError::DifferentOrgs);
                    }
                    namespace = Some(ns);
                    repository_names.push(name.to_string());
                }
                _ => return Err(GitHubTokenError::NotAGitHubRepository(repo.clone())),
            }
        }
        let namespace = namespace
            .ok_or(GitHubTokenError::NoRepositories)?
            .to_string();

        // Each permission is `name:level`. The name must not contain a slash,
        // and a name may appear only once.
        let mut permissions = HashMap::new();
        for permission in &request.permissions {
            match permission.split_once(':') {
                Some((name, level)) if !name.contains('/') => {
                    if permissions
                        .insert(name.to_string(), level.to_string())
                        .is_some()
                    {
                        return Err(GitHubTokenError::DuplicatePermission(name.into()));
                    }
                }
                _ => return Err(GitHubTokenError::NotAPermission(permission.into())),
            }
        }

        Ok(Self {
            namespace,
            repository_names,
            permissions,
        })
    }

    /// The single org/user namespace all repositories belong to.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Repository names without their namespace prefix, as the GitHub API
    /// expects them.
    pub fn repository_names(&self) -> &[String] {
        &self.repository_names
    }

    /// Requested permissions as a map of permission name to access level.
    pub fn permissions(&self) -> &HashMap<String, String> {
        &self.permissions
    }
}

#[derive(Debug)]
struct State {
    client: Client,
    client_id: String,
    private_key: EncodingKey,
}

#[derive(Clone, Debug)]
pub struct GitHubTokens {
    state: Option<Arc<State>>,
}

impl GitHubTokens {
    pub fn new(settings: &Settings) -> Result<Self, GitHubTokenError> {
        let base = settings.params_base_path.as_deref();
        if let Some(github) = &settings.github {
            // The key may be inline or read from a file on the parameters
            // volume; `resolve` performs any required I/O.
            let private_key = github.private_key.resolve(base)?;
            Ok(GitHubTokens {
                state: Some(Arc::new(State {
                    client: Client::new(),
                    client_id: github.client_id.clone(),
                    private_key: EncodingKey::from_rsa_pem(private_key.expose_secret().as_bytes())
                        .map_err(GitHubTokenError::LoadPrivateKey)?,
                })),
            })
        } else {
            Ok(GitHubTokens { state: None })
        }
    }

    pub async fn get(&self, request: &GitHubTokenRequest) -> Result<Token, GitHubTokenError> {
        let state = self.state.as_ref().ok_or(GitHubTokenError::NoCredentials)?;

        // Validate and parse the request once. Every consumer below reads the
        // parsed fields rather than re-splitting the raw request strings.
        let parsed = ParsedGitHubRequest::parse(request)?;

        // Generate a JWT valid for 5 minutes, used to authenticate with GitHub.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("we time travelled earlier than 1970, go collect your Nobel prize")
            .as_secs();
        let jwt = jsonwebtoken::encode(
            &jsonwebtoken::Header {
                alg: Algorithm::RS256,
                ..Default::default()
            },
            &serde_json::json!({
                "iss": state.client_id,
                "iat": now - 10, // Handle skewed clocks.
                "exp": now + 300,
            }),
            &state.private_key,
        )
        .map_err(GitHubTokenError::EncodeJwt)?;

        // Get the installation ID. We look for the namespace in both the users and the
        // organizations, to gracefully handle when the app is installed on a personal account
        // rather than an organization.
        let mut found_installation = None;
        for kind in ["orgs", "users"] {
            let response = github_request::<InstallationResponse>(
                state
                    .client
                    .get(format!(
                        "https://api.github.com/{kind}/{}/installation",
                        parsed.namespace()
                    ))
                    .bearer_auth(&jwt),
            )
            .await;
            match response {
                Ok(response) => found_installation = Some(response.id),
                Err(GitHubTokenError::GitHubError(_, StatusCode::NOT_FOUND, _)) => continue,
                Err(err) => return Err(err),
            }
        }
        let installation = found_installation
            .ok_or_else(|| GitHubTokenError::AppNotInstalled(parsed.namespace().into()))?;

        // Request the access token from GitHub.
        let access_token: AccessTokenResponse = github_request(
            state
                .client
                .post(format!(
                    "https://api.github.com/app/installations/{installation}/access_tokens"
                ))
                .bearer_auth(&jwt)
                .json(&serde_json::json!({
                    "repositories": parsed.repository_names(),
                    "permissions": parsed.permissions(),
                })),
        )
        .await?;

        Ok(Token {
            access_token: access_token.token,
        })
    }

    pub async fn repository_visibility(&self, repo: &str) -> Result<String, GitHubTokenError> {
        #[derive(serde::Deserialize)]
        struct Repo {
            visibility: String,
        }

        let state = self.state.as_ref().ok_or(GitHubTokenError::NoCredentials)?;
        let token = self
            .get(&GitHubTokenRequest {
                repositories: vec![repo.into()],
                permissions: vec!["metadata:read".into()],
            })
            .await?;
        Ok(github_request::<Repo>(
            state
                .client
                .get(format!("https://api.github.com/repos/{repo}"))
                .bearer_auth(token.access_token),
        )
        .await?
        .visibility)
    }
}

#[derive(serde::Deserialize)]
struct InstallationResponse {
    id: u64,
}

#[derive(serde::Deserialize)]
struct AccessTokenResponse {
    token: String,
}

async fn github_request<T>(request: RequestBuilder) -> Result<T, GitHubTokenError>
where
    T: DeserializeOwned,
{
    #[derive(serde::Deserialize)]
    struct GitHubError {
        message: String,
    }

    let response = request
        .header("user-agent", USER_AGENT)
        .send()
        .await
        .map_err(GitHubTokenError::Http)?;
    let status = response.status();

    if status.is_success() {
        response.json().await.map_err(GitHubTokenError::Http)
    } else {
        let url = response.url().to_string();
        let text = response.text().await.map_err(GitHubTokenError::Http)?;
        // GitHub usually sends error responses as JSON, but if there is an upstream error with
        // GitHub non-JSON might be returned. Gracefully handle that.
        match serde_json::from_str(&text) {
            Ok(GitHubError { message }) => Err(GitHubTokenError::GitHubError(url, status, message)),
            Err(_) => Err(GitHubTokenError::GitHubError(url, status, text)),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GitHubTokenError {
    #[error("GitHub credentials are not configured for this instance of oidcx")]
    NoCredentials,
    #[error("Failed to resolve the GitHub App private key")]
    ResolveParam(#[from] ParamResolutionError),
    #[error("Failed to load the GitHub App private key")]
    LoadPrivateKey(#[source] jsonwebtoken::errors::Error),
    #[error("Failed to encode the JWT")]
    EncodeJwt(#[source] jsonwebtoken::errors::Error),
    #[error("Repository name {0} is not in the `org/name` format")]
    NotAGitHubRepository(String),
    #[error("The repositories requested for this token belong to different organizations")]
    DifferentOrgs,
    #[error("The requested token asked for access to no repositories")]
    NoRepositories,
    #[error("HTTP error")]
    Http(#[source] reqwest::Error),
    #[error("Request to {0} failed with status {1}: {2}")]
    GitHubError(String, StatusCode, String),
    #[error("The permission {0} is requested multiple times")]
    DuplicatePermission(String),
    #[error("The permission string {0} is not a valid permission")]
    NotAPermission(String),
    #[error("oidcx's GitHub App is not installed on {0}")]
    AppNotInstalled(String),
}

impl GitHubTokenError {
    pub fn safe_to_expose(&self) -> bool {
        match self {
            GitHubTokenError::ResolveParam(..)
            | GitHubTokenError::LoadPrivateKey(..)
            | GitHubTokenError::EncodeJwt(..)
            | GitHubTokenError::Http(..) => false,
            GitHubTokenError::NoCredentials
            | GitHubTokenError::NotAGitHubRepository(..)
            | GitHubTokenError::DifferentOrgs
            | GitHubTokenError::NoRepositories
            | GitHubTokenError::DuplicatePermission(..)
            | GitHubTokenError::GitHubError(..)
            | GitHubTokenError::AppNotInstalled(..)
            | GitHubTokenError::NotAPermission(..) => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(repositories: &[&str], permissions: &[&str]) -> GitHubTokenRequest {
        GitHubTokenRequest {
            repositories: repositories.iter().map(|s| s.to_string()).collect(),
            permissions: permissions.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn parses_single_repository() {
        let parsed =
            ParsedGitHubRequest::parse(&request(&["oxidecomputer/hubris"], &["contents:read"]))
                .unwrap();
        assert_eq!(parsed.namespace(), "oxidecomputer");
        assert_eq!(parsed.repository_names(), &["hubris".to_string()]);
    }

    #[test]
    fn parses_multiple_repositories_in_same_namespace() {
        let parsed = ParsedGitHubRequest::parse(&request(
            &["oxidecomputer/hubris", "oxidecomputer/bootleby"],
            &["contents:read"],
        ))
        .unwrap();
        assert_eq!(parsed.namespace(), "oxidecomputer");
        assert_eq!(
            parsed.repository_names(),
            &["hubris".to_string(), "bootleby".to_string()]
        );
    }

    #[test]
    fn rejects_repositories_from_different_namespaces() {
        let err = ParsedGitHubRequest::parse(&request(
            &["oxidecomputer/hubris", "someoneelse/repo"],
            &["contents:read"],
        ))
        .unwrap_err();
        assert!(
            matches!(err, GitHubTokenError::DifferentOrgs),
            "got: {err:?}"
        );
    }

    #[test]
    fn rejects_repository_without_namespace() {
        let err =
            ParsedGitHubRequest::parse(&request(&["justaname"], &["contents:read"])).unwrap_err();
        assert!(
            matches!(err, GitHubTokenError::NotAGitHubRepository(ref r) if r == "justaname"),
            "got: {err:?}"
        );
    }

    #[test]
    fn rejects_repository_with_extra_slashes() {
        // A repo with more than one slash must be rejected, not silently
        // reinterpreted, so the namespace can't be confused.
        let err = ParsedGitHubRequest::parse(&request(
            &["oxidecomputer/hubris/extra"],
            &["contents:read"],
        ))
        .unwrap_err();
        assert!(
            matches!(err, GitHubTokenError::NotAGitHubRepository(ref r) if r == "oxidecomputer/hubris/extra"),
            "got: {err:?}"
        );
    }

    #[test]
    fn rejects_empty_repositories() {
        let err = ParsedGitHubRequest::parse(&request(&[], &["contents:read"])).unwrap_err();
        assert!(
            matches!(err, GitHubTokenError::NoRepositories),
            "got: {err:?}"
        );
    }

    #[test]
    fn parses_permissions() {
        let parsed = ParsedGitHubRequest::parse(&request(
            &["oxidecomputer/hubris"],
            &["contents:read", "pull_requests:write"],
        ))
        .unwrap();
        assert_eq!(
            parsed.permissions().get("contents"),
            Some(&"read".to_string())
        );
        assert_eq!(
            parsed.permissions().get("pull_requests"),
            Some(&"write".to_string())
        );
        assert_eq!(parsed.permissions().len(), 2);
    }

    #[test]
    fn rejects_permission_without_level() {
        let err = ParsedGitHubRequest::parse(&request(&["oxidecomputer/hubris"], &["contents"]))
            .unwrap_err();
        assert!(
            matches!(err, GitHubTokenError::NotAPermission(ref p) if p == "contents"),
            "got: {err:?}"
        );
    }

    #[test]
    fn rejects_permission_with_slash_in_name() {
        // A slash in the permission name could let a crafted permission masquerade
        // as a repository path; it must be rejected.
        let err =
            ParsedGitHubRequest::parse(&request(&["oxidecomputer/hubris"], &["org/contents:read"]))
                .unwrap_err();
        assert!(
            matches!(err, GitHubTokenError::NotAPermission(ref p) if p == "org/contents:read"),
            "got: {err:?}"
        );
    }

    #[test]
    fn rejects_duplicate_permission() {
        let err = ParsedGitHubRequest::parse(&request(
            &["oxidecomputer/hubris"],
            &["contents:read", "contents:write"],
        ))
        .unwrap_err();
        assert!(
            matches!(err, GitHubTokenError::DuplicatePermission(ref p) if p == "contents"),
            "got: {err:?}"
        );
    }

    #[test]
    fn permission_level_keeps_extra_colons() {
        // `split_once(':')` only splits on the first colon, so a level may itself
        // contain colons. This is benign (GitHub would reject an invalid level,
        // and the policy layer rejects unknown action strings), but we pin the
        // behavior so it can't change unnoticed.
        let parsed = ParsedGitHubRequest::parse(&request(
            &["oxidecomputer/hubris"],
            &["contents:read:extra"],
        ))
        .unwrap();
        assert_eq!(
            parsed.permissions().get("contents"),
            Some(&"read:extra".to_string())
        );
    }

    #[test]
    fn empty_permissions_parse_to_empty_map() {
        // parse() itself permits empty permissions (the policy layer guards
        // against empty requests); the map is simply empty.
        let parsed = ParsedGitHubRequest::parse(&request(&["oxidecomputer/hubris"], &[])).unwrap();
        assert!(parsed.permissions().is_empty());
    }

    #[test]
    fn private_key_errors_are_not_exposed() {
        let err = GitHubTokenError::ResolveParam(ParamResolutionError::FileRead {
            path: "/secret/key.pem".into(),
            source: std::io::Error::other("boom"),
        });
        assert!(
            !err.safe_to_expose(),
            "private key path/IO errors must not be exposed to clients"
        );
    }

    #[test]
    fn request_validation_errors_are_safe_to_expose() {
        assert!(GitHubTokenError::DifferentOrgs.safe_to_expose());
        assert!(GitHubTokenError::NoRepositories.safe_to_expose());
        assert!(GitHubTokenError::NotAGitHubRepository("x".into()).safe_to_expose());
        assert!(GitHubTokenError::NotAPermission("x".into()).safe_to_expose());
    }
}
