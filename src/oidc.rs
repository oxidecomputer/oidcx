// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use jsonwebtoken::{
    Algorithm, DecodingKey, Validation,
    jwk::{JwkSet, KeyAlgorithm},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt::Debug, str::FromStr};
use thiserror::Error;
use tracing::instrument;

use crate::settings::Settings;

#[derive(Debug, Error)]
pub enum OidcError {
    #[error("Invalid OIDC configuration")]
    InvalidOidcConfig,
    #[error("Failed to parse token header")]
    InvalidHeader(#[source] jsonwebtoken::errors::Error),
    #[error("Failed to decode token")]
    InvalidToken(#[source] jsonwebtoken::errors::Error),
    #[error("Failed to create decoding key")]
    InvalidKey(#[source] jsonwebtoken::errors::Error),
    #[error("Missing kid in token header")]
    MissingKid,
    #[error("JWK must define a key algorithm")]
    MissingKeyAlgorithm,
    #[error("{0} did not match any known keys")]
    UnknownKid(String),
    #[error("Key algorithm {0} is not supported")]
    UnsupportedAlgorithm(KeyAlgorithm),
    #[error("Token claims do not satisfy claim constraints")]
    ValidationFailed,
    #[error("External call failed")]
    Request(#[from] reqwest::Error),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OidcProvider {
    url: String,
}

impl OidcProvider {
    pub fn new(url: String) -> Self {
        Self { url }
    }

    pub async fn fetch_config(&self, client: &reqwest::Client) -> Result<OidcConfig, OidcError> {
        let response = client.get(&self.url).send().await?;
        let config: OidcConfig = response.json().await?;
        Ok(config)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OidcConfig {
    issuer: String,
    jwks_uri: String,
    subject_types_supported: Vec<String>,
    response_types_supported: Vec<String>,
    claims_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
    scopes_supported: Vec<String>,
}

impl OidcConfig {
    pub async fn resolve(self, client: &reqwest::Client) -> Result<ResolvedOidcConfig, OidcError> {
        let response = client.get(&self.jwks_uri).send().await?;
        let jwks = response.json::<JwkSet>().await?;
        Ok(ResolvedOidcConfig {
            issuer: self.issuer,
            jwks,
            subject_types_supported: self.subject_types_supported,
            response_types_supported: self.response_types_supported,
            claims_supported: self.claims_supported,
            id_token_signing_alg_values_supported: self
                .id_token_signing_alg_values_supported
                .into_iter()
                .map(|alg| Algorithm::from_str(&alg))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|err| {
                    tracing::error!(?err, "Failed to parse supported algorithm");
                    OidcError::InvalidOidcConfig
                })?,
            scopes_supported: self.scopes_supported,
        })
    }
}

#[derive(Debug)]
pub struct ResolvedOidcConfig {
    pub issuer: String,
    pub jwks: JwkSet,
    pub subject_types_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub claims_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<Algorithm>,
    pub scopes_supported: Vec<String>,
}

impl ResolvedOidcConfig {
    #[instrument(skip(self, token))]
    pub fn validate(&self, settings: &Settings, token: &str) -> Result<Claims, OidcError> {
        let header = jsonwebtoken::decode_header(token).map_err(OidcError::InvalidHeader)?;
        let kid = header.kid.ok_or(OidcError::MissingKid)?;
        let jwk = self
            .jwks
            .find(&kid)
            .ok_or_else(|| OidcError::UnknownKid(kid))?;
        let decoding_key = DecodingKey::from_jwk(&jwk).map_err(OidcError::InvalidKey)?;

        let mut validation = Validation::new(key_algo_to_algo(
            jwk.common
                .key_algorithm
                .ok_or(OidcError::MissingKeyAlgorithm)?,
        )?);
        validation.set_audience(&[&settings.audience]);
        validation.set_issuer(&[&self.issuer]);

        Ok(Claims {
            claims: jsonwebtoken::decode(token, &decoding_key, &validation)
                .map_err(|err| {
                    tracing::info!(?err, expected = ?settings.audience, "Audience does not match");
                    OidcError::InvalidToken(err)
                })?
                .claims,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Claims {
    claims: HashMap<String, ClaimValue>,
}

impl Claims {
    pub fn get_str(&self, key: &str) -> Option<&str> {
        match self.claims.get(key)? {
            ClaimValue::String(s) => Some(s.as_str()),
            ClaimValue::Number(_) => None,
        }
    }
}

#[derive(serde::Deserialize, Clone)]
#[serde(untagged)]
enum ClaimValue {
    Number(i64),
    String(String),
}

impl std::fmt::Debug for ClaimValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Number(val) => std::fmt::Debug::fmt(val, f),
            Self::String(val) => std::fmt::Debug::fmt(val, f),
        }
    }
}

fn key_algo_to_algo(key_algorithm: KeyAlgorithm) -> Result<Algorithm, OidcError> {
    Ok(match key_algorithm {
        KeyAlgorithm::HS256 => Algorithm::HS256,
        KeyAlgorithm::HS384 => Algorithm::HS384,
        KeyAlgorithm::HS512 => Algorithm::HS512,
        KeyAlgorithm::ES256 => Algorithm::ES256,
        KeyAlgorithm::ES384 => Algorithm::ES384,
        KeyAlgorithm::RS256 => Algorithm::RS256,
        KeyAlgorithm::RS384 => Algorithm::RS384,
        KeyAlgorithm::RS512 => Algorithm::RS512,
        KeyAlgorithm::PS256 => Algorithm::PS256,
        KeyAlgorithm::PS384 => Algorithm::PS384,
        KeyAlgorithm::PS512 => Algorithm::PS512,
        KeyAlgorithm::EdDSA => Algorithm::EdDSA,
        _ => Err(OidcError::UnsupportedAlgorithm(key_algorithm))?,
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IssuerClaim {
    pub iss: String,
}
