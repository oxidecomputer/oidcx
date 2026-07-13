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
        // Require these claims to be present. Without this, a token missing
        // `aud` or `iss` could slip past the corresponding checks depending on
        // the library's defaults. `aud` in particular is the cross-service
        // isolation boundary, so it must always be present and validated.
        validation.set_required_spec_claims(&["exp", "aud", "iss"]);

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

#[cfg(test)]
impl Claims {
    pub fn from_json(value: serde_json::Value) -> Self {
        Self {
            claims: serde_json::from_value(value).expect("invalid test claims JSON"),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_str_returns_string_value() {
        let claims = Claims::from_json(serde_json::json!({
            "iss": "https://example.com",
            "sub": "user123"
        }));
        assert_eq!(claims.get_str("iss"), Some("https://example.com"));
        assert_eq!(claims.get_str("sub"), Some("user123"));
    }

    #[test]
    fn get_str_returns_none_for_number() {
        let claims = Claims::from_json(serde_json::json!({
            "iat": 1234567890
        }));
        assert_eq!(claims.get_str("iat"), None);
    }

    #[test]
    fn get_str_returns_none_for_missing_key() {
        let claims = Claims::from_json(serde_json::json!({
            "iss": "https://example.com"
        }));
        assert_eq!(claims.get_str("nonexistent"), None);
    }
}

#[cfg(test)]
mod jwt_validation_tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use std::time::{SystemTime, UNIX_EPOCH};

    // A throwaway RSA keypair generated solely for these tests. The matching
    // public key parameters are embedded in the JWKS below.
    const TEST_KEY_PEM: &str = include_str!("../test_fixtures/test_rsa_key.pem");
    const TEST_KID: &str = "test-key";
    const TEST_ISSUER: &str = "https://token.actions.githubusercontent.com";
    const TEST_AUDIENCE: &str = "https://oidcx.example.com";

    // Public key (n, e) of TEST_KEY_PEM in base64url form.
    const JWK_N: &str = "kXMiJsiWS_dpudfVUZfk2HC50le8P0V3PYrmYYgRFcoxIl-3tUS1KoA_DOWrVsw1-4k52hvAA24_nGnP9Wdma_s0meoWUeOMAMVrOLU3J4YKjWEG37T8uqOd--NzzUHliH9-Gg08R89IeLbKOHAGBkG38W5D1oT2oAu15FXN2azVPRokQhAYtakydLg9hJymDunnu8Jz27wxFKEfHJqjpyAGDOrb2WGhVgGH5ByP16jDKKHJd-Tq9TvzbLUlj6N2a1RkhEeaeKH18-aaMTdFLF_VARC4EMPjMdg-ZeMc_kqrvRuSPip8NTkfEHJjkG2DLL3RKNDB_2nbuiZZl5DLLQ";
    const JWK_E: &str = "AQAB";

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn test_config() -> ResolvedOidcConfig {
        let jwks: JwkSet = serde_json::from_value(serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "kid": TEST_KID,
                "alg": "RS256",
                "use": "sig",
                "n": JWK_N,
                "e": JWK_E,
            }]
        }))
        .expect("failed to build test JWKS");

        ResolvedOidcConfig {
            issuer: TEST_ISSUER.to_string(),
            jwks,
            subject_types_supported: vec![],
            response_types_supported: vec![],
            claims_supported: vec![],
            id_token_signing_alg_values_supported: vec![Algorithm::RS256],
            scopes_supported: vec![],
        }
    }

    fn test_settings(audience: &str) -> Settings {
        Settings {
            audience: audience.to_string(),
            policy_path: std::path::PathBuf::new(),
            log_directory: None,
            port: None,
            providers: vec![],
            oxide: None,
            github: None,
        }
    }

    fn valid_claims() -> serde_json::Value {
        serde_json::json!({
            "iss": TEST_ISSUER,
            "aud": TEST_AUDIENCE,
            "exp": now() + 300,
            "iat": now() - 10,
            "jti": "test-jti",
            "repository": "oxidecomputer/hubris",
        })
    }

    /// Sign a token with RS256 using the test private key (the legitimate path).
    fn sign_rs256(claims: serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(TEST_KID.to_string());
        let key = EncodingKey::from_rsa_pem(TEST_KEY_PEM.as_bytes())
            .expect("failed to load test signing key");
        encode(&header, &claims, &key).expect("failed to sign test token")
    }

    #[test]
    fn accepts_valid_token() {
        let config = test_config();
        let settings = test_settings(TEST_AUDIENCE);
        let token = sign_rs256(valid_claims());
        let claims = config
            .validate(&settings, &token)
            .expect("a correctly signed token with the right aud/iss/exp should be accepted");
        assert_eq!(claims.get_str("repository"), Some("oxidecomputer/hubris"));
    }

    #[test]
    fn rejects_wrong_audience() {
        // Token minted for this service but the service expects a different
        // audience — must be rejected (cross-service replay protection).
        let config = test_config();
        let settings = test_settings("https://some-other-service.example.com");
        let token = sign_rs256(valid_claims());
        assert!(
            config.validate(&settings, &token).is_err(),
            "token with mismatched audience must be rejected"
        );
    }

    #[test]
    fn rejects_missing_audience() {
        // A token with no `aud` claim must not be accepted, otherwise a token
        // not scoped to any service could be replayed here.
        let config = test_config();
        let settings = test_settings(TEST_AUDIENCE);
        let mut claims = valid_claims();
        claims.as_object_mut().unwrap().remove("aud");
        let token = sign_rs256(claims);
        assert!(
            config.validate(&settings, &token).is_err(),
            "token without an aud claim must be rejected"
        );
    }

    #[test]
    fn rejects_wrong_issuer() {
        let config = test_config();
        let settings = test_settings(TEST_AUDIENCE);
        let mut claims = valid_claims();
        claims["iss"] = serde_json::json!("https://evil.example.com");
        let token = sign_rs256(claims);
        assert!(
            config.validate(&settings, &token).is_err(),
            "token with mismatched issuer must be rejected"
        );
    }

    #[test]
    fn rejects_missing_issuer() {
        let config = test_config();
        let settings = test_settings(TEST_AUDIENCE);
        let mut claims = valid_claims();
        claims.as_object_mut().unwrap().remove("iss");
        let token = sign_rs256(claims);
        assert!(
            config.validate(&settings, &token).is_err(),
            "token without an iss claim must be rejected"
        );
    }

    #[test]
    fn rejects_expired_token() {
        let config = test_config();
        let settings = test_settings(TEST_AUDIENCE);
        let mut claims = valid_claims();
        claims["exp"] = serde_json::json!(now() - 3600);
        let token = sign_rs256(claims);
        assert!(
            config.validate(&settings, &token).is_err(),
            "expired token must be rejected"
        );
    }

    #[test]
    fn rejects_missing_exp() {
        let config = test_config();
        let settings = test_settings(TEST_AUDIENCE);
        let mut claims = valid_claims();
        claims.as_object_mut().unwrap().remove("exp");
        let token = sign_rs256(claims);
        assert!(
            config.validate(&settings, &token).is_err(),
            "token without an exp claim must be rejected"
        );
    }

    #[test]
    fn rejects_unknown_kid() {
        // The token references a key that isn't in the JWKS.
        let config = test_config();
        let settings = test_settings(TEST_AUDIENCE);
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("some-other-key".to_string());
        let key = EncodingKey::from_rsa_pem(TEST_KEY_PEM.as_bytes()).unwrap();
        let token = encode(&header, &valid_claims(), &key).unwrap();
        let err = config.validate(&settings, &token).unwrap_err();
        assert!(
            matches!(err, OidcError::UnknownKid(_)),
            "expected UnknownKid, got: {err:?}"
        );
    }

    #[test]
    fn rejects_tampered_signature() {
        // Sign a valid token, then corrupt the signature segment. Verifies the
        // RS256 signature is actually checked.
        let config = test_config();
        let settings = test_settings(TEST_AUDIENCE);
        let token = sign_rs256(valid_claims());
        let mut parts: Vec<&str> = token.split('.').collect();
        let tampered_sig = if parts[2].starts_with('A') {
            format!("B{}", &parts[2][1..])
        } else {
            format!("A{}", &parts[2][1..])
        };
        parts[2] = &tampered_sig;
        let tampered = parts.join(".");
        assert!(
            config.validate(&settings, &tampered).is_err(),
            "token with a tampered signature must be rejected"
        );
    }

    #[test]
    fn rejects_hs256_key_confusion() {
        // The classic RS256 → HS256 key confusion attack: an attacker signs a
        // token with HS256, using the (public) RSA key material as the HMAC
        // secret, hoping the verifier will treat the public key as a shared
        // secret. The JWKS declares RS256, so validation must only accept
        // RS256 and reject the HS256 token on algorithm grounds, before any
        // signature check.
        let config = test_config();
        let settings = test_settings(TEST_AUDIENCE);

        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(TEST_KID.to_string());
        // The attacker can use any secret; the public key bytes are the usual
        // choice. It does not matter — the algorithm itself must be refused.
        let secret = EncodingKey::from_secret(JWK_N.as_bytes());
        let token = encode(&header, &valid_claims(), &secret).unwrap();

        let err = config.validate(&settings, &token).unwrap_err();
        assert!(
            matches!(err, OidcError::InvalidToken(_)),
            "HS256 token must be rejected, got: {err:?}"
        );
    }

    #[test]
    fn rejects_none_algorithm() {
        // An `alg: none` (unsigned) token must never be accepted.
        // jsonwebtoken refuses to even encode `none`, so craft the token
        // manually: base64url(header).base64url(claims). with an empty sig.
        use base64::Engine;
        let config = test_config();
        let settings = test_settings(TEST_AUDIENCE);
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = engine.encode(
            serde_json::json!({ "alg": "none", "typ": "JWT", "kid": TEST_KID }).to_string(),
        );
        let payload = engine.encode(valid_claims().to_string());
        let token = format!("{header}.{payload}.");
        assert!(
            config.validate(&settings, &token).is_err(),
            "unsigned (alg: none) token must be rejected"
        );
    }
}
