// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use oxide::{ByteStream, Client, ClientConfig, ClientConsoleAuthExt, OxideAuthError};
use schemars::JsonSchema;
use secrecy::ExposeSecret;
use serde::Deserialize;
use std::collections::HashMap;
use tap::TapFallible;
use thiserror::Error;
use tracing::instrument;
use v_api_param::ParamResolutionError;

use crate::{
    endpoints::Token,
    oauth::{DeviceAccessTokenError, DeviceAccessTokenGrant, DeviceAuthorizationResponse},
    settings::Settings,
    util::{ByteStreamError, Url, parse_bytestream},
};

static CLIENT_ID: &str = "730ae5f1-a728-4a5d-9a06-cf09b653cca6";

#[derive(Debug, Error)]
pub enum OxideError {
    #[error("Error reading response")]
    ByteStream(#[from] ByteStreamError),
    #[error("Failed to issue device access token request")]
    DeviceAuthRequest(#[from] DeviceAccessTokenError),
    #[error("Failed to resolve the silo manifest or a silo credential")]
    ResolveParam(#[from] ParamResolutionError),
    #[error("The silo {0} is not configured in this instance of oidcx")]
    SiloNotConfigured(String),
    #[error("The configured silo url {0} is not a valid url: {1}")]
    InvalidSiloUrl(String, String),
    #[error("Failed to authenticate with silo {0}")]
    AuthFailed(String, #[source] OxideAuthError),
    #[error("Remote service error")]
    Oxide(#[from] oxide::Error<oxide::types::Error>),
    #[error("Remote service error")]
    OxideByteError(#[from] oxide::Error<ByteStream>),
    #[error("The Oxide token provider is not configured")]
    NotConfigured,
    #[error("Tokens with no expiration are not allowed")]
    NoExpirationDisallowed,
    #[error("The duration of this token is more than the maximum of {0} seconds")]
    TooLongExpiration(u32),
}

impl OxideError {
    pub fn safe_to_expose(&self) -> bool {
        match self {
            OxideError::ByteStream(..)
            | OxideError::DeviceAuthRequest(..)
            | OxideError::AuthFailed(..)
            | OxideError::Oxide(..)
            | OxideError::OxideByteError(..)
            | OxideError::ResolveParam(..)
            | OxideError::InvalidSiloUrl(..) => false,
            OxideError::SiloNotConfigured(..)
            | OxideError::NotConfigured
            | OxideError::NoExpirationDisallowed
            | OxideError::TooLongExpiration(..) => true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Hash, PartialEq, Eq)]
pub struct OxideTokenRequest {
    pub silo: Url,
    pub duration: u32,
}

#[derive(Debug)]
pub struct OxideTokens {
    state: Option<State>,
}

impl OxideTokens {
    pub fn new(settings: &Settings) -> Result<Self, OxideError> {
        let base = settings.params_base_path.as_deref();

        let Some(oxide) = &settings.oxide else {
            return Ok(Self { state: None });
        };

        // The set of silos is environment-specific and unknown at build time,
        // so it lives in a manifest on the parameters volume rather than in the
        // static settings.toml. Resolving the `JsonParam` reads and parses that
        // manifest into a `url -> credential` map.
        let manifest = oxide.silos.resolve(base)?;

        let mut clients = HashMap::new();
        for (url, credential) in manifest {
            // The credential may be inline or read from a file on the volume.
            // `resolve` performs any required I/O and trims trailing newlines,
            // which would otherwise break token parsing.
            let token = credential.resolve(base)?;

            // Normalize the manifest key through the same canonical form used
            // to look up clients for an incoming request, so the two always
            // agree regardless of trailing slash, host case, or default port.
            let silo = url
                .parse::<reqwest::Url>()
                .map_err(|e| OxideError::InvalidSiloUrl(url.clone(), e.to_string()))?
                .to_string();

            let config = ClientConfig::default().with_host_and_token(&silo, token.expose_secret());
            clients.insert(
                silo.clone(),
                Client::new_authenticated_config(&config)
                    .map_err(|e| OxideError::AuthFailed(silo, e))?,
            );
        }
        Ok(Self {
            state: Some(State {
                clients,
                allow_tokens_without_expiry: oxide.allow_tokens_without_expiry,
                max_duration: oxide.max_duration,
            }),
        })
    }

    #[instrument(skip(self), err(Debug))]
    pub async fn get(&self, request: &OxideTokenRequest) -> Result<Token, OxideError> {
        let Some(state) = &self.state else {
            return Err(OxideError::NotConfigured.into());
        };

        validate_duration(
            request.duration,
            state.allow_tokens_without_expiry,
            state.max_duration,
        )?;

        let client = state
            .clients
            .get(&request.silo.to_string())
            .ok_or_else(|| {
                tracing::info!(available = ?state.clients.keys(), "Requested silo has not found");
                OxideError::SiloNotConfigured(request.silo.to_string())
            })?;

        let device_response = match client
            .device_auth_request()
            .body_map(|body| {
                body.client_id(CLIENT_ID)
                    .ttl_seconds(if request.duration == 0 {
                        None
                    } else {
                        Some(request.duration.try_into().unwrap())
                    })
            })
            .send()
            .await
        {
            Ok(data) => {
                parse_bytestream::<DeviceAuthorizationResponse>(data.into_inner().into_inner())
                    .await?
            }
            Err(err) => {
                tracing::error!(?err, "Failed to issue device auth request");

                // Attempt to parse the error response
                match err {
                    oxide::Error::ErrorResponse(stream) => {
                        let error_data =
                            parse_bytestream::<DeviceAccessTokenError>(stream.into_inner_stream())
                                .await?;
                        return Err(error_data.into());
                    }
                    _ => return Err(err.into()),
                }
            }
        };

        // Once we have the user code, submit it to the API to confirm the request
        client
            .device_auth_confirm()
            .body_map(|body| body.user_code(device_response.user_code))
            .send()
            .await
            .tap_err(|err| {
                tracing::error!(?err, "Failed to confirm device auth request");
            })?;

        // Given that we are performing these requests serially, the token should be
        // ready by the time we make this call
        let data = client
            .device_access_token()
            .body_map(|body| {
                body.client_id(CLIENT_ID)
                    .device_code(device_response.device_code)
                    .grant_type("urn:ietf:params:oauth:grant-type:device_code")
            })
            .send()
            .await
            .tap_err(|err| {
                tracing::error!(?err, "Failed to retrieve device access token");
            })?
            .into_inner()
            .into_inner();
        let access_token_response = parse_bytestream::<DeviceAccessTokenGrant>(data).await?;

        Ok(Token {
            access_token: access_token_response.access_token,
        })
    }
}

#[derive(Debug)]
struct State {
    clients: HashMap<String, Client>,
    allow_tokens_without_expiry: bool,
    max_duration: u32,
}

/// Validate the requested token lifetime against the instance's policy.
///
/// A duration of `0` means "no expiration" and is only permitted when the
/// instance explicitly allows it. Any duration above `max_duration` is
/// rejected. Note `duration` is a `u32`, so `0` is the only "non-positive"
/// value that can occur.
fn validate_duration(
    duration: u32,
    allow_tokens_without_expiry: bool,
    max_duration: u32,
) -> Result<(), OxideError> {
    if duration == 0 && !allow_tokens_without_expiry {
        return Err(OxideError::NoExpirationDisallowed);
    }
    if duration > max_duration {
        return Err(OxideError::TooLongExpiration(max_duration));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX: u32 = 3600;

    #[test]
    fn rejects_zero_duration_when_expiry_required() {
        let err = validate_duration(0, false, MAX).unwrap_err();
        assert!(
            matches!(err, OxideError::NoExpirationDisallowed),
            "got: {err:?}"
        );
    }

    #[test]
    fn allows_zero_duration_when_configured() {
        validate_duration(0, true, MAX)
            .expect("a zero duration must be allowed when the instance permits it");
    }

    #[test]
    fn allows_normal_duration() {
        validate_duration(300, false, MAX).expect("an in-bounds duration must be allowed");
    }

    #[test]
    fn allows_duration_at_max_boundary() {
        validate_duration(MAX, false, MAX).expect("a duration equal to the max must be allowed");
    }

    #[test]
    fn rejects_duration_exceeding_max() {
        let err = validate_duration(MAX + 1, false, MAX).unwrap_err();
        assert!(
            matches!(err, OxideError::TooLongExpiration(m) if m == MAX),
            "got: {err:?}"
        );
    }

    #[test]
    fn rejects_overlong_duration_even_when_no_expiry_allowed() {
        // allow_tokens_without_expiry only relaxes the zero case; it must not
        // permit a duration above the maximum.
        let err = validate_duration(MAX + 1, true, MAX).unwrap_err();
        assert!(
            matches!(err, OxideError::TooLongExpiration(m) if m == MAX),
            "got: {err:?}"
        );
    }

    #[test]
    fn duration_errors_are_safe_to_expose() {
        assert!(OxideError::NoExpirationDisallowed.safe_to_expose());
        assert!(OxideError::TooLongExpiration(MAX).safe_to_expose());
    }
}
