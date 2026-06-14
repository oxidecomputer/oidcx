// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use oxide::{ByteStream, Client, ClientConfig, ClientConsoleAuthExt, OxideAuthError};
use schemars::JsonSchema;
use serde::Deserialize;
use std::{collections::HashMap, path::PathBuf};
use tap::TapFallible;
use thiserror::Error;

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
    #[error("Silo token located at {0} is malformed")]
    ReadToken(PathBuf, #[source] std::io::Error),
    #[error("The silo {0} is not configured in this instance of oidcx")]
    SiloNotConfigured(String),
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
            | OxideError::ReadToken(..) => false,
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
        let Some(settings) = &settings.oxide else {
            return Ok(Self { state: None });
        };

        let mut clients = HashMap::new();
        for (silo, token_path) in &settings.silos {
            let token = std::fs::read_to_string(&token_path)
                .map_err(|e| OxideError::ReadToken(token_path.clone(), e))?;
            let config = ClientConfig::default().with_host_and_token(silo, token);
            clients.insert(
                silo.clone(),
                Client::new_authenticated_config(&config)
                    .map_err(|e| OxideError::AuthFailed(silo.clone(), e))?,
            );
        }
        Ok(Self {
            state: Some(State {
                clients,
                allow_tokens_without_expiry: settings.allow_tokens_without_expiry,
                max_duration: settings.max_duration,
            }),
        })
    }

    pub async fn get(&self, request: &OxideTokenRequest) -> Result<Token, OxideError> {
        let Some(state) = &self.state else {
            return Err(OxideError::NotConfigured.into());
        };

        if request.duration <= 0 && !state.allow_tokens_without_expiry {
            return Err(OxideError::NoExpirationDisallowed.into());
        }
        if request.duration > state.max_duration {
            return Err(OxideError::TooLongExpiration(state.max_duration).into());
        }

        let client = state
            .clients
            .get(&*request.silo.as_str())
            .ok_or_else(|| OxideError::SiloNotConfigured(request.silo.to_string()))?;

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
