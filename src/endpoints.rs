// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use dropshot::{HttpError, HttpResponseOk, RequestContext, TypedBody, endpoint};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::token::github::GitHubTokenRequest;
use crate::token::oxide::OxideTokenRequest;
use crate::{context::Context, oidc::IssuerClaim};

// An Oxide access token with a fixed expiration time.
#[derive(Debug, Serialize, JsonSchema)]
pub struct Token {
    pub access_token: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExchangeBody {
    caller_identity: String,
    #[serde(flatten)]
    request: TokenRequest,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(tag = "service", rename_all = "lowercase")]
pub enum TokenRequest {
    Oxide(OxideTokenRequest),
    GitHub(GitHubTokenRequest),
}

/// Exchange an OIDC provider identity token for an Oxide access token.
#[endpoint {
    path = "/exchange",
    method = POST,
}]
pub async fn exchange(
    rqctx: RequestContext<Context>,
    body: TypedBody<ExchangeBody>,
) -> Result<HttpResponseOk<Token>, HttpError> {
    let ctx = rqctx.context();
    let body = body.into_inner();

    let issuer = jsonwebtoken::dangerous::insecure_decode::<IssuerClaim>(&body.caller_identity)
        .map_err(|err| {
            tracing::info!(?err, "Failed to decode token");
            HttpError::for_bad_request(None, "Invalid token".to_string())
        })?
        .claims
        .iss;

    let provider = ctx
        .providers
        .get(&issuer)
        .ok_or_else(|| {
            tracing::info!(issuer, "Provider not found for issuer");
            HttpError::for_bad_request(None, "Unsupported issuer".to_string())
        })?
        .clone();

    // Continue to the next authorization if the token does not match the required constraints
    let principal = {
        let provider = provider.read().unwrap();
        let claims = provider
            .config
            .validate(&ctx.settings, &body.caller_identity)
            .map_err(|err| {
                tracing::info!(?err, "Failed to validate token");
                HttpError::for_bad_request(None, "Token validation failed".to_string())
            })?;
        (provider.build_principal)(&claims).map_err(|err| {
            tracing::info!(?err, "Failed to construct principal");
            HttpError::for_bad_request(None, format!("Failed to construct principal: {err}"))
        })?
    };

    ctx.policy
        .ensure_allowed(&principal, &body.request)
        .await
        .map_err(|err| {
            // Never disclose *why* authorization failed. The specific variant
            // (e.g. "repository not found" vs "does not match the policy")
            // would otherwise let an unauthorized caller probe for information
            // about internal data.
            tracing::info!(?err, "Failed to match the token against the policy");
            HttpError::for_bad_request(None, "A policy failure occurred".to_string())
        })?;

    Ok(HttpResponseOk(match &body.request {
        TokenRequest::Oxide(oxide) => ctx.oxide_tokens.get(oxide).await.map_err(|err| {
            tracing::error!(?err, "Failed to generate token");
            if err.safe_to_expose() {
                HttpError::for_bad_request(None, format!("Failed to generate token: {err}"))
            } else {
                HttpError::for_internal_error("Failed to generate token".to_string())
            }
        })?,
        TokenRequest::GitHub(github) => ctx.github_tokens.get(github).await.map_err(|err| {
            tracing::error!(?err, "Failed to generate token");
            if err.safe_to_expose() {
                HttpError::for_bad_request(None, format!("Failed to generate token: {err}"))
            } else {
                HttpError::for_internal_error("Failed to generate token".to_string())
            }
        })?,
    }))
}
