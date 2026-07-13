// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use schemars::JsonSchema;
use schemars::schema::{InstanceType, SchemaObject, StringValidation};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use std::{fmt, ops::Deref, str::FromStr};
use thiserror::Error;

/// A newtype wrapper around [`reqwest::Url`] that implements [`JsonSchema`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Url(reqwest::Url);

impl Url {
    pub fn into_inner(self) -> reqwest::Url {
        self.0
    }
}

impl Deref for Url {
    type Target = reqwest::Url;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for Url {
    type Err = <reqwest::Url as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        reqwest::Url::from_str(s).map(Url)
    }
}

impl From<reqwest::Url> for Url {
    fn from(url: reqwest::Url) -> Self {
        Url(url)
    }
}

impl JsonSchema for Url {
    fn schema_name() -> String {
        "Url".to_string()
    }

    fn json_schema(_gen: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        SchemaObject {
            instance_type: Some(InstanceType::String.into()),
            format: Some("uri".to_string()),
            string: Some(Box::new(StringValidation {
                min_length: Some(1),
                ..Default::default()
            })),
            ..Default::default()
        }
        .into()
    }
}

#[derive(Debug, Error)]
pub enum ByteStreamError {
    #[error("Failed to read bytes from stream")]
    FailedToRead,
    #[error("Failed to parse read bytes")]
    FailedToParse,
}

pub async fn parse_bytestream<T>(
    mut stream: Pin<Box<dyn Stream<Item = reqwest::Result<Bytes>> + Send + Sync>>,
) -> Result<T, ByteStreamError>
where
    T: DeserializeOwned,
{
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        bytes.extend(
            chunk
                .map_err(|err| {
                    tracing::error!(?err, "Failed to read byte stream");
                    ByteStreamError::FailedToRead
                })?
                .to_vec(),
        );
    }

    Ok(serde_json::from_slice::<T>(&bytes).map_err(|err| {
        tracing::error!(?err, "Failed to parse byte stream");
        ByteStreamError::FailedToParse
    })?)
}
