// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::net::{SocketAddr, SocketAddrV4};
use tap::TapFallible;
use tracing_appender::non_blocking::NonBlocking;
use tracing_subscriber::EnvFilter;

use crate::{
    context::Context,
    server::{ServerConfig, server},
    settings::Settings,
};

mod context;
mod endpoints;
mod oauth;
mod oidc;
mod policy;
mod providers;
mod server;
mod settings;
mod token;
mod util;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let mut args = std::env::args();
    let _ = args.next();
    let config_path = args.next();
    let settings = Settings::new(config_path.map(|path| vec![path]))?;

    let (writer, _guard) = if let Some(log_directory) = &settings.log_directory {
        let file_appender = tracing_appender::rolling::daily(log_directory, "oidcx.log");
        tracing_appender::non_blocking(file_appender)
    } else {
        NonBlocking::new(std::io::stdout())
    };

    let _subscriber = tracing_subscriber::fmt()
        .with_file(false)
        .with_line_number(false)
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(writer)
        .json()
        .init();

    let address = SocketAddr::V4(SocketAddrV4::new(
        "0.0.0.0".parse()?,
        settings.port.unwrap_or(8080),
    ));
    let context = Context::new(settings).await?;

    tracing::info!("Constructed context");

    let http = server(ServerConfig {
        context,
        server_address: address,
    })
    .or_else(|err| anyhow::bail!(err))?;

    http.start()
        .await
        .tap_err(|err| {
            tracing::error!(error = ?err, "HTTP server failed");
        })
        .or_else(|err| anyhow::bail!(err))?;

    Ok(())
}
