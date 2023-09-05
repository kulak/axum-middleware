use std::env;

use anyhow::Result;
use axum_middleware::jwt_auth_delegate;
use flexi_logger::Logger;

use axum::{response::Html, routing::get, Router};
use tower::ServiceBuilder;

use log::info;

use jwt_auth_delegate::JwtValidator;
use tower_http::validate_request::ValidateRequestHeaderLayer;

fn app() -> Result<Router> {
    let middleware = ServiceBuilder::new().layer(ValidateRequestHeaderLayer::custom(
        JwtValidator::new(env::var("COOKIE_NAME")?, env::var("VALIDATE_URL")?),
    ));

    Ok(Router::new().route("/", get(handler)).layer(middleware))
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv()?;

    let _logger = Logger::try_with_str("info")?.start();

    info!("running application");
    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app()?.into_make_service())
        .await?;
    Ok(())
}

async fn handler() -> Html<&'static str> {
    Html("<h1>Hello, World!</h1>")
}
