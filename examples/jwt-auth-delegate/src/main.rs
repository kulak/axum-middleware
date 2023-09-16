use std::env;

use anyhow::{Result, Context};
use axum::Extension;
use axum::response::IntoResponse;
use axum_middleware::jwt_auth_delegate::{self, UserId32};

use axum::{
    routing::{on, MethodFilter},
    Router,
};

use flexi_logger::Logger;
use jwt_auth_delegate::JwtValidator;
use tower_http::auth::AsyncRequireAuthorizationLayer;

#[tokio::main]
async fn main() -> Result<()> {
    Logger::try_with_str("info")?.start()?;

    dotenvy::dotenv()?;

    let cookie_name = env::var("COOKIE_NAME").context("COOKIE_NAME")?;
    let validate_uri = env::var("VALIDATE_URL").context("VALIDATE_URL")?.parse().context("PARSE")?;

    let layer = AsyncRequireAuthorizationLayer::new(JwtValidator::<UserId32>::new(cookie_name, validate_uri));

    let app = Router::new()
        .route_service("/", on(MethodFilter::GET, handle))
        .layer(layer);

    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

async fn handle(Extension(UserId32(user_id)): Extension<UserId32>) -> impl IntoResponse {
    return format!("HELLO User ID: {}", user_id).into_response();
}
