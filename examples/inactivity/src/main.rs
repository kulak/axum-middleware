use anyhow::Result;
use flexi_logger::Logger;
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

use axum::{middleware::from_fn_with_state, response::Html, routing::get, Router};
use tower::ServiceBuilder;

use axum_middleware::inactivity;

use log::info;

#[derive(Clone)]
struct AppState {
    inactivity_state: inactivity::InactivityState,
}

impl axum::extract::FromRef<AppState> for inactivity::InactivityState {
    fn from_ref(app_state: &AppState) -> inactivity::InactivityState {
        app_state.inactivity_state.clone()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let _logger = Logger::try_with_str("info")?.start();
    info!("Started Application");

    let inactivity_state = inactivity::InactivityState {
        last_accessed: Arc::new(Mutex::new(OffsetDateTime::now_utc())),
    };
    let state = AppState {
        inactivity_state: inactivity_state.clone(),
    };

    let app = Router::new()
        .route("/", get(handler))
        .layer(
            ServiceBuilder::new()
                .layer(from_fn_with_state(state.clone(), inactivity::track_request)),
        )
        .with_state(state);

    info!("running application");
    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .with_graceful_shutdown(inactivity::wait_for_idle(inactivity_state, 5, 1))
        .await
        .unwrap();

    info!("Finished Application");
    Ok(())
}

async fn handler() -> Html<&'static str> {
    Html("<h1>Hello, World!</h1>")
}
