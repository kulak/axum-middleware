use axum::{
    extract::State,
    http::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;
use tokio::time::interval;

#[derive(Clone)]
pub struct InactivityState {
    pub last_accessed: Arc<Mutex<OffsetDateTime>>,
}

pub async fn track_request<B>(
    State(state): State<InactivityState>,
    request: Request<B>,
    next: Next<B>,
) -> Result<impl IntoResponse, Response> {
    {
        let mut lock = state.last_accessed.lock().unwrap();
        // info!("in track request, updating last accessed state {}", lock);
        *lock = OffsetDateTime::now_utc();
    }
    Ok(next.run(request).await)
}

pub async fn wait_for_idle(state: InactivityState, limit_secs: i64, check_interval_secs: u64) {
    let mut interval = interval(core::time::Duration::from_secs(check_interval_secs));
    loop {
        {
            let now = OffsetDateTime::now_utc();
            let idle: time::Duration;
            {
                let last = state.last_accessed.lock().unwrap();
                idle = now - *last;
            }
            if idle.whole_seconds() > limit_secs {
                return;
            };
        }
        interval.tick().await;
    }
}
