use futures_util::future::BoxFuture;
use http::{
    header::COOKIE,
    HeaderMap, HeaderValue, Request, Response, StatusCode, Uri,
};
use http_body::combinators::UnsyncBoxBody;
use log::{error, trace};
use tower_http::auth::AsyncAuthorizeRequest;

#[derive(Clone)]
pub struct JwtValidator {
    cookie_name: String,
    validate_url: Uri,
}

impl JwtValidator {
    pub fn new(cookie_name: String, validate_url: Uri) -> Self {
        Self {
            cookie_name: cookie_name,
            validate_url: validate_url,
        }
    }
}

enum AuthResult {
    AuthOk(UserId),
    AuthErr(StatusCode),
}

use AuthResult::{AuthErr, AuthOk};

impl<B> AsyncAuthorizeRequest<B> for JwtValidator
where
    B: Send + 'static,
{
    type RequestBody = B;
    // ResponseBody type is set by AsyncRequireAuthorizationLayer, can't change it.
    type ResponseBody = UnsyncBoxBody<axum::body::Bytes, axum::Error>;
    type Future = BoxFuture<'static, Result<Request<B>, Response<Self::ResponseBody>>>;

    fn authorize(&mut self, mut request: Request<B>) -> Self::Future {
        let cookie_name = self.cookie_name.clone();
        let validate_url = self.validate_url.clone();
        let headers = request.headers().clone();

        let r = Box::pin(async move {
            match auth_with_remote(cookie_name, validate_url, headers).await {
                AuthOk(user_id) => {
                    request.extensions_mut().insert(user_id);
                    Ok(request)
                }
                AuthErr(status_code) => {
                    let mut r = Response::default();
                    *r.status_mut() = status_code;
                    Err(r)
                }
            }
        });
        // be a future that resolves to `Result<Request<B>, Response<UnsyncBoxBody<Bytes, Error>>>`
        r
    }
}

#[derive(Debug)]
pub struct UserId(pub String);

async fn auth_with_remote(
    cookie_name: String,
    validate_url: Uri,
    headers: HeaderMap<HeaderValue>,
) -> AuthResult {
    match headers.get(COOKIE) {
        Some(headver_value_wraper) => {
            // extract JWT
            match headver_value_wraper.to_str() {
                Ok(header_value) => {
                    for cookie in header_value.to_string().split(';') {
                        // extract cookie name  name=value; expires=; ...
                        if let Some((req_cookie_name, jwt)) = cookie.split_once("=") {
                            if req_cookie_name.eq(cookie_name.as_str()) {
                                match send_message(validate_url.clone(), cookie).await {
                                    Ok(is_valid) => {
                                        if !is_valid {
                                            return AuthErr(StatusCode::FORBIDDEN);
                                        }
                                        // extract subject ID as user ID
                                        return get_user_id(jwt);
                                    }
                                    Err(err) => {
                                        error!("failed to authenticate with gateway: {}", err);
                                        return AuthErr(StatusCode::BAD_GATEWAY);
                                    }
                                }
                            }
                        }
                    }
                    return AuthErr(StatusCode::UNAUTHORIZED);
                }
                _ => {
                    return AuthErr(StatusCode::BAD_REQUEST);
                }
            }
        }
        _ => {
            return AuthErr(StatusCode::UNAUTHORIZED);
        }
    }
}

async fn send_message(url: Uri, cookie: &str) -> Result<bool, anyhow::Error> {
    let https = hyper_tls::HttpsConnector::new();
    let client = hyper::client::Client::builder().build::<_, hyper::Body>(https);
    let mut req = Request::default();
    (*req.headers_mut()).insert(COOKIE, HeaderValue::from_str(cookie)?);
    *req.uri_mut() = url;
    let resp = client.request(req).await?;
    Ok(resp.status() == StatusCode::OK)
}

fn get_user_id(jwt_str: &str) -> AuthResult {
    match jwt::Token::<jwt::Header, jwt::RegisteredClaims, _>::parse_unverified(jwt_str) {
        Ok(jwt) => {
            if let Some(subject) = jwt.claims().subject.clone() {
                AuthOk(UserId(subject))
            } else {
                trace!("JWT without sub: {}", jwt_str);
                AuthErr(StatusCode::BAD_REQUEST)
            }
        }
        Err(err) => {
            trace!("JWT failed to parse: {}, jwt: {}", err, jwt_str);
            AuthErr(StatusCode::BAD_REQUEST)
        }
    }
}
