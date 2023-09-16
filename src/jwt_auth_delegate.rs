use std::marker::PhantomData;

use futures_util::future::BoxFuture;
use http::{
    header::COOKIE,
    HeaderMap, HeaderValue, Request, Response, StatusCode, Uri,
};
use http_body::combinators::UnsyncBoxBody;
use log::{error, trace};
use tower_http::auth::AsyncAuthorizeRequest;

pub trait FromJwtSubject
where 
    Self: Clone + std::marker::Send + std::marker::Sync + 'static
{
    fn from_jwt_sub(jwt_sub: String) -> Result<Self, StatusCode>;
}

#[derive(Clone)]
pub struct JwtValidator<U> 
where
    U: Clone,
{
    cookie_name: String,
    validate_url: Uri,
    phantom: PhantomData<U>
}

impl<U> JwtValidator<U> 
where
    U: Clone
{
    pub fn new(cookie_name: String, validate_url: Uri) -> Self {
        Self {
            cookie_name: cookie_name,
            validate_url: validate_url,
            phantom: PhantomData,
        }
    }
}

impl<B, U> AsyncAuthorizeRequest<B> for JwtValidator<U>
where
    B: Send + 'static,
    U: Clone + std::marker::Send + std::marker::Sync + FromJwtSubject + 'static,
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
            match auth_with_remote::<U>(cookie_name, validate_url, headers).await {
                Ok(user_id) => {
                    request.extensions_mut().insert(user_id);
                    Ok(request)
                }
                Err(status_code) => {
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

#[derive(Debug, Clone)]
pub struct UserId(pub String);

impl FromJwtSubject for UserId
{
    fn from_jwt_sub(jwt_sub: String) -> Result<Self, StatusCode> {
        Ok(UserId(jwt_sub))
    }
}

#[derive(Debug, Clone)]
pub struct UserId32(pub i32);

impl FromJwtSubject for UserId32 {
    fn from_jwt_sub(jwt_sub: String) -> Result<Self, StatusCode> {
        match jwt_sub.parse::<i32>() {
            Ok(num) => Ok(UserId32(num)),
            Err(_) => Err(StatusCode::BAD_REQUEST),
        }
    }
}

async fn auth_with_remote<U>(
    cookie_name: String,
    validate_url: Uri,
    headers: HeaderMap<HeaderValue>,
) -> Result<U, StatusCode> 
where
    U: Clone + std::marker::Send + std::marker::Sync + FromJwtSubject + 'static
{
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
                                            return Err(StatusCode::FORBIDDEN);
                                        }
                                        // extract subject ID as user ID
                                        return get_user_id::<U>(jwt);
                                    }
                                    Err(err) => {
                                        error!("failed to authenticate with gateway: {}", err);
                                        return Err(StatusCode::BAD_GATEWAY);
                                    }
                                }
                            }
                        }
                    }
                    return Err(StatusCode::UNAUTHORIZED);
                }
                _ => {
                    return Err(StatusCode::BAD_REQUEST);
                }
            }
        }
        _ => {
            return Err(StatusCode::UNAUTHORIZED);
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

fn get_user_id<U>(jwt_str: &str) -> Result<U, StatusCode> 
where
    U: Clone + std::marker::Send + std::marker::Sync + FromJwtSubject + 'static,
{
    match jwt::Token::<jwt::Header, jwt::RegisteredClaims, _>::parse_unverified(jwt_str) {
        Ok(jwt) => {
            if let Some(subject) = jwt.claims().subject.clone() {
                U::from_jwt_sub(subject)
            } else {
                trace!("JWT without sub: {}", jwt_str);
                Err(StatusCode::BAD_REQUEST)
            }
        }
        Err(err) => {
            trace!("JWT failed to parse: {}, jwt: {}", err, jwt_str);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}
