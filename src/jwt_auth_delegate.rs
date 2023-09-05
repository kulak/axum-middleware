use http::{header, Request, Response, StatusCode};
use http_body::Body;
use log::{error, warn};
use std::{fmt, marker::PhantomData};

use tower_http::validate_request::ValidateRequest;

pub struct JwtValidator<ResBody> {
    cookie_name: String,
    validate_url: String,
    _ty: PhantomData<fn() -> ResBody>,
}

impl<ResBody> JwtValidator<ResBody> {
    pub fn new(cookie_name: String, validate_url: String) -> Self
    where
        ResBody: Body + Default,
    {
        Self {
            cookie_name: cookie_name,
            validate_url: validate_url,
            _ty: PhantomData,
        }
    }

    fn send_message(&self, cookie: &str) -> Result<bool, anyhow::Error> {
        let response = ureq::get(self.validate_url.as_str())
            .set("Cookie", cookie)
            .call()?;
        Ok(response.status() == 200)
    }
}

impl<ResBody> Clone for JwtValidator<ResBody> {
    fn clone(&self) -> Self {
        Self {
            cookie_name: self.cookie_name.clone(),
            validate_url: self.validate_url.clone(),
            _ty: PhantomData,
        }
    }
}

impl<ResBody> fmt::Debug for JwtValidator<ResBody> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwtBearer")
            .field("header_value", &self.cookie_name.as_str())
            .finish()
    }
}

impl<B, ResBody> ValidateRequest<B> for JwtValidator<ResBody>
where
    ResBody: Body + Default,
{
    type ResponseBody = ResBody;

    fn validate(&mut self, request: &mut Request<B>) -> Result<(), Response<Self::ResponseBody>> {
        match request.headers().get(header::COOKIE) {
            Some(headver_value_wraper) => {
                // extract JWT

                match headver_value_wraper.to_str() {
                    Ok(header_value) => {
                        for cookie in header_value.to_string().split(';') {
                            // extract cookie name  name=value; expires=; ...
                            if let Some((req_cookie_name, _)) = cookie.split_once("=") {
                                if req_cookie_name.eq(self.cookie_name.as_str()) {
                                    // found JWT coockie
                                    // send verification request

                                    match self.send_message(cookie) {
                                        Err(err) => {
                                            error!("failed to authenticate with gateway: {}", err);

                                            let mut res = Response::new(ResBody::default());
                                            *res.status_mut() = StatusCode::BAD_GATEWAY;
                                            return Err(res);
                                        }
                                        Ok(is_valid) => {
                                            if is_valid {
                                                return Ok(());
                                            } else {
                                                let mut res = Response::new(ResBody::default());
                                                *res.status_mut() = StatusCode::FORBIDDEN;
                                                return Err(res);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        warn!("failed to find JWT cookie");

                        let mut res = Response::new(ResBody::default());
                        *res.status_mut() = StatusCode::UNAUTHORIZED;
                        Err(res)
                    }
                    Err(err) => {
                        warn!("failed to get cookie value: {}", err);

                        let mut res = Response::new(ResBody::default());
                        *res.status_mut() = StatusCode::BAD_REQUEST;
                        Err(res)
                    }
                }
            }
            _ => {
                warn!("failed to get cookie header");

                let mut res = Response::new(ResBody::default());
                *res.status_mut() = StatusCode::UNAUTHORIZED;
                Err(res)
            }
        }
    }
}
