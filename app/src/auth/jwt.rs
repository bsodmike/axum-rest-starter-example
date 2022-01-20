use app_core::error::{self, Error, Kind};
use async_redis_session::RedisSessionStore;
use axum::{
    async_trait,
    body::{self, Body, BoxBody, Bytes, Full, HttpBody},
    extract::{
        extractor_middleware, rejection::*, Extension, Form, FromRequest, Path, RequestParts,
        TypedHeader,
    },
    handler::Handler,
    headers::{authorization::Bearer, Authorization, Cookie, Header, HeaderMapExt},
    http::{
        self, header::HeaderName, header::LOCATION, uri::Parts, HeaderMap, HeaderValue, Method,
        Request, StatusCode, Uri,
    },
    response::{Html, IntoResponse, Json, Redirect, Response},
    routing::{get, post, Router},
    AddExtensionLayer,
};
use axum_extra::middleware::{self, Next};
use chrono;
use jsonwebtoken::{
    decode, encode, DecodingKey, EncodingKey, Header as JWTHeader, TokenData, Validation,
};
use regex::Regex;
use serde::{de, Deserialize, Serialize};
use std::fmt::Display;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    sub: String,
    company: String,
    exp: usize,
}

impl Display for Claims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Email: {}\nCompany: {}", self.sub, self.company)
    }
}

impl AuthBody {
    fn new(access_token: String) -> Self {
        Self {
            access_token,
            token_type: "Bearer".to_string(),
        }
    }
}

pub async fn authorize(
    Json(payload): Json<AuthPayload>,
    Extension(app_state): Extension<crate::AppState>,
) -> Result<Json<AuthBody>, error::AuthError> {
    // Check if the user sent the credentials
    if payload.client_id.is_empty() || payload.client_secret.is_empty() {
        return Err(error::AuthError::MissingCredentials);
    }
    // Here you can check the user credentials from a database
    if payload.client_id != "foo" || payload.client_secret != "bar" {
        return Err(error::AuthError::WrongCredentials);
    }

    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::days(2))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        sub: "b@b.com".to_owned(),
        company: "ACME".to_owned(),
        exp: expiration as usize,
    };
    // Create the authorization token
    let token = encode(
        &JWTHeader::default(),
        &claims,
        &app_state.jwt_config.keys.encoding,
    )
    .map_err(|_| error::AuthError::TokenCreation)?;

    // Send the authorized token
    Ok(Json(AuthBody::new(token)))
}

pub async fn api_auth<B>(req: Request<B>, next: Next<B>) -> Result<Response, error::AuthError> {
    let uri = req.uri();
    let path = uri.path();

    /*
     * Auth for JWT for any URI starting with /api
     */
    let _token_data: TokenData<Claims>;
    if let Some(value) = extract_path_root(&path, r"^(?P<path_root>/api)").await? {
        tracing::debug!("Uri: {}", &value);

        let app_state = req
            .extensions()
            .get::<crate::AppState>()
            .expect("Unable to fetch `AppState`");
        let headers = req.headers();

        tracing::info!("Extracting bearer token");
        let TypedHeader(Authorization(bearer)) =
            match headers.typed_try_get::<Authorization<Bearer>>() {
                Ok(Some(value)) => TypedHeader(value),
                _ => {
                    return Err(error::AuthError::InvalidToken);
                }
            };
        tracing::info!("Bearer token: {:?}", &bearer.token());

        // Decode the user data
        tracing::info!("Decoding token");
        _token_data = decode::<Claims>(
            bearer.token(),
            &app_state.jwt_config.keys.decoding,
            &Validation::default(),
        )
        .map_err(|err| {
            tracing::error!("Decoding JWT token error! {:?}", err.to_string());

            error::AuthError::InvalidToken
        })?;
    };

    Ok(next.run(req).await)
}

#[derive(Debug)]
pub struct Keys {
    encoding: EncodingKey,
    decoding: DecodingKey<'static>,
}

impl Keys {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret).into_static(),
        }
    }
}

impl Clone for Keys {
    fn clone(&self) -> Self {
        Self {
            encoding: self.encoding.clone(),
            decoding: self.decoding.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AuthBody {
    access_token: String,
    token_type: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthPayload {
    client_id: String,
    client_secret: String,
}

pub async fn extract_path_root<'a>(
    input: &'a str,
    target: &'a str,
) -> Result<Option<&'a str>, error::UriError> {
    let re: Regex = Regex::new(target).unwrap();

    Ok(re
        .captures(input)
        .and_then(|cap| cap.name("path_root").map(|el| el.as_str())))
}
