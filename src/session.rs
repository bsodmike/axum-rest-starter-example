use async_session::{MemoryStore, Session as AsyncSession, SessionStore as _};
use axum::{
    async_trait,
    body::{Body, BoxBody, HttpBody},
    extract::{
        extractor_middleware, rejection::TypedHeaderRejection,
        rejection::TypedHeaderRejectionReason, Extension, Form, FromRequest, Path, RequestParts,
        TypedHeader,
    },
    headers::{Cookie, HeaderMap, HeaderMapExt},
    http::{self, header::HeaderName, HeaderValue, Request, StatusCode},
    response::{IntoResponse, Response},
};
use axum_extra::middleware::{self, Next};
use rand::RngCore;
use redis::AsyncCommands;
use redis::Client;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use uuid::Uuid;

use crate::{errors, AppState};

pub const AXUM_SESSION_COOKIE_NAME: &str = "axum-session";
pub const AXUM_USER_UUID: &str = "axum-user-uuid";

pub async fn session_uuid_middleware<B>(mut req: Request<B>, next: Next<B>) -> impl IntoResponse {
    let app_state = req
        .extensions()
        .get::<AppState>()
        .expect("`AppState` extension missing!");
    let redis_client: &redis::Client = &app_state.redis_cookie_client;
    let mut redis_connection = redis_client
        .get_async_connection()
        .await
        .expect("Unable to fetch redis connection!");

    let headers = req.headers();
    let mut headers_copy = HeaderMap::new();

    for header in headers.iter() {
        let (k, v) = header;
        let hv = v.to_str().expect("Unable to fetch header value");

        let value: &str = hv;
        let header_value: HeaderValue = HeaderValue::from_str(value).unwrap();
        let header_name: HeaderName = HeaderName::from_str(k.as_str()).unwrap();
        headers_copy.insert(header_name, header_value);
    }

    tracing::debug!("Headers copied: {:?}", &headers_copy);

    let cookie = headers.typed_try_get::<Cookie>().unwrap();

    let session_cookie = cookie
        .as_ref()
        .and_then(|cookie| cookie.get(AXUM_SESSION_COOKIE_NAME));
    tracing::debug!("Session cookie: {:?}", &session_cookie);

    // return the new created session cookie for client
    if session_cookie.is_none() {
        let user_id = UserId::new();
        let new_uuid = user_id.0.to_hyphenated().to_string();
        let raw_uuid: &str = new_uuid.as_str();
        let gen_cookie = generate_cookie(64);
        let new_cookie: &str = gen_cookie.as_str();

        // Store session UUID against the cookie hash into Redis
        let persist_cookie = new_cookie;

        #[allow(clippy::clone_double_ref)]
        let persist_raw_uuid = raw_uuid.clone();

        let _redis_set = if let Ok(value) = redis_connection
            .set::<String, String, String>(persist_cookie.to_string(), persist_raw_uuid.to_string())
            .await
        {
            value
        } else {
            tracing::error!("Unable to persist cookie hash!");

            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        };

        tracing::debug!(
            "Created UUID {:?} for user cookie, {:?}={:?}",
            raw_uuid,
            AXUM_SESSION_COOKIE_NAME,
            new_cookie
        );

        // Return response only, without advancing through the middleware stack; we pass the cookie
        // back to the client and redirect to the root path. This should only happen once per every
        // request that does not include a valid session cookie.
        let _body = axum::body::Body::empty().boxed_unsync();
        let mut res = Response::builder()
            .status(StatusCode::SEE_OTHER)
            .body(_body)
            .unwrap();

        let cookie_value =
            HeaderValue::from_str(format!("{}={}", AXUM_SESSION_COOKIE_NAME, new_cookie).as_str())
                .unwrap();
        let headers = res.headers_mut();
        headers.insert(
            http::header::LOCATION,
            req.uri().to_string().parse().unwrap(),
        );
        headers.insert(http::header::SET_COOKIE, cookie_value);

        // It is also possible to call `let res = res.map(axum::body::boxed)`
        // to correct the response type.
        let res = res.into_response();

        tracing::debug!("Session UUID Creation: Done. Response: {:?}", res);
        return Ok(res);
    }

    tracing::debug!(
        "session_uuid_middleware: got session cookie from user agent, {:?}={:?}",
        AXUM_SESSION_COOKIE_NAME,
        &session_cookie.unwrap()
    );

    // continue to decode session, fetch UUID from Redis
    let raw_session_cookie: &str = session_cookie.unwrap();
    let fetched_uuid: String = redis_connection.get(raw_session_cookie).await.unwrap();

    let user_id = if let Ok(user_id) = uuid::Uuid::parse_str(&fetched_uuid) {
        user_id
    } else {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };

    let request_headers = req.headers_mut();
    request_headers.insert(
        AXUM_USER_UUID,
        HeaderValue::from_str(format!("{}", UserId::from(user_id).0).as_str()).unwrap(),
    );

    /*
     * Call the next handler in the middleware stack
     */
    let mut res = next.run(req).await;

    let mut _headers = res.headers_mut();
    headers_copy.insert(
        AXUM_USER_UUID,
        HeaderValue::from_str(format!("{}", UserId::from(user_id).0).as_str()).unwrap(),
    );
    _headers = &mut headers_copy;

    tracing::debug!("session_uuid_middleware, Headers: {:?}", &_headers);
    dbg!(&_headers);

    Ok(res)
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct UserId(pub Uuid);

impl UserId {
    fn new() -> Self {
        Self(Uuid::new_v4())
    }

    fn from(provided_uuid: uuid::Uuid) -> Self {
        Self(provided_uuid)
    }
}

#[derive(Deserialize, Debug, Clone, Copy)]
pub struct Session {
    pub uuid: uuid::Uuid,
}

impl Session {
    pub async fn update(
        self,
        headers: &HeaderMap,
        client: &redis::Client,
        name: &str,
    ) -> Result<(), errors::Error> {
        let user_uuid: &HeaderValue =
            if let Some(value) = headers.get(crate::session::AXUM_USER_UUID) {
                value
            } else {
                return Err(errors::Error::NotImplementedError);
            };

        let mut con = client
            .get_async_connection()
            .await
            .expect("Unable to connect to Redis!");
        let uuid = user_uuid.to_str().unwrap();
        let _ = if let Ok(val) = con.set::<&str, &str, String>(uuid, name).await {
            val
        } else {
            return Err(errors::Error::RedisSetError);
        };

        let result: String = con.get(uuid).await.unwrap();
        println!("->> User UUID: {}\n", result);

        Ok(())
    }
}

#[async_trait]
impl<B> FromRequest<B> for Session
where
    B: Send, // required by `async_trait`
{
    type Rejection = http::StatusCode;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        // Connect to Redis
        let Extension(app_state) = Extension::<AppState>::from_request(req)
            .await
            .expect("`AppState` extension missing!");
        let redis_client: &redis::Client = &app_state.redis_cookie_client;
        let mut redis_connection = redis_client
            .get_async_connection()
            .await
            .expect("Unable to fetch redis connection!");

        let cookie = Option::<TypedHeader<Cookie>>::from_request(req)
            .await
            .unwrap();

        tracing::debug!("cookie: {:?}", cookie);

        let session_cookie = cookie
            .as_ref()
            .and_then(|cookie| cookie.get(crate::session::AXUM_SESSION_COOKIE_NAME));

        tracing::debug!(
            "session_uuid_middleware: got session cookie from user agent, {:?}={:?}",
            crate::session::AXUM_SESSION_COOKIE_NAME,
            &session_cookie.unwrap()
        );

        // continue to decode the session cookie
        let raw_session_cookie: &str = session_cookie.unwrap();
        let fetched_uuid: String = redis_connection
            .get::<String, String>(raw_session_cookie.to_string())
            .await
            .unwrap();

        let user_id = if let Ok(user_id) = uuid::Uuid::parse_str(&fetched_uuid) {
            user_id
        } else {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        };

        Ok(Self {
            uuid: UserId::from(user_id).0,
        })
    }
}

/// generates a random cookie value
fn generate_cookie(len: usize) -> String {
    let mut key = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut key);
    base64::encode(key)
}
