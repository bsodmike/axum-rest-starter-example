use async_session::{MemoryStore, Session, SessionStore as _};
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
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use uuid::Uuid;

pub const AXUM_SESSION_COOKIE_NAME: &str = "axum_session";
pub const AXUM_USER_UUID: &str = "axum_user_uuid";

pub async fn session_uuid_middleware<B>(req: Request<B>, next: Next<B>) -> impl IntoResponse {
    let store = req
        .extensions()
        .get::<MemoryStore>()
        .expect("`MemoryStore` extension missing");

    let headers = req.headers();
    let mut headers_copy = HeaderMap::new();

    for header in headers.iter() {
        let _header = header.clone();
        if let (k, v) = header {
            let hv = v.to_str().expect("Unable to fetch header value");

            let value: &str = hv;
            let header_value: HeaderValue = HeaderValue::from_str(value).unwrap();
            let header_name: HeaderName = HeaderName::from_str(k.as_str()).unwrap();
            headers_copy.insert(header_name, header_value);
        };
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
        let mut session = Session::new();
        session.insert("user_id", user_id).unwrap();
        let cookie = store.store_session(session).await.unwrap().unwrap();

        tracing::debug!(
            "Created UUID {:?} for user cookie, {:?}={:?}",
            user_id,
            AXUM_SESSION_COOKIE_NAME,
            cookie
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
            HeaderValue::from_str(format!("{}={}", AXUM_SESSION_COOKIE_NAME, cookie).as_str())
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

    // continue to decode the session cookie
    let user_id = if let Some(session) = store
        .load_session(session_cookie.unwrap().to_owned())
        .await
        .unwrap()
    {
        if let Some(user_id) = session.get::<UserId>("user_id") {
            tracing::debug!(
                "session_uuid_middleware: session decoded success, user_id={:?}",
                user_id
            );
            user_id
        } else {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    } else {
        tracing::debug!(
            "session_uuid_middleware: Error!! Session does not exist in store, {}={}",
            AXUM_SESSION_COOKIE_NAME,
            session_cookie.unwrap()
        );
        return Err(StatusCode::BAD_REQUEST);
    };

    // TODO need to use the User UUID
    let mut res = next.run(req).await;
    let mut _headers = res.headers_mut();
    headers_copy.insert(
        AXUM_USER_UUID,
        HeaderValue::from_str(format!("{}", user_id.0).as_str()).unwrap(),
    );
    _headers = &mut headers_copy;

    Ok(res)
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct UserId(pub Uuid);

impl UserId {
    fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

pub struct UserFromSession {
    pub uuid: uuid::Uuid,
}

#[async_trait]
impl<B> FromRequest<B> for UserFromSession
where
    B: Send, // required by `async_trait`
{
    type Rejection = http::StatusCode;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let Extension(store) = Extension::<MemoryStore>::from_request(req)
            .await
            .expect("`MemoryStore` extension missing");

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
        let user_id = if let Some(session) = store
            .load_session(session_cookie.unwrap().to_owned())
            .await
            .unwrap()
        {
            if let Some(user_id) = session.get::<crate::session::UserId>("user_id") {
                tracing::debug!(
                    "session_uuid_middleware: session decoded success, user_id={:?}",
                    user_id
                );
                user_id
            } else {
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        } else {
            tracing::debug!(
                "session_uuid_middleware: Err session does not exist in store, {}={}",
                crate::session::AXUM_SESSION_COOKIE_NAME,
                session_cookie.unwrap()
            );
            return Err(StatusCode::BAD_REQUEST);
        };

        Ok(Self { uuid: user_id.0 })
    }
}
