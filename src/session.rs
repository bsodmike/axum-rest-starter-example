use async_session::{MemoryStore, Session, SessionStore as _};
use axum::{
    body::{Body, BoxBody, HttpBody},
    headers::{Cookie, HeaderMapExt},
    http::{self, HeaderValue, Request, StatusCode},
    response::{IntoResponse, Response},
};
use axum_extra::middleware::{self, Next};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const AXUM_SESSION_COOKIE_NAME: &str = "axum_session";

pub async fn session_uuid_middleware<B>(req: Request<B>, next: Next<B>) -> impl IntoResponse {
    let store = req
        .extensions()
        .get::<MemoryStore>()
        .expect("`MemoryStore` extension missing");

    let headers = req.headers();
    let cookie = headers.typed_try_get::<Cookie>().unwrap();

    let session_cookie = cookie
        .as_ref()
        .and_then(|cookie| cookie.get(AXUM_SESSION_COOKIE_NAME));

    dbg!(&cookie);
    dbg!(&session_cookie);

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
        headers.insert(http::header::LOCATION, "/".parse().unwrap());
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
    let _user_id = if let Some(session) = store
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
            "session_uuid_middleware: Err session does not exist in store, {}={}",
            AXUM_SESSION_COOKIE_NAME,
            session_cookie.unwrap()
        );
        return Err(StatusCode::BAD_REQUEST);
    };

    let res = next.run(req).await;

    Ok(res)
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct UserId(pub Uuid);

impl UserId {
    fn new() -> Self {
        Self(Uuid::new_v4())
    }
}
