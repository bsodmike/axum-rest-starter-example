use crate::{
    error::{self, Error, ErrorImpl, Kind},
    BoxError,
};
use async_redis_session::RedisSessionStore;
use async_session::{MemoryStore, Session, SessionStore};
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
use cookie::{self, SameSite};
use futures::future::TryFutureExt;
use rand::RngCore;
use redis::AsyncCommands;
use redis::Client;
use serde::{de, Deserialize, Serialize};
use std::error::Error as ErrorTrait;
use std::str::FromStr;
use tracing::Instrument;
use uuid::Uuid;

pub const AXUM_SESSION_COOKIE_NAME: &str = "axum-session";
pub const AXUM_SESSION_ID: &str = "axum-session-id";

pub async fn session<
    B,
    T: std::marker::Sync + SessionStore,
    U: Default + std::marker::Sync + Serialize,
>(
    mut req: Request<B>,
    next: Next<B>,
) -> impl IntoResponse {
    // Fetch domain from env var
    let domain = match std::env::var("DOMAIN") {
        Ok(value) => value,
        Err(err) => panic!("$DOMAIN is not set: {:?}", err),
    };
    dbg!(&domain);

    if domain.as_str() == "" {
        panic!(
            "App domain is missing {:?}",
            error::new(Kind::EnvironmentVariableMissing)
        )
    };

    // Fetch SessionStore
    let store = req
        .extensions()
        .get::<T>()
        .expect("`RedisSessionStore` extension missing!");

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
        let mut session = Session::new();

        /*
         * Initialise a new user instance with new UUID
         */
        match session.insert("user", U::default()) {
            Ok(value) => value,
            Err(err) => {
                tracing::error!("Error: Unable to update session with user {:?}", err);

                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

        let session_clone = session.clone();
        //let cookie = store.store_session(session).await.unwrap();
        //dbg!(&cookie);

        let cookie: String = match store.store_session(session).await {
            Ok(value) => match value {
                Some(cookie_value) => cookie_value,
                None => {
                    tracing::error!("Unable to fetch cookie value from new session!");

                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
            },
            Err(err) => {
                tracing::error!("Error whilst attempting to update store {:?}", err);

                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

        tracing::debug!("Updated Session: {:?}", &session_clone.id());

        tracing::debug!(
            "Created cookie {:?}={:?} for UUID {} / for Session: {:?}",
            AXUM_SESSION_COOKIE_NAME,
            &cookie,
            &new_uuid,
            &session_clone
        );

        // Return response only, without advancing through the middleware stack; we pass the cookie
        // back to the client and redirect to the root path. This should only happen once per every
        // request that does not include a valid session cookie.
        let _body = axum::body::Body::empty().boxed_unsync();
        let mut res = Response::builder()
            .status(StatusCode::SEE_OTHER)
            .body(_body)
            .unwrap();

        let headers = res.headers_mut();
        headers.insert(
            http::header::LOCATION,
            req.uri().to_string().parse().unwrap(),
        );

        let full_cookie = cookie::Cookie::build(AXUM_SESSION_COOKIE_NAME, &cookie)
            .domain(&domain)
            .path("/")
            .secure(true)
            .same_site(SameSite::Strict)
            .http_only(true)
            .finish();

        let set_cookie = HeaderValue::from_str(full_cookie.to_string().as_str()).unwrap();
        headers.insert(http::header::SET_COOKIE, set_cookie);

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

    let session_cookie_clone = session_cookie.clone();
    // continue to decode session, fetch UUID from Redis
    let session: Session = match store
        .load_session(session_cookie.unwrap().to_string())
        .await
    {
        Ok(value) => match value {
            Some(session_value) => session_value,
            None => {
                /*
                 * FIXME: ideally, we should generate a new session and redirect the user to the
                 * path they've requested.
                 */
                tracing::error!(
                    "Error! Unable to locate session in backend! Cookie: {:?}",
                    session_cookie_clone
                );

                return Err(StatusCode::BAD_REQUEST);
            }
        },
        Err(err) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    let request_headers = req.headers_mut();
    request_headers.insert(
        AXUM_SESSION_ID,
        HeaderValue::from_str(format!("{}", &session.id()).as_str()).unwrap(),
    );

    /*
     * Call the next handler in the middleware stack
     */
    let mut res = next.run(req).await;

    let mut _headers = res.headers_mut();
    headers_copy.insert(
        AXUM_SESSION_ID,
        HeaderValue::from_str(format!("{}", session.id()).as_str()).unwrap(),
    );
    _headers = &mut headers_copy;

    tracing::debug!("session_uuid_middleware, Headers: {:?}", &_headers);
    dbg!(&_headers);

    Ok(res)
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct UserId(pub Uuid);

impl UserId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    #[allow(dead_code)]
    fn from(provided_uuid: uuid::Uuid) -> Self {
        Self(provided_uuid)
    }
}

impl Default for UserId {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn body_content<T>(body_taken: Option<Body>) -> Result<T, Error>
where
    T: de::DeserializeOwned,
{
    let body = if let Some(value) = body_taken {
        value
    } else {
        return Err(error::new(Kind::NotImplementedError));
    };

    let body_bytes = hyper::body::to_bytes(body).await?;
    let body_deserialized = match serde_urlencoded::from_bytes::<T>(&body_bytes) {
        Ok(value) => value,
        Err(err) => {
            tracing::error!("Error: Unable to deserialize request body {:?}", err);

            return Err(error::new(Kind::NotImplementedError));
        }
    };

    Ok(body_deserialized)
}

pub async fn update<U: Serialize>(
    headers: &HeaderMap,
    store: &RedisSessionStore,
    user: U,
) -> Result<(), Error> {
    let cookie_result = match headers.typed_try_get::<Cookie>() {
        Ok(Some(value)) => TypedHeader(value),
        _ => {
            return Err(error::new(Kind::NotImplementedError));
        }
    };

    let session_cookie = &cookie_result
        .get(AXUM_SESSION_COOKIE_NAME)
        .expect("Unable to fetch session cookie!");

    tracing::debug!(
        "handle_form: got session cookie from user agent, {:?}={:?}",
        AXUM_SESSION_COOKIE_NAME,
        &session_cookie
    );

    // Use `session_cookie` to load the session
    let mut session: Session = match store.load_session(session_cookie.to_string()).await {
        Ok(value) => match value {
            Some(session_value) => session_value,
            None => {
                tracing::error!("Error: Unable to load session!");

                return Err(error::new(Kind::NotImplementedError));
            }
        },
        Err(err) => {
            return Err(error::new(Kind::NotImplementedError));
        }
    };

    session.set_cookie_value(session_cookie.to_string());

    match session.insert("user", user) {
        Ok(value) => value,
        Err(err) => {
            tracing::error!("Error: Unable to update session with user {:?}", err);

            return Err(error::new(Kind::NotImplementedError));
        }
    };

    let _: String = match store.store_session(session).await {
        Ok(value) => match value {
            Some(cookie_value) => {
                tracing::debug!(
                    "Store updated OK / Cookie value returned {:?}",
                    cookie_value
                );

                cookie_value
            }
            None => {
                tracing::debug!("Store updated OK / No cookie value returned");

                String::from("")
            }
        },
        Err(err) => {
            tracing::error!("Error whilst attempting to update store {:?}", err);

            return Err(error::new(Kind::NotImplementedError));
        }
    };

    Ok(())
}

pub async fn fetch<T>(headers: &HeaderMap, store: &RedisSessionStore, key: &str) -> Result<T, Error>
where
    T: de::DeserializeOwned,
{
    let cookie_result = match headers.typed_try_get::<Cookie>() {
        Ok(Some(value)) => TypedHeader(value),
        _ => {
            return Err(error::new(Kind::NotImplementedError));
        }
    };

    let session_cookie = &cookie_result
        .get(AXUM_SESSION_COOKIE_NAME)
        .expect("Unable to fetch session cookie!");

    tracing::debug!(
        "handle_form: got session cookie from user agent, {:?}={:?}",
        AXUM_SESSION_COOKIE_NAME,
        &session_cookie
    );

    // Use `session_cookie` to load the session
    let session: Session = match store.load_session(session_cookie.to_string()).await {
        Ok(value) => match value {
            Some(session_value) => session_value,
            None => {
                tracing::error!("Error: Unable to load session!");

                return Err(error::new(Kind::NotImplementedError));
            }
        },
        Err(err) => {
            return Err(error::new(Kind::NotImplementedError));

            //FIXME need to solve error handling approach
            //`async-session` does not implement `std::error::Error` for it's re-export of
            //`anyhow::Error`.
            //let error = Error {
            //    inner: Box::new(error::ErrorImpl {
            //        kind: Kind::NotImplementedError,
            //        cause: Some(Box::new(err)),
            //    }),
            //};
            //return Err(error);
        }
    };

    let session_fetched: T = match session.get::<T>(key) {
        Some(val) => val,
        None => {
            tracing::error!("Unable to fetch user from session!");

            return Err(error::new(Kind::NotImplementedError));
        }
    };

    Ok(session_fetched)
}
