#![allow(unused_imports)]
use async_session::{MemoryStore, Session, SessionStore as _};
use axum::headers::HeaderMapExt;
use axum::{
    async_trait,
    body::{Body, BoxBody, Bytes},
    extract::{
        extractor_middleware, rejection::TypedHeaderRejection,
        rejection::TypedHeaderRejectionReason, Extension, Form, FromRequest, Path, RequestParts,
        TypedHeader,
    },
    handler::Handler,
    headers::Cookie,
    http::{self, header::LOCATION, HeaderMap, HeaderValue, Method, Request, StatusCode, Uri},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post, Router},
    AddExtensionLayer, Json,
};
use axum_extra::middleware::{self, Next};
use config::*;
use glob::glob;
use once_cell::sync::Lazy;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::convert::Infallible;
use std::env;
use std::net::SocketAddr;
use tower::{
    filter::AsyncFilterLayer, limit::ConcurrencyLimitLayer, util::AndThenLayer, BoxError,
    ServiceBuilder,
};
use tower_http::trace::TraceLayer;
use uuid::Uuid;

pub mod configure;
pub mod errors;
pub mod wrappers;

use crate::errors::{ApiResult, Error};

pub static CONFIG: Lazy<config::Config> = Lazy::new(|| {
    let mut glob_path = "conf/development/*";
    let mut settings = Config::default();

    let run_mode = match std::env::var("RUST_ENV") {
        Ok(value) => value,
        Err(_) => String::new(),
    };

    if run_mode.eq("production") {
        glob_path = "conf/production/*";
        println!("RUST_ENV={}", run_mode);
    }

    settings
        .merge(
            glob(glob_path)
                .unwrap()
                .map(|path| File::from(path.unwrap()))
                .collect::<Vec<_>>(),
        )
        .unwrap();
    settings
});

#[derive(Clone)]
struct AppState {
    redis_client: redis::Client,
}

const AXUM_SESSION_COOKIE_NAME: &str = "axum_session";

#[tokio::main]
async fn main() {
    // Set the RUST_LOG, if it hasn't been explicitly defined
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "register_otp=debug,tower_http=debug")
    }
    tracing_subscriber::fmt::init();

    // `MemoryStore` just used as an example. Don't use this in production.
    let store = MemoryStore::new();

    let middleware_stack = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(AddExtensionLayer::new(AppState {
            redis_client: crate::wrappers::redis_wrapper::connect().await,
        }))
        .layer(middleware::from_fn(print_request_info_middleware))
        .layer(AddExtensionLayer::new(store))
        .layer(middleware::from_fn(session_uuid_middleware));

    // build our application with some routes
    let app = Router::new()
        .route("/", get(show_form).post(accept_form))
        .route("/foo", get(foo_handler))
        //.route_layer(extractor_middleware::<SessionUUID>())
        .layer(middleware_stack);

    // add a fallback service for handling routes to unknown paths
    let app = app.fallback(handler_404.into_service());

    // run it with hyper
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn foo_handler() {}

// Session management
async fn session_uuid_middleware(
    req: Request<Body>,
    next: Next<Body>,
) -> Result<impl IntoResponse, StatusCode> {
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
        //return Err((StatusCode::BAD_REQUEST, "Session cookie does not exist!"));

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

        let mut res = next.run(req).await;
        let res_headers = res.headers_mut();
        let cookie_value =
            HeaderValue::from_str(format!("{}={}", AXUM_SESSION_COOKIE_NAME, cookie).as_str())
                .unwrap();
        res_headers.insert(http::header::SET_COOKIE, cookie_value);

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

async fn print_request_info_middleware(
    req: Request<Body>,
    next: Next<Body>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let (parts, body) = req.into_parts();

    println!("Request body:");
    dbg!(&body);
    let bytes = buffer_and_print("request", body).await?;

    println!("Request parts:");
    dbg!(&parts);
    let req = Request::from_parts(parts, Body::from(bytes));

    let mut res = next.run(req).await;

    let headers = res.headers_mut();
    dbg!(headers);

    let (parts, body) = res.into_parts();

    println!("Response body:");
    dbg!(&body);
    let bytes = buffer_and_print("response", body).await?;

    println!("Response parts:");
    dbg!(&parts);
    let res = Response::from_parts(parts, Body::from(bytes));

    Ok(res)
}

async fn buffer_and_print<B>(direction: &str, body: B) -> Result<Bytes, (StatusCode, String)>
where
    B: axum::body::HttpBody<Data = Bytes>,
    B::Error: std::fmt::Display,
{
    let bytes = match hyper::body::to_bytes(body).await {
        Ok(bytes) => bytes,
        Err(err) => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("failed to read {} body: {}", direction, err),
            ));
        }
    };

    if let Ok(body) = std::str::from_utf8(&bytes) {
        tracing::debug!("{} body = {:?}", direction, body);
    }

    Ok(bytes)
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
struct UserId(Uuid);

impl UserId {
    fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

// Frontend logic
async fn show_form() -> Html<&'static str> {
    Html(
        r#"
        <!doctype html>
        <html>
            <head></head>
            <body>
                <form action="/" method="post">
                    <label for="name">
                        Enter your name:
                        <input type="text" name="name">
                    </label>
                    <label>
                        Enter your email:
                        <input type="text" name="email">
                    </label>
                    <input type="submit" value="Subscribe!">
                </form>
            </body>
        </html>
        "#,
    )
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct Input {
    name: String,
    email: String,
}

async fn accept_form(Form(input): Form<Input>, state: Extension<AppState>) -> Redirect {
    dbg!(&input);

    match save_form(&input, &state).await {
        Ok(_) => (),
        Err(e) => tracing::error!("Failed: {:?}", e),
    }

    Redirect::to("/".parse().unwrap())
}

async fn save_form(input: &Input, state: &Extension<AppState>) -> redis::RedisResult<()> {
    let client = &state.redis_client;
    let mut con = client.get_async_connection().await?;

    let name = input.name.to_owned();
    let name_str = &name[..];

    con.set("async-key1", name_str).await?;
    let result: String = con.get("async-key1").await?;
    println!("->> my_key: {}\n", result);

    Ok(())
}

async fn handler_404(method: Method, uri: Uri) -> impl IntoResponse {
    StatusCode::NOT_FOUND
}
