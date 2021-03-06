//! This is the main application

#![forbid(unsafe_code)]
#![deny(unreachable_pub, private_in_public)]
#![allow(unused_imports)]
#![warn(rust_2018_idioms, future_incompatible, nonstandard_style)]

use app_core::error::{self, Error, Kind};
use async_redis_session::RedisSessionStore;
use async_session::{Session, SessionStore as _};
use axum::headers::HeaderMapExt;
use axum::{
    async_trait,
    body::{self, Body, BoxBody, Bytes, Full},
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
use axum_extra::middleware::{self as axum_middleware, Next};
use axum_rest_middleware::{self, middleware as RestMiddleware};
use config::*;
use glob::glob;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use std::{collections::HashMap, env};
use tower::{
    filter::AsyncFilterLayer, limit::ConcurrencyLimitLayer, util::AndThenLayer, BoxError,
    ServiceBuilder,
};
use tower_http::trace::TraceLayer;
use uuid::Uuid;

pub mod api;
pub mod auth;
pub mod configure;
pub mod handlers;
pub mod middleware;
pub mod wrappers;

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
#[allow(dead_code)]
pub struct AppState {
    redis_session_client: redis::Client,
    jwt_config: JWTConfig,
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct JWTConfig {
    keys: auth::jwt::Keys,
    client_id: String,
    client_secret: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct User {
    pub uuid: String,
    pub name: String,
    pub email: String,
}

impl Default for User {
    fn default() -> Self {
        User {
            uuid: Uuid::new_v4().to_string(),
            name: String::from(""),
            email: String::from(""),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set the RUST_LOG, if it hasn't been explicitly defined
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var(
            "RUST_LOG",
            "axum_rest_starter_example=debug,tower_http=debug",
        )
    }
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_file(true)
        .with_line_number(true)
        .init();

    let redis_session_db: String = configure::fetch_configuration("redis_session_db").await?;

    let session_client =
        crate::wrappers::redis_wrapper::connect(HashMap::from([("db", redis_session_db.clone())]))
            .await?;

    let jwt_secret: String = configure::fetch_configuration("jwt_secret").await?;
    let jwt_client_id: String = configure::fetch_configuration("jwt_client_id").await?;
    let jwt_client_secret: String = configure::fetch_configuration("jwt_client_secret").await?;

    let app_state = AppState {
        redis_session_client: crate::wrappers::redis_wrapper::connect(HashMap::from([(
            "db",
            redis_session_db,
        )]))
        .await?,
        jwt_config: JWTConfig {
            keys: auth::jwt::Keys::new(jwt_secret.as_bytes()),
            client_id: jwt_client_id,
            client_secret: jwt_client_secret,
        },
    };
    let store = RedisSessionStore::from_client(session_client);

    let middleware_stack = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(AddExtensionLayer::new(app_state))
        .layer(axum_extra::middleware::from_fn(
            crate::middleware::debugging::print_request_info_middleware,
        ))
        .layer(AddExtensionLayer::new(store))
        .layer(axum_extra::middleware::from_fn(
            RestMiddleware::session::<_, RedisSessionStore, User>,
        ))
        .layer(axum_extra::middleware::from_fn(auth::jwt::api_auth));

    // build our application with some routes
    let app = Router::new()
        .route("/", get(handlers::show_form).post(handlers::handle_form))
        .route("/privacy-policy", get(handlers::privacy_policy_handler))
        .route("/authorize", post(auth::jwt::authorize))
        .route("/api/protected", get(api::protected))
        .route(
            "/api/v1/drops/:drop_id/registrations",
            post(api::handle_registration_post),
        )
        .layer(middleware_stack);

    // add a fallback service for handling routes to unknown paths
    let app = app.fallback(handlers::handler_404.into_service());

    // run it with hyper
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}
