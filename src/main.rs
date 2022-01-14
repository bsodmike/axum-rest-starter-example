#![allow(unused_imports)]
use async_session::{MemoryStore, Session, SessionStore as _};
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
use config::*;
use glob::glob;
use once_cell::sync::Lazy;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use serde_json::json;
use session::session_uuid_middleware;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::{collections::HashMap, env};
use tower::{
    filter::AsyncFilterLayer, limit::ConcurrencyLimitLayer, util::AndThenLayer, BoxError,
    ServiceBuilder,
};
use tower_http::trace::TraceLayer;

pub mod configure;
pub mod errors;
pub mod handlers;
pub mod middleware;
pub mod session;
pub mod wrappers;

use crate::errors::{ApiResult, CustomError};

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
pub struct AppState {
    redis_session_client: redis::Client,
    redis_cookie_client: redis::Client,
}

#[tokio::main]
async fn main() {
    // Set the RUST_LOG, if it hasn't been explicitly defined
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "register_otp=debug,tower_http=debug")
    }
    tracing_subscriber::fmt::init();

    // `MemoryStore` just used as an example. Don't use this in production.
    let store = MemoryStore::new();

    let redis_session_db: String = configure::fetch::<String>(String::from("redis_session_db"))
        .expect("Redis Session DB configuration missing!");
    let redis_cookie_db: String = configure::fetch::<String>(String::from("redis_cookie_db"))
        .expect("Redis Cookie DB configuration missing!");

    let middleware_stack = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(AddExtensionLayer::new(AppState {
            redis_session_client: crate::wrappers::redis_wrapper::connect(HashMap::from([(
                "db",
                redis_session_db,
            )]))
            .await,
            redis_cookie_client: crate::wrappers::redis_wrapper::connect(HashMap::from([(
                "db",
                redis_cookie_db,
            )]))
            .await,
        }))
        //.layer(axum_extra::middleware::from_fn(
        //    crate::middleware::debugging::print_request_info_middleware,
        //))
        .layer(AddExtensionLayer::new(store))
        .layer(axum_extra::middleware::from_fn(
            session::session_uuid_middleware,
        ));

    // build our application with some routes
    let app = Router::new()
        .route("/", get(handlers::show_form).post(handlers::accept_form))
        .route("/privacy-policy", get(handlers::privacy_policy_handler))
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
}
