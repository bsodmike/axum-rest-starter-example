#![allow(unused_imports)]
use axum::{
    async_trait,
    body::Body,
    extract::{Extension, Form, Path},
    handler::Handler,
    http::{header::LOCATION, Method, Request, Response, Result, StatusCode, Uri},
    response::{Html, IntoResponse, Redirect},
    routing::{get, post, Router},
    AddExtensionLayer, Json,
};
use config::*;
use glob::glob;
use once_cell::sync::Lazy;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::env;
use std::net::SocketAddr;
use tower::{limit::ConcurrencyLimitLayer, ServiceBuilder};
use tower_http::trace::TraceLayer;

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

#[tokio::main]
async fn main() {
    // Set the RUST_LOG, if it hasn't been explicitly defined
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "register_otp=debug,tower_http=debug")
    }
    tracing_subscriber::fmt::init();

    let middleware_stack = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(AddExtensionLayer::new(AppState {
            redis_client: crate::wrappers::redis_wrapper::connect().await,
        }));

    // build our application with some routes
    let app = Router::new()
        .route("/", get(show_form).post(accept_form))
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
