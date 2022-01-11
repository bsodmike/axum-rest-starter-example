use askama::Template;
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
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use serde_json::json;

pub async fn privacy_policy_handler() {}

// Templates
#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    uuid: uuid::Uuid,
}

struct HtmlTemplate<T>(T);

impl<T> IntoResponse for HtmlTemplate<T>
where
    T: Template,
{
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(err) => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(body::boxed(Full::from(format!(
                    "Failed to render template. Error: {}",
                    err
                ))))
                .unwrap(),
        }
    }
}

pub async fn show_form(session_user: crate::session::UserFromSession) -> impl IntoResponse {
    let uuid = session_user.uuid;
    let template = IndexTemplate { uuid };
    HtmlTemplate(template)
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub struct Input {
    name: String,
    email: String,
}

pub async fn accept_form(Form(input): Form<Input>, state: Extension<crate::AppState>) -> Redirect {
    dbg!(&input);

    match save_form(&input, &state).await {
        Ok(_) => (),
        Err(e) => tracing::error!("Failed: {:?}", e),
    }

    Redirect::to("/".parse().unwrap())
}

pub async fn save_form(
    input: &Input,
    state: &Extension<crate::AppState>,
) -> redis::RedisResult<()> {
    let client = &state.redis_client;
    let mut con = client.get_async_connection().await?;

    let name = input.name.to_owned();
    let name_str = &name[..];

    con.set("async-key1", name_str).await?;
    let result: String = con.get("async-key1").await?;
    println!("->> my_key: {}\n", result);

    Ok(())
}

pub async fn handler_404(method: Method, uri: Uri) -> impl IntoResponse {
    StatusCode::NOT_FOUND
}
