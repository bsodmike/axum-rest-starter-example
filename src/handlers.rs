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
    headers::{Cookie, Header, HeaderMapExt},
    http::{
        self, header::HeaderName, header::LOCATION, HeaderMap, HeaderValue, Method, Request,
        StatusCode, Uri,
    },
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post, Router},
    AddExtensionLayer, Json,
};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    errors::CustomError,
    session::{Session, AXUM_USER_UUID},
};
use std::fmt::{self, Display};

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

pub async fn show_form(session: crate::session::Session) -> impl IntoResponse {
    let uuid = session.uuid;
    let template = IndexTemplate { uuid };
    HtmlTemplate(template)
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub struct Input {
    name: String,
    email: String,
}

impl fmt::Display for Input {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{{}, {}}}", self.name, self.email)
    }
}

pub async fn accept_form(
    Form(input): Form<Input>,
    session: crate::session::Session,
    headers: HeaderMap,
    state: Extension<crate::AppState>,
) -> impl IntoResponse {
    crate::utils::tracing_debug(
        std::panic::Location::caller(),
        format!("Form input: {:?}", &input),
    )
    .await;

    let name = input.name.to_owned();
    let name_str = &name[..];

    match session
        .update(&headers, &state.redis_session_client, &name_str)
        .await
    {
        Ok(_) => (),
        Err(err) => {
            crate::utils::tracing_error(
                std::panic::Location::caller(),
                format!("Error during Session update: {:?}", err),
            )
            .await;
        }
    }

    // Redirect::to("/".parse().unwrap())
    let mut response = Response::builder()
        .status(StatusCode::SEE_OTHER)
        .body(Body::empty())
        .unwrap();

    let headers = response.headers_mut();
    headers.insert(LOCATION, "/".parse().unwrap());

    response
}

pub async fn handler_404(_method: Method, _uri: Uri) -> impl IntoResponse {
    StatusCode::NOT_FOUND
}
