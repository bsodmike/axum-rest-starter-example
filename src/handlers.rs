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

use crate::{errors::Error, session::AXUM_USER_UUID};

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

//pub struct ExtractUserUUID(HeaderValue);
//
//#[async_trait]
//impl<T, B> FromRequest<B> for ExtractUserUUID<T>
//where
//    T: Header,
//    B: Send,
//{
//    type Rejection = TypedHeaderRejection;
//
//    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {}
//}

pub async fn accept_form(
    Form(input): Form<Input>,
    headers: HeaderMap,
    state: Extension<crate::AppState>,
) -> impl IntoResponse {
    dbg!(&input);

    let err_value = HeaderValue::from_str("").unwrap();

    dbg!(&headers);
    dbg!(headers.get(crate::session::AXUM_USER_UUID));

    let header: &HeaderValue = if let Some(value) = headers.get(crate::session::AXUM_USER_UUID) {
        value
    } else {
        tracing::error!("Session UUID missing!");

        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::empty())
            .unwrap();
    };
    dbg!(header);
    println!("------>>>>>> HEADER");
    dbg!(headers);

    //match save_form(&state, &input).await {
    //    Ok(_) => (),
    //    Err(e) => tracing::error!("Failed: {:?}", e),
    //}

    // Redirect::to("/".parse().unwrap())
    let mut response = Response::builder()
        .status(StatusCode::SEE_OTHER)
        .body(Body::empty())
        .unwrap();

    let headers = response.headers_mut();
    headers.insert(LOCATION, "/".parse().unwrap());

    response
}

pub async fn save_form(
    state: &Extension<crate::AppState>,
    input: &Input,
) -> redis::RedisResult<()> {
    let client = &state.redis_session_client;
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
