use crate::User;
use app_core::error::{self, Kind};
use askama::Template;
use async_redis_session::RedisSessionStore;
use axum::{
    async_trait,
    body::{self, Body, BoxBody, Bytes, Full, HttpBody},
    extract::{
        extractor_middleware, rejection::*, Extension, Form, FromRequest, Path, RequestParts,
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
use axum_rest_middleware::{
    extractors,
    middleware::{self as RestMiddleware},
};
use hyper::body::Buf;
use redis::AsyncCommands;
use serde::{de, Deserialize, Serialize};
use serde_json::json;
use std::fmt::{self, Display};

pub async fn privacy_policy_handler() {}

// Templates
#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    user: User,
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

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub struct FormFields {
    name: String,
    email: String,
}

impl fmt::Display for FormFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{{}, {}}}", self.name, self.email)
    }
}

pub async fn show_form(
    user_extractor: extractors::UserExtractor<User, RedisSessionStore>,
) -> impl IntoResponse {
    let user = user_extractor.0;
    let template = IndexTemplate { user };
    HtmlTemplate(template)
}

pub async fn handle_form(req: Request<Body>) -> impl IntoResponse {
    let mut req_parts = RequestParts::new(req);
    let body = req_parts.take_body();

    //Instead of using `Bytes::from_request`, as this also causes an immutable borrow, use hyper to
    //fetch the body data as bytes
    let body_deserialized = match RestMiddleware::body_content::<FormFields>(body).await {
        Ok(value) => value,
        _ => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap();
        }
    };

    tracing::debug!("handle_form: Body {:?}", body_deserialized);

    let store = &mut req_parts
        .extensions()
        .unwrap()
        .get::<RedisSessionStore>()
        .expect("`RedisSessionStore` extension missing!");

    //Implement the same approach as `TypedHeader<Cookie>::from_request` without causing an
    //immutable borrow on the request.
    let headers = if let Some(value) = req_parts.headers() {
        value
    } else {
        return Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::empty())
            .unwrap();
    };

    // Fetch existing user from store
    let user = match RestMiddleware::fetch::<User>(headers, store, "user").await {
        Ok(value) => value,
        _ => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap();
        }
    };

    let user_data = crate::User {
        uuid: user.uuid,
        name: body_deserialized.name.clone(),
        email: body_deserialized.email.clone(),
    };

    // Update store
    match RestMiddleware::update(headers, store, &user_data).await {
        Ok(_) => {}
        _ => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap();
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
