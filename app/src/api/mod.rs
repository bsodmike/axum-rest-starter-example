use crate::auth::jwt;
use app_core::error::{self, Error, Kind};
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
    response::{Html, IntoResponse, Json, Redirect, Response},
    routing::{get, post, Router},
    AddExtensionLayer,
};
use axum_rest_middleware::middleware::{self as RestMiddleware};
use hyper::body::Buf;
use redis::AsyncCommands;
use serde::{de, Deserialize, Serialize};
use serde_json::json;
use serde_urlencoded::ser;

#[derive(Serialize, Deserialize, Debug)]
#[allow(dead_code)]
struct RegistrationForm {
    registration_form: RegistrationFormFields,
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(dead_code)]
struct RegistrationFormFields {
    firstname: String,
    lastname: String,
    address_line1: String,
    address_line2: String,
    address_number: String,
    postcode: String,
    city: String,
    state: String,
    phone_number: String,
    email: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(dead_code)]
struct RegistrationResponse {
    registration_id: u32,
}

pub async fn protected(_req: Request<Body>) -> Result<String, error::AuthError> {
    Ok(format!("Welcome to the protected area :)\n"))
}

pub async fn handle_registration_post(
    Path(drop_id): Path<u32>,
    req: Request<Body>,
) -> Result<Response, Error> {
    let mut req_parts = RequestParts::new(req);
    let body = req_parts.take_body();
    dbg!(&body);

    let body_deserialized = match body_json::<RegistrationForm>(body).await {
        Ok(value) => value,
        _ => return Ok(respond_bad_request().await?),
    };
    dbg!(&body_deserialized);

    //Validate form response

    //Check Redis if the address & email exist for drop. No?

    //Check PG if the unique address & email exist for drop. No?

    //Persist registration into Redis with key = session id.

    // Return registration ID
    Ok(
        Json(json!({ "registration": RegistrationResponse { registration_id: 1 } }))
            .into_response(),
    )
}

pub async fn body_json<T>(body_taken: Option<Body>) -> Result<T, Error>
where
    T: de::DeserializeOwned,
{
    let body = if let Some(value) = body_taken {
        value
    } else {
        return Err(error::new(Kind::NotImplementedError));
    };

    let body_bytes = hyper::body::to_bytes(body).await?;
    let body_deserialized = match serde_json::from_slice::<T>(&body_bytes) {
        Ok(value) => value,
        Err(err) => {
            tracing::error!("Error: Unable to deserialize request body {:?}", err);

            return Err(error::new(Kind::NotImplementedError));
        }
    };

    Ok(body_deserialized)
}

pub(crate) async fn respond_bad_request() -> Result<Response, Error> {
    let json_response = Json(json!({ "status": "400" }));

    Ok(json_response.into_response())
}
