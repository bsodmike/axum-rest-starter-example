use axum::{
    body::{Body, Bytes},
    http::{self, Request, StatusCode},
    response::{IntoResponse, Response},
};
use axum_extra::middleware::{self, Next};

pub async fn print_request_info_middleware(
    req: Request<Body>,
    next: Next<Body>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let (parts, body) = req.into_parts();

    tracing::debug!("Request headers:");
    dbg!(&parts.headers);

    tracing::debug!("Request body:");
    let bytes = buffer_and_print("request", body).await?;

    tracing::debug!("Request parts:");
    let req = Request::from_parts(parts, Body::from(bytes));

    let res = next.run(req).await;

    let headers = res.headers();
    tracing::debug!("Response headers:");
    dbg!(headers);

    let (parts, body) = res.into_parts();

    tracing::debug!("Response body:");
    let bytes = buffer_and_print("response", body).await?;

    tracing::debug!("Response parts:");
    let res = Response::from_parts(parts, Body::from(bytes));

    Ok(res)
}

pub async fn buffer_and_print<B>(direction: &str, body: B) -> Result<Bytes, (StatusCode, String)>
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
