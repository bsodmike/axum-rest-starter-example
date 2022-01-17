use crate::errors::CustomError;
use anyhow::Error;
use std::panic::Location;

pub async fn tracing_debug(
    location: &'static Location<'static>,
    msg: String,
) -> Result<(), CustomError> {
    let custom_format = format!("[{}:{}]", location.file(), location.line());

    tracing::debug!("{}: {}", custom_format, msg);

    Ok(())
}

pub async fn tracing_error(
    location: &'static Location<'static>,
    msg: String,
) -> Result<(), CustomError> {
    let custom_format = format!("[{}:{}]", location.file(), location.line());

    tracing::error!("{}: {}", custom_format, msg);

    Ok(())
}
