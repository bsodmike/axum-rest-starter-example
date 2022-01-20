use crate::configure;
use app_core::error::{self, Error, Kind};
use redis::AsyncCommands;
use std::{collections::HashMap, env};

pub async fn connect(data: HashMap<&str, String>) -> Result<redis::Client, error::Error> {
    let redis_host_name: String = configure::fetch_configuration("redis_host_name").await?;
    let redis_password: String = configure::fetch_configuration("redis_password").await?;
    let redis_port: String = configure::fetch_configuration("redis_port").await?;
    let redis_session_db = data.get("db").unwrap();

    //println!("\n->> redis_host_name: {}", redis_host_name);
    //println!("->> redis_password: {}", redis_password);
    //println!("->> redis_session_db: {}", redis_session_db);
    //println!("->> redis_port: {}", redis_port);

    //if Redis server needs secure connection
    let uri_scheme = match env::var("IS_TLS") {
        Ok(_) => "rediss",
        Err(_) => "redis",
    };

    // TODO Need to support providing a password to the Redis connection and strip out secret
    // details when logging the connection URL
    let redis_conn_url = format!(
        "{}://{}:{}/{}",
        uri_scheme, redis_host_name, redis_port, redis_session_db
    );
    tracing::info!("Connecting to URL: {}\n", redis_conn_url);

    Ok(redis::Client::open(redis_conn_url).expect("Failed to connect to Redis"))
}
