use crate::configure;
use crate::errors::Error;
use redis::AsyncCommands;
use std::{collections::HashMap, env};

pub async fn connect(details: HashMap<&str, i8>) -> redis::Client {
    let redis_host_name: String =
        configure::fetch::<String>(String::from("redis_host_name")).unwrap_or_default();
    let redis_password: String =
        configure::fetch::<String>(String::from("redis_password")).unwrap_or_default();
    let redis_db: String = configure::fetch::<String>(String::from("redis_db")).unwrap_or_default();
    let redis_port: String =
        configure::fetch::<String>(String::from("redis_port")).unwrap_or_default();

    if redis_host_name.as_str() == "" {
        panic!(
            "Redis hostname is missing {:?}",
            Error::ConfigurationSecretMissing
        )
    };

    if redis_password.as_str() == "" {
        panic!(
            "Redis password is missing {:?}",
            Error::ConfigurationSecretMissing
        )
    };

    if redis_db.as_str() == "" {
        panic!(
            "Redis db is missing {:?}",
            Error::ConfigurationSecretMissing
        )
    };

    if redis_port.as_str() == "" {
        panic!(
            "Redis port is missing {:?}",
            Error::ConfigurationSecretMissing
        )
    };

    //println!("\n->> redis_host_name: {}", redis_host_name);
    //println!("->> redis_password: {}", redis_password);
    //println!("->> redis_db: {}", redis_db);
    //println!("->> redis_port: {}", redis_port);

    let redis_db = 0;
    let redis_port = 6400;

    //if Redis server needs secure connection
    let uri_scheme = match env::var("IS_TLS") {
        Ok(_) => "rediss",
        Err(_) => "redis",
    };

    // TODO Need to support providing a password to the Redis connection and strip out secret
    // details when logging the connection URL
    let redis_conn_url = format!(
        "{}://{}:{}/{}",
        uri_scheme, redis_host_name, redis_port, redis_db
    );
    println!("->> Redis connecting to URL: {}\n", redis_conn_url);

    redis::Client::open(redis_conn_url).expect("Failed to connect to Redis")
}
