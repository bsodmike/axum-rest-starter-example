use crate::configure;
use app_core::error::{self, Kind};
use redis::AsyncCommands;
use std::{collections::HashMap, env};

pub async fn connect(data: HashMap<&str, String>) -> redis::Client {
    let redis_host_name: String =
        configure::fetch::<String>(String::from("redis_host_name")).unwrap_or_default();
    let redis_password: String =
        configure::fetch::<String>(String::from("redis_password")).unwrap_or_default();
    let redis_port: String =
        configure::fetch::<String>(String::from("redis_port")).unwrap_or_default();
    let redis_session_db = data.get("db").unwrap();

    if redis_host_name.as_str() == "" {
        panic!(
            "Redis hostname is missing {:?}",
            error::new(Kind::ConfigurationSecretMissing)
        )
    };

    if redis_password.as_str() == "" {
        panic!(
            "Redis password is missing {:?}",
            error::new(Kind::ConfigurationSecretMissing)
        )
    };

    if redis_session_db.as_str() == "" {
        panic!(
            "Redis session db is missing {:?}",
            error::new(Kind::ConfigurationSecretMissing)
        )
    };

    if redis_port.as_str() == "" {
        panic!(
            "Redis port is missing {:?}",
            error::new(Kind::ConfigurationSecretMissing)
        )
    };

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
    println!("->> Redis connecting to URL: {}\n", redis_conn_url);

    redis::Client::open(redis_conn_url).expect("Failed to connect to Redis")
}
