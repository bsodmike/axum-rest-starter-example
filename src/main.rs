use axum::{extract::Form, response::Html, routing::get, Router};
use redis::{AsyncCommands, AsyncIter};
use redis::{Commands, Connection, RedisError, RedisResult};
use serde::Deserialize;
use std::env;
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    // Set the RUST_LOG, if it hasn't been explicitly defined
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "register_otp=debug,tower_http=debug")
    }
    tracing_subscriber::fmt::init();

    // build our application with some routes
    let app = Router::new().route("/", get(show_form).post(accept_form));

    // run it with hyper
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn show_form() -> Html<&'static str> {
    Html(
        r#"
        <!doctype html>
        <html>
            <head></head>
            <body>
                <form action="/" method="post">
                    <label for="name">
                        Enter your name:
                        <input type="text" name="name">
                    </label>
                    <label>
                        Enter your email:
                        <input type="text" name="email">
                    </label>
                    <input type="submit" value="Subscribe!">
                </form>
            </body>
        </html>
        "#,
    )
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct Input {
    name: String,
    email: String,
}

async fn accept_form(Form(input): Form<Input>) {
    dbg!(&input);

    save_form(&input).await; // TODO: This needs to be handled
}

async fn save_form(input: &Input) -> redis::RedisResult<()> {
    let client = connect();
    let mut con = client.await.get_async_connection().await?;

    let name = input.name.to_owned();
    let name_str = &name[..];

    con.set("async-key1", name_str).await?;
    let result: String = con.get("async-key1").await?;
    println!("->> my_key: {}\n", result);

    Ok(())
}

// TODO move redis related logic to a module
async fn connect() -> redis::Client {
    //let redis_host_name =
    //  env::var("REDIS_HOSTNAME").expect("missing environment variable REDIS_HOSTNAME");
    //let redis_password = env::var("REDIS_PASSWORD").unwrap_or_default();
    let redis_host_name = "127.0.0.1";
    let redis_db = 0;
    let redis_port = 6400;

    //if Redis server needs secure connection
    let uri_scheme = match env::var("IS_TLS") {
        Ok(_) => "rediss",
        Err(_) => "redis",
    };

    let redis_conn_url = format!(
        "{}://{}:{}/{}",
        uri_scheme, redis_host_name, redis_port, redis_db
    );
    //println!("{}", redis_conn_url);

    redis::Client::open(redis_conn_url).expect("Failed to connect to Redis")
}
