# register-otp

[![CI](https://github.com/bsodmike/register_otp/actions/workflows/rust.yml/badge.svg)](https://github.com/bsodmike/register_otp/actions/workflows/rust.yml)

## Dev Setup

(1) Run `docker compose up` to fire up a local Redis server on port `6400`.

(2) Create `conf/development/config.yml` with the following defaults

```
---
redis_host_name: "127.0.0.1"
redis_password: replaceme
redis_cookie_db: 0
redis_session_db: 1
redis_port: 6400
```

(3) Run `cargo run` to run the Axum frontend and visit http://localhost:3000
