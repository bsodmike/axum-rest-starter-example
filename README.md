# axum-rest-starter-example

## Important Tasks

- [ ] Ensure session UUID is unique
- [ ] Protect `/api/` with JWT
- [ ] Add CSRF
- [ ] CORS?

## Dev Setup

(1) Run `docker compose up` to fire up a local Redis server on port `6400`.

(2) Create `conf/development/config.yml` with the following defaults

```
---
jwt_secret: "resetme"
redis_host_name: "127.0.0.1"
redis_password: replaceme
redis_session_db: 0
redis_port: 6400
```

(3) Run `rustup update` and `rustup override set stable` within the root of the project. You can
also run `cargo build`.

(4) Run `DOMAIN=localhost cargo run` to run the Axum frontend and visit http://localhost:3000

The domain value set above is used for the session cookie.

## API

Any API requests made locally need a valid cookie persisted in Redis.  You can
simply visit http://localhost:3000 and fetch the cookie value from STDOUT or
from a browser debugging console

### Frontend

#### POST /api/v1/drops/drop_id/registrations

```
curl --location --request POST 'localhost:3000/api/v1/drops/2/registrations' \
--header 'Content-Type: application/json' \
--header 'Cookie: axum-session=AQ+nalsDoBvb3shGpgZA9PVl6aiHivAdB6p3mxMkn3mGn6VZGGzQuIUDlyjdfp2/Qjf96HsHkeLNy/vHVTEMdA==' \
--data-raw '{
  "raffle": {
    "agree_to_join": true,
    "accept_privacy_policy": true
  },
  "registration_form": {
    "firstname": "",
    "lastname": "",
    "address_line1": "",
    "address_line2": "",
    "address_number": "",
    "postcode": "",
    "city": "",
    "state": "",
    "phone_number": "",
    "email": "",
  }
}'
```

### API JWT

#### /api is protected

For this test, `/api/protected` is just a testing path. If the client has no
valid cookie, the REST middleware layer will return a new cookie.  JWT auth sits
in top of this, hence the basic session cookie still needs to be provided.

```
curl --location --request GET 'localhost:3000/api/protected/' \                                                                                        13:45:27
                          --header 'Cookie: axum-session=AQ+nalsDoBvb3shGpgZA9PVl6aiHivAdB6p3mxMkn3mGn6VZGGzQuIUDlyjdfp2/Qjf96HsHkeLNy/vHVTEMdA==' \
                          --header 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjEwMDAwMDAwMDAwfQ.M3LAZmrzUkXDC1q
5mSzFAs_kJrwuKz3jOoDmjJ0G4gM'
{"error":"Invalid token!"}
```

#### /authorize

Notice the JSON data required to obtain an auth token. The `client_id` and
`client_secret` are set as application configuration secrets (optionally, these
can be stored in the DB if we wish).

```
curl --location --request POST 'localhost:3000/authorize' \                                                                                            13:45:57
                          --header 'Cookie: axum-session=AQ+nalsDoBvb3shGpgZA9PVl6aiHivAdB6p3mxMkn3mGn6VZGGzQuIUDlyjdfp2/Qjf96HsHkeLNy/vHVTEMdA==' \
                          --header 'Content-Type: application/json' \
                          --data-raw '{
                          "client_id": "foo",
                          "client_secret": "bar"
                      }'
{"access_token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjEwMDAwMH0.riR9JGJyrgPWbfIsgs1rQyQulAjSezF72ex0hLtp7P4","token_type":"Bearer"}
```

#### Any /api path with a valid token

Ensure the JWT token expiration is set correctly, by default we are setting it
as 1 hour.

```
curl --location --request GET 'localhost:3000/api/protected/' \                                                                                        14:33:26
                          --header 'Cookie: axum-session=AQ+nalsDoBvb3shGpgZA9PVl6aiHivAdB6p3mxMkn3mGn6VZGGzQuIUDlyjdfp2/Qjf96HsHkeLNy/vHVTEMdA==' \
                          --header 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjE2NDI1ODY2MDZ9._uA7XhkcblejqGAGJ
a0ZjLNJ3IxLER_jlPVL3HInCCc'
Welcome to the protected area :)
```

## MSRV

This project is tested agains the most [recent stable rust version](https://gist.github.com/alexheretic/d1e98d8433b602e57f5d0a9637927e0c).
