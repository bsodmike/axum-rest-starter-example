use crate::{errors::CustomError, session::session_uuid_middleware};
use async_session::{Session, SessionStore};
use axum::async_trait;

#[derive(Debug, Clone, Copy)]
pub struct RedisStore;

impl RedisStore {
    /// constructs a new RedisStore
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl SessionStore for RedisStore {
    async fn load_session(&self, cookie_value: String) -> async_session::Result<Option<Session>> {
        let session = Session::new();

        Ok(session.validate())
    }

    async fn store_session(&self, session: Session) -> async_session::Result<Option<String>> {
        Ok(Some(String::new()))
    }

    async fn destroy_session(&self, _session: Session) -> async_session::Result {
        Ok(())
    }

    async fn clear_store(&self) -> async_session::Result {
        Ok(())
    }
}
