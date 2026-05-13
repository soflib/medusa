//! `history` table — append-only audit log.
use chrono::{DateTime, Utc};
use std::net::IpAddr;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::FromRow;
use uuid::Uuid;
use super::enums::HistoryAction;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct History {
    pub id:             i64,
    pub actor_id:       Option<Uuid>,
    pub actor_email:    Option<String>,
    pub action:         HistoryAction,
    pub target_user_id: Option<Uuid>,
    pub sign_doc_id:    Option<Uuid>,
    pub token_id:       Option<Uuid>,
    pub key_id:         Option<Uuid>,
    pub ip_address:     Option<IpAddr>,
    pub user_agent:     Option<String>,
    pub metadata:       Option<JsonValue>,
    pub success:        bool,
    pub error_message:  Option<String>,
    pub created_at:     DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct CreateHistory {
    pub actor_id:       Option<Uuid>,
    pub actor_email:    Option<String>,
    pub action:         Option<HistoryAction>,
    pub target_user_id: Option<Uuid>,
    pub sign_doc_id:    Option<Uuid>,
    pub token_id:       Option<Uuid>,
    pub key_id:         Option<Uuid>,
    pub ip_address:     Option<IpAddr>,
    pub user_agent:     Option<String>,
    pub metadata:       Option<JsonValue>,
    pub success:        bool,
    pub error_message:  Option<String>,
}

impl CreateHistory {
    pub fn new(action: HistoryAction) -> Self {
        Self { action: Some(action), success: true, ..Default::default() }
    }
    pub fn actor(mut self, id: Uuid, email: impl Into<String>) -> Self {
        self.actor_id    = Some(id);
        self.actor_email = Some(email.into());
        self
    }
    pub fn target_user(mut self, id: Uuid) -> Self {
        self.target_user_id = Some(id);
        self
    }
    pub fn sign_doc(mut self, id: Uuid) -> Self {
        self.sign_doc_id = Some(id);
        self
    }
    pub fn token(mut self, id: Uuid) -> Self {
        self.token_id = Some(id);
        self
    }
    pub fn key(mut self, id: Uuid) -> Self {
        self.key_id = Some(id);
        self
    }
    pub fn ip(mut self, ip: IpAddr) -> Self {
        self.ip_address = Some(ip);
        self
    }
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }
    pub fn metadata(mut self, v: JsonValue) -> Self {
        self.metadata = Some(v);
        self
    }
    pub fn failed(mut self, msg: impl Into<String>) -> Self {
        self.success       = false;
        self.error_message = Some(msg.into());
        self
    }
}