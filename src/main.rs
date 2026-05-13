use std::net::SocketAddr;
use std::sync::Arc;
use dotenvy::dotenv;
use rand::RngCore;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod generated;
mod dal;
mod errors;
mod domain;
mod service;
mod security;
mod infrastructure;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();

    // ── Key generation helper (run once, paste output into .env) ─────────────
    if std::env::args().any(|a| a == "--generate-keys") {
        let (local, secret, public) = service::token::TokenService::generate_keys()
            .expect("key generation failed");
        let revoc  = hex::encode(rand_32());
        let tenant = hex::encode(rand_32());
        println!("PASETO_LOCAL_KEY={local}");
        println!("PASETO_SECRET_KEY={secret}");
        println!("PASETO_PUBLIC_KEY={public}");
        println!("REVOCATION_STORE_KEY={revoc}");
        println!("TENANT_SECRETS_KEY={tenant}");
        return Ok(());
    }

    // ── File-based logging (daily rotation, no console output) ───────────────
    let log_dir = std::env::var("LOG_DIR").unwrap_or_else(|_| "logs".to_string());
    let file_appender = tracing_appender::rolling::daily(&log_dir, "security-core.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false)
                .with_target(true)
                .with_thread_ids(false),
        )
        .init();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        log_dir = %log_dir,
        "security-core starting"
    );

    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");

    let pool = infrastructure::db::postgres::pool::create_pool(&database_url, 10)
        .await
        .expect("failed to connect to database");

    tracing::info!("database pool ready");

    // ── Repositories ──────────────────────────────────────────────────────────
    let user_repo          = Arc::new(dal::user::UserRepository::new(pool.clone()));
    let tenant_repo        = Arc::new(dal::tenant::TenantRepository::new(pool.clone()));
    let payment_repo       = Arc::new(dal::tenant_payment::TenantPaymentRepository::new(pool.clone()));
    let refresh_token_repo = Arc::new(dal::token::RefreshTokenRepository::new(pool.clone()));
    let history_repo       = Arc::new(dal::history::HistoryRepository::new(pool.clone()));
    let secrets_repo       = Arc::new(dal::secrets::TenantSecretsRepository::new(pool.clone()));

    // ── Token service (loads keys from env) ───────────────────────────────────
    let token_svc = Arc::new(
        service::token::TokenService::from_env()
            .expect("failed to load PASETO keys — run TokenService::generate_keys() first"),
    );

    // ── Revocation store (loads key + path from env, creates dir if needed) ───
    let revoc_store = Arc::new(
        security::revocation_store::RevocationStore::from_env()
            .await
            .expect("failed to initialise revocation store"),
    );

    // ── Secrets service ───────────────────────────────────────────────────────
    let secrets_svc = Arc::new(
        service::secrets::TenantSecretsService::from_env(secrets_repo)
            .expect("failed to load TENANT_SECRETS_KEY — generate with `openssl rand -hex 32`"),
    );

    // ── Auth service ──────────────────────────────────────────────────────────
    let auth_service = Arc::new(service::auth::AuthService::new(
        user_repo.clone(),
        refresh_token_repo,
        history_repo,
        token_svc,
        revoc_store,
        secrets_svc.clone(),
    ));

    // ── gRPC handler ──────────────────────────────────────────────────────────
    let app_db_url = std::env::var("ARQETH_APP_DB_URL")
        .expect("ARQETH_APP_DB_URL must be set (shared application database URL)");
    let admin_db_url = std::env::var("ARQETH_ADMIN_DB_URL").unwrap_or_default();

    let user_service = service::user::UserService::new(user_repo);
    let handler = infrastructure::grpc::handler::AuthGrpcHandler::new(
        user_service,
        auth_service,
        tenant_repo,
        payment_repo,
        secrets_svc,
        Arc::new(pool),
        app_db_url,
        admin_db_url,
    );

    let addr: SocketAddr = std::env::var("GRPC_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:50051".to_string())
        .parse()
        .expect("invalid GRPC_ADDR");

    tracing::info!(addr = %addr, "gRPC server ready");

    #[cfg(debug_assertions)]
    {
        tracing::warn!("running in insecure dev mode — no mTLS");
        infrastructure::grpc::server::start_insecure(addr, handler).await?;
    }

    #[cfg(not(debug_assertions))]
    {
        let ca_cert     = std::fs::read("certs/ca.crt").expect("ca.crt not found");
        let server_cert = std::fs::read("certs/server.crt").expect("server.crt not found");
        let server_key  = std::fs::read("certs/server.key").expect("server.key not found");
        infrastructure::grpc::server::start_mtls(
            addr, handler, &ca_cert, &server_cert, &server_key,
        ).await?;
    }

    Ok(())
}

fn rand_32() -> [u8; 32] {
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}
