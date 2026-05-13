use sqlx::{Connection, PgConnection, PgPool};

/// Creates a new PostgreSQL database using a direct admin connection.
///
/// `db_name` is always generated internally as `arqeth_t_<uuid_simple>` —
/// it never comes from user input, so format! interpolation is safe here.
/// Uses a raw connection (not a pool) because CREATE DATABASE cannot run
/// inside a transaction.
pub async fn create_private_database(admin_url: &str, db_name: &str) -> Result<(), sqlx::Error> {
    let mut conn = PgConnection::connect(admin_url).await?;
    sqlx::query(&format!("CREATE DATABASE {db_name}"))
        .execute(&mut conn)
        .await?;
    Ok(())
}

/// Provisions a tenant schema inside an already-created private database.
///
/// Opens a temporary single-connection pool to `db_url` and delegates to
/// `create_tenant_schema`. The pool is dropped after the call.
pub async fn init_private_db_schema(
    db_url: &str,
    schema_name: &str,
) -> Result<(), sqlx::Error> {
    let pool = PgPool::connect(db_url).await?;
    crate::dal::schema::create_tenant_schema(&pool, schema_name).await?;
    pool.close().await;
    Ok(())
}

/// Replaces the database-name path segment in a PostgreSQL connection URL.
///
/// Input:  `postgresql://user:pass@host:5432/old_db`
/// Output: `postgresql://user:pass@host:5432/new_db`
pub fn replace_db_name(base_url: &str, new_db: &str) -> String {
    if let Some(pos) = base_url.rfind('/') {
        format!("{}/{}", &base_url[..pos], new_db)
    } else {
        format!("{}/{}", base_url, new_db)
    }
}
