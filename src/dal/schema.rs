use sqlx::PgPool;

/// Creates a per-tenant schema and all application tables inside it.
///
/// `schema_name` is always generated internally as `t_<uuid_no_dashes>` —
/// it never comes from user input, so format! interpolation is safe here.
pub async fn create_tenant_schema(pool: &PgPool, schema_name: &str) -> Result<(), sqlx::Error> {
    let s = schema_name;

    // ── Schema ────────────────────────────────────────────────────────────────
    sqlx::query(&format!("CREATE SCHEMA IF NOT EXISTS {s}"))
        .execute(pool).await?;

    // ── shared updated_at trigger function ────────────────────────────────────
    sqlx::query(&format!(
        "CREATE OR REPLACE FUNCTION {s}.set_updated_at() \
         RETURNS TRIGGER LANGUAGE plpgsql AS $$ \
         BEGIN NEW.updated_at = NOW(); RETURN NEW; END; $$"
    )).execute(pool).await?;

    // ── cpa_catalogos ─────────────────────────────────────────────────────────
    sqlx::query(&format!(
        "CREATE TABLE IF NOT EXISTS {s}.cpa_catalogos ( \
            id          SERIAL      PRIMARY KEY, \
            tipo        SMALLINT    NOT NULL DEFAULT 0, \
            nombre      TEXT        NOT NULL, \
            activo      BOOLEAN     NOT NULL DEFAULT TRUE, \
            comentarios TEXT, \
            created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(), \
            updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW() \
        )"
    )).execute(pool).await?;

    sqlx::query(&format!("CREATE INDEX IF NOT EXISTS idx_{s}_catalogos_tipo   ON {s}.cpa_catalogos(tipo)"))
        .execute(pool).await?;
    sqlx::query(&format!("CREATE INDEX IF NOT EXISTS idx_{s}_catalogos_activo ON {s}.cpa_catalogos(activo)"))
        .execute(pool).await?;
    sqlx::query(&format!(
        "CREATE OR REPLACE TRIGGER trg_cpa_catalogos_updated_at \
         BEFORE UPDATE ON {s}.cpa_catalogos \
         FOR EACH ROW EXECUTE FUNCTION {s}.set_updated_at()"
    )).execute(pool).await?;

    // ── cpa_clientes ──────────────────────────────────────────────────────────
    sqlx::query(&format!(
        "CREATE TABLE IF NOT EXISTS {s}.cpa_clientes ( \
            id           SERIAL      PRIMARY KEY, \
            nombre       TEXT        NOT NULL, \
            direccion    TEXT        NOT NULL DEFAULT '', \
            telefono     TEXT        NOT NULL DEFAULT '', \
            mail         TEXT        NOT NULL DEFAULT '', \
            cuenta_banco TEXT        NOT NULL DEFAULT '', \
            comentarios  TEXT        NOT NULL DEFAULT '', \
            tipo         INTEGER     NOT NULL DEFAULT 0, \
            activo       BOOLEAN     NOT NULL DEFAULT TRUE, \
            condiciones  TEXT        NOT NULL DEFAULT '', \
            created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(), \
            updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW() \
        )"
    )).execute(pool).await?;

    sqlx::query(&format!("CREATE INDEX IF NOT EXISTS idx_{s}_clientes_tipo   ON {s}.cpa_clientes(tipo)"))
        .execute(pool).await?;
    sqlx::query(&format!("CREATE INDEX IF NOT EXISTS idx_{s}_clientes_activo ON {s}.cpa_clientes(activo)"))
        .execute(pool).await?;
    sqlx::query(&format!(
        "CREATE OR REPLACE TRIGGER trg_cpa_clientes_updated_at \
         BEFORE UPDATE ON {s}.cpa_clientes \
         FOR EACH ROW EXECUTE FUNCTION {s}.set_updated_at()"
    )).execute(pool).await?;

    // ── cpa_centroscosto ──────────────────────────────────────────────────────
    sqlx::query(&format!(
        "CREATE TABLE IF NOT EXISTS {s}.cpa_centroscosto ( \
            id          SERIAL      PRIMARY KEY, \
            nombre      TEXT        NOT NULL, \
            tipo        INTEGER     NOT NULL DEFAULT 0, \
            comentarios TEXT        NOT NULL DEFAULT '', \
            activo      BOOLEAN     NOT NULL DEFAULT TRUE, \
            created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(), \
            updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW() \
        )"
    )).execute(pool).await?;

    sqlx::query(&format!("CREATE INDEX IF NOT EXISTS idx_{s}_centroscosto_activo ON {s}.cpa_centroscosto(activo)"))
        .execute(pool).await?;
    sqlx::query(&format!(
        "CREATE OR REPLACE TRIGGER trg_cpa_centroscosto_updated_at \
         BEFORE UPDATE ON {s}.cpa_centroscosto \
         FOR EACH ROW EXECUTE FUNCTION {s}.set_updated_at()"
    )).execute(pool).await?;

    // ── cpa_proveedores ───────────────────────────────────────────────────────
    sqlx::query(&format!(
        "CREATE TABLE IF NOT EXISTS {s}.cpa_proveedores ( \
            id           SERIAL      PRIMARY KEY, \
            nombre       TEXT        NOT NULL, \
            contacto     TEXT        NOT NULL DEFAULT '', \
            direccion    TEXT        NOT NULL DEFAULT '', \
            telefono     TEXT        NOT NULL DEFAULT '', \
            mail         TEXT        NOT NULL DEFAULT '', \
            cuenta_banco TEXT        NOT NULL DEFAULT '', \
            tipo         INTEGER     NOT NULL DEFAULT 0, \
            giro         INTEGER     NOT NULL DEFAULT 0, \
            comentarios  TEXT        NOT NULL DEFAULT '', \
            activo       BOOLEAN     NOT NULL DEFAULT TRUE, \
            rfc          TEXT        NOT NULL DEFAULT '', \
            created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(), \
            updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW() \
        )"
    )).execute(pool).await?;

    sqlx::query(&format!("CREATE INDEX IF NOT EXISTS idx_{s}_proveedores_tipo   ON {s}.cpa_proveedores(tipo)"))
        .execute(pool).await?;
    sqlx::query(&format!("CREATE INDEX IF NOT EXISTS idx_{s}_proveedores_activo ON {s}.cpa_proveedores(activo)"))
        .execute(pool).await?;
    sqlx::query(&format!(
        "CREATE OR REPLACE TRIGGER trg_cpa_proveedores_updated_at \
         BEFORE UPDATE ON {s}.cpa_proveedores \
         FOR EACH ROW EXECUTE FUNCTION {s}.set_updated_at()"
    )).execute(pool).await?;

    // ── sys_accesosrapidos ────────────────────────────────────────────────────
    sqlx::query(&format!(
        "CREATE TABLE IF NOT EXISTS {s}.sys_accesosrapidos ( \
            id       INTEGER PRIMARY KEY, \
            funcion  TEXT    NOT NULL DEFAULT '', \
            tool_tip TEXT    NOT NULL DEFAULT '', \
            imagen   TEXT    NOT NULL DEFAULT '' \
        )"
    )).execute(pool).await?;

    sqlx::query(&format!(
        "INSERT INTO {s}.sys_accesosrapidos (id, funcion, tool_tip, imagen) \
         SELECT s.id, '', '', '' FROM generate_series(1,8) AS s(id) \
         ON CONFLICT (id) DO NOTHING"
    )).execute(pool).await?;

    // ── sys_configura (fila única id=1) ───────────────────────────────────────
    sqlx::query(&format!(
        "CREATE TABLE IF NOT EXISTS {s}.sys_configura ( \
            id              INTEGER     PRIMARY KEY DEFAULT 1, \
            nom_empresa     TEXT        NOT NULL DEFAULT '', \
            tipo_unidad     TEXT        NOT NULL DEFAULT '', \
            num_rens_ppto   INTEGER     NOT NULL DEFAULT 20, \
            image_path      TEXT        NOT NULL DEFAULT '', \
            i_top           INTEGER     NOT NULL DEFAULT 0, \
            i_rig           INTEGER     NOT NULL DEFAULT 0, \
            i_bot           INTEGER     NOT NULL DEFAULT 0, \
            i_lef           INTEGER     NOT NULL DEFAULT 0, \
            ppto_color_edit TEXT        NOT NULL DEFAULT '', \
            color_nivel1    TEXT        NOT NULL DEFAULT '', \
            color_nivel2    TEXT        NOT NULL DEFAULT '', \
            color_nivel3    TEXT        NOT NULL DEFAULT '', \
            color_nivel4    TEXT        NOT NULL DEFAULT '', \
            i_dias_previos  INTEGER     NOT NULL DEFAULT 0, \
            num_rens_proy   INTEGER     NOT NULL DEFAULT 20, \
            num_rens_otros  INTEGER     NOT NULL DEFAULT 20, \
            fin_tarea       INTEGER     NOT NULL DEFAULT 5, \
            pag_ancho_total INTEGER     NOT NULL DEFAULT 0, \
            largo_concepto  INTEGER     NOT NULL DEFAULT 40, \
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW() \
        )"
    )).execute(pool).await?;

    sqlx::query(&format!(
        "INSERT INTO {s}.sys_configura (id) VALUES (1) ON CONFLICT (id) DO NOTHING"
    )).execute(pool).await?;

    sqlx::query(&format!(
        "CREATE OR REPLACE TRIGGER trg_sys_configura_updated_at \
         BEFORE UPDATE ON {s}.sys_configura \
         FOR EACH ROW EXECUTE FUNCTION {s}.set_updated_at()"
    )).execute(pool).await?;

    Ok(())
}
