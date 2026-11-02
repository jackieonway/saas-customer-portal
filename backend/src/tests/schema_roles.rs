//! The portal starts only as an independently authenticated, restricted LOGIN.
use super::{insert, Owned};
use anyhow::{anyhow, ensure, Result};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::time::Duration;
use uuid::Uuid;

fn identifier(value: &str) -> Result<String> {
    ensure!(
        value.len() <= 63
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'),
        "unsafe owned role or database identifier"
    );
    Ok(format!("\"{value}\""))
}

fn literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

async fn provision(
    pool: &PgPool,
    database: &str,
    owner: &str,
    runtime: &str,
    password: &str,
    marker: &str,
) -> Result<()> {
    let mut tx = pool.begin().await?;
    let existing: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_roles WHERE rolname=ANY($1)")
        .bind(vec![owner, runtime])
        .fetch_one(&mut *tx)
        .await?;
    ensure!(existing == 0, "owned portal roles already exist");
    let owner = identifier(owner)?;
    let runtime = identifier(runtime)?;
    let database = identifier(database)?;
    let setup = format!(
        "CREATE ROLE {owner} NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
         CREATE ROLE {runtime} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD {password};
         COMMENT ON ROLE {owner} IS {marker}; COMMENT ON ROLE {runtime} IS {marker};
         ALTER DATABASE {database} OWNER TO {owner};
         ALTER SCHEMA public OWNER TO {owner};
         REVOKE ALL ON DATABASE {database} FROM PUBLIC;
         GRANT CONNECT ON DATABASE {database} TO {runtime};
         REVOKE ALL ON SCHEMA public FROM PUBLIC;
         GRANT USAGE ON SCHEMA public TO {runtime};
         ALTER TABLE public._sqlx_migrations OWNER TO {owner};
         ALTER TABLE public.portal_browsers OWNER TO {owner};
         ALTER TABLE public.portal_login_flows OWNER TO {owner};
         ALTER TABLE public.portal_sessions OWNER TO {owner};
         ALTER TABLE public.portal_backchannel_logout_receipts OWNER TO {owner};
         ALTER TABLE public.portal_backchannel_logout_sources OWNER TO {owner};
         ALTER FUNCTION public.is_uuid_v7(uuid) OWNER TO {owner};
         ALTER FUNCTION public.portal_public_source_immutable() OWNER TO {owner};
         REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
         REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
         GRANT SELECT,INSERT,UPDATE,DELETE ON public.portal_browsers,public.portal_login_flows,public.portal_sessions TO {runtime};
         GRANT SELECT,INSERT ON public.portal_backchannel_logout_receipts,public.portal_backchannel_logout_sources TO {runtime};
         GRANT EXECUTE ON FUNCTION public.is_uuid_v7(uuid) TO {runtime};",
        password = literal(password),
        marker = literal(marker)
    );
    sqlx::raw_sql(&setup).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

async fn rejected(pool: &PgPool, sql: &str, code: &str, label: &str) -> Result<()> {
    match sqlx::raw_sql(sql).execute(pool).await {
        Err(sqlx::Error::Database(error)) if error.code().as_deref() == Some(code) => Ok(()),
        Err(sqlx::Error::Database(error)) => Err(anyhow!(
            "{label}: unexpected PostgreSQL code {}",
            error.code().as_deref().unwrap_or("absent")
        )),
        Err(_) => Err(anyhow!("{label}: unexpected non-database failure")),
        Ok(_) => Err(anyhow!("{label}: forbidden statement succeeded")),
    }
}

async fn exercise(
    admin: PgPool,
    runtime: PgPool,
    owner_pool: PgPool,
    owner: String,
    runtime_name: String,
) -> Result<()> {
    let principal: (String, String) =
        sqlx::query_as("SELECT current_user::text,session_user::text")
            .fetch_one(&runtime)
            .await?;
    ensure!(
        principal == (runtime_name.clone(), runtime_name.clone()),
        "portal runtime was simulated with SET ROLE"
    );
    ensure!(
        crate::schema_readiness::verify(&runtime).await.is_ok(),
        "minimal portal LOGIN failed schema readiness"
    );
    ensure!(
        crate::schema_readiness::verify(&admin).await.is_err(),
        "portal readiness accepted its migration administrator"
    );
    let owner_principal: (String, String) =
        sqlx::query_as("SELECT current_user::text,session_user::text")
            .fetch_one(&owner_pool)
            .await?;
    ensure!(
        owner_principal.0 == owner && owner_principal.0 != owner_principal.1,
        "owner negative fixture did not assume its NOLOGIN owner"
    );
    ensure!(
        crate::schema_readiness::verify(&owner_pool).await.is_err(),
        "portal readiness accepted an object owner"
    );
    for (sql, label) in [
        (
            "UPDATE portal_backchannel_logout_receipts SET jti_digest=jti_digest",
            "runtime replay ledger UPDATE",
        ),
        (
            "DELETE FROM portal_backchannel_logout_receipts",
            "runtime replay ledger DELETE",
        ),
        (
            "TRUNCATE portal_backchannel_logout_receipts",
            "runtime replay ledger TRUNCATE",
        ),
        (
            "UPDATE portal_backchannel_logout_sources SET sid_digest=sid_digest",
            "runtime original logout source UPDATE",
        ),
        (
            "DELETE FROM portal_backchannel_logout_sources",
            "runtime original logout source DELETE",
        ),
        (
            "TRUNCATE portal_backchannel_logout_sources",
            "runtime original logout source TRUNCATE",
        ),
        (
            "SELECT * FROM _sqlx_migrations",
            "runtime migration history read",
        ),
        (
            "CREATE TABLE public.portal_runtime_escape(id int)",
            "runtime table creation",
        ),
        (
            "CREATE TEMP TABLE portal_runtime_escape(id int)",
            "runtime temporary table creation",
        ),
        (
            "CREATE SCHEMA portal_runtime_escape",
            "runtime schema creation",
        ),
        (
            "ALTER TABLE portal_sessions ADD COLUMN runtime_escape int",
            "runtime schema alteration",
        ),
    ] {
        rejected(&runtime, sql, "42501", label).await?;
    }
    rejected(
        &runtime,
        &format!("SET ROLE {}", identifier(&owner)?),
        "42501",
        "runtime owner SET ROLE",
    )
    .await?;
    sqlx::raw_sql(&format!(
        "REVOKE UPDATE ON public.portal_sessions FROM {}",
        identifier(&runtime_name)?
    ))
    .execute(&admin)
    .await?;
    let incomplete_rejected = crate::schema_readiness::verify(&runtime).await.is_err();
    sqlx::raw_sql(&format!(
        "GRANT UPDATE ON public.portal_sessions TO {}",
        identifier(&runtime_name)?
    ))
    .execute(&admin)
    .await?;
    ensure!(
        incomplete_rejected,
        "portal readiness accepted a missing individual UPDATE privilege"
    );

    let mut state = super::super::state(vec![]);
    state.pool = runtime.clone();
    let session = insert(&state).await?;
    for (column, value) in [
        ("oidc_public_sid", "e".repeat(64)),
        ("oidc_public_sub", "another-opaque-pairwise-subject".into()),
    ] {
        rejected(
            &runtime,
            &format!(
                "UPDATE portal_sessions SET {column}={} WHERE id='{}'",
                literal(&value),
                session.id
            ),
            "23514",
            "immutable original public RP source",
        )
        .await?;
    }
    let original: (String, String) =
        sqlx::query_as("SELECT oidc_public_sid,oidc_public_sub FROM portal_sessions WHERE id=$1")
            .bind(session.id)
            .fetch_one(&runtime)
            .await?;
    ensure!(
        original == (session.oidc_public_sid, session.oidc_public_sub),
        "rejected source substitution changed the original RP binding"
    );
    let receipt = Uuid::now_v7();
    let digest = crate::boundary::digest(&receipt.to_string());
    sqlx::query("INSERT INTO portal_backchannel_logout_receipts(id,issuer,client_id,jti_digest,issued_at,expires_at) VALUES($1,$2,$3,$4,clock_timestamp(),clock_timestamp()+interval '5 minutes')")
        .bind(receipt).bind(session.issuer).bind(session.oidc_client_id).bind(digest).execute(&runtime).await?;
    rejected(
        &runtime,
        &format!("INSERT INTO portal_backchannel_logout_receipts(id,issuer,client_id,jti_digest,issued_at,expires_at) SELECT '{}',issuer,client_id,jti_digest,issued_at,expires_at FROM portal_backchannel_logout_receipts WHERE id='{receipt}'",Uuid::now_v7()),
        "23505",
        "replayed JTI within the original issuer and RP",
    ).await?;
    let receipts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM portal_backchannel_logout_receipts")
            .fetch_one(&runtime)
            .await?;
    ensure!(receipts == 1, "replayed JTI changed the append-only ledger");
    ensure!(
        crate::schema_readiness::verify(&runtime).await.is_ok(),
        "negative statements damaged minimal portal runtime readiness"
    );
    Ok(())
}

async fn drop_roles(admin: &PgPool, prefix: &str, marker: &str) -> Result<()> {
    ensure!(
        prefix.starts_with("portal20_roles_") && prefix.len() == "portal20_roles_".len() + 32,
        "refusing role cleanup outside the task-owned namespace"
    );
    let mut removed = true;
    for suffix in ["runtime", "owner"] {
        let role = format!("{prefix}_{suffix}");
        let quoted = identifier(&role)?;
        let ownership = sqlx::query_scalar::<_, Option<String>>(
            "SELECT shobj_description(oid,'pg_authid') FROM pg_roles WHERE rolname=$1",
        )
        .bind(&role)
        .fetch_optional(admin)
        .await;
        match ownership {
            Ok(None) => {}
            Ok(Some(Some(found))) if found == marker => {
                removed &= sqlx::raw_sql(&format!("DROP ROLE {quoted}"))
                    .execute(admin)
                    .await
                    .is_ok();
            }
            _ => removed = false,
        }
    }
    ensure!(removed, "owned portal role cleanup incomplete");
    Ok(())
}

#[tokio::test]
#[ignore = "requires explicit task-owned PostgreSQL and cluster identity"]
async fn phase20_pg_real_login_enforces_portal_schema_and_replay_boundaries() -> Result<()> {
    let db = Owned::new().await?;
    let cleanup_admin = match PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with((*db.admin.connect_options()).clone())
        .await
    {
        Ok(pool) => pool,
        Err(_) => {
            db.finish().await?;
            return Err(anyhow!("owned role cleanup administration unavailable"));
        }
    };
    let prefix = format!("portal20_roles_{}", Uuid::now_v7().simple());
    let owner = format!("{prefix}_owner");
    let runtime = format!("{prefix}_runtime");
    let marker = format!("portal-phase20-roles/{}", db.name);
    let mut runtime_pool: Option<PgPool> = None;
    let mut owner_pool: Option<PgPool> = None;
    let result = async {
        let password = crate::boundary::secret()?;
        provision(&db.pool, &db.name, &owner, &runtime, &password, &marker).await?;
        runtime_pool = Some(
            PgPoolOptions::new()
                .max_connections(2)
                .acquire_timeout(Duration::from_secs(5))
                .connect_with(
                    (*db.pool.connect_options())
                        .clone()
                        .username(&runtime)
                        .password(&password),
                )
                .await
                .map_err(|_| anyhow!("owned real portal LOGIN unavailable"))?,
        );
        let assume_owner = format!("SET ROLE {}", identifier(&owner)?);
        owner_pool = Some(
            PgPoolOptions::new()
                .max_connections(1)
                .after_connect(move |connection, _| {
                    let statement = assume_owner.clone();
                    Box::pin(async move {
                        sqlx::query(&statement).execute(&mut *connection).await?;
                        Ok(())
                    })
                })
                .connect_with((*db.pool.connect_options()).clone())
                .await?,
        );
        let checked_runtime = runtime_pool
            .as_ref()
            .ok_or_else(|| anyhow!("missing runtime fixture"))?
            .clone();
        let checked_owner = owner_pool
            .as_ref()
            .ok_or_else(|| anyhow!("missing owner fixture"))?
            .clone();
        let checked_admin = db.pool.clone();
        let checked_owner_name = owner.clone();
        let checked_runtime_name = runtime.clone();
        // Catch assertion panics from fixture helpers before closing pools and
        // dropping the owned database and roles below.
        tokio::spawn(async move {
            exercise(
                checked_admin,
                checked_runtime,
                checked_owner,
                checked_owner_name,
                checked_runtime_name,
            )
            .await
        })
        .await
        .map_err(|_| anyhow!("owned portal role assertions panicked"))?
    }
    .await;
    if let Some(pool) = runtime_pool {
        pool.close().await;
    }
    if let Some(pool) = owner_pool {
        pool.close().await;
    }
    let database_cleanup = db.finish().await;
    let roles_cleanup = drop_roles(&cleanup_admin, &prefix, &marker).await;
    cleanup_admin.close().await;
    eprintln!("portal_role_owned_cleanup assertions_ok={} database_removed={} roles_removed={} runtime_pool_closed=true owner_pool_closed=true",result.is_ok(),database_cleanup.is_ok(),roles_cleanup.is_ok());
    ensure!(
        database_cleanup.is_ok() && roles_cleanup.is_ok(),
        "owned portal schema test cleanup incomplete"
    );
    result
}
