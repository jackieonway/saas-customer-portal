//! Read-only checks for the portal's independent canonical schema and runtime.
use crate::error::AppError;

pub(crate) async fn verify(pool: &sqlx::PgPool) -> Result<(), AppError> {
    let ready:bool=sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_roles runtime WHERE runtime.rolname=current_user \
          AND current_user=session_user AND runtime.rolcanlogin AND NOT runtime.rolsuper \
          AND NOT runtime.rolcreaterole AND NOT runtime.rolcreatedb AND NOT runtime.rolreplication AND NOT runtime.rolbypassrls \
          AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members membership WHERE membership.member=runtime.oid) \
          AND NOT has_database_privilege(current_user,current_database(),'CREATE') \
          AND NOT has_database_privilege(current_user,current_database(),'TEMP') \
          AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace namespace WHERE namespace.nspname!~'^pg_' \
            AND namespace.nspname<>'information_schema' AND has_schema_privilege(current_user,namespace.oid,'CREATE')) \
          AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object JOIN pg_catalog.pg_namespace namespace ON namespace.oid=object.relnamespace \
            WHERE namespace.nspname!~'^pg_' AND namespace.nspname<>'information_schema' AND pg_has_role(current_user,object.relowner,'MEMBER')) \
          AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object JOIN pg_catalog.pg_namespace namespace ON namespace.oid=object.relnamespace \
            WHERE namespace.nspname='public' AND object.relkind IN('r','p') \
              AND object.relname NOT IN('_sqlx_migrations','portal_browsers','portal_login_flows','portal_sessions','portal_backchannel_logout_receipts','portal_backchannel_logout_sources')) \
          AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['portal_browsers','portal_login_flows','portal_sessions']) expected(name) \
            CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE']) required(privilege) \
            WHERE to_regclass('public.'||expected.name) IS NULL OR NOT has_table_privilege(current_user,'public.'||expected.name,required.privilege)) \
          AND has_table_privilege(current_user,'public.portal_backchannel_logout_receipts','SELECT') \
          AND has_table_privilege(current_user,'public.portal_backchannel_logout_receipts','INSERT') \
          AND NOT has_any_column_privilege(current_user,'public.portal_backchannel_logout_receipts','UPDATE,REFERENCES') \
          AND NOT has_table_privilege(current_user,'public.portal_backchannel_logout_receipts','DELETE,TRUNCATE,TRIGGER') \
          AND has_table_privilege(current_user,'public.portal_backchannel_logout_sources','SELECT') \
          AND has_table_privilege(current_user,'public.portal_backchannel_logout_sources','INSERT') \
          AND NOT has_any_column_privilege(current_user,'public.portal_backchannel_logout_sources','UPDATE,REFERENCES') \
          AND NOT has_table_privilege(current_user,'public.portal_backchannel_logout_sources','DELETE,TRUNCATE,TRIGGER') \
          AND NOT has_any_column_privilege(current_user,'public._sqlx_migrations','INSERT,UPDATE,REFERENCES') \
          AND NOT has_table_privilege(current_user,'public._sqlx_migrations','DELETE,TRUNCATE,TRIGGER') \
          AND has_function_privilege(current_user,'public.is_uuid_v7(uuid)','EXECUTE') \
          AND (SELECT count(*) FROM pg_catalog.pg_attribute attribute \
            WHERE attribute.attrelid='public.portal_sessions'::regclass AND attribute.attname IN('oidc_public_sid','oidc_public_sub') \
              AND attribute.atttypid='text'::regtype AND attribute.attnotnull AND NOT attribute.attisdropped)=2 \
          AND EXISTS(SELECT 1 FROM pg_catalog.pg_trigger guard WHERE guard.tgrelid='public.portal_sessions'::regclass \
            AND guard.tgname='portal_public_source_immutable' AND guard.tgenabled='O' AND NOT guard.tgisinternal))")
        .fetch_one(pool).await.map_err(|_|AppError::Unavailable)?;
    if ready {
        Ok(())
    } else {
        Err(AppError::Unavailable)
    }
}
