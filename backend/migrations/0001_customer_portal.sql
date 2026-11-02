-- Fresh installation baseline. Existing installations must be recreated; no historical adoption.
-- PostgreSQL 17+, application-generated UUIDv7, SSO-only console.
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;

CREATE FUNCTION public.is_uuid_v7(value uuid) RETURNS boolean
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    SET search_path TO 'pg_catalog'
    AS $$
 SELECT (get_byte(uuid_send(value),6)>>4)=7 AND (get_byte(uuid_send(value),8)&192)=128
$$;

SET default_table_access_method = heap;

CREATE TABLE public.portal_browsers (
    id uuid NOT NULL,
    token_hash text NOT NULL,
    generation bigint NOT NULL,
    current_session_id uuid,
    created_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT portal_browsers_check CHECK ((expires_at > created_at)),
    CONSTRAINT portal_browsers_current_session_id_check CHECK (((current_session_id IS NULL) OR public.is_uuid_v7(current_session_id))),
    CONSTRAINT portal_browsers_generation_check CHECK ((generation >= 0)),
    CONSTRAINT portal_browsers_id_check CHECK (public.is_uuid_v7(id)),
    CONSTRAINT portal_browsers_token_hash_check CHECK ((token_hash ~ '^[0-9a-f]{64}$'::text))
);

CREATE TABLE public.portal_login_flows (
    context_selection_required boolean NOT NULL DEFAULT false,
    switch_session_id uuid CHECK (switch_session_id IS NULL OR public.is_uuid_v7(switch_session_id)),
    switch_version bigint CHECK (switch_version>=1),
    CONSTRAINT portal_login_flows_switch_binding_check CHECK ((switch_session_id IS NULL)=(switch_version IS NULL)),
    id uuid NOT NULL,
    browser_id uuid NOT NULL,
    browser_generation bigint NOT NULL,
    state_hash text NOT NULL,
    binder_hash text NOT NULL,
    nonce_hash text NOT NULL,
    verifier_ciphertext text NOT NULL,
    return_path text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    CONSTRAINT portal_login_flows_binder_hash_check CHECK ((binder_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT portal_login_flows_browser_generation_check CHECK ((browser_generation >= 0)),
    CONSTRAINT portal_login_flows_browser_id_check CHECK (public.is_uuid_v7(browser_id)),
    CONSTRAINT portal_login_flows_check CHECK ((expires_at > created_at)),
    CONSTRAINT portal_login_flows_id_check CHECK (public.is_uuid_v7(id)),
    CONSTRAINT portal_login_flows_nonce_hash_check CHECK ((nonce_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT portal_login_flows_state_hash_check CHECK ((state_hash ~ '^[0-9a-f]{64}$'::text))
);

CREATE TABLE public.portal_sessions (
    pending_selection_ciphertext text,
    id uuid NOT NULL,
    browser_id uuid NOT NULL,
    token_hash text NOT NULL,
    user_id uuid NOT NULL,
    account_version bigint NOT NULL,
    global_session_id uuid NOT NULL,
    oidc_client_id uuid NOT NULL,
    oidc_grant_id uuid NOT NULL,
    oidc_client_policy_version bigint NOT NULL,
    issuer text NOT NULL,
    auth_time bigint NOT NULL,
    nonce_hash text NOT NULL,
    access_ciphertext text NOT NULL,
    refresh_ciphertext text NOT NULL,
    access_expires_at timestamp with time zone NOT NULL,
    version bigint NOT NULL,
    membership_id uuid,
    organization_id uuid,
    identity_version bigint,
    customer_ciphertext text,
    customer_expires_at timestamp with time zone,
    customer_needs_renewal boolean DEFAULT false NOT NULL,
    refresh_lease_id uuid,
    refresh_started_at timestamp with time zone,
    refresh_uncertain boolean DEFAULT false NOT NULL,
    context_lease_id uuid,
    context_started_at timestamp with time zone,
    logout_request_id uuid,
    logout_scope text,
    logout_confirmed_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    CONSTRAINT portal_sessions_account_version_check CHECK ((account_version >= 1)),
    CONSTRAINT portal_sessions_auth_time_check CHECK ((auth_time > 0)),
    CONSTRAINT portal_sessions_browser_id_check CHECK (public.is_uuid_v7(browser_id)),
    CONSTRAINT portal_sessions_check CHECK ((expires_at > created_at)),
    CONSTRAINT portal_sessions_check1 CHECK (((membership_id IS NULL) = (organization_id IS NULL))),
    CONSTRAINT portal_sessions_check2 CHECK (((membership_id IS NULL) = (identity_version IS NULL))),
    CONSTRAINT portal_sessions_check3 CHECK (((membership_id IS NULL) = (customer_ciphertext IS NULL))),
    CONSTRAINT portal_sessions_check4 CHECK (((membership_id IS NULL) = (customer_expires_at IS NULL))),
    CONSTRAINT portal_sessions_check5 CHECK (((refresh_lease_id IS NULL) = (refresh_started_at IS NULL))),
    CONSTRAINT portal_sessions_check6 CHECK (((context_lease_id IS NULL) = (context_started_at IS NULL))),
    CONSTRAINT portal_sessions_check7 CHECK (((logout_request_id IS NULL) = (logout_scope IS NULL))),
    CONSTRAINT portal_sessions_context_lease_id_check CHECK (((context_lease_id IS NULL) OR public.is_uuid_v7(context_lease_id))),
    CONSTRAINT portal_sessions_global_session_id_check CHECK (public.is_uuid_v7(global_session_id)),
    CONSTRAINT portal_sessions_id_check CHECK (public.is_uuid_v7(id)),
    CONSTRAINT portal_sessions_identity_version_check CHECK (((identity_version IS NULL) OR (identity_version >= 1))),
    CONSTRAINT portal_sessions_logout_request_id_check CHECK (((logout_request_id IS NULL) OR public.is_uuid_v7(logout_request_id))),
    CONSTRAINT portal_sessions_logout_scope_check CHECK ((logout_scope = ANY (ARRAY['GLOBAL'::text, 'PORTAL'::text]))),
    CONSTRAINT portal_sessions_membership_id_check CHECK (((membership_id IS NULL) OR public.is_uuid_v7(membership_id))),
    CONSTRAINT portal_sessions_nonce_hash_check CHECK ((nonce_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT portal_sessions_oidc_client_id_check CHECK (public.is_uuid_v7(oidc_client_id)),
    CONSTRAINT portal_sessions_oidc_client_policy_version_check CHECK ((oidc_client_policy_version >= 1)),
    CONSTRAINT portal_sessions_oidc_grant_id_check CHECK (public.is_uuid_v7(oidc_grant_id)),
    CONSTRAINT portal_sessions_organization_id_check CHECK (((organization_id IS NULL) OR public.is_uuid_v7(organization_id))),
    CONSTRAINT portal_sessions_refresh_lease_id_check CHECK (((refresh_lease_id IS NULL) OR public.is_uuid_v7(refresh_lease_id))),
    CONSTRAINT portal_sessions_token_hash_check CHECK ((token_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT portal_sessions_user_id_check CHECK (public.is_uuid_v7(user_id)),
    CONSTRAINT portal_sessions_version_check CHECK ((version >= 1))
);

ALTER TABLE ONLY public.portal_browsers
    ADD CONSTRAINT portal_browsers_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.portal_browsers
    ADD CONSTRAINT portal_browsers_token_hash_key UNIQUE (token_hash);

ALTER TABLE ONLY public.portal_login_flows
    ADD CONSTRAINT portal_login_flows_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.portal_login_flows
    ADD CONSTRAINT portal_login_flows_state_hash_key UNIQUE (state_hash);

ALTER TABLE ONLY public.portal_sessions
    ADD CONSTRAINT portal_sessions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.portal_sessions
    ADD CONSTRAINT portal_sessions_token_hash_key UNIQUE (token_hash);

CREATE INDEX portal_login_flows_expiry ON public.portal_login_flows USING btree (expires_at);

CREATE INDEX portal_sessions_expiry ON public.portal_sessions USING btree (expires_at);

CREATE INDEX portal_sessions_subject ON public.portal_sessions USING btree (user_id);

ALTER TABLE ONLY public.portal_login_flows
    ADD CONSTRAINT portal_login_flows_browser_id_fkey FOREIGN KEY (browser_id) REFERENCES public.portal_browsers(id);

ALTER TABLE ONLY public.portal_sessions
    ADD CONSTRAINT portal_sessions_browser_id_fkey FOREIGN KEY (browser_id) REFERENCES public.portal_browsers(id);

ALTER TABLE public.portal_sessions
    ADD COLUMN oidc_public_sid text NOT NULL CHECK (oidc_public_sid ~ '^[0-9a-f]{64}$'),
    ADD COLUMN oidc_public_sub text NOT NULL CHECK (octet_length(oidc_public_sub) BETWEEN 1 AND 256 AND oidc_public_sub ~ '^[!-~]+$'),
    ADD CONSTRAINT portal_logout_confirmation_binding CHECK (logout_confirmed_at IS NULL OR logout_request_id IS NOT NULL);
CREATE FUNCTION public.portal_public_source_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path TO pg_catalog,public AS $$
BEGIN
    IF (NEW.oidc_public_sid,NEW.oidc_public_sub) IS DISTINCT FROM (OLD.oidc_public_sid,OLD.oidc_public_sub) THEN
        RAISE EXCEPTION 'PORTAL_PUBLIC_SOURCE_IMMUTABLE' USING ERRCODE='23514';
    END IF;
    IF (OLD.logout_request_id IS NOT NULL AND (NEW.logout_request_id,NEW.logout_scope) IS DISTINCT FROM (OLD.logout_request_id,OLD.logout_scope))
       OR (OLD.logout_confirmed_at IS NOT NULL AND NEW.logout_confirmed_at IS DISTINCT FROM OLD.logout_confirmed_at) THEN
        RAISE EXCEPTION 'PORTAL_LOGOUT_RECEIPT_IMMUTABLE' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER portal_public_source_immutable BEFORE UPDATE ON public.portal_sessions
FOR EACH ROW EXECUTE FUNCTION public.portal_public_source_immutable();
CREATE TABLE public.portal_backchannel_logout_receipts (
    id uuid PRIMARY KEY CHECK (public.is_uuid_v7(id)),
    issuer text NOT NULL CHECK (issuer ~ '^https://[^/?#[:space:]]+$'),
    client_id uuid NOT NULL CHECK (public.is_uuid_v7(client_id)),
    jti_digest text NOT NULL CHECK (jti_digest ~ '^[0-9a-f]{64}$'),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at>issued_at),
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(issuer,client_id,jti_digest)
);
CREATE INDEX portal_backchannel_logout_receipts_expiry ON public.portal_backchannel_logout_receipts(expires_at);
CREATE TABLE public.portal_backchannel_logout_sources (
    id uuid PRIMARY KEY CHECK (public.is_uuid_v7(id)),
    issuer text NOT NULL CHECK (issuer ~ '^https://[^/?#[:space:]]+$'),
    client_id uuid NOT NULL CHECK (public.is_uuid_v7(client_id)),
    sid_digest text NOT NULL CHECK (sid_digest ~ '^[0-9a-f]{64}$'),
    sub_digest text NOT NULL CHECK (sub_digest ~ '^[0-9a-f]{64}$'),
    revoked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(issuer,client_id,sid_digest)
);

SET check_function_bodies = true;
SELECT pg_catalog.set_config('search_path','public,pg_catalog,pg_temp',false);
