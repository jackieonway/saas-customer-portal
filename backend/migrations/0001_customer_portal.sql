-- This database contains only the portal RP's persistence. No account/member
-- authority or platform business table is mirrored into it.
CREATE FUNCTION public.is_uuid_v7(value uuid) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE SET search_path=pg_catalog AS $$
 SELECT (get_byte(uuid_send(value),6)>>4)=7 AND (get_byte(uuid_send(value),8)&192)=128
$$;
CREATE TABLE portal_browsers (
 id uuid PRIMARY KEY CHECK(public.is_uuid_v7(id)),
 token_hash text NOT NULL UNIQUE CHECK(token_hash ~ '^[0-9a-f]{64}$'),
 generation bigint NOT NULL CHECK(generation>=0),
 current_session_id uuid CHECK(current_session_id IS NULL OR public.is_uuid_v7(current_session_id)),
 created_at timestamptz NOT NULL,expires_at timestamptz NOT NULL CHECK(expires_at>created_at)
);
CREATE TABLE portal_login_flows (
 id uuid PRIMARY KEY CHECK(public.is_uuid_v7(id)),
 browser_id uuid NOT NULL REFERENCES portal_browsers(id) CHECK(public.is_uuid_v7(browser_id)),
 browser_generation bigint NOT NULL CHECK(browser_generation>=0),
 state_hash text NOT NULL UNIQUE CHECK(state_hash ~ '^[0-9a-f]{64}$'),
 binder_hash text NOT NULL CHECK(binder_hash ~ '^[0-9a-f]{64}$'),
 nonce_hash text NOT NULL CHECK(nonce_hash ~ '^[0-9a-f]{64}$'),
 verifier_ciphertext text NOT NULL,return_path text NOT NULL,
 created_at timestamptz NOT NULL,expires_at timestamptz NOT NULL CHECK(expires_at>created_at),consumed_at timestamptz
);
CREATE INDEX portal_login_flows_expiry ON portal_login_flows(expires_at);
CREATE TABLE portal_sessions (
 id uuid PRIMARY KEY CHECK(public.is_uuid_v7(id)),
 browser_id uuid NOT NULL REFERENCES portal_browsers(id) CHECK(public.is_uuid_v7(browser_id)),
 token_hash text NOT NULL UNIQUE CHECK(token_hash ~ '^[0-9a-f]{64}$'),
 user_id uuid NOT NULL CHECK(public.is_uuid_v7(user_id)),
 account_version bigint NOT NULL CHECK(account_version>=0),
 global_session_id uuid NOT NULL CHECK(public.is_uuid_v7(global_session_id)),
 oidc_client_id uuid NOT NULL CHECK(public.is_uuid_v7(oidc_client_id)),
 oidc_grant_id uuid NOT NULL CHECK(public.is_uuid_v7(oidc_grant_id)),
 oidc_client_policy_version bigint NOT NULL CHECK(oidc_client_policy_version>=1),
 issuer text NOT NULL,auth_time bigint NOT NULL CHECK(auth_time>0),
 nonce_hash text NOT NULL CHECK(nonce_hash ~ '^[0-9a-f]{64}$'),
 access_ciphertext text NOT NULL,refresh_ciphertext text NOT NULL,access_expires_at timestamptz NOT NULL,
 version bigint NOT NULL CHECK(version>=1),
 membership_id uuid CHECK(membership_id IS NULL OR public.is_uuid_v7(membership_id)),
 organization_id uuid CHECK(organization_id IS NULL OR public.is_uuid_v7(organization_id)),
 identity_version bigint CHECK(identity_version IS NULL OR identity_version>=1),
 customer_ciphertext text,customer_expires_at timestamptz,customer_needs_renewal boolean NOT NULL DEFAULT false,
 refresh_lease_id uuid CHECK(refresh_lease_id IS NULL OR public.is_uuid_v7(refresh_lease_id)),
 refresh_started_at timestamptz,refresh_uncertain boolean NOT NULL DEFAULT false,
 context_lease_id uuid CHECK(context_lease_id IS NULL OR public.is_uuid_v7(context_lease_id)),
 context_started_at timestamptz,
 logout_request_id uuid CHECK(logout_request_id IS NULL OR public.is_uuid_v7(logout_request_id)),
 logout_scope text CHECK(logout_scope IN ('GLOBAL','PORTAL')),logout_confirmed_at timestamptz,
 created_at timestamptz NOT NULL,expires_at timestamptz NOT NULL CHECK(expires_at>created_at),revoked_at timestamptz,
 CHECK((membership_id IS NULL)=(organization_id IS NULL)),
 CHECK((membership_id IS NULL)=(identity_version IS NULL)),
 CHECK((membership_id IS NULL)=(customer_ciphertext IS NULL)),
 CHECK((membership_id IS NULL)=(customer_expires_at IS NULL)),
 CHECK((refresh_lease_id IS NULL)=(refresh_started_at IS NULL)),
 CHECK((context_lease_id IS NULL)=(context_started_at IS NULL)),
 CHECK((logout_request_id IS NULL)=(logout_scope IS NULL))
);
CREATE INDEX portal_sessions_subject ON portal_sessions(user_id);
CREATE INDEX portal_sessions_expiry ON portal_sessions(expires_at);
