-- =====================================================================
-- a-guard database: roles, schema, and Row-Level Security.
--
-- Enforcement model (three questions, three mechanisms):
--   SCOPE       (what operation?)  -> HTTP layer 401/403 (not here)
--   CAPABILITY  (read or write?)   -> GRANTs on two DATA roles below
--   VISIBILITY  (whose rows?)      -> RLS policies keyed on app.sub
--
-- Run as:  psql -U postgres -d agent_auth -f aguard/db/schema.sql
-- Idempotent: safe to re-run (CREATE IF NOT EXISTS / DROP IF EXISTS).
-- =====================================================================

-- -- -- 0. clean slate for re-runs (objects only; roles persist) ---------
DROP TABLE IF EXISTS agent_audit;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS auth_codes;
DROP VIEW IF EXISTS agent_documents;
DROP TABLE IF EXISTS documents;

-- -- -- 1. login roles (connect, own nothing, grant nothing) -------------
-- psycopg connects AS these. Least-privilege pools per capability class.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_login_human') THEN
    CREATE ROLE app_login_human LOGIN PASSWORD 'human-pool-secret-dev';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_login_agent') THEN
    CREATE ROLE app_login_agent LOGIN PASSWORD 'agent-pool-secret-dev';
  END IF;
  -- The authorization server's own login: it owns token bookkeeping and
  -- nothing else. It must NOT be able to read tenant documents.
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_login_auth') THEN
    CREATE ROLE app_login_auth LOGIN PASSWORD 'auth-pool-secret-dev';
  END IF;
END $$;

-- Separate audit logs per capability class.
ALTER ROLE app_login_human SET log_statement = 'none';
ALTER ROLE app_login_agent SET log_statement = 'all';
ALTER ROLE app_login_auth SET log_statement = 'none';

-- -- -- 2. data roles (no login; privileges here, keyed to capability) ---
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_user') THEN
    CREATE ROLE app_user NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_readonly') THEN
    CREATE ROLE agent_readonly NOLOGIN;
  END IF;
  -- Authorization-server state role: token tables only, no tenant data.
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auth_service') THEN
    CREATE ROLE auth_service NOLOGIN;
  END IF;
END $$;

-- Exact-one-role memberships: each login can SET ROLE to exactly one data
-- role. This irreversibility is what makes agent->human escalation
-- a *membership violation* (database-enforced), not a code bug.
REVOKE app_user FROM app_login_agent;
REVOKE app_user FROM app_login_human;
REVOKE app_user FROM app_login_auth;
REVOKE agent_readonly FROM app_login_agent;
REVOKE agent_readonly FROM app_login_human;
REVOKE agent_readonly FROM app_login_auth;
REVOKE auth_service FROM app_login_agent;
REVOKE auth_service FROM app_login_human;
REVOKE auth_service FROM app_login_auth;
GRANT app_user TO app_login_human;
GRANT agent_readonly TO app_login_agent;
GRANT auth_service TO app_login_auth;

-- -- -- 3. least-privilege grants -----------------------------------------
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO app_user, agent_readonly, auth_service;

ALTER DEFAULT PRIVILEGES FOR ROLE "app_login_human", "app_login_agent",
  "app_login_auth", "app_user", "agent_readonly", "auth_service", postgres
  REVOKE ALL ON TABLES FROM app_user, agent_readonly, auth_service;

-- NOTE: tables are created below owned by the applying superuser; ownership
-- is immediately safe because RLS is FORCEd on them (owner included).

-- -- -- 4. tables ----------------------------------------------------------
CREATE TABLE documents (
  id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  owner_sub   text NOT NULL,          -- OIDC sub: alice or svc:, tenant key
  title       text NOT NULL,
  body        text NOT NULL,
  internal_notes text NOT NULL DEFAULT ''  -- NEVER visible to agents
);

CREATE TABLE agent_audit (
  id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  ts            timestamptz NOT NULL DEFAULT now(),
  subject       text NOT NULL,        -- OIDC sub
  client_id     text NOT NULL,
  request_id    text NOT NULL,
  statement     text NOT NULL,        -- redacted before insert
  rows_returned integer NOT NULL DEFAULT 0
);

-- -- -- 4b. authorization-server state ---------------------------------------
-- Token bookkeeping. NOT tenant data: it is the AS's own operational state,
-- reachable only by the auth_service role. Persisting it is what lets the
-- process restart (or run several workers) without losing single-use code
-- tombstones or refresh-family revocation state.
CREATE TABLE auth_codes (
  code_hash             text PRIMARY KEY,   -- sha256 of the raw code
  client_id             text NOT NULL,
  redirect_uri          text NOT NULL,
  subject               text NOT NULL,
  scope                 text NOT NULL,
  code_challenge        text NOT NULL,
  code_challenge_method text NOT NULL,
  nonce                 text,
  resource              text,               -- RFC 8707 aud binding
  issued_at             bigint NOT NULL,
  expires_at            bigint NOT NULL,
  redeemed_at           bigint              -- NULL = live; set = tombstone
);
CREATE INDEX auth_codes_expires_idx ON auth_codes (expires_at);

CREATE TABLE refresh_tokens (
  token_hash text PRIMARY KEY,              -- sha256 of the raw token
  family_id  text NOT NULL,
  client_id  text NOT NULL,
  subject    text NOT NULL,
  scope      text NOT NULL,
  issued_at  bigint NOT NULL,
  expires_at bigint NOT NULL,
  retired    boolean NOT NULL DEFAULT false,
  revoked    boolean NOT NULL DEFAULT false
);
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_expires_idx ON refresh_tokens (expires_at);

-- -- -- 5. RLS: ON + FORCED, fail-closed policies --------------------------
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;

-- Human path: own rows only; admins may read all (explicit allowlist).
DROP POLICY IF EXISTS documents_human ON documents;
CREATE POLICY documents_human ON documents
  FOR ALL
  USING (
    owner_sub = NULLIF(current_setting('app.sub', true), '')
    OR current_setting('app.role', true) = 'human_admin'
  )
  WITH CHECK (
    owner_sub = NULLIF(current_setting('app.sub', true), '')
    OR current_setting('app.role', true) = 'human_admin'
  );

-- Agent path: SELECT own-tenant rows only; writes unconditionally denied.
DROP POLICY IF EXISTS documents_agent_select ON documents;
CREATE POLICY documents_agent_select ON documents
  FOR SELECT
  USING (owner_sub = NULLIF(current_setting('app.sub', true), ''));

-- Egress-safe projection: the agent's SELECT surface. security_invoker
-- keeps base-table RLS enforced (pre-PG15 views ran as OWNER = silent all-rows).
CREATE OR REPLACE VIEW agent_documents WITH (security_invoker = true) AS
  SELECT id, owner_sub, title, body FROM documents;

-- -- -- 6. grants on objects -------------------------------------------------
GRANT ALL ON documents TO app_user;
GRANT USAGE, SELECT ON SEQUENCE documents_id_seq TO app_user;
-- Agent: NO table-wide SELECT (GRANTs are additive — never grant it first).
-- Allowlist only the safe columns; internal_notes has *no matching grant*,
-- so any query touching it is denied at parse time. REVOKE ALL first keeps
-- re-runs idempotent regardless of prior state.
REVOKE ALL ON documents FROM agent_readonly;
GRANT SELECT (id, owner_sub, title, body) ON documents TO agent_readonly;
GRANT SELECT ON agent_documents TO app_user, agent_readonly;
GRANT SELECT, INSERT ON agent_audit TO app_user, agent_readonly;
GRANT USAGE, SELECT ON SEQUENCE agent_audit_id_seq TO app_user, agent_readonly;

-- AS state: auth_service owns the token tables and NOTHING else.
-- The tenant roles get no access to tokens; the AS gets no tenant data.
GRANT SELECT, INSERT, UPDATE, DELETE ON auth_codes, refresh_tokens TO auth_service;
REVOKE ALL ON documents, agent_documents, agent_audit FROM auth_service;
REVOKE ALL ON auth_codes, refresh_tokens FROM app_user, agent_readonly;

-- -- -- 7. anti-escalation hardening ----------------------------------------
ALTER ROLE agent_readonly NOLOGIN NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE app_user NOLOGIN NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
-- Temp tables are a DATABASE privilege, not a role attribute: PUBLIC holds
-- TEMPORARY by default, which lets any role fill the disk. Revoke per role.
REVOKE TEMPORARY ON DATABASE agent_auth FROM agent_readonly, PUBLIC;
GRANT TEMPORARY ON DATABASE agent_auth TO app_user;
