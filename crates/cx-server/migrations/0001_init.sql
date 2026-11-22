CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    oidc_issuer TEXT NOT NULL,
    oidc_subject TEXT NOT NULL,
    email TEXT NOT NULL,
    display_name TEXT NOT NULL,
    groups JSONB NOT NULL DEFAULT '[]'::jsonb,
    status TEXT NOT NULL DEFAULT 'active',
    created_at BIGINT NOT NULL,
    last_login_at BIGINT NOT NULL,
    UNIQUE(oidc_issuer, oidc_subject)
);

CREATE TABLE IF NOT EXISTS access_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    allowed_profiles JSONB,
    expires_at BIGINT NOT NULL,
    revoked_at BIGINT,
    created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS cli_logins (
    login_id TEXT PRIMARY KEY,
    user_code TEXT NOT NULL UNIQUE,
    poll_secret_hash TEXT NOT NULL,
    oidc_state TEXT NOT NULL UNIQUE,
    oidc_nonce TEXT NOT NULL,
    pkce_verifier TEXT NOT NULL,
    status TEXT NOT NULL,
    approved_token TEXT,
    approved_user_id TEXT,
    expires_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS virtual_keys (
    id TEXT PRIMARY KEY,
    key_hash TEXT NOT NULL UNIQUE,
    owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    profile_name TEXT NOT NULL,
    expires_at BIGINT,
    revoked_at BIGINT,
    created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_virtual_keys_owner_profile
    ON virtual_keys(owner_user_id, profile_name)
    WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS secrets (
    name TEXT NOT NULL,
    scope TEXT NOT NULL,
    owner_user_id TEXT NOT NULL,
    blob JSONB NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY(name, scope, owner_user_id)
);

CREATE TABLE IF NOT EXISTS revoked_sessions (
    session_id TEXT PRIMARY KEY,
    revoked_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    occurred_at BIGINT NOT NULL,
    user_id TEXT NOT NULL,
    user_email TEXT NOT NULL,
    session_id TEXT NOT NULL,
    profile_name TEXT NOT NULL,
    route_tier TEXT NOT NULL,
    target_host TEXT NOT NULL,
    target_port INTEGER NOT NULL,
    http_method TEXT,
    http_path TEXT,
    status_code INTEGER,
    decision TEXT NOT NULL,
    deny_reason TEXT,
    client_ip TEXT NOT NULL,
    latency_ms BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_occurred_at ON audit_logs(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id, occurred_at DESC);
