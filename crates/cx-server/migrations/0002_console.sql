CREATE TABLE IF NOT EXISTS profiles (
    name TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    allow_groups JSONB NOT NULL DEFAULT '[]'::jsonb,
    allow_users JSONB NOT NULL DEFAULT '[]'::jsonb,
    deny_hosts JSONB NOT NULL DEFAULT '[]'::jsonb,
    fallback_action TEXT NOT NULL DEFAULT 'client_passthrough',
    revision TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    updated_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS profile_platforms (
    profile_name TEXT NOT NULL REFERENCES profiles(name) ON DELETE CASCADE,
    id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    params JSONB NOT NULL DEFAULT '{}'::jsonb,
    secret_bindings JSONB NOT NULL DEFAULT '{}'::jsonb,
    preset TEXT,
    rules JSONB NOT NULL DEFAULT '[]'::jsonb,
    routing_override JSONB NOT NULL DEFAULT '{}'::jsonb,
    virtual_key_override JSONB,
    allow_insecure_http BOOLEAN NOT NULL DEFAULT FALSE,
    updated_by TEXT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (profile_name, id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_profile_platforms_unique_named_provider
    ON profile_platforms (profile_name, provider_id)
    WHERE provider_id <> 'generic-http';

ALTER TABLE virtual_keys
    ADD COLUMN IF NOT EXISTS platform_id TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_virtual_keys_owner_profile_platform
    ON virtual_keys (owner_user_id, profile_name, platform_id)
    WHERE revoked_at IS NULL;

ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS platform_id TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_cursor
    ON audit_logs (user_id, id DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_profile_platform_cursor
    ON audit_logs (profile_name, platform_id, id DESC);
