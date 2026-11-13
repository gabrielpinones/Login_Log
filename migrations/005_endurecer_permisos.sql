REVOKE DELETE ON users FROM login_log_app;
REVOKE UPDATE ON users FROM login_log_app;
GRANT UPDATE (password_hash, password_changed_at, failed_attempts, locked_until) ON users TO login_log_app;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;

ALTER FUNCTION auth_event_canonical(auth_events) SET search_path = pg_catalog, public;
