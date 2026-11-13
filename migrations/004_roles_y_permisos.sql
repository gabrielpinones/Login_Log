-- El rol es del clúster y esta migración corre en varias bases (desarrollo y pruebas), por eso se
-- crea solo si no existe. La contraseña no va aquí: la sincroniza scripts/migrate.ts desde la URL.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'login_log_app') THEN
    CREATE ROLE login_log_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
EXCEPTION
  -- Otra migración concurrente sobre otra base pudo crearlo entre la comprobación y el CREATE.
  WHEN duplicate_object THEN NULL;
END
$$;

GRANT USAGE ON SCHEMA public TO login_log_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON users, sessions TO login_log_app;

GRANT SELECT, INSERT ON auth_events TO login_log_app;
-- Explícito aunque no se hayan concedido: documenta la intención y anula concesiones previas.
REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON auth_events FROM login_log_app;
