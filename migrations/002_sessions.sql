CREATE TABLE sessions (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- SHA-256 en hex del token: quien lea la tabla no puede usar los valores para suplantar sesiones.
  token_hash   text NOT NULL UNIQUE,
  user_id      uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  -- Límite absoluto de vida, independiente de la actividad.
  expires_at   timestamptz NOT NULL,
  revoked_at   timestamptz,
  end_reason   text CONSTRAINT sessions_end_reason_valido
                 CHECK (end_reason IN ('logout', 'idle_timeout', 'absolute_timeout', 'password_change')),
  source_ip    inet,
  user_agent   text
);

CREATE INDEX sessions_user_id_idx ON sessions (user_id);
