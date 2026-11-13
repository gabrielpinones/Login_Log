CREATE TABLE users (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email               text NOT NULL UNIQUE CONSTRAINT users_email_minusculas CHECK (email = lower(email)),
  password_hash       text NOT NULL,
  role                text NOT NULL DEFAULT 'user' CONSTRAINT users_role_valido CHECK (role IN ('user', 'admin')),
  failed_attempts     integer NOT NULL DEFAULT 0,
  locked_until        timestamptz,
  created_at          timestamptz NOT NULL DEFAULT now(),
  password_changed_at timestamptz NOT NULL DEFAULT now()
);
