-- Registro de auditoría de autenticación: solo inserción y encadenado por hashes.
CREATE TABLE auth_events (
  -- Sin identity ni secuencia: lo asigna el trigger dentro del bloqueo (ver auth_events_encadenar).
  seq             bigint PRIMARY KEY,
  event_id        uuid NOT NULL UNIQUE,
  occurred_at     timestamptz NOT NULL,
  event_type      text NOT NULL,
  outcome         text NOT NULL CONSTRAINT auth_events_outcome_valido CHECK (outcome IN ('success', 'failure')),
  reason          text,
  severity        text NOT NULL CONSTRAINT auth_events_severity_valida CHECK (severity IN ('info', 'warn', 'error')),
  -- user_id y session_id sin FK: el registro debe sobrevivir al borrado del usuario o de la sesión.
  user_id         uuid,
  identifier_hash text,
  session_id      uuid,
  source_ip       inet,
  user_agent      text CONSTRAINT auth_events_user_agent_largo CHECK (char_length(user_agent) <= 256),
  http_method     text,
  route           text CONSTRAINT auth_events_route_largo CHECK (char_length(route) <= 256),
  http_status     integer,
  request_id      uuid,
  service         text NOT NULL,
  version         text NOT NULL,
  environment     text NOT NULL,
  hostname        text NOT NULL,
  details         jsonb NOT NULL DEFAULT '{}',
  prev_hash       text NOT NULL,
  hash            text NOT NULL
);

CREATE INDEX auth_events_occurred_at_idx ON auth_events (occurred_at);
CREATE INDEX auth_events_user_id_idx ON auth_events (user_id, occurred_at);
CREATE INDEX auth_events_source_ip_idx ON auth_events (source_ip, occurred_at);
CREATE INDEX auth_events_event_type_idx ON auth_events (event_type, occurred_at);
CREATE INDEX auth_events_identifier_hash_idx ON auth_events (identifier_hash, occurred_at);

-- Texto canónico de una fila para el hash. jsonb ordena las claves y normaliza espacios, así que
-- el resultado no depende del orden de columnas. occurred_at se formatea en UTC explícito para
-- que el hash no cambie con la zona horaria de la sesión que lo calcula.
CREATE FUNCTION auth_event_canonical(e auth_events) RETURNS text
LANGUAGE sql
STABLE
AS $$
  SELECT jsonb_build_object(
    'seq',             e.seq,
    'event_id',        e.event_id,
    'occurred_at',     to_char(e.occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'event_type',      e.event_type,
    'outcome',         e.outcome,
    'reason',          e.reason,
    'severity',        e.severity,
    'user_id',         e.user_id,
    'identifier_hash', e.identifier_hash,
    'session_id',      e.session_id,
    'source_ip',       host(e.source_ip),
    'user_agent',      e.user_agent,
    'http_method',     e.http_method,
    'route',           e.route,
    'http_status',     e.http_status,
    'request_id',      e.request_id,
    'service',         e.service,
    'version',         e.version,
    'environment',     e.environment,
    'hostname',        e.hostname,
    'details',         e.details
  )::text
$$;

-- seq se asigna aquí, después de tomar el bloqueo, y no con identity: un valor identity se toma
-- antes del bloqueo, y con inserciones concurrentes el orden de seq podría no coincidir con el
-- orden de la cadena, con lo que la verificación por seq fallaría.
-- search_path fijo para que un esquema anterior en la ruta no pueda suplantar las funciones usadas.
CREATE FUNCTION auth_events_encadenar() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  ultimo_seq  bigint;
  ultimo_hash text;
BEGIN
  -- Clave fija propia de esta cadena; serializa las inserciones hasta el fin de cada transacción.
  PERFORM pg_advisory_xact_lock(7305214486019001);

  SELECT seq, hash INTO ultimo_seq, ultimo_hash
  FROM auth_events
  ORDER BY seq DESC
  LIMIT 1;

  NEW.seq := coalesce(ultimo_seq, 0) + 1;
  NEW.prev_hash := coalesce(ultimo_hash, repeat('0', 64));
  NEW.hash := encode(sha256(convert_to(NEW.prev_hash || auth_event_canonical(NEW), 'UTF8')), 'hex');
  RETURN NEW;
END
$$;

CREATE TRIGGER auth_events_encadenar_trg
  BEFORE INSERT ON auth_events
  FOR EACH ROW EXECUTE FUNCTION auth_events_encadenar();

CREATE FUNCTION auth_events_rechazar_cambios() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'auth_events es de solo inserción: % no está permitido', TG_OP
    USING HINT = 'El registro de auditoría es inmutable; las correcciones se registran como eventos nuevos.';
END
$$;

CREATE TRIGGER auth_events_sin_update_delete_trg
  BEFORE UPDATE OR DELETE ON auth_events
  FOR EACH ROW EXECUTE FUNCTION auth_events_rechazar_cambios();

CREATE TRIGGER auth_events_sin_truncate_trg
  BEFORE TRUNCATE ON auth_events
  FOR EACH STATEMENT EXECUTE FUNCTION auth_events_rechazar_cambios();

COMMENT ON TABLE auth_events IS 'Registro de auditoría de autenticación. Solo inserción; cadena SHA-256 verificable por seq.';
