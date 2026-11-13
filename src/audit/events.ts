type Outcome = 'success' | 'failure';
type Severity = 'info' | 'warn' | 'error';

interface CatalogEntry {
  readonly outcome: Outcome;
  readonly severity: Severity;
  /** Valor de ECS event.category. */
  readonly category: string;
  /** Códigos de motivo permitidos (lista cerrada). */
  readonly reasons: readonly string[];
}

export const EVENT_CATALOG = {
  'auth.register.success': { outcome: 'success', severity: 'info', category: 'iam', reasons: [] },
  'auth.register.failure': {
    outcome: 'failure',
    severity: 'warn',
    category: 'iam',
    reasons: ['email_taken', 'weak_password', 'invalid_input'],
  },
  'auth.login.success': { outcome: 'success', severity: 'info', category: 'authentication', reasons: [] },
  'auth.login.failure': {
    outcome: 'failure',
    severity: 'warn',
    category: 'authentication',
    reasons: ['unknown_user', 'bad_password', 'account_locked', 'rate_limited', 'invalid_input'],
  },
  'auth.logout': { outcome: 'success', severity: 'info', category: 'authentication', reasons: [] },
  'auth.account.locked': { outcome: 'success', severity: 'warn', category: 'iam', reasons: [] },
  'auth.account.unlocked': { outcome: 'success', severity: 'info', category: 'iam', reasons: [] },
  'auth.role.changed': { outcome: 'success', severity: 'warn', category: 'iam', reasons: [] },
  'auth.ratelimit.triggered': {
    outcome: 'failure',
    severity: 'warn',
    category: 'intrusion_detection',
    reasons: [],
  },
  'auth.password.change.success': { outcome: 'success', severity: 'info', category: 'iam', reasons: [] },
  'auth.password.change.failure': {
    outcome: 'failure',
    severity: 'warn',
    category: 'iam',
    reasons: ['bad_current_password', 'weak_password', 'invalid_input', 'rate_limited'],
  },
  'session.created': { outcome: 'success', severity: 'info', category: 'session', reasons: [] },
  'session.expired': {
    outcome: 'success',
    severity: 'info',
    category: 'session',
    reasons: ['idle_timeout', 'absolute_timeout'],
  },
  'session.revoked': { outcome: 'success', severity: 'info', category: 'session', reasons: ['password_change'] },
  'authz.denied': {
    outcome: 'failure',
    severity: 'warn',
    category: 'web',
    reasons: ['no_session', 'insufficient_role'],
  },
  'security.csrf.rejected': {
    outcome: 'failure',
    severity: 'warn',
    category: 'web',
    reasons: ['origin_mismatch', 'origin_missing'],
  },
  'audit.log.viewed': { outcome: 'success', severity: 'info', category: 'database', reasons: [] },
  'audit.write.failed': { outcome: 'failure', severity: 'error', category: 'database', reasons: [] },
} as const satisfies Record<string, CatalogEntry>;

export type EventType = keyof typeof EVENT_CATALOG;

export type ReasonOf<K extends EventType> = (typeof EVENT_CATALOG)[K]['reasons'][number];

export type AuditDetails = Record<string, string | number | boolean | null>;

interface AuditEventCommon {
  userId?: string | null;
  /** Identificador tal como lo escribió el usuario; solo se persiste su HMAC. */
  identifier?: string;
  sessionId?: string | null;
  httpStatus?: number;
  details?: AuditDetails;
}

/** audit.write.failed lo emite solo el propio módulo cuando falla la escritura. */
type RecordableType = Exclude<EventType, 'audit.write.failed'>;

export type AuditEventInput = {
  [K in RecordableType]: { type: K } & AuditEventCommon &
    ([ReasonOf<K>] extends [never] ? { reason?: never } : { reason: ReasonOf<K> });
}[RecordableType];
