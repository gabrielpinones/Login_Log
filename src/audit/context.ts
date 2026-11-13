import type { Request } from 'express';

export interface AuditContext {
  requestId?: string;
  sourceIp?: string;
  userAgent?: string;
  method?: string;
  route?: string;
}

export function auditContextFrom(req: Request): AuditContext {
  return {
    requestId: req.requestId,
    sourceIp: req.ip,
    userAgent: req.get('user-agent'),
    method: req.method,
    // req.path excluye la query string, que puede traer datos sensibles.
    route: req.baseUrl + req.path,
  };
}
