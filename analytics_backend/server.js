import Fastify from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import jwt from '@fastify/jwt';
import dotenv from 'dotenv';
import { z } from 'zod';

dotenv.config();

const server = Fastify({ logger: true });

await server.register(helmet, { contentSecurityPolicy: false });
await server.register(cors, {
  origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',') : true
});
await server.register(rateLimit, { max: 120, timeWindow: '1 minute' });
await server.register(jwt, {
  secret: process.env.ADMIN_JWT_SECRET || 'change-me-in-production'
});

const clientKeys = new Set(
  (process.env.CLIENT_API_KEYS || '')
    .split(',')
    .map((key) => key.trim())
    .filter(Boolean)
);

const requireClient = async (request, reply) => {
  const apiKey = request.headers['x-api-key'];
  if (!apiKey || !clientKeys.has(apiKey)) {
    return reply.code(401).send({ success: false, error: 'invalid_api_key' });
  }
};

const requireAdmin = async (request, reply) => {
  try {
    await request.jwtVerify();
  } catch (err) {
    return reply.code(401).send({ success: false, error: 'unauthorized' });
  }
};

const analyticsEventSchema = z.object({
  ts: z.string().datetime().optional(),
  event_type: z.enum(['scan_started', 'scan_completed', 'scan_failed', 'scan_status']),
  scan_id: z.string().uuid().optional(),
  scan_status: z.enum(['completed', 'failed', 'in_progress']).optional(),
  scan_type: z.string().min(1).optional(),
  anon_user_id: z.string().min(6).optional(),
  target_domain_hash: z.string().min(6).optional(),
  severity: z
    .object({
      low: z.number().int().min(0).optional(),
      medium: z.number().int().min(0).optional(),
      high: z.number().int().min(0).optional(),
      critical: z.number().int().min(0).optional()
    })
    .optional(),
  vuln_types: z.record(z.number().int().min(0)).optional(),
  meta: z.record(z.any()).optional()
});

server.get('/health', async () => ({ status: 'ok' }));

server.post('/v1/admin/login', async (request, reply) => {
  const { username, password } = request.body || {};
  if (!username || !password) {
    return reply.code(400).send({ success: false, error: 'missing_credentials' });
  }

  const adminUser = process.env.ADMIN_USERNAME;
  const adminPass = process.env.ADMIN_PASSWORD;
  if (adminUser && adminPass && (username !== adminUser || password !== adminPass)) {
    return reply.code(401).send({ success: false, error: 'invalid_credentials' });
  }

  const token = server.jwt.sign({ sub: username, role: 'admin' }, { expiresIn: '8h' });
  return { success: true, token };
});

server.post('/v1/analytics/events', { preHandler: requireClient }, async (request, reply) => {
  const parsed = analyticsEventSchema.safeParse(request.body);
  if (!parsed.success) {
    return reply.code(400).send({
      success: false,
      error: 'invalid_event',
      details: parsed.error.flatten()
    });
  }

  // TODO: Persist to database (TimescaleDB/ClickHouse).
  // Ensure IPs are hashed or truncated server-side and never store raw PII.

  return reply.code(202).send({ success: true });
});

server.get('/v1/admin/analytics/summary', { preHandler: requireAdmin }, async () => ({
  total_scans: 1280,
  unique_users: 312,
  returning_users: 198,
  completion_rate: 0.94,
  timeframe: 'last_30_days'
}));

server.get('/v1/admin/analytics/traffic', { preHandler: requireAdmin }, async () => ({
  interval: 'daily',
  series: [
    { day: '2026-01-25', total_users: 42, unique_users: 30 },
    { day: '2026-01-26', total_users: 48, unique_users: 33 },
    { day: '2026-01-27', total_users: 61, unique_users: 41 },
    { day: '2026-01-28', total_users: 52, unique_users: 36 },
    { day: '2026-01-29', total_users: 67, unique_users: 45 },
    { day: '2026-01-30', total_users: 71, unique_users: 47 },
    { day: '2026-01-31', total_users: 58, unique_users: 39 }
  ]
}));

server.get('/v1/admin/analytics/scans', { preHandler: requireAdmin }, async () => ({
  by_status: [
    { status: 'completed', count: 1180 },
    { status: 'failed', count: 60 },
    { status: 'in_progress', count: 40 }
  ],
  by_type: [
    { type: 'full', count: 730 },
    { type: 'quick', count: 410 },
    { type: 'custom', count: 140 }
  ]
}));

server.get('/v1/admin/analytics/severity', { preHandler: requireAdmin }, async () => ({
  distribution: [
    { severity: 'low', count: 480 },
    { severity: 'medium', count: 290 },
    { severity: 'high', count: 140 },
    { severity: 'critical', count: 38 }
  ]
}));

server.get('/v1/admin/analytics/top-vuln-types', { preHandler: requireAdmin }, async () => ({
  items: [
    { type: 'XSS', count: 122 },
    { type: 'SQLi', count: 94 },
    { type: 'Missing CSP', count: 88 },
    { type: 'Open Redirect', count: 61 },
    { type: 'Insecure Headers', count: 55 }
  ]
}));

server.get('/v1/admin/analytics/top-domains', { preHandler: requireAdmin }, async () => ({
  items: [
    { domain_hash: 'c0f3...9a1', scans: 48 },
    { domain_hash: '9d12...f4c', scans: 41 },
    { domain_hash: 'ab77...2dd', scans: 37 },
    { domain_hash: 'ef01...891', scans: 34 }
  ]
}));

const port = Number(process.env.PORT) || 4000;
const host = process.env.HOST || '0.0.0.0';

server.listen({ port, host });
