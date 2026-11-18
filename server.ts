import crypto from 'node:crypto';
import path from 'node:path';
import express from 'express';
import dotenv from 'dotenv';
import { db, initDatabase, nowIso, recordAuditLog, verifyPassword } from './src/server/db.ts';
import { hashSessionToken, loadStaffFromRequest, requireAuth } from './src/server/auth.ts';
import type { AuthenticatedRequest } from './src/server/auth.ts';
import { publicRouter } from './src/server/publicRoutes.ts';
import { adminRouter } from './src/server/adminRoutes.ts';
import {
  handleRazorpayWebhook,
  handleSignedAttachmentDownload,
  projectRouter,
} from './src/server/projectRoutes.ts';
import { printingRouter, store3dRouter } from './src/server/printingRoutes.ts';
import { safeJsonParse } from './src/server/helpers.ts';
import { ROLE_DEFAULT_PERMISSIONS } from './src/types/cms.ts';
import type { StaffPermissions, StaffRole } from './src/types/cms.ts';

dotenv.config();
initDatabase();

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === 'production';

app.use(express.json({ limit: '55mb' }));

// Health check
app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'NexustekFusion' });
});

// ==================== AUTH ROUTES ====================

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    res.status(400).json({ error: 'Email and password are required.' });
    return;
  }

  const row = db
    .prepare('SELECT * FROM staff_users WHERE lower(email) = lower(?) LIMIT 1')
    .get(String(email).trim()) as
    | {
        id: string;
        name: string;
        email: string;
        password_hash: string;
        role: StaffRole;
        permissions_json: string;
        is_active: number;
        last_login_at: string | null;
        created_at: string;
      }
    | undefined;

  if (!row || !verifyPassword(String(password), row.password_hash)) {
    res.status(401).json({ error: 'Invalid email or password.' });
    return;
  }
  if (!row.is_active) {
    res.status(403).json({ error: 'This staff account is deactivated. Contact a Super Admin.' });
    return;
  }

  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = hashSessionToken(rawToken);
  const ts = nowIso();
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

  db.prepare(
    `INSERT INTO staff_sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)`
  ).run(tokenHash, row.id, expiresAt, ts);
  db.prepare(`UPDATE staff_users SET last_login_at = ? WHERE id = ?`).run(ts, row.id);

  recordAuditLog({
    actorId: row.id,
    actorEmail: row.email,
    actorRole: row.role,
    action: 'STAFF_LOGIN',
    resourceType: 'session',
    resourceId: row.id,
    summary: `${row.email} signed into the Admin Console.`,
  });

  const permissions = safeJsonParse<StaffPermissions>(
    row.permissions_json,
    ROLE_DEFAULT_PERMISSIONS[row.role]
  );

  res.cookie('ntf_session', rawToken, {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProduction,
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: '/',
  });

  res.json({
    token: rawToken,
    user: {
      id: row.id,
      name: row.name,
      email: row.email,
      role: row.role,
      permissions,
      is_active: Boolean(row.is_active),
      last_login_at: ts,
      created_at: row.created_at,
    },
  });
});

app.get('/api/auth/me', (req, res) => {
  const session = loadStaffFromRequest(req);
  if (!session) {
    res.status(401).json({ error: 'Not authenticated.' });
    return;
  }
  res.json({ user: session.user });
});

app.post('/api/auth/logout', requireAuth, (req: AuthenticatedRequest, res) => {
  if (req.sessionTokenHash) {
    db.prepare('DELETE FROM staff_sessions WHERE token_hash = ?').run(req.sessionTokenHash);
  }
  res.clearCookie('ntf_session', { path: '/' });
  res.json({ loggedOut: true });
});

// ==================== DOMAIN ROUTERS ====================

app.use('/api/public', publicRouter);
app.use('/api/projects', projectRouter);
app.use('/api/3d-printing', printingRouter);
app.use('/api/store-3d', store3dRouter);
app.get('/api/files/signed/:id', handleSignedAttachmentDownload);
app.post('/api/webhooks/razorpay', (req, res) => {
  void handleRazorpayWebhook(req, res);
});
app.use('/api/admin', adminRouter);

// ==================== FRONTEND SERVING (VITE / DIST) ====================

async function startServer() {
  if (!isProduction) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (req, res, next) => {
      if (req.path.startsWith('/api/')) {
        next();
        return;
      }
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`NexustekFusion server listening on http://0.0.0.0:${PORT}`);
  });
}

void startServer();
