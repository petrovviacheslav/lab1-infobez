import express from 'express';
import escapeHtml from 'escape-html';
import { rateLimit } from 'express-rate-limit';
import { checkPassword, hashPassword, issueToken, jwtKey, verifyToken } from './security.js';

const validText = (value, max) => typeof value === 'string' && value.trim().length > 0 && value.length <= max;
const serialize = (note) => ({
  id: note.id,
  title: escapeHtml(note.title),
  content: escapeHtml(note.content),
});

export async function createApp(db, secret) {
  const key = jwtKey(secret);
  const dummyHash = await hashPassword('dummy account timing equalization');
  const app = express();
  app.disable('x-powered-by');
  app.use((_req, res, next) => {
    res.set({
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
      'Cache-Control': 'no-store',
    });
    next();
  });

  // One middleware protects the entire /api namespace, including future routes.
  app.use('/api', async (req, res, next) => {
    const header = req.get('authorization') || '';
    if (!header.startsWith('Bearer ') || header.length > 2048) {
      return res.status(401).json({ error: 'invalid_token' });
    }
    try {
      const userId = await verifyToken(header.slice(7), key);
      if (!db.prepare('SELECT id FROM users WHERE id = ?').get(userId)) {
        return res.status(401).json({ error: 'invalid_token' });
      }
      res.locals.userId = userId;
    } catch {
      return res.status(401).json({ error: 'invalid_token' });
    }
    next();
  });

  app.use('/auth/login', rateLimit({
    windowMs: 60_000,
    limit: 10,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { error: 'too_many_attempts' },
  }));
  app.use(express.json({ limit: '8kb', strict: true }));

  app.post('/auth/login', async (req, res) => {
    const { username, password } = req.body ?? {};
    if (!validText(username, 64) || !validText(password, 256)) {
      return res.status(400).json({ error: 'invalid_credentials_format' });
    }
    const user = db.prepare('SELECT id, password_hash FROM users WHERE username = ?').get(username);
    const passwordMatches = await checkPassword(password, user?.password_hash ?? dummyHash);
    if (!user || !passwordMatches) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    res.json({ access_token: await issueToken(user.id, key), token_type: 'Bearer', expires_in: 900 });
  });

  app.get('/api/data', (_req, res) => {
    const notes = db.prepare('SELECT id, title, content FROM notes WHERE owner_id = ? ORDER BY id')
      .all(res.locals.userId);
    res.json(notes.map(serialize));
  });

  app.post('/api/notes', (req, res) => {
    const { title, content } = req.body ?? {};
    if (!validText(title, 120) || !validText(content, 4000)) {
      return res.status(400).json({ error: 'title_and_content_required', limits: { title: 120, content: 4000 } });
    }
    const result = db.prepare('INSERT INTO notes (owner_id, title, content) VALUES (?, ?, ?)')
      .run(res.locals.userId, title, content);
    res.status(201).json(serialize({ id: Number(result.lastInsertRowid), title, content }));
  });

  app.use((_req, res) => res.status(404).json({ error: 'not_found' }));
  app.use((err, _req, res, _next) => {
    if (err.type === 'entity.too.large') return res.status(413).json({ error: 'body_too_large' });
    if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'invalid_json' });
    console.error('Request failed:', err.message);
    res.status(500).json({ error: 'internal_error' });
  });
  return app;
}
