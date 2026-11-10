import { openDatabase } from './database.js';
import { hashPassword } from './security.js';

const username = process.env.SEED_USERNAME;
const password = process.env.SEED_PASSWORD;
if (!username || username.length > 64 || !username.trim() ||
    !password || password.length < 12 || password.length > 256 || !password.trim()) {
  throw new Error('Set SEED_USERNAME (1–64 characters) and SEED_PASSWORD (12–256 characters)');
}
process.umask(0o077);
const db = openDatabase(process.env.DATABASE_PATH || 'notes.sqlite');
try {
  const hash = await hashPassword(password);
  const result = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?) ON CONFLICT(username) DO NOTHING')
    .run(username, hash);
  console.log(result.changes ? 'User created; only the scrypt hash was stored.' : 'User already exists; credentials unchanged.');
} finally {
  db.close();
}
