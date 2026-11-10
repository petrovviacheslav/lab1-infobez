import { createApp } from './app.js';
import { openDatabase } from './database.js';
import { jwtKey } from './security.js';

jwtKey(process.env.JWT_SECRET);
process.umask(0o077);
const db = openDatabase(process.env.DATABASE_PATH || 'notes.sqlite');
const app = await createApp(db, process.env.JWT_SECRET);
const server = app.listen(Number(process.env.PORT || 3000), process.env.HOST || '127.0.0.1', () => {
  console.log(`Secure Notes API listening on http://${process.env.HOST || '127.0.0.1'}:${server.address().port}`);
});
const shutdown = () => server.close(() => { db.close(); });
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
