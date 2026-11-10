import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import { promisify } from 'node:util';
import { createApp } from '../src/app.js';
import { openDatabase } from '../src/database.js';
import { hashPassword } from '../src/security.js';

const run = promisify(execFile);
const secret = randomBytes(32).toString('hex');
const password = randomBytes(24).toString('base64url');
const db = openDatabase(':memory:');
db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)')
  .run('slava', await hashPassword(password));
const server = (await createApp(db, secret)).listen(0, '127.0.0.1');
await once(server, 'listening');
const base = `http://127.0.0.1:${server.address().port}`;
let token;

async function call(label, path, expected, { body, authenticated = false } = {}) {
  const args = ['--silent', '--show-error', '--max-time', '10', '--write-out', '\nHTTP %{http_code}', base + path];
  if (body !== undefined) args.push('-H', 'Content-Type: application/json', '-d', JSON.stringify(body));
  if (authenticated) args.push('-H', `Authorization: Bearer ${token}`);
  const { stdout } = await run('curl', args);
  const marker = stdout.lastIndexOf('\nHTTP ');
  const data = JSON.parse(stdout.slice(0, marker));
  const status = Number(stdout.slice(marker + 6));
  assert.equal(status, expected, label);
  console.log(`\n${label}\n${body === undefined ? 'GET' : 'POST'} ${path}\nHTTP ${status}`);
  const printable = { ...data };
  if (printable.access_token) printable.access_token = '<JWT hidden>';
  console.log(JSON.stringify(Array.isArray(data) ? data : printable, null, 2));
  return data;
}

try {
  console.log('Secure Notes API — real curl requests to a local HTTP server');
  console.log('Temporary in-memory SQLite; generated password and JWT are hidden.');
  console.log('Expected HTTP codes are checked with assertions.');
  await call('1. Access without token is denied', '/api/data', 401);
  const login = await call('2. Successful login', '/auth/login', 200,
    { body: { username: 'slava', password } });
  token = login.access_token;
  await call('3. Wrong password is denied', '/auth/login', 401,
    { body: { username: 'slava', password: 'wrong' } });
  await call('4. SQL injection cannot bypass authentication', '/auth/login', 401,
    { body: { username: "' OR 1=1 --", password: 'wrong' } });
  await call('5. Create a note', '/api/notes', 201,
    { authenticated: true, body: { title: 'Lab 1', content: 'My private note' } });
  const xss = await call('6. XSS payload is escaped', '/api/notes', 201,
    { authenticated: true, body: { title: 'XSS test', content: '<script>alert(1)</script>' } });
  assert.equal(xss.content, '&lt;script&gt;alert(1)&lt;/script&gt;');
  const notes = await call('7. Read own notes with a valid token', '/api/data', 200, { authenticated: true });
  assert.equal(notes.length, 2);
  assert.equal(notes[1].content, xss.content);
  await call('8. Invalid input is rejected', '/api/notes', 400,
    { authenticated: true, body: { title: 'Missing content' } });
  console.log('\nPASS: all 8 curl scenarios matched the expected responses.');
} finally {
  await new Promise((resolve) => server.close(resolve));
  db.close();
}
