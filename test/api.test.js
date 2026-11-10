import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { SignJWT } from 'jose';
import { createApp } from '../src/app.js';
import { openDatabase } from '../src/database.js';
import { checkPassword, hashPassword, issueToken, jwtKey } from '../src/security.js';

const secret = randomBytes(32).toString('hex');
const key = jwtKey(secret);
const password = randomBytes(24).toString('base64url');
const db = openDatabase(':memory:');
let server, base, token, otherToken, storedHash;

async function request(path, { method = 'GET', body, bearer, raw } = {}) {
  const headers = {};
  if (bearer) headers.Authorization = `Bearer ${bearer}`;
  if (body !== undefined || raw !== undefined) headers['Content-Type'] = 'application/json';
  const response = await fetch(base + path, {
    method, headers, body: raw ?? (body === undefined ? undefined : JSON.stringify(body)),
    signal: AbortSignal.timeout(5000),
  });
  return { status: response.status, data: await response.json(), headers: response.headers };
}

async function customToken(claims, signingKey = key, algorithm = 'HS256') {
  return new SignJWT(claims).setProtectedHeader({ alg: algorithm, typ: 'JWT' }).sign(signingKey);
}

before(async () => {
  storedHash = await hashPassword(password);
  db.prepare('INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)').run(1, 'slava', storedHash);
  db.prepare('INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)').run(2, 'other', storedHash);
  const app = await createApp(db, secret);
  server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  base = `http://127.0.0.1:${server.address().port}`;
  token = await issueToken(1, key);
  otherToken = await issueToken(2, key);
});

after(async () => {
  if (server) await new Promise((resolve) => server.close(resolve));
  db.close();
});

test('passwords use salted scrypt; correct password succeeds and wrong one fails', async () => {
  assert.match(storedHash, /^scrypt\$[a-f0-9]{32}\$[a-f0-9]{128}$/);
  assert.ok(!storedHash.includes(password));
  assert.notEqual(await hashPassword(password), storedHash);
  assert.equal(await checkPassword(password, storedHash), true);
  assert.equal(await checkPassword('wrong password', storedHash), false);
});

test('startup rejects absent or short JWT secret', async () => {
  await assert.rejects(createApp(db), /JWT_SECRET/);
  await assert.rejects(createApp(db, 'short'), /JWT_SECRET/);
});

test('login returns a usable JWT with a 15 minute lifetime', async () => {
  const result = await request('/auth/login', { method: 'POST', body: { username: 'slava', password } });
  assert.equal(result.status, 200);
  assert.equal(result.data.token_type, 'Bearer');
  assert.equal(result.data.expires_in, 900);
  assert.equal((await request('/api/data', { bearer: result.data.access_token })).status, 200);
});

test('wrong password, unknown account and SQL injection have the same denial', async () => {
  for (const username of ['slava', 'missing', "' OR 1=1 --"]) {
    const result = await request('/auth/login', { method: 'POST', body: { username, password: 'wrong' } });
    assert.equal(result.status, 401);
    assert.deepEqual(result.data, { error: 'invalid_credentials' });
  }
});

test('both protected endpoints reject missing tokens', async () => {
  assert.equal((await request('/api/data')).status, 401);
  assert.equal((await request('/api/notes', { method: 'POST', body: {} })).status, 401);
});

test('malformed, wrongly signed and unsigned tokens are rejected', async () => {
  const unsigned = Buffer.from('{"alg":"none","typ":"JWT"}').toString('base64url') + '.' +
    Buffer.from('{"sub":"1","exp":9999999999}').toString('base64url') + '.';
  for (const bearer of ['not-a-jwt', unsigned, await issueToken(1, jwtKey(randomBytes(32).toString('hex')))]) {
    assert.equal((await request('/api/data', { bearer })).status, 401);
  }
});

test('expired, future, incomplete and wrong issuer or audience claims are rejected', async () => {
  const now = Math.floor(Date.now() / 1000);
  const claims = { sub: '1', iat: now, exp: now + 900, iss: 'secure-notes-api', aud: 'secure-notes-client' };
  for (const override of [
    { iat: now - 1200, exp: now - 300 }, { iat: now + 600 }, { exp: undefined },
    { iat: undefined }, { sub: undefined }, { iss: 'attacker' }, { aud: 'attacker' },
    { sub: 'NaN' }, { sub: '1 OR 1=1' }, { sub: '9999999999999999999999999' },
  ]) {
    const bearer = await customToken({ ...claims, ...override });
    assert.equal((await request('/api/data', { bearer })).status, 401);
  }
});

test('tokens using an unexpected signing algorithm are rejected', async () => {
  const now = Math.floor(Date.now() / 1000);
  const bearer = await customToken({ sub: '1', iat: now, exp: now + 900,
    iss: 'secure-notes-api', aud: 'secure-notes-client' }, key, 'HS384');
  assert.equal((await request('/api/data', { bearer })).status, 401);
});

test('a valid token for a deleted or nonexistent account is rejected', async () => {
  assert.equal((await request('/api/data', { bearer: await issueToken(99, key) })).status, 401);
});

test('create note and list data; caller cannot choose another owner', async () => {
  const result = await request('/api/notes', { method: 'POST', bearer: token,
    body: { title: 'First note', content: 'Private text', owner_id: 2 } });
  assert.equal(result.status, 201);
  assert.deepEqual(result.data, { id: 1, title: 'First note', content: 'Private text' });
  assert.deepEqual((await request('/api/data', { bearer: token })).data, [result.data]);
  assert.deepEqual((await request('/api/data', { bearer: otherToken })).data, []);
});

test('XSS is escaped on creation and read; source text remains in SQLite', async () => {
  const result = await request('/api/notes', { method: 'POST', bearer: token,
    body: { title: '<img src=x onerror=alert(1)>', content: '<script>alert("x")</script> & \'x\'' } });
  assert.equal(result.status, 201);
  assert.equal(result.data.title, '&lt;img src=x onerror=alert(1)&gt;');
  assert.equal(result.data.content, '&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; &amp; &#39;x&#39;');
  assert.deepEqual((await request('/api/data', { bearer: token })).data[1], result.data);
  assert.equal(db.prepare('SELECT title FROM notes WHERE id = ?').get(result.data.id).title,
    '<img src=x onerror=alert(1)>');
});

test('SQL-like note text is stored as data and does not change schema', async () => {
  const content = "'); DROP TABLE users; --";
  assert.equal((await request('/api/notes', { method: 'POST', bearer: token,
    body: { title: 'SQL test', content } })).status, 201);
  assert.equal(db.prepare('SELECT count(*) AS total FROM users').get().total, 2);
  assert.equal(db.prepare('SELECT content FROM notes WHERE id = ?').get(3).content, content);
});

test('invalid note bodies and out-of-range strings return 400', async () => {
  for (const body of [null, [], {}, { title: 5, content: 'x' }, { title: ' ', content: 'x' },
    { title: 'x', content: false }, { title: 'x'.repeat(121), content: 'x' },
    { title: 'x', content: 'x'.repeat(4001) }]) {
    assert.equal((await request('/api/notes', { method: 'POST', bearer: token, body })).status, 400);
  }
});

test('login validates body types and field sizes', async () => {
  for (const body of [{}, { username: {}, password: 'x' }, { username: 'x', password: 'x'.repeat(257) }]) {
    assert.equal((await request('/auth/login', { method: 'POST', body })).status, 400);
  }
});

test('broken JSON and oversized bodies return JSON errors without stack traces', async () => {
  const broken = await request('/api/notes', { method: 'POST', bearer: token, raw: '{' });
  assert.equal(broken.status, 400);
  assert.deepEqual(broken.data, { error: 'invalid_json' });
  const huge = await request('/api/notes', { method: 'POST', bearer: token,
    body: { title: 'x', content: 'x'.repeat(10000) } });
  assert.equal(huge.status, 413);
});

test('responses have JSON content type, no-store, nosniff and CSP', async () => {
  const { headers } = await request('/api/data', { bearer: token });
  assert.match(headers.get('content-type'), /^application\/json/);
  assert.equal(headers.get('cache-control'), 'no-store');
  assert.equal(headers.get('x-content-type-options'), 'nosniff');
  assert.match(headers.get('content-security-policy'), /default-src 'none'/);
  assert.equal(headers.get('x-powered-by'), null);
});

test('unknown routes return JSON; future /api routes are also protected', async () => {
  assert.equal((await request('/missing')).status, 404);
  assert.equal((await request('/api/future')).status, 401);
  assert.equal((await request('/api/future', { bearer: token })).status, 404);
});

test('login attempts are limited per IP with Retry-After', async () => {
  let result;
  for (let i = 0; i < 11; i++) result = await request('/auth/login', { method: 'POST', body: {} });
  assert.equal(result.status, 429);
  assert.deepEqual(result.data, { error: 'too_many_attempts' });
  assert.ok(Number(result.headers.get('retry-after')) > 0);
});
