import { randomBytes, scrypt as derive, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { SignJWT, jwtVerify } from 'jose';

const scrypt = promisify(derive);
// OWASP scrypt parameters: N=2^17, r=8, p=1 (128 MiB per derivation).
const options = { N: 131072, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

export async function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  const key = await scrypt(password, salt, 64, options);
  return `scrypt$${salt}$${key.toString('hex')}`;
}

export async function checkPassword(password, stored) {
  const [, salt, expected] = stored.split('$');
  const key = await scrypt(password, salt, 64, options);
  return timingSafeEqual(key, Buffer.from(expected, 'hex'));
}

export function jwtKey(secret) {
  if (typeof secret !== 'string' || Buffer.byteLength(secret) < 32) {
    throw new Error('JWT_SECRET must contain at least 32 bytes');
  }
  return new TextEncoder().encode(secret);
}

export function issueToken(userId, key) {
  return new SignJWT({})
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setSubject(String(userId))
    .setIssuer('secure-notes-api')
    .setAudience('secure-notes-client')
    .setIssuedAt()
    .setExpirationTime('15m')
    .sign(key);
}

export async function verifyToken(token, key) {
  const { payload } = await jwtVerify(token, key, {
    algorithms: ['HS256'],
    typ: 'JWT',
    issuer: 'secure-notes-api',
    audience: 'secure-notes-client',
    requiredClaims: ['sub', 'iat', 'exp'],
    maxTokenAge: '15m',
  });
  if (!/^[1-9]\d*$/.test(payload.sub) || !Number.isSafeInteger(Number(payload.sub))) {
    throw new Error('Invalid subject');
  }
  return Number(payload.sub);
}
