# Express and Node backends

What this covers: middleware order, a hardened skeleton, sessions, JWT, uploads, shutdown and containers.
Read it when: `framework: express`, `fastify`, `hono` or `koa`.
After reading you can: check middleware order and harden a hand-rolled backend.
Last checked: 2026-11-13.

## How this stack works
Express runs middleware and routers in registration order. A router mounted before the auth middleware is public.

## What is public and what is secret
Secrets live in environment variables; session and JWT secrets must be long and random (SEC-010).

## The failure modes AI tools produce here
Auth middleware registered after routers (AUTH-003); `jwt.decode` instead of `jwt.verify` (AUTH-005); `cors()` with defaults next to cookies (API-003); stack traces in errors (API-004); path traversal and shell injection (API-015, API-016); `nodemon` as the start command (DEP-001); `jsonwebtoken` before 9.0.0 and `mongoose` before 6.13.6, 7.8.4 or 8.9.5 have advisories (https://github.com/advisories/GHSA-qwph-4952-7xr6, https://github.com/advisories/GHSA-vg7j-7cwx-8wgw).

## How to review it
`server.js` registration order, every router, the auth middleware, upload and file routes, Dockerfile.

## Correct patterns
```js
const app = express();
app.disable('x-powered-by');                       // or helmet()
app.set('trust proxy', 1);                         // behind a load balancer
app.use(cors({ origin: process.env.ALLOWED_ORIGINS.split(','), credentials: true }));
app.use(express.json({ limit: '100kb' }));
app.use('/api/auth', limiter, authRouter);          // public, rate limited
app.use(requireAuth);                               // everything below needs a verified token
app.use('/api/files', filesRouter);
app.use((err, req, res, next) => { logger.error(err); res.status(500).json({ error: 'Server error' }); });
```
JWT: `jwt.verify(token, secret, { algorithms: ['HS256'] })`, short expiry, secret from the environment with no fallback. Passwords: argon2id, scrypt or bcrypt.

## How to test it
Request each router without a token; send `../../.env` to download routes; oversized bodies get 413.

## Owner dashboard settings to confirm
Host secrets; process manager or container restart policy; backups of the database.

## Checks this playbook supports
AUTH-002, AUTH-003, AUTH-005, AUTH-007, AUTH-010, AUTH-018, API-003, API-004, API-009, API-015, API-016, DEP-001, DEP-009, SEC-010.
