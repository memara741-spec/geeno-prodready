# Prisma and Drizzle

What this covers: ORMs bypass database policies; authorisation must be in application code.
Read it when: `orm: prisma` or `drizzle` (also Mongoose and Sequelize).
After reading you can: find mass assignment, raw queries and missing scoping.
Last checked: 2026-11-13.

## How this stack works
ORMs connect with a privileged role, so database row policies do not apply unless configured deliberately. Every query must carry the ownership or tenant condition.

## What is public and what is secret
Connection strings are secret and server-only (DB-014).

## The failure modes AI tools produce here
`data: body` mass assignment (DB-013); `$queryRawUnsafe` with interpolation (DB-012); `findMany()` with no `take`; returning whole user rows; a client per request on serverless (DB-018).

## How to review it
Every `create`, `update`, `delete` and raw call; the schema for ownership columns.

## Correct patterns
```ts
const data = schema.parse(await req.json());   // pick fields explicitly
await prisma.task.update({ where: { id, orgId: user.orgId }, data: { title: data.title } });
await prisma.$queryRaw`SELECT * FROM "Task" WHERE title ILIKE ${'%' + q + '%'}`;  // tagged template, parameterised
```
One client per runtime (cache on `globalThis`); use the pooled connection URL on serverless.

## How to test it
Add a cross-tenant test and an extra-field test.

## Owner dashboard settings to confirm
Database backups; least-privilege application role.

## Checks this playbook supports
DB-012, DB-013, DB-014, DB-018, DB-019, API-005, API-008, API-019.
