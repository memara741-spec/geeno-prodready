# Fixture: nextjs-prisma-authjs

**Story.** A three-person agency built "TeamTasks" with Claude Code for a client: a task manager where each
customer organisation sees only its own tasks. Next.js 14 App Router, Prisma on Postgres, Auth.js with
email and password. It has been "almost done" for a month and nobody has written a test.

**What is planted.** The task update writes the whole request body; search uses `$queryRawUnsafe` with
interpolation; tasks are not filtered by organisation; users can set their own `role`; the Auth.js secret
falls back to `dev-secret`; full user rows with password hashes are returned; assignees are loaded one
query per task; the task list is unbounded; a debug route dumps the environment; one route creates a new
Prisma client per request; a client component imports Prisma; the seed creates an admin with a known
password; there are no tests and no CI; the dependency list has a misspelled package, an undeclared
import, an unused package, a test runner in production dependencies and a GPL-licensed library; the
framework version is out of support. See `expected.json`.
