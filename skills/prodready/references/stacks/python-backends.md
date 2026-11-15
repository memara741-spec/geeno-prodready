# Flask, FastAPI and Django

What this covers: debug flags, secret keys, CORS, dependency-based auth and the Django deploy checklist.
Read it when: `framework: django`, `flask` or `fastapi`.
After reading you can: review Python backends for the common mistakes.
Last checked: 2026-11-13.

## How this stack works
Views and routes are HTTP handlers; auth is usually a decorator, dependency or permission class.

## What is public and what is secret
`SECRET_KEY` and similar must come from the environment, never the repository (SEC-010).

## The failure modes AI tools produce here
`DEBUG = True` in production; `@csrf_exempt` on authenticated views; f-strings in `cursor.execute`; wildcard CORS with credentials; `yaml.load` and `pickle.loads` on input; Django releases out of support (supported on 2026-11-13: 5.2 LTS, 6.0, 6.1; source https://endoflife.date/django).

## How to review it
settings module, urls, views, dependencies, any raw SQL.

## Correct patterns
Django: set `ALLOWED_HOSTS`, secure cookie flags and HSTS, and run `python manage.py check --deploy`. FastAPI: use `Depends(get_current_user)` on every data route and pydantic models for input. Use parameterised queries and the ORM.

## How to test it
Call views without a session; run the deploy check command.

## Owner dashboard settings to confirm
Host environment and database backups.

## Checks this playbook supports
SEC-010, AUTH-002, AUTH-015, API-003, API-004, DB-012, DEP-001, DEPS-002.
