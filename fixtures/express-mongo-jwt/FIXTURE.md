# Fixture: express-mongo-jwt

**Story.** Karim asked an AI assistant for "a simple Node backend with login" for ShipNote, an app where
delivery drivers attach notes and documents to shipments. The result is an Express server with MongoDB,
hand-rolled JWT sessions, file upload and a small GraphQL endpoint, shipped in a Docker container to a VPS.

**What is planted.** The JWT secret is the literal `secret`; the auth middleware uses `jwt.decode`;
passwords are hashed with MD5; there is no rate limiting on login; a magic code `123456` signs anyone in;
the reset token is predictable and returned in the response; `cors()` runs with defaults next to cookie
sessions; errors return stack traces; the download route joins a user-supplied file name into a path; a
shell command is built from the request body; uploads keep the original file name with no limits; the user
update writes the whole request body; user and webhook routes are mounted before the auth middleware; the
GitHub webhook is unsigned; the container runs as root from `node:latest`, copies everything and starts
`nodemon`. See `expected.json`.
