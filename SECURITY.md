# Security Policy

GuardianAI is intended for authorised security evaluation of AI workflows and integrations you own or are explicitly permitted to test.

## Safety Controls

- Credential-like keys (api key, secret, token, password, credential, authorization, private key) are redacted before workflow snapshots are stored or model context is built.
- The CLI blocks live execution unless `--confirm-side-effects` is passed or `GUARDIAN_ALLOW_SIDE_EFFECTS=true` is set.
- The web dashboard executes scenarios with side effects confirmed automatically. Run it only against a test environment.
- Live database inspection (`database.enabled`) is read-only and limited to the tables you list, with a bounded number of sample rows.
- When `GUARDIAN_DB_URL` is set, Guardian also writes a small marker to a dedicated control table (`guardian_active_session`) and reads the workflow's tool-call log to judge results. It does not write to business tables.
- Use a test database and test integrations for any workflow that can write data, send messages or call external services.

## Sensitive Data

Do not commit API keys, access tokens, passwords, database credentials, `.env` files, run output (`runs/`), local databases, or production customer data.

Use `.env.example` for placeholder values only.
