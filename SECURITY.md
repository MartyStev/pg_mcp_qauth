# Security Policy

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

This project is an authorization boundary for a database — security issues are taken
seriously. Report them privately instead:

- Use GitHub's **"Report a vulnerability"** (private security advisory) on this repository, or
- Email the maintainer at the address in your fork/repo settings.

Include: a description of the issue, reproduction steps, affected version, and any
suggested fix. You can expect an initial acknowledgement within **72 hours** and
follow-up as the fix progresses. Please give us a reasonable window to patch before
public disclosure.

## Scope

Areas of particular interest:

- JWT validation (signature, `iss`, `aud`, `exp`, algorithm pinning)
- SQL guard bypasses (statements that mutate data or read system catalogs / files)
- Role resolution and `SET LOCAL ROLE` / RLS session-variable handling
- Connection-pool state leakage between requests

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| < 0.2   | :x:                |

## Hardening Notes for Deployers

The SQL guard's function denylist is defense-in-depth, not the primary control. The
primary guarantees come from Postgres itself. When deploying:

- Run the pool user (`PG_USER`) as a **non-superuser, non-owner** of the data tables.
- Grant only `SELECT` (and `USAGE` on the needed schemas) to the target roles.
- Enable **RLS** with `FORCE ROW LEVEL SECURITY` on sensitive tables.
- `REVOKE EXECUTE` on dangerous functions (`pg_read_file`, `lo_import`, `pg_sleep*`, …)
  from `PUBLIC` and the target roles.

See `README.md` → "Defense in depth" (or `README.ru.md` → "Защита в глубине") for details.
