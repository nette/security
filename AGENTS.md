# To My Agents!

It is my fervent wish that this file guide every AI coding agent working with code in this repository.

## Documentation

Any distilled, agent-facing documentation for this package - how it works
internally and the rationale behind key design decisions - lives in `docs/`.
Consult it before non-trivial changes; it is the source of truth from which the
public manual is distilled.

Almost all the expensive-to-reconstruct knowledge is in one subsystem - the
`Permission` ACL resolution engine - plus a few `User` and storage invariants.
This is security-critical: read `docs/internals.md` before touching
authorization logic.

## Project Overview

Nette Security provides authentication (login/logout via pluggable
`Authenticator`s), authorization (role-based ACL via `Permission`), and identity
persistence (`UserStorage`: session or cookie). Standalone library. Developers
**implement the interfaces, never extend the concrete classes**.

- **PHP Version**: 8.1 - 8.5
- **Package**: `nette/security`

## Essential Commands

```bash
# Run all tests
vendor/bin/tester tests -s        # or: composer tester
vendor/bin/tester tests/Security.DI/ -s

# Static analysis (PHPStan level 8)
composer phpstan
```

## Conventions

- Every file starts with `declare(strict_types=1);`; **tabs**; single quotes unless
  the string has an apostrophe; no `Abstract`/`Interface`/`I` prefixes; Nette Coding
  Standard. Mark password parameters with `#[\SensitiveParameter]`.
- Tests are Nette Tester `.phpt` (`tests/Security/`, `tests/Security.DI/`,
  `tests/Security.Http/`) plus PHPStan type tests in `tests/types/`;
  `Permission*.phpt` holds 40+ ACL scenarios.
- Commit messages: lowercase imperative, no trailing period, `component: change`
  (e.g. `User: support for custom authenticators`).

## Working in this repo

- **`Permission` rule types are plain booleans, not an enum:** `Allow = true`,
  `Deny = false`, `All = null` (wildcard), and `getRuleType()` returns `?bool`
  (`null` = no rule). The default state is **deny-all (whitelist)**.
- **`isAllowed()` resolves along three axes:** walk the resource tree (a more
  specific resource wins over its parents) x DFS the role DAG (the **most recently
  added parent has the highest weight**) x privilege (a specific privilege before
  `allPrivileges`). For a whole-resource query (`privilege = All`), **any single
  deny vetoes** the blanket allow.
- **A failed `assert` callback makes the rule *not apply*** (falls through as if
  absent) - except on the ultimate default rule, where it returns the **inverted**
  type. Assertions receive string IDs and reach objects via
  `getQueriedRole()`/`getQueriedResource()`; `isAllowed()` saves and restores the
  queried role/resource in a `finally`, so it is re-entrant (an assertion may call
  `isAllowed()` again) and exception-safe.
- **Effective roles come from login state, not the retained identity.** After
  `logout()` the identity is kept by default (`persistIdentity`), but roles drop to
  guest - which is why `isInRole()`/`isAllowed()` need no prior `isLoggedIn()` check
  and a retained identity never leaks its privileges.
- **`loadStoredData()` runs once; `wakeupIdentity()` may return `null` to revoke
  auth** on a request (the per-request role-refresh/token seam); `sleepIdentity()`
  is its `login()`-time counterpart. **Switching the storage namespace requires
  `refreshStorage()`** or `User` serves stale authentication.
- User-facing how-to (fluent ACL API, `IdentityHandler`/guest identity, password
  hashing, NEON config, presenter integration, multiple authenticators) is manual
  material and lives in the public web docs, not here.
