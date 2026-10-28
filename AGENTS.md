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

`docs/upgrading.md` records, per released version, every change visible to
users of the package (renames, removals, deprecations, signatures, behavior,
configuration), each with its commit hash; internal changes are not in it. It
is the place to look up the history of a public symbol. Do not write to it; it
is extended at release time from the git history.

## Project Overview

Nette Security provides authentication (login/logout via pluggable
`Authenticator`s), authorization (`Voter`s, the role-based ACL `Permission` being one of them), and identity
persistence (`UserStorage`: session or cookie). Standalone library. Developers
**implement the interfaces, never extend the concrete classes**.

- **PHP Version**: 8.3 - 8.6
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

- **Voters receive a `Principal`, never the `User`:** its identity is `null` unless
  logged in, whereas `User::getId()` keeps returning the retained identity's ID
  after logout. Ownership is `hasId()` (false for a guest), never a comparison
  with an ID; `createPrincipal()` takes an identity as it is and calls no hook
  (`getPrincipal()` is built on it).
  `Principal::isAllowed()` combines the votes: one `Vote::Forbid`
  wins, else one `Vote::Allow` suffices, else not allowed. A voter that does not
  allow abstains (`Vote::allowIf()`); forbidding is always deliberate. `Permission`
  is a voter: its `vote()` ORs the roles, forbids on an explicit deny rule but
  abstains on the default deny-all, and abstains on roles and resources the ACL
  does not know, unlike the throwing `isAllowed()`.
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
  type. Assertions receive the role and resource of the matching rule (ancestors
  under inheritance), `getQueriedRole()`/`getQueriedResource()` the queried names;
  all are strings, `Role` objects are refused and a `Resource` object only maps an
  entity to a name. `isAllowed()` saves and restores the
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
