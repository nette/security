# Security internals

How `nette/security` works underneath, for agents editing it. Almost all the
expensive-to-reconstruct knowledge lives in one subsystem — the `Permission` ACL
resolution engine — so this is one file, weighted heavily toward it. `User`,
`Authenticator`, `Identity`, and `UserStorage` are mostly readable from their
signatures; only a few of their invariants are captured here.

## Rule encoding: booleans and null, not an enum

Three constants (`Authorizator`) permeate every branch and are easy to
misread:

- `All = null` — the "any role / any resource / any privilege" wildcard.
- `Allow = true`, `Deny = false` — rule **types are plain booleans**.

Consequently the internal `getRuleType()` returns **`?bool`**: `null` = "no rule
found", `true` = allow, `false` = deny. The **default state is deny-all**: the
root rule (`$rules['allResources']['allRoles']['allPrivileges']`) is seeded to
`Deny`, so an ACL with no rules denies everything (whitelist model).

## `$rules`: a three-axis nested map with string keys

The entire ACL state is one nested array (`Permission::$rules`) indexed on
three specificity axes:

```
byResource[<res>] | allResources        (resource axis)
  → byRole[<role>] | allRoles           (role axis)
    → byPrivilege[<priv>] | allPrivileges   (privilege axis)
      → { type: Allow|Deny, assert: ?callable }
```

`getRules($resource, $role, $create)` navigates the first two axes **by
reference** (so callers mutate in place). The `all*` string keys are magic
sentinels that cannot collide with user IDs: user-supplied names live one level
deeper, under the sibling `byResource`/`byRole`/`byPrivilege` subarrays, so even
a role literally named `allRoles` lands in `byRole['allRoles']`. Roles and
resources are stored as **string IDs**; the
`Role`/`Resource` objects passed to `isAllowed()` are reduced to IDs immediately.

## `isAllowed()`: the resolution algorithm (the emergent model)

This is what you can only get by tracing. `isAllowed()` resolves a
`(role, resource, privilege)` query by two nested traversals:

1. **Resource axis — walk up the resource tree.** Starting at the queried
   resource, search the role DAG (step 2); if undecided, consult the `allRoles`
   pseudo-parent at this resource; then move to the resource's parent
   (`resources[$resource]['parent']`) and repeat, ending at `allResources`.
   **More specific resources win over their parents.**
2. **Role axis — DFS over the role DAG** (`searchRolePrivileges`). A
   stack-based depth-first search from the queried role up through parents. Since
   parents are pushed in insertion order and popped last-first, **the most
   recently added parent has the highest weight** (`addRole('x', ['a','b'])` → `b`
   wins conflicts). A `$visited` set guards the DAG against diamond re-checks.
3. **Privilege axis — specific before general.** For any (resource, role) pair,
   a rule on the exact `$privilege` is consulted before the `allPrivileges` rule.

**Deny wins for whole-resource queries.** When the privilege is `All` (asking
"may this role do *anything* here"), the search scans every `byPrivilege` rule
and returns `Deny` if **any** of them denies, before falling back to the
`allPrivileges` rule. A single specific deny vetoes the blanket allow.

The first definitive `Allow`/`Deny` found in this order is returned; if the whole
traversal finds nothing, the deny-all root answers.

## Assertions: conditional rules, an inverted default, and queried-state lifetime

A rule may carry an `assert` callback. In `getRuleType()`:

- If the assertion returns **false, the rule does not apply** — it yields `null`
  and resolution falls through to the next candidate, exactly as if the rule were
  absent. This is the trap for anyone reading only static rules: a present rule
  can be silently skipped at query time.
- **The one exception is the ultimate default rule** (all resources, all roles,
  all privileges). A failed assertion there has nothing left to fall back to, so
  it returns the **inverted** type (`Allow`→`Deny`, `Deny`→`Allow`) to force a
  definite answer.
- Assertions receive **string IDs**, not objects. To reach the actual queried
  object they call `getQueriedRole()` / `getQueriedResource()`, which return
  whatever was passed to `isAllowed()`.
- `isAllowed()` stores the queried role/resource in object state and
  unconditionally **nulls both on normal return**. There is **no save/restore
  and no `finally`**: a nested `isAllowed()` call from inside an assertion
  clobbers the queried state and leaves it `null` for the rest of the outer
  assertion, and an exception mid-query (unknown role/resource) leaves stale
  values behind. An assertion must read `getQueriedRole()`/`getQueriedResource()`
  **before** recursing into `isAllowed()`.

## User: effective roles come from login state, not the retained identity

`User` is a thin facade over `UserStorage` + an `Authenticator`/`Authorizator`.
The few non-obvious invariants:

- **Effective roles track the login state, not the identity object**
  (`getRoles()`). Logged in → the identity's roles (or `authenticatedRole`);
  **not** logged in → the guest identity's roles or `[guestRole]`. So after
  `logout()`, even though the identity is **retained** by default
  (`persistIdentity`), the user drops to guest roles. This is why
  `isInRole()`/`isAllowed()` need no prior `isLoggedIn()` check — and why a
  retained identity never leaks its privileges.
- **State is loaded lazily once, and can be vetoed on load.**
  `loadStoredData()` runs a single time (guarded by `$authenticated !== null`),
  reads the storage state, and — if the authenticator is an `IdentityHandler` —
  passes the stored identity through **`wakeupIdentity()`, which may return
  `null` to revoke authentication** on this request. `wakeupIdentity` is the
  per-request role-refresh / token-revalidation seam; `sleepIdentity` is its
  counterpart at `login()` time (e.g. storing only a token for cookie storage).
- **`refreshStorage()` discards the cached state.** Switching the storage
  **namespace** (multiple independent logins per session) without calling
  `refreshStorage()` leaves `User` serving stale authentication.
- **Guest identity is resolved on read only and never written to storage**;
  its resolution is cached and invalidated by `setAuthenticator`/`refreshStorage`.
  It comes from `getGuestIdentity()` on the `IdentityHandler` authenticator — an
  **optional** method declared only as `@method` phpDoc and detected via
  `method_exists`, not part of the interface proper.
- **`User::isAllowed()` is a disjunction over effective roles**: the user
  is allowed if **any single** of their roles is allowed — a deny resolved for
  one role never vetoes another role's allow. Single-role resolution lives in
  `Permission`; the multi-role OR lives only here. This is the opposite polarity
  of the deny-veto inside a whole-resource query, which applies per role.

## Storages: session and cookie are not interchangeable

`UserStorage::getState()` returns the tuple `[authenticated, identity,
logoutReason]`; everything else differs between the two implementations:

- **`SessionStorage` checks expiration lazily and it slides.** The check runs in
  `getSessionSection()` on first access: expired → `LogoutInactivity` (and the
  identity is dropped only if `expireIdentity` was set); not expired →
  `expireTime` is pushed forward by `expireDelta` (sliding window). Both
  `saveAuthentication()` **and** `clearAuthentication()` regenerate the session
  ID (session-fixation defence) — login/logout mutate the whole session, not just
  the `Nette.Http.UserStorage/<namespace>` section. `setNamespace()` drops the
  cached section; the `User`-side counterpart it needs is `refreshStorage()`.
- **`CookieStorage` stores only `$identity->getId()`** and requires it to be at
  least 13 chars — i.e. a random token, never a database ID. `getState()`
  reconstructs a bare `SimpleIdentity` (no roles, no data), so cookie storage is
  usable only with an `IdentityHandler`: `sleepIdentity()` returns the token
  identity, `wakeupIdentity()` resolves it back to the real one.
  `clearAuthentication()` **ignores `$clearIdentity`** — the cookie is always
  deleted, so **`persistIdentity` has no effect with cookie storage**.
- In the DI bridge (`SecurityExtension`), `cookieDomain: 'domain'` is a magic
  literal resolved at runtime to the request's second-level domain.

## Legacy seams and BC constraints

- **`User::login()` branches on `instanceof Authenticator`**: the modern
  interface gets `authenticate($username, $password)`, the deprecated
  `IAuthenticator` gets a single credentials array. `IAuthenticator::authenticate()`
  exists only as a commented-out declaration plus `@method` phpDoc — PHP does not
  enforce it, which is why `phpstan.neon` carries an ignore for `User.php`.
- `compatibility.php` `class_alias`es the removed `IAuthorizator`/`IResource`/`IRole`
  names and is excluded from PHPStan analysis.
- **`SimpleIdentity extends Identity` — the deprecated class is the parent**,
  kept so identities serialized in existing sessions keep unserializing. Don't
  flip the hierarchy or remove `Identity`.
- `Identity::setId()` normalizes numeric strings to int only when the round-trip
  is lossless (`'123'` → `123`; `'0123'` stays a string).

## Navigation map

| Concern | Where |
|---|---|
| Rule constants, `?bool` typing | `Authorizator`, `Permission::getRuleType` |
| ACL state shape | `Permission::$rules`, `getRules` |
| Resolution order (resource × role × privilege) | `Permission::isAllowed`, `searchRolePrivileges` |
| Assertions, queried role/resource | `Permission::getRuleType`, `getQueriedRole`/`getQueriedResource` |
| Effective roles, login state, multi-role OR | `User::getRoles`, `isInRole`, `isAllowed` |
| Identity lifecycle, veto, seams | `User::loadStoredData`, `login`/`logout`, `IdentityHandler` |
| Sliding expiration, fixation defence, namespaces | `SessionStorage` |
| Token-only persistence, `persistIdentity` no-op | `CookieStorage` |
| Legacy authenticator dispatch, BC aliases | `User::login`, `IAuthenticator`, `compatibility.php` |
