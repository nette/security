# Upgrading nette/security

## 3.2.6

- **Changed** `Nette\Security\Permission::getQueriedRole()` now returns `null` when called before the first `Nette\Security\Permission::isAllowed()` call; previously it threw an `Error` about an uninitialized property (676e4c0d)
- **Changed** `Nette\Security\Permission::getQueriedResource()` now returns `null` when called before the first `Nette\Security\Permission::isAllowed()` call; previously it threw an `Error` about an uninitialized property (676e4c0d)
- **Changed** `Nette\Security\SimpleAuthenticator::verifyPassword()` now verifies a stored password that matches the crypt format (`$ident$` followed by 20 or more characters) with `password_verify()`; previously every stored password was compared literally, so a plain-text password of that shape no longer authenticates (6cad44db)

## 3.2.5

- **Changed** `Nette\Security\Identity::setId()` now converts to int only a string of plain digits without a leading zero; a numeric string with a sign, decimal point, whitespace or exponent stays a string; also affects `Nette\Security\SimpleIdentity`, which inherits the method (50ce3c4b)

## 3.2.3

- **Signature** `Nette\Security\User::setExpiration()` now declares the return type `static`; affects subclasses overriding it (25091e96)
- **Signature** `Nette\Security\Identity::__construct()`: `$id` is now typed `string|int` and `$roles` `string|array|null`; another type throws `TypeError` (25091e96, cf89e178)
- **Changed** `Nette\Security\User::getRoles()` now returns an empty array when the identity returns no roles; previously it fell back to `Nette\Security\User::$authenticatedRole` (25091e96)

## 3.2.1

- **Renamed** `$user` → `$username` of `Nette\Security\Authenticator::authenticate()`; the old name was removed; affects named arguments and implementations (6e19bf60)
- **Renamed** `$user` → `$username` of `Nette\Security\User::login()`; the old name was removed; affects named arguments (6e19bf60)

## 3.2.0

- **Removed** `Nette\Security\IUserStorage` (deprecated since 3.1.0): implement `Nette\Security\UserStorage`; the old name was removed (590b965c)
- **Removed** `Nette\Security\IUserStorage::CLEAR_IDENTITY`: pass `true` as the second argument of `Nette\Security\User::setExpiration()` (590b965c)
- **Replaced** `Nette\Security\IUserStorage::isAuthenticated()` with `Nette\Security\UserStorage::getState()`, which returns `[bool $authenticated, ?Nette\Security\IIdentity $identity, ?int $logoutReason]` (590b965c)
- **Replaced** `Nette\Security\IUserStorage::getIdentity()` with `Nette\Security\UserStorage::getState()`, which returns `[bool $authenticated, ?Nette\Security\IIdentity $identity, ?int $logoutReason]` (590b965c)
- **Replaced** `Nette\Security\IUserStorage::getLogoutReason()` with `Nette\Security\UserStorage::getState()`, which returns `[bool $authenticated, ?Nette\Security\IIdentity $identity, ?int $logoutReason]` (590b965c)
- **Replaced** `Nette\Security\IUserStorage::setAuthenticated()` with `Nette\Security\UserStorage::saveAuthentication()` and `Nette\Security\UserStorage::clearAuthentication()`, which store the identity and the authenticated flag in one call (590b965c)
- **Replaced** `Nette\Security\IUserStorage::setIdentity()` with `Nette\Security\UserStorage::saveAuthentication()`, which stores the identity and the authenticated flag in one call (590b965c)
- **Replaced** `Nette\Security\IUserStorage::setExpiration()` with `Nette\Security\UserStorage::setExpiration()`, whose second parameter is a plain `bool $clearIdentity` instead of a bit flag (590b965c)
- **Renamed** `Nette\Security\IUserStorage::MANUAL` → `Nette\Security\User::LogoutManual`; the old name was removed (590b965c)
- **Renamed** `Nette\Security\IUserStorage::INACTIVITY` → `Nette\Security\User::LogoutInactivity`; the old name was removed (590b965c)
- **Renamed** `Nette\Security\UserStorage::LogoutManual` → `Nette\Security\User::LogoutManual`; the old name was removed (151890b8)
- **Renamed** `Nette\Security\UserStorage::LogoutInactivity` → `Nette\Security\User::LogoutInactivity`; the old name was removed (151890b8)
- **Deprecated** `Nette\Security\Authenticator::IDENTITY_NOT_FOUND`: use `Nette\Security\Authenticator::IdentityNotFound` (alias since 3.1.8); the old name is silently deprecated (fe89d526)
- **Deprecated** `Nette\Security\Authenticator::INVALID_CREDENTIAL`: use `Nette\Security\Authenticator::InvalidCredential` (alias since 3.1.8); the old name is silently deprecated (fe89d526)
- **Deprecated** `Nette\Security\Authenticator::FAILURE`: use `Nette\Security\Authenticator::Failure` (alias since 3.1.8); the old name is silently deprecated (fe89d526)
- **Deprecated** `Nette\Security\Authenticator::NOT_APPROVED`: use `Nette\Security\Authenticator::NotApproved` (alias since 3.1.8); the old name is silently deprecated (fe89d526)
- **Deprecated** `Nette\Security\Authorizator::ALL`: use `Nette\Security\Authorizator::All` (alias since 3.1.8); the old name is silently deprecated (fe89d526)
- **Deprecated** `Nette\Security\Authorizator::ALLOW`: use `Nette\Security\Authorizator::Allow` (alias since 3.1.8); the old name is silently deprecated (fe89d526)
- **Deprecated** `Nette\Security\Authorizator::DENY`: use `Nette\Security\Authorizator::Deny` (alias since 3.1.8); the old name is silently deprecated (fe89d526)
- **Deprecated** `Nette\Security\User::LOGOUT_MANUAL`: use `Nette\Security\User::LogoutManual` (alias since 3.1.8); the old name is silently deprecated (fe89d526)
- **Deprecated** `Nette\Security\User::LOGOUT_INACTIVITY`: use `Nette\Security\User::LogoutInactivity` (alias since 3.1.8); the old name is silently deprecated (fe89d526)
- **Deprecated** `Nette\Security\UserStorage::LOGOUT_MANUAL`: use `Nette\Security\User::LogoutManual`; the old name is silently deprecated (151890b8)
- **Deprecated** `Nette\Security\UserStorage::LOGOUT_INACTIVITY`: use `Nette\Security\User::LogoutInactivity`; the old name is silently deprecated (151890b8)
- **Signature** `Nette\Security\User::getAuthenticator()`: the deprecated `$throw` parameter was removed and the return type is no longer nullable, so the method always throws when no authenticator is set; use `Nette\Security\User::getAuthenticatorIfExists()` to get `null` (b87b3e7c)
- **Signature** `Nette\Security\User::getAuthorizator()`: the deprecated `$throw` parameter was removed and the return type is no longer nullable, so the method always throws when no authorizator is set; use `Nette\Security\User::getAuthorizatorIfExists()` to get `null` (b87b3e7c)
- **Signature** `Nette\Security\User::__construct()`: the first parameter is now a required `Nette\Security\UserStorage $storage`; the former `$legacyStorage` and the former fourth parameter `$storage` are gone (590b965c)
- **Signature** `Nette\Security\User::getStorage()` now declares the return type `Nette\Security\UserStorage`; previously it declared none and could return an `Nette\Security\IUserStorage` (590b965c)
- **Signature** `Nette\Security\User::setExpiration()`: `$expire` is typed `?string` and `$clearIdentity` is a `bool` defaulting to `false`; previously it also accepted an int flag and `null` (590b965c)
- **Signature** `Nette\Security\Authorizator::isAllowed()`: all three parameters are now typed `?string`; affects every implementation of the interface (e843379f)
- **Signature** `Nette\Security\Permission::setRule()` now returns `void`; previously it returned `$this` and could be chained; affects subclasses overriding it (e843379f)
- **Signature** native PHP 8 types were added throughout the package; affects implementations, subclasses overriding a member and callers passing `null`: `Nette\Security\Passwords::__construct()`, `Nette\Security\Permission::addRole()`, `Nette\Security\Permission::addResource()`, `Nette\Security\Permission::allow()`, `Nette\Security\Permission::deny()`, `Nette\Security\Permission::removeAllow()`, `Nette\Security\Permission::removeDeny()`, `Nette\Security\Permission::isAllowed()`, `Nette\Security\User::login()`, `Nette\Security\User::setAuthenticator()`, `Nette\Security\User::setAuthorizator()`, `Nette\Security\User::$guestRole`, `Nette\Security\User::$authenticatedRole`, `Nette\Security\User::$onLoggedIn`, `Nette\Security\User::$onLoggedOut`, `Nette\Security\Identity::setId()`, `Nette\Security\Identity::setRoles()` (e843379f, dc329d35)
- **Changed** `Nette\Security\User::setExpiration()` now silently ignores a third argument; previously it was merged into `$clearIdentity` and triggered `E_USER_DEPRECATED` (b87b3e7c)
- **Changed** `Nette\Security\User::setExpiration()` now throws `TypeError` when `$expire` is neither a string nor `null`; previously it only triggered `E_USER_DEPRECATED` (e843379f)
- **Changed** `Nette\Security\Passwords`, `Nette\Security\Permission`, `Nette\Security\SimpleAuthenticator`, `Nette\Security\Identity`, `Nette\Bridges\SecurityHttp\SessionStorage`, `Nette\Bridges\SecurityHttp\CookieStorage` and `Nette\Bridges\SecurityTracy\UserPanel` no longer use `Nette\SmartObject`; access to an undefined member raises a plain PHP error instead of `Nette\MemberAccessException` (0e93577e)

## 3.1.8

- **Renamed** `Nette\Security\Authenticator::IDENTITY_NOT_FOUND` → `Nette\Security\Authenticator::IdentityNotFound`; the old name still works as an alias (caadca87)
- **Renamed** `Nette\Security\Authenticator::INVALID_CREDENTIAL` → `Nette\Security\Authenticator::InvalidCredential`; the old name still works as an alias (caadca87)
- **Renamed** `Nette\Security\Authenticator::FAILURE` → `Nette\Security\Authenticator::Failure`; the old name still works as an alias (caadca87)
- **Renamed** `Nette\Security\Authenticator::NOT_APPROVED` → `Nette\Security\Authenticator::NotApproved`; the old name still works as an alias (caadca87)
- **Renamed** `Nette\Security\Authorizator::ALL` → `Nette\Security\Authorizator::All`; the old name still works as an alias (caadca87)
- **Renamed** `Nette\Security\Authorizator::ALLOW` → `Nette\Security\Authorizator::Allow`; the old name still works as an alias (caadca87)
- **Renamed** `Nette\Security\Authorizator::DENY` → `Nette\Security\Authorizator::Deny`; the old name still works as an alias (caadca87)
- **Renamed** `Nette\Security\User::LOGOUT_MANUAL` → `Nette\Security\User::LogoutManual`; the old name still works as an alias (caadca87)
- **Renamed** `Nette\Security\User::LOGOUT_INACTIVITY` → `Nette\Security\User::LogoutInactivity`; the old name still works as an alias (caadca87)
- **Renamed** `Nette\Security\UserStorage::LOGOUT_MANUAL` → `Nette\Security\UserStorage::LogoutManual`; the old name still works as an alias (caadca87)
- **Renamed** `Nette\Security\UserStorage::LOGOUT_INACTIVITY` → `Nette\Security\UserStorage::LogoutInactivity`; the old name still works as an alias (caadca87)

## 3.1.6

- **Renamed** `$userlist` → `$passwords` of `Nette\Security\SimpleAuthenticator::__construct()`; the old name was removed; affects named arguments (3562c803)
- **Renamed** `$usersRoles` → `$roles` of `Nette\Security\SimpleAuthenticator::__construct()`; the old name was removed; affects named arguments (3562c803)
- **Renamed** `$usersData` → `$data` of `Nette\Security\SimpleAuthenticator::__construct()`; the old name was removed; affects named arguments (3562c803)
- **Signature** `Nette\Security\SimpleAuthenticator::authenticate()`: `$username` is typed `string` and `$password` is required; the `array $credentials` call form was removed and no longer triggers `E_USER_DEPRECATED`, it throws `TypeError` (ec010e7d)

## 3.1.4

- **Renamed** `Nette\Security\User::MANUAL` → `Nette\Security\User::LOGOUT_MANUAL`; the old name is silently deprecated (9127bfef)
- **Renamed** `Nette\Security\User::INACTIVITY` → `Nette\Security\User::LOGOUT_INACTIVITY`; the old name is silently deprecated (9127bfef)
- **Signature** `Nette\Security\User::setExpiration()`: the second parameter is now `$clearIdentity` and takes a bool; pass `true` instead of `Nette\Security\IUserStorage::CLEAR_IDENTITY`; the named argument `flags:` no longer exists (6e23b318)

## 3.1.3

- **Changed** `Nette\Bridges\SecurityHttp\CookieStorage::saveAuthentication()` now throws `LogicException` when the identity id is shorter than 13 characters; previously it stored the cookie (d7d9beec)
- **Changed** `Nette\Bridges\SecurityHttp\CookieStorage::getState()` now reports an unauthenticated state for a cookie shorter than 13 characters; previously it restored the identity (d7d9beec)
- **Changed** `Nette\Security\User::$onLoggedOut` handlers are invoked after the state is cleared, so `Nette\Security\User::isLoggedIn()` returns `false` inside them; previously it returned `true` (817ee98a)
- **Changed** `Nette\Security\User::login()` now forwards all its arguments to `Nette\Security\Authenticator::authenticate()`; previously only the user name and the password were passed (5d68727d)
- **Changed** `Nette\Security\User::$onLoggedIn` now defaults to `[]` and is invoked through `Nette\Utils\Arrays::invoke()`; assigning `null` to it previously did nothing and now throws `TypeError` when the event fires (12df4f17)
- **Changed** `Nette\Security\User::$onLoggedOut` now defaults to `[]` and is invoked through `Nette\Utils\Arrays::invoke()`; assigning `null` to it previously did nothing and now throws `TypeError` when the event fires (12df4f17)

## 3.1.2

- **Config** `security.userStorage` is now a `Nette\Security\UserStorage` service created by `Nette\Bridges\SecurityHttp\SessionStorage`; the previous service of type `Nette\Security\IUserStorage` backed by `Nette\Http\UserStorage` moved to `security.legacyUserStorage` (3537b70e)

## 3.1.0

- **Removed** `Nette\Security\IAuthenticator::authenticate()`: implement `Nette\Security\Authenticator::authenticate()`; the declaration remains on the old interface only as a `@method` annotation (5db5f804)
- **Removed** `Nette\Security\Passwords::hash()` in its static v2.x call form taking `$options`: create an instance and pass the algorithm and the options to the constructor (a602c887)
- **Removed** `Nette\Security\Passwords::needsRehash()` in its static v2.x call form taking `$options`: create an instance and pass the algorithm and the options to the constructor (a602c887)
- **Replaced** `Nette\Security\IAuthenticator` with `Nette\Security\Authenticator`: implement `authenticate(string $user, string $password)` instead of `authenticate(array $credentials)`; the old interface is silently deprecated (5db5f804)
- **Replaced** `Nette\Security\IUserStorage` with `Nette\Security\UserStorage`: implement `saveAuthentication()`, `clearAuthentication()`, `getState()` and `setExpiration()` instead of `setIdentity()`, `getIdentity()`, `setAuthenticated()`, `isAuthenticated()` and `getLogoutReason()`; the old interface is silently deprecated (9986f15d)
- **Renamed** `Nette\Security\IAuthorizator` → `Nette\Security\Authorizator`; the old name still works as an alias (3f209f10)
- **Renamed** `Nette\Security\IResource` → `Nette\Security\Resource`; the old name still works as an alias (3f209f10)
- **Renamed** `Nette\Security\IRole` → `Nette\Security\Role`; the old name still works as an alias (3f209f10)
- **Renamed** `Nette\Security\Identity` → `Nette\Security\SimpleIdentity`; the old name is silently deprecated (e13731cc)
- **Deprecated** `security.roles`: build the `Nette\Security\Authorizator` service yourself; using the key triggers `E_USER_DEPRECATED` (cbd4e8c3)
- **Deprecated** `security.resources`: build the `Nette\Security\Authorizator` service yourself; using the key triggers `E_USER_DEPRECATED` (cbd4e8c3)
- **Signature** `Nette\Security\SimpleAuthenticator::authenticate()` takes `string $username, string $password` instead of `array $credentials`; the array form still works but triggers `E_USER_DEPRECATED` (7491dd1e)
- **Signature** `Nette\Security\User::__construct()`: the first parameter is now the optional `$legacyStorage` for a legacy `Nette\Security\IUserStorage` and a `Nette\Security\UserStorage` is passed as the fourth parameter `$storage`; with neither the constructor throws `Nette\InvalidStateException` (9986f15d)
- **Signature** `Nette\Security\User::getStorage()` no longer declares a return type; it returns a `Nette\Security\UserStorage` or an `Nette\Security\IUserStorage` depending on the configured storage (9986f15d)
- **Changed** `Nette\Security\Identity::setId()` now throws `Nette\InvalidArgumentException` when the id is neither a string nor an int; previously any type was accepted (ff9770d8)

## 3.0.5

- **Config** `security.debugger`: when the key is not set, the panel is registered according to the presence of a `Tracy\Bar` service in the container; previously it followed whether `Tracy\IBarPanel` was available (248ac3a6)

## 3.0.2

- **Deprecated** `Nette\Security\User::hasAuthenticator()`: use `Nette\Security\User::getAuthenticatorIfExists() !== null`; the old name is silently deprecated (f18cf84a)
- **Deprecated** `Nette\Security\User::hasAuthorizator()`: use `Nette\Security\User::getAuthorizatorIfExists() !== null`; the old name is silently deprecated (f18cf84a)

## 3.0.1

- **Removed** `Nette\Security\IUserStorage::BROWSER_CLOSED`: there is no replacement (0cab335e)
- **Removed** `Nette\Security\User::BROWSER_CLOSED`: there is no replacement (0cab335e)
- **Removed** `Nette\Security\Passwords::BCRYPT_COST`: pass the cost in the constructor options (0cab335e)
- **Replaced** `Nette\Security\Passwords::hash()` with an instance method: construct `Nette\Security\Passwords` with the algorithm and the options and call `hash($password)`; the method is no longer static and no longer takes `$options` (e0da0108)
- **Replaced** `Nette\Security\Passwords::needsRehash()` with an instance method: construct `Nette\Security\Passwords` with the algorithm and the options and call `needsRehash($hash)`; the method is no longer static and no longer takes `$options` (e0da0108)
- **Replaced** `Nette\Security\Passwords::verify()` with an instance method: construct `Nette\Security\Passwords` and call `verify($password, $hash)`; the method is no longer static (e0da0108)
- **Signature** `Nette\Security\IAuthenticator::authenticate()` now declares the return type `Nette\Security\IIdentity`; affects every implementation, which may no longer return `null` (84024f61)
- **Signature** `Nette\Security\IUserStorage::setExpiration()`: the first parameter was renamed from `$time` to `$expire` and is typed `?string`; affects implementations and named arguments (1d69f824)
- **Signature** `Nette\Security\IUserStorage::setIdentity()`: `$identity` is typed `?Nette\Security\IIdentity` and lost its default value; affects implementations (84024f61)
- **Signature** `Nette\Security\Identity::__construct()`: `$data` is typed `iterable`; another type throws `TypeError` (84024f61)
- **Signature** `Nette\Security\User::login()`: the first parameter is required and `$password` is typed `string`; previously both defaulted to `null` (5c4065cb)
- **Signature** `Nette\Security\User::getAuthenticator()`: the `$throw` parameter was removed and the return type is `?Nette\Security\IAuthenticator`; passing an argument triggers `E_USER_DEPRECATED`; use `Nette\Security\User::hasAuthenticator()` to test for a handler (e041dca8)
- **Signature** `Nette\Security\User::getAuthorizator()`: the `$throw` parameter was removed and the return type is `?Nette\Security\IAuthorizator`; passing an argument triggers `E_USER_DEPRECATED`; use `Nette\Security\User::hasAuthorizator()` to test for a handler (e041dca8)
- **Signature** `Nette\Security\User::setExpiration()`: the third parameter `$clearIdentity` was removed and the second parameter `$flags` must be an int; pass `Nette\Security\IUserStorage::CLEAR_IDENTITY` instead of `true` (84ada184)
- **Signature** `Nette\Security\User::getAuthenticator()`, `Nette\Security\User::getAuthorizator()`, `Nette\Security\User::getIdentity()`, `Nette\Security\User::getLogoutReason()`, `Nette\Security\User::getStorage()`, `Nette\Security\User::isInRole()`, `Nette\Security\User::isLoggedIn()` and `Nette\Security\User::logout()` are now `final`; affects subclasses overriding them (c7cc80bb)
- **Signature** native PHP 7.1 scalar and return types were added throughout the package; affects implementations, subclasses overriding a member and callers passing `null`: `Nette\Security\IAuthorizator::isAllowed()`, `Nette\Security\IIdentity::getRoles()`, `Nette\Security\IResource::getResourceId()`, `Nette\Security\IRole::getRoleId()`, `Nette\Security\IUserStorage::getIdentity()`, `Nette\Security\IUserStorage::isAuthenticated()`, `Nette\Security\IUserStorage::setAuthenticated()`, `Nette\Security\IUserStorage::getLogoutReason()`, `Nette\Security\Identity::__get()`, `Nette\Security\Identity::__set()`, `Nette\Security\Identity::__isset()`, `Nette\Security\Permission::addRole()`, `Nette\Security\Permission::addResource()`, `Nette\Security\Permission::allow()`, `Nette\Security\Permission::deny()`, `Nette\Security\Permission::setRule()`, `Nette\Security\Permission::roleInheritsFrom()`, `Nette\Security\Permission::resourceInheritsFrom()`, `Nette\Security\User::isInRole()`, `Nette\Bridges\SecurityTracy\UserPanel::getTab()`, `Nette\Bridges\SecurityTracy\UserPanel::getPanel()` (84024f61)
- **Changed** `Nette\Security\User::setExpiration()` triggers `E_USER_DEPRECATED` when `$expire` is neither a string nor `null`; previously any type was accepted (5c4065cb)
- **Changed** `Nette\Security\Passwords` now hashes with `PASSWORD_DEFAULT`; previously it always used bcrypt, so the resulting hash may be longer than 60 characters and the database column may need widening; pass `PASSWORD_BCRYPT` to the constructor to keep the previous algorithm (7c6b5d71)
- **Changed** `Nette\Security\Passwords::hash()` reports an out-of-range `cost` option with the `Nette\InvalidStateException` raised from `password_hash()`; previously it checked the range itself and threw `Nette\InvalidArgumentException` (e0da0108)
- **Config** `security.debugger` defaults to whether `Tracy\IBarPanel` is available; previously it defaulted to `true`, so without Tracy installed the panel is no longer registered (a07f0133)
