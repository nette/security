# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Nette Security is a standalone PHP library providing authentication, authorization, and role-based access control (ACL) for the Nette Framework ecosystem.

- **Type**: Reusable PHP library/package
- **PHP Support**: 8.2 - 8.5
- **Key Components**: Authentication (User login/logout), Authorization (Permission checking), ACL (Access Control Lists)
- **Documentation**: https://doc.nette.org/access-control

## Essential Commands

### Testing
```bash
# Run all tests
composer run tester

# Run specific test file
vendor/bin/tester tests/Security/User.login.phpt -s

# Run tests in specific directory
vendor/bin/tester tests/Security.DI/ -s

# Single-threaded execution (useful for debugging)
vendor/bin/tester tests -s
```

### Code Quality
```bash
# Run PHPStan static analysis
composer run phpstan
```

## Architecture Overview

### Three-Pillar Design

The library separates security concerns into three independent domains:

1. **Authentication** (`src/Security/User.php`, `Authenticator.php`)
   - User identity verification (login/logout)
   - Session management and expiration
   - Credential validation through pluggable authenticators

2. **Authorization** (`src/Security/Permission.php`, `Authorizator.php`)
   - Role-based access control
   - Resource and privilege management
   - Dynamic permission assertions

3. **Persistence** (`src/Bridges/SecurityHttp/`)
   - Session-based storage (default)
   - Cookie-based storage (alternative)
   - Custom storage implementations via `UserStorage` interface

### Interface-First Philosophy

The codebase uses interface segregation for extensibility:

- `Authenticator` → `SimpleAuthenticator` (example implementation)
- `Authorizator` → `Permission` (full ACL implementation)
- `UserStorage` → `SessionStorage`, `CookieStorage`
- `IIdentity` → `SimpleIdentity`

**Key principle**: Developers implement interfaces, never extend concrete classes.

### Directory Structure

```
src/
├── Security/                    # Core authentication/authorization
│   ├── User.php                # Central user management (250 lines)
│   ├── Permission.php          # Complete ACL implementation (600 lines)
│   ├── Passwords.php           # Password hashing utilities
│   ├── Authenticator.php       # Authentication contract
│   └── SimpleAuthenticator.php # Basic implementation for testing
│
└── Bridges/                    # Framework integration
    ├── SecurityDI/             # Dependency injection container
    ├── SecurityHttp/           # Session and cookie storage
    └── SecurityTracy/          # Debugger panel
```

## Testing Conventions

### Test File Format

Tests use Nette Tester with `.phpt` extension:

```php
<?php
declare(strict_types=1);

use Tester\Assert;

require __DIR__ . '/../bootstrap.php';

test('User login with valid credentials', function () {
	$user = new Nette\Security\User(...);
	// Test implementation
	Assert::true($user->isLoggedIn());
});
```

**Important**: Use `test()` function with descriptive title as first parameter. Do not add comments before `test()` calls.

### Testing Exceptions

Use `Assert::exception()` for expected exceptions:

```php
Assert::exception(
	fn() => $user->login('invalid', 'credentials'),
	Nette\Security\AuthenticationException::class,
	'User not found.',
);
```

For entire test blocks that should throw, use `testException()`.

### Test Organization

- **Unit tests**: `tests/Security/` - Core functionality (User, Permission, Passwords)
- **Integration tests**: `tests/Security.DI/` - DI container integration
- **Storage tests**: `tests/Security.Http/` - Session/Cookie storage
- **ACL tests**: `tests/Security/Permission*.phpt` - 30+ comprehensive ACL scenarios

## Coding Standards

### General Rules

- Every PHP file must include `declare(strict_types=1)`
- Use TABS for indentation (never spaces)
- Single quotes for strings unless containing apostrophes
- All code, comments, variables in English only
- Return type and opening brace on separate lines for methods
- No space before parentheses in arrow functions: `fn($a) => $b`

### Type Declarations

- All properties, parameters, and return values must have types
- Interface methods don't need visibility (always public)
- Use `#[\SensitiveParameter]` attribute for password parameters

### Naming Conventions

- PascalCase for classes, interfaces, constants
- camelCase for methods and properties
- Never use `Abstract`, `Interface`, or `I` prefixes

### Documentation

- Focus on describing purpose, not duplicating signature information
- Start method docs with 3rd person singular present tense verb
- Document array contents: `@return string[]`
- Use two spaces after `@param` and `@return` type declarations

Example:
```php
/**
 * Verifies user credentials against database.
 * @return SimpleIdentity  User identity with roles and metadata
 * @throws AuthenticationException
 */
public function authenticate(string $username, string $password): IIdentity
{
	// Implementation
}
```

## Important Implementation Patterns

### Identity Persistence After Logout

**Critical behavior**: Logout does NOT delete identity by default. Identity remains available for personalization even when not authenticated.

```php
$user->logout();           // Logs out but keeps identity
$user->logout(true);       // Logs out AND clears identity
$user->getIdentity();      // Still available after logout()
$user->isLoggedIn();       // false after logout()

// Check why user was logged out
$reason = $user->getLogoutReason();
if ($reason === Nette\Security\UserStorage::LogoutInactivity) {
	// User was logged out due to inactivity timeout
} elseif ($reason === Nette\Security\UserStorage::LogoutManual) {
	// User was logged out manually via logout()
}
```

### IdentityHandler Interface

Implement `IdentityHandler` to customize how identity is saved/restored from storage:

```php
final class Authenticator implements
	Nette\Security\Authenticator,
	Nette\Security\IdentityHandler
{
	public function sleepIdentity(IIdentity $identity): IIdentity
	{
		// Called before identity is written to storage
		// Useful for: replacing full identity with token-only proxy (for cookie storage)
		return new SimpleIdentity($identity->authtoken);
	}

	public function wakeupIdentity(IIdentity $identity): ?IIdentity
	{
		// Called after identity is read from storage
		// Useful for: refreshing user roles from database, validating tokens
		$userId = $identity->getId();
		$identity->setRoles($this->getUserRoles($userId));
		return $identity; // Return null to log user out
	}
}
```

**Use cases:**
- Updating user roles on each request without re-login
- Cookie-based authentication with auth tokens
- Validating session integrity

### Events: $onLoggedIn, $onLoggedOut

User object provides events for login/logout lifecycle hooks:

```php
$user->onLoggedIn[] = function (Nette\Security\User $user) {
	// Log login event, update last_login timestamp, send notification, etc.
};

$user->onLoggedOut[] = function (Nette\Security\User $user) {
	// Clear user-specific cache, log logout event, etc.
};
```

### Role Inheritance and Weight

When a role inherits from multiple parents with conflicting permissions, **last role has highest weight**:

```php
$acl->addRole('john', ['admin', 'guest']); // 'guest' wins conflicts
$acl->addRole('mary', ['guest', 'admin']); // 'admin' wins conflicts
```

### Session Namespace for Multiple Authentications

Support independent authentication contexts within single session. **Critical**: Set namespace in `checkRequirements()` of base presenter:

```php
// In BasePresenter for admin module
public function checkRequirements($element): void
{
	$this->getUser()->getStorage()->setNamespace('backend');
	parent::checkRequirements($element);
}

// In BasePresenter for frontend
public function checkRequirements($element): void
{
	$this->getUser()->getStorage()->setNamespace('frontend');
	parent::checkRequirements($element);
}
```

### Multiple Authenticators

When using different authenticators for different parts of application, restrict autowiring with `autowired: self`:

```neon
services:
	-
		create: FrontAuthenticator
		autowired: self  # Only autowire when explicitly requested
	-
		create: AdminAuthenticator
		autowired: self
```

Then inject specific authenticator and set it before login:

```php
class SignPresenter extends Nette\Application\UI\Presenter
{
	public function __construct(
		private FrontAuthenticator $authenticator,
	) {
	}

	protected function createComponentSignInForm(): Form
	{
		$form->onSuccess[] = function ($form, $data) {
			$user = $this->getUser();
			$user->setAuthenticator($this->authenticator);
			$user->login($data->username, $data->password);
		};
	}
}
```

### Dynamic Permission Assertions

Use callbacks for context-aware authorization:

```php
$assertion = function (Permission $acl, string $role, string $resource, string $privilege): bool {
	$role = $acl->getQueriedRole();       // Actual role object
	$resource = $acl->getQueriedResource(); // Actual resource object
	return $role->id === $resource->authorId; // Custom logic
};

$acl->allow('registered', 'article', 'edit', $assertion);
```

### AuthorizatorFactory Pattern

Create Permission ACL as a DI service using factory method:

```php
namespace App\Model;

class AuthorizatorFactory
{
	public static function create(): Nette\Security\Permission
	{
		$acl = new Nette\Security\Permission;

		// Define roles
		$acl->addRole('guest');
		$acl->addRole('registered', 'guest');
		$acl->addRole('admin', 'registered');

		// Define resources
		$acl->addResource('article');
		$acl->addResource('comment');

		// Define permissions
		$acl->allow('guest', ['article', 'comment'], 'view');
		$acl->allow('registered', 'comment', 'add');
		$acl->allow('admin', $acl::All, ['view', 'edit', 'add']);

		return $acl;
	}
}
```

Register in configuration:

```neon
services:
	- App\Model\AuthorizatorFactory::create
```

### Password Hashing Best Practices

The `Passwords` class handles secure password hashing with bcrypt:

```php
// Hash contains algorithm identifier, cost, and salt - store all together
$hash = $passwords->hash($password); // Store this in database (255 chars recommended)

// Verify password
if ($passwords->verify($password, $hash)) {
	// Password correct
}

// Upgrade hash when algorithm/cost changes
if ($passwords->needsRehash($hash)) {
	$newHash = $passwords->hash($password);
	// Update database with new hash
}
```

**Cost parameter** (higher = slower = more secure):
- Cost 10: ~80ms (default)
- Cost 11: ~160ms
- Cost 12: ~320ms (recommended for production)

Configure in NEON:

```neon
services:
	security.passwords: Nette\Security\Passwords(::PASSWORD_BCRYPT, [cost: 12])
```

## NEON Configuration

### Simple Authentication (Testing Only)

Define users directly in configuration using `SimpleAuthenticator`:

```neon
security:
	# Show user panel in Tracy Bar
	debugger: true  # (bool) defaults to true

	users:
		# Simple format: username: password
		johndoe: secret123

		# Extended format with roles and data
		janedoe:
			password: secret123
			roles: [admin]
			data:
				name: Jane Doe
				email: jane@example.com
```

### ACL Configuration

Define roles and resources as configuration basis for `Permission`:

```neon
security:
	roles:
		guest:
		registered: [guest]    # Inherits from guest
		admin: [registered]    # Inherits from registered

	resources:
		article:
		comment: [article]     # Inherits from article
		poll:
```

### User Storage Configuration

```neon
security:
	authentication:
		# Period of inactivity before logout
		expiration: 30 minutes

		# Storage type: session (default) or cookie
		storage: session
```

### Cookie Storage Configuration

When using `storage: cookie`, additional options are available:

```neon
security:
	authentication:
		storage: cookie
		cookieName: userId              # (string) defaults to 'userid'
		cookieDomain: 'example.com'     # (string|domain)
		cookieSamesite: Lax             # (Strict|Lax|None) defaults to Lax
```

**Important**: Cookie storage requires implementing `IdentityHandler` to store only auth token (not full identity) in cookie.

### DI Services

These services are automatically registered in the DI container:

| Service Name              | Type                         | Description                      |
|---------------------------|------------------------------|----------------------------------|
| `security.authenticator`  | `Authenticator`              | Credential verification          |
| `security.authorizator`   | `Authorizator`               | Permission checking (ACL)        |
| `security.passwords`      | `Passwords`                  | Password hashing utilities       |
| `security.user`           | `User`                       | Current user management          |
| `security.userStorage`    | `UserStorage`                | Identity persistence layer       |

Access via dependency injection:

```php
class MyService
{
	public function __construct(
		private Nette\Security\User $user,
		private Nette\Security\Passwords $passwords,
	) {
	}
}
```

## Presenter Integration Patterns

### Verify Login in Presenters

Use `startup()` method to enforce authentication:

```php
protected function startup()
{
	parent::startup();
	if (!$this->getUser()->isLoggedIn()) {
		$this->redirect('Sign:in');
	}
}
```

### Verify Permissions in Presenters

Use `startup()` method to enforce authorization:

```php
protected function startup()
{
	parent::startup();
	if (!$this->getUser()->isAllowed('backend')) {
		$this->error('Forbidden', 403);
	}
}
```

**"Less Code, More Security" Principle**: When checking roles with `isInRole()`, you don't need to verify `isLoggedIn()` first. The method automatically works with effective roles: logged-in users get their assigned roles, logged-out users automatically get the special `guest` role. This reduces boilerplate while maintaining security:

```php
// GOOD: Simple and secure
if ($user->isInRole('admin')) {
	deleteItem();
}

// BAD: Unnecessary verbosity
if ($user->isLoggedIn() && $user->isInRole('admin')) {
	deleteItem();
}
```

### Set Session Namespace for Module

Use `checkRequirements()` in BasePresenter:

```php
public function checkRequirements($element): void
{
	$this->getUser()->getStorage()->setNamespace('backend');
	parent::checkRequirements($element);
}
```

## Common Pitfalls

1. **Don't check isLoggedIn() before isInRole()** - `isInRole()` handles logged-out users with automatic 'guest' role
2. **Don't assume logout() clears identity** - Use `logout(true)` if you need to clear identity
3. **Remember ACL inheritance order** - Last parent role has highest weight in conflicts
4. **Session expiration must be ≤ session lifetime** - Set with `$user->setExpiration('30 minutes')`
5. **Password hash storage needs 255 chars** - Hash contains algorithm, cost, and salt; use VARCHAR(255) or TEXT
6. **Cookie storage requires IdentityHandler** - Never store full identity in cookie, only auth token
7. **Don't use SimpleAuthenticator in production** - It's for testing only; implement custom Authenticator with database
8. **Update hashes when algorithm changes** - Use `needsRehash()` to detect and upgrade old hashes on login

## Commit Message Style

- Lowercase, imperative mood
- No period at end
- Format: `component: change description` or direct action
- Examples: `User: support for custom authenticators`, `fixed session expiration handling`

## CI/CD Pipeline

GitHub Actions run on all pull requests:
- Tests across PHP 8.2, 8.3, 8.4, 8.5
- Code style checks (Nette Code Checker)
- Static analysis (PHPStan Level 5)
- Code coverage tracking
