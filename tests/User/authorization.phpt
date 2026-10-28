<?php declare(strict_types=1);

/**
 * Test: Nette\Security\User authorization.
 */

use Nette\Security\{IIdentity, Role, SimpleIdentity};
use Tester\Assert;

require __DIR__ . '/../bootstrap.php';
require __DIR__ . '/MockUserStorage.php';


// Setup environment
$_COOKIE = [];
ob_start();


class Authenticator implements Nette\Security\Authenticator
{
	public function authenticate(string $username, string $password): IIdentity
	{
		if ($username !== 'john') {
			throw new Nette\Security\AuthenticationException('Unknown user', self::IdentityNotFound);

		} elseif ($password !== 'xxx') {
			throw new Nette\Security\AuthenticationException('Password not match', self::InvalidCredential);

		} else {
			return new SimpleIdentity('John Doe', ['admin', 'tester']);
		}
	}
}


class Authorizator implements Nette\Security\Authorizator
{
	public function isAllowed($role = self::All, $resource = self::All, $privilege = self::All): bool
	{
		return $role === 'admin' && !str_contains($resource, 'jany');
	}
}

class TesterRole implements Role
{
	public function getRoleId(): string
	{
		return 'tester';
	}
}

$user = new Nette\Security\User(new MockUserStorage);

// guest
Assert::false($user->isLoggedIn());


Assert::same(['guest'], $user->getRoles());
Assert::false($user->isInRole('admin'));
Assert::false($user->isInRole('tester'));
Assert::true($user->isInRole('guest'));


// authenticated
$handler = new Authenticator;
$user->setAuthenticator($handler);

// login as john
$user->login('john', 'xxx');

Assert::true($user->isLoggedIn());
Assert::same(['admin', 'tester'], $user->getRoles());
Assert::true($user->isInRole('admin'));
Assert::true($user->isInRole('tester'));
Assert::false($user->isInRole('guest'));


// authorization
Assert::exception(
	fn() => $user->isAllowed('delete_file'),
	Nette\InvalidStateException::class,
	'Authorizator has not been set.',
);

$handler = new Authorizator;
$user->setAuthorizator($handler);

Assert::true($user->isAllowed('delete_file'));
Assert::false($user->isAllowed('sleep_with_jany'));


// log out
// logging out...
$user->logout();

Assert::false($user->isAllowed('delete_file'));


// a Role object in the identity is no longer supported
$user->login(new SimpleIdentity('John Doe', ['admin', new TesterRole]));
Assert::exception(
	fn() => $user->getRoles(),
	Nette\InvalidStateException::class,
	'Roles of Nette\Security\SimpleIdentity must be names, TesterRole given. Role objects are no longer supported.',
);
Assert::exception(
	fn() => $user->isInRole('admin'),
	Nette\InvalidStateException::class,
);
