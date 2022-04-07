<?php

/**
 * Test: Nette\Security\User authorization.
 */

declare(strict_types=1);

use Nette\Security\IIdentity;
use Nette\Security\Role;
use Nette\Security\SimpleIdentity;
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
			return new SimpleIdentity('John Doe', ['admin', new TesterRole]);
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

$user = new Nette\Security\User(null, null, null, new MockUserStorage);

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
Assert::equal(['admin', new TesterRole], $user->getRoles());
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
$user->logout(false);

Assert::false($user->isAllowed('delete_file'));
