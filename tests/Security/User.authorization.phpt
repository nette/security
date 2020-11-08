<?php

/**
 * Test: Nette\Security\User authorization.
 */

declare(strict_types=1);

use Nette\Security\IAuthenticator;
use Nette\Security\IAuthorizator;
use Nette\Security\Identity;
use Nette\Security\IRole;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';
require __DIR__ . '/MockUserStorage.php';


// Setup environment
$_COOKIE = [];
ob_start();


class Authenticator implements IAuthenticator
{
	public function authenticate(array $credentials): Nette\Security\IIdentity
	{
		[$username, $password] = $credentials;
		if ($username !== 'john') {
			throw new Nette\Security\AuthenticationException('Unknown user', self::IDENTITY_NOT_FOUND);

		} elseif ($password !== 'xxx') {
			throw new Nette\Security\AuthenticationException('Password not match', self::INVALID_CREDENTIAL);

		} else {
			return new Identity('John Doe', ['admin', new TesterRole]);
		}
	}
}


class Authorizator implements IAuthorizator
{
	public function isAllowed($role = self::ALL, $resource = self::ALL, $privilege = self::ALL): bool
	{
		return $role === 'admin' && strpos($resource, 'jany') === false;
	}
}

class TesterRole implements IRole
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
Assert::equal(['admin', new TesterRole], $user->getRoles());
Assert::true($user->isInRole('admin'));
Assert::true($user->isInRole('tester'));
Assert::false($user->isInRole('guest'));


// authorization
Assert::exception(function () use ($user) {
	$user->isAllowed('delete_file');
}, Nette\InvalidStateException::class, 'Authorizator has not been set.');

$handler = new Authorizator;
$user->setAuthorizator($handler);

Assert::true($user->isAllowed('delete_file'));
Assert::false($user->isAllowed('sleep_with_jany'));


// log out
// logging out...
$user->logout(false);

Assert::false($user->isAllowed('delete_file'));
