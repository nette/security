<?php

/**
 * Test: Nette\Security\User authentication.
 */

declare(strict_types=1);

use Nette\Security\IIdentity;
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
			throw new Nette\Security\AuthenticationException('Unknown user', self::IDENTITY_NOT_FOUND);

		} elseif ($password !== 'xxx') {
			throw new Nette\Security\AuthenticationException('Password not match', self::INVALID_CREDENTIAL);

		} else {
			return new SimpleIdentity('John Doe', 'admin');
		}
	}
}


$user = new Nette\Security\User(new MockUserStorage);

$counter = (object) [
	'login' => 0,
	'logout' => 0,
];

$user->onLoggedIn[] = function () use ($counter) {
	$counter->login++;
};

$user->onLoggedOut[] = function () use ($counter) {
	$counter->logout++;
};


Assert::false($user->isLoggedIn());
Assert::null($user->getIdentity());
Assert::null($user->getId());


// authenticate
Assert::exception(function () use ($user) {
	// login without handler
	$user->login('jane', '');
}, Nette\InvalidStateException::class, 'Authenticator has not been set.');

$handler = new Authenticator;
$user->setAuthenticator($handler);

Assert::exception(function () use ($user) {
	// login as jane
	$user->login('jane', '');
}, Nette\Security\AuthenticationException::class, 'Unknown user');

Assert::exception(function () use ($user) {
	// login as john
	$user->login('john', '');
}, Nette\Security\AuthenticationException::class, 'Password not match');

// login as john#2
$user->login('john', 'xxx');
Assert::same(1, $counter->login);
Assert::true($user->isLoggedIn());
Assert::equal(new SimpleIdentity('John Doe', 'admin'), $user->getIdentity());
Assert::same('John Doe', $user->getId());

// login as john#3
$user->logout(true);
Assert::same(1, $counter->logout);
$user->login(new SimpleIdentity('John Doe', 'admin'));
Assert::same(2, $counter->login);
Assert::true($user->isLoggedIn());
Assert::equal(new SimpleIdentity('John Doe', 'admin'), $user->getIdentity());


// log out
// logging out...
$user->logout(false);
Assert::same(2, $counter->logout);

Assert::false($user->isLoggedIn());
Assert::equal(new SimpleIdentity('John Doe', 'admin'), $user->getIdentity());


// logging out and clearing identity...
$user->logout(true);
Assert::same(2, $counter->logout); // not logged in -> logout event not triggered

Assert::false($user->isLoggedIn());
Assert::null($user->getIdentity());


// namespace
// login as john#2?
$user->login('john', 'xxx');
Assert::same(3, $counter->login);
Assert::true($user->isLoggedIn());
