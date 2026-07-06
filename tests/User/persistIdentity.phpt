<?php declare(strict_types=1);

/**
 * Test: Nette\Security\User persistIdentity.
 */

use Nette\Security\SimpleIdentity;
use Nette\Security\User;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';
require __DIR__ . '/MockUserStorage.php';


test('identity is kept after logout by default', function () {
	$user = new User(new MockUserStorage);
	$user->login(new SimpleIdentity('John Doe', 'admin'));

	$user->logout();

	Assert::false($user->isLoggedIn());
	Assert::equal(new SimpleIdentity('John Doe', 'admin'), $user->getIdentity());
	Assert::same('John Doe', $user->getId());
});


test('identity is discarded after logout when persistIdentity is off', function () {
	$user = new User(new MockUserStorage);
	$user->persistIdentity = false;
	$user->login(new SimpleIdentity('John Doe', 'admin'));

	$user->logout();

	Assert::false($user->isLoggedIn());
	Assert::null($user->getIdentity());
	Assert::null($user->getId());
});


test('identity already stored without authentication is not exposed when persistIdentity is off', function () {
	$storage = new MockUserStorage;
	$user = new User($storage);
	$user->login(new SimpleIdentity('John Doe', 'admin'));
	$user->logout(); // identity stays in storage, not authenticated

	// fresh User over the same storage with persistIdentity off (e.g. after disabling it in config)
	$user = new User($storage);
	$user->persistIdentity = false;

	Assert::false($user->isLoggedIn());
	Assert::null($user->getIdentity());
	Assert::null($user->getId());
});
