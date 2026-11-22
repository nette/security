<?php declare(strict_types=1);

/**
 * Test: Nette\Security\MemoryStorage
 */

use Nette\Security\{MemoryStorage, SimpleIdentity, User};
use Tester\Assert;

require __DIR__ . '/../bootstrap.php';


test('login, logout and a retained identity', function () {
	$identity = new SimpleIdentity(1, ['admin']);
	$user = new User(new MemoryStorage);
	Assert::false($user->isLoggedIn());

	$user->login($identity);
	Assert::true($user->isLoggedIn());
	Assert::same($identity, $user->getIdentity());

	$user->logout();
	Assert::false($user->isLoggedIn());
	Assert::same($identity, $user->getIdentity());
	Assert::same(User::LogoutManual, $user->getLogoutReason());
});


test('logout clearing the identity', function () {
	$storage = new MemoryStorage;
	$storage->saveAuthentication(new SimpleIdentity(1));
	$storage->clearAuthentication(clearIdentity: true);
	Assert::same([false, null, User::LogoutManual], $storage->getState());
});


test('expiration is ignored', function () {
	$storage = new MemoryStorage;
	$storage->saveAuthentication($identity = new SimpleIdentity(1));
	$storage->setExpiration('1 minute', clearIdentity: true);
	Assert::same([true, $identity, null], $storage->getState());
});
