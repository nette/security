<?php declare(strict_types=1);

/**
 * Test: Nette\Security\User getRoles() returns an identity's empty roles verbatim,
 * without falling back to $authenticatedRole or $guestRole.
 */

use Nette\Security\IIdentity;
use Nette\Security\SimpleIdentity;
use Nette\Security\User;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';
require __DIR__ . '/MockUserStorage.php';


test('logged-in identity with empty roles is returned as-is (no authenticatedRole)', function () {
	$authenticator = new class implements Nette\Security\Authenticator {
		public function authenticate(string $username, string $password): IIdentity
		{
			return new SimpleIdentity('john', []);
		}
	};
	$user = new User(new MockUserStorage, $authenticator);
	$user->login('john', 'pass');

	Assert::true($user->isLoggedIn());
	Assert::same([], $user->getRoles());
});


test('guest identity with empty roles is returned as-is (no guestRole)', function () {
	$authenticator = new class implements Nette\Security\Authenticator, Nette\Security\IdentityHandler {
		public function authenticate(string $username, string $password): IIdentity
		{
			return new SimpleIdentity('john', ['admin']);
		}


		public function sleepIdentity(IIdentity $identity): IIdentity
		{
			return $identity;
		}


		public function wakeupIdentity(IIdentity $identity): ?IIdentity
		{
			return $identity;
		}


		public function getGuestIdentity(): ?IIdentity
		{
			return new SimpleIdentity('guest', []);
		}
	};
	$user = new User(new MockUserStorage, $authenticator);

	Assert::false($user->isLoggedIn());
	Assert::same([], $user->getRoles());
});
