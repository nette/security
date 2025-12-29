<?php declare(strict_types=1);

/**
 * Test: Nette\Security\User with IdentityHandler.
 */

use Nette\Security\IIdentity;
use Nette\Security\SimpleIdentity;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';
require __DIR__ . '/MockUserStorage.php';


// Setup environment
$_COOKIE = [];
ob_start();


class AuthenticatorWithHandler implements Nette\Security\Authenticator, Nette\Security\IdentityHandler
{
	public array $sleepCalls = [];
	public array $wakeupCalls = [];


	public function authenticate(string $username, string $password): IIdentity
	{
		if ($username !== 'john') {
			throw new Nette\Security\AuthenticationException('Unknown user', self::IdentityNotFound);
		} elseif ($password !== 'xxx') {
			throw new Nette\Security\AuthenticationException('Password not match', self::InvalidCredential);
		} else {
			return new SimpleIdentity('john', ['user'], ['name' => 'John Doe']);
		}
	}


	public function sleepIdentity(IIdentity $identity): IIdentity
	{
		$this->sleepCalls[] = $identity;
		// Simulate token-only storage (e.g., for cookies)
		// Store only ID, not roles or data
		return new SimpleIdentity($identity->getId());
	}


	public function wakeupIdentity(IIdentity $identity): ?IIdentity
	{
		$this->wakeupCalls[] = $identity;
		// Simulate refreshing roles from database
		// Real implementation would fetch fresh data from DB
		return new SimpleIdentity($identity->getId(), ['admin', 'user'], ['name' => 'John Doe Updated']);
	}
}


test('IdentityHandler.sleepIdentity() is called on login', function () {
	$handler = new AuthenticatorWithHandler;
	$user = new Nette\Security\User(new MockUserStorage);
	$user->setAuthenticator($handler);

	Assert::count(0, $handler->sleepCalls);

	$user->login('john', 'xxx');

	// sleepIdentity should be called once
	Assert::count(1, $handler->sleepCalls);

	// Original identity should have 'user' role
	Assert::same(['user'], $handler->sleepCalls[0]->getRoles());
	Assert::same(['name' => 'John Doe'], $handler->sleepCalls[0]->getData());
});


test('IdentityHandler.wakeupIdentity() is called when accessing identity', function () {
	$storage = new MockUserStorage;
	$handler = new AuthenticatorWithHandler;
	$user = new Nette\Security\User($storage);
	$user->setAuthenticator($handler);

	$user->login('john', 'xxx');

	// Reset counters
	$handler->wakeupCalls = [];

	// Create new User instance with same storage to simulate new request
	$user2 = new Nette\Security\User($storage);
	$user2->setAuthenticator($handler);

	Assert::count(0, $handler->wakeupCalls);

	// Accessing identity should trigger wakeup
	$identity = $user2->getIdentity();

	Assert::count(1, $handler->wakeupCalls);

	// wakeupIdentity received the "slept" identity (ID only)
	Assert::same('john', $handler->wakeupCalls[0]->getId());
	Assert::same([], $handler->wakeupCalls[0]->getRoles());

	// But returned identity has updated roles from wakeup
	Assert::same(['admin', 'user'], $identity->getRoles());
	Assert::same(['name' => 'John Doe Updated'], $identity->getData());
});


test('IdentityHandler.wakeupIdentity() returning null logs user out', function () {
	$handler = new class implements Nette\Security\Authenticator, Nette\Security\IdentityHandler {
		public function authenticate(string $username, string $password): IIdentity
		{
			return new SimpleIdentity('john', ['user']);
		}


		public function sleepIdentity(IIdentity $identity): IIdentity
		{
			return $identity;
		}


		public function wakeupIdentity(IIdentity $identity): ?IIdentity
		{
			// Simulate invalid token/expired session
			return null;
		}
	};

	$storage = new MockUserStorage;
	$user = new Nette\Security\User($storage);
	$user->setAuthenticator($handler);

	$user->login('john', 'xxx');
	Assert::true($user->isLoggedIn());

	// Create new User instance to trigger wakeup
	$user2 = new Nette\Security\User($storage);
	$user2->setAuthenticator($handler);

	// wakeupIdentity returns null → user should be logged out
	Assert::false($user2->isLoggedIn());
	Assert::null($user2->getIdentity());
});


test('IdentityHandler is not called when authenticator does not implement it', function () {
	$handler = new class implements Nette\Security\Authenticator {
		public int $authCount = 0;


		public function authenticate(string $username, string $password): IIdentity
		{
			$this->authCount++;
			return new SimpleIdentity('john', ['user']);
		}
	};

	$storage = new MockUserStorage;
	$user = new Nette\Security\User($storage);
	$user->setAuthenticator($handler);

	$user->login('john', 'xxx');
	Assert::same(1, $handler->authCount);

	// Create new User instance - should just return stored identity without wakeup
	$user2 = new Nette\Security\User($storage);
	$user2->setAuthenticator($handler);

	$identity = $user2->getIdentity();
	Assert::same('john', $identity->getId());
	Assert::same(['user'], $identity->getRoles());

	// authenticate should not be called again
	Assert::same(1, $handler->authCount);
});
