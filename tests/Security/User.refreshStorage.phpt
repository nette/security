<?php declare(strict_types=1);

/**
 * Test: Nette\Security\User refreshStorage() method.
 */

use Nette\Security\IIdentity;
use Nette\Security\SimpleIdentity;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


// Setup environment
$_COOKIE = [];
ob_start();


class MutableStorage implements Nette\Security\UserStorage
{
	private bool $authenticated = false;
	private ?IIdentity $identity = null;
	private ?int $reason = null;


	public function saveAuthentication(IIdentity $identity): void
	{
		$this->authenticated = true;
		$this->identity = $identity;
		$this->reason = null;
	}


	public function clearAuthentication(bool $clearIdentity): void
	{
		$this->authenticated = false;
		$this->reason = Nette\Security\User::LogoutManual;
		if ($clearIdentity) {
			$this->identity = null;
		}
	}


	public function getState(): array
	{
		return [$this->authenticated, $this->identity, $this->reason];
	}


	public function setExpiration(?string $expire, bool $clearIdentity): void
	{
	}


	// Test helpers
	public function externallyModifyIdentity(callable $modifier): void
	{
		$this->identity = $modifier($this->identity);
	}


	public function externallyModifyRoles(array $newRoles): void
	{
		if ($this->identity) {
			$this->identity = new SimpleIdentity(
				$this->identity->getId(),
				$newRoles,
				$this->identity->getData(),
			);
		}
	}


	public function externallyLogout(): void
	{
		$this->authenticated = false;
		$this->reason = Nette\Security\User::LogoutInactivity;
	}
}


class SimpleAuthenticator implements Nette\Security\Authenticator
{
	public function authenticate(string $username, string $password): IIdentity
	{
		return new SimpleIdentity($username, ['user']);
	}
}


test('refreshStorage() reloads identity from storage', function () {
	$storage = new MutableStorage;
	$user = new Nette\Security\User($storage);
	$user->setAuthenticator(new SimpleAuthenticator);

	$user->login('john', 'xxx');
	$identity1 = $user->getIdentity();

	Assert::same('john', $identity1->getId());
	Assert::same(['user'], $identity1->getRoles());

	// Externally modify storage (e.g., another request updated roles in database)
	$storage->externallyModifyRoles(['admin', 'user']);

	// Without refresh - still old cached identity
	$identity2 = $user->getIdentity();
	Assert::same($identity1, $identity2); // Same object
	Assert::same(['user'], $identity2->getRoles()); // Old roles

	// After refresh - new identity loaded
	$user->refreshStorage();
	$identity3 = $user->getIdentity();

	Assert::notSame($identity1, $identity3); // Different object
	Assert::same('john', $identity3->getId());
	Assert::same(['admin', 'user'], $identity3->getRoles()); // New roles!
});


test('refreshStorage() updates authentication state', function () {
	$storage = new MutableStorage;
	$user = new Nette\Security\User($storage);
	$user->setAuthenticator(new SimpleAuthenticator);

	$user->login('john', 'xxx');
	Assert::true($user->isLoggedIn());

	// External logout (e.g., session timeout in storage)
	$storage->externallyLogout();

	// Without refresh - still appears logged in (cached state)
	Assert::true($user->isLoggedIn());

	// After refresh - state updated
	$user->refreshStorage();
	Assert::false($user->isLoggedIn());
	Assert::same(Nette\Security\User::LogoutInactivity, $user->getLogoutReason());
});


test('refreshStorage() reloads data from storage', function () {
	$storage = new MutableStorage;
	$user = new Nette\Security\User($storage);
	$user->setAuthenticator(new SimpleAuthenticator);

	$user->login('john', 'xxx');

	// Get identity - it's now cached
	$identity1 = $user->getIdentity();
	Assert::notNull($identity1);

	// Externally modify storage
	$storage->externallyModifyRoles(['admin']);

	// Without refresh - still old cached value
	Assert::same(['user'], $user->getRoles());

	// Refresh clears cache
	$user->refreshStorage();

	// Next access loads fresh from storage with new roles
	Assert::same(['admin'], $user->getRoles());
});


test('refreshStorage() with IdentityHandler triggers wakeup again', function () {
	$wakeupCount = 0;

	$handler = new class ($wakeupCount) implements Nette\Security\Authenticator, Nette\Security\IdentityHandler {
		public function __construct(
			private int &$wakeupCount,
		) {
		}


		public function authenticate(string $username, string $password): IIdentity
		{
			return new SimpleIdentity($username, ['user']);
		}


		public function sleepIdentity(IIdentity $identity): IIdentity
		{
			return $identity;
		}


		public function wakeupIdentity(IIdentity $identity): ?IIdentity
		{
			$this->wakeupCount++;
			// Each wakeup adds a role
			return new SimpleIdentity(
				$identity->getId(),
				array_merge($identity->getRoles(), ['role' . $this->wakeupCount]),
			);
		}
	};

	$storage = new MutableStorage;
	$user = new Nette\Security\User($storage);
	$user->setAuthenticator($handler);

	$user->login('john', 'xxx');

	// After login, identity is cached - no wakeup yet
	$identity1 = $user->getIdentity();
	Assert::same(0, $wakeupCount); // No wakeup after fresh login
	Assert::same(['user'], $identity1->getRoles());

	// Refresh triggers wakeup on next access
	$user->refreshStorage();
	$identity2 = $user->getIdentity();
	Assert::same(1, $wakeupCount); // First wakeup
	Assert::same(['user', 'role1'], $identity2->getRoles());

	// Another refresh and access - wakeup gets fresh identity from storage again
	$user->refreshStorage();
	$identity3 = $user->getIdentity();
	Assert::same(2, $wakeupCount); // Second wakeup
	// Note: wakeupIdentity receives the stored identity (just ['user']), not previous wakeup result
	Assert::same(['user', 'role2'], $identity3->getRoles());
});


test('refreshStorage() does not affect storage data', function () {
	$storage = new MutableStorage;
	$user = new Nette\Security\User($storage);
	$user->setAuthenticator(new SimpleAuthenticator);

	$user->login('john', 'xxx');

	// Get state before refresh
	[$auth1, $id1, $reason1] = $storage->getState();

	$user->refreshStorage();

	// Get state after refresh - should be unchanged
	[$auth2, $id2, $reason2] = $storage->getState();

	Assert::same($auth1, $auth2);
	Assert::same($id1, $id2);
	Assert::same($reason1, $reason2);
});


test('refreshStorage() on logged out user works without error', function () {
	$storage = new MutableStorage;
	$user = new Nette\Security\User($storage);

	Assert::false($user->isLoggedIn());

	// Should not throw
	$user->refreshStorage();

	Assert::false($user->isLoggedIn());
	Assert::null($user->getIdentity());
});


test('Multiple refreshStorage() calls work correctly', function () {
	$storage = new MutableStorage;
	$user = new Nette\Security\User($storage);
	$user->setAuthenticator(new SimpleAuthenticator);

	$user->login('john', 'xxx');

	for ($i = 0; $i < 5; $i++) {
		$user->refreshStorage();
		Assert::true($user->isLoggedIn());
		Assert::same('john', $user->getId());
	}

	// Modify storage
	$storage->externallyModifyRoles(['admin']);

	$user->refreshStorage();
	Assert::same(['admin'], $user->getIdentity()->getRoles());
});


test('refreshStorage() allows detecting external identity changes', function () {
	$storage = new MutableStorage;
	$user = new Nette\Security\User($storage);
	$user->setAuthenticator(new SimpleAuthenticator);

	$user->login('john', 'xxx');
	$initialData = $user->getIdentity()->getData();

	// Simulate another process updating user data in storage
	$storage->externallyModifyIdentity(fn($identity) => new SimpleIdentity(
		$identity->getId(),
		$identity->getRoles(),
		['updated' => true, 'timestamp' => time()],
	));

	// Refresh to get updated data
	$user->refreshStorage();
	$updatedData = $user->getIdentity()->getData();

	Assert::notSame($initialData, $updatedData);
	Assert::true($updatedData['updated']);
	Assert::type('int', $updatedData['timestamp']);
});
