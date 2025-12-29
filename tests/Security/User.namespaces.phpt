<?php declare(strict_types=1);

/**
 * Test: Nette\Security\User with storage namespaces for multiple authentication contexts.
 */

use Nette\Security\IIdentity;
use Nette\Security\SimpleIdentity;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


// Setup environment
$_COOKIE = [];
ob_start();


class MockNamespacedStorage implements Nette\Security\UserStorage
{
	private array $namespaces = [];
	private string $currentNamespace = '';


	public function saveAuthentication(IIdentity $identity): void
	{
		$this->namespaces[$this->currentNamespace] = [
			'authenticated' => true,
			'identity' => $identity,
			'reason' => null,
		];
	}


	public function clearAuthentication(bool $clearIdentity): void
	{
		if (isset($this->namespaces[$this->currentNamespace])) {
			$this->namespaces[$this->currentNamespace]['authenticated'] = false;
			$this->namespaces[$this->currentNamespace]['reason'] = Nette\Security\User::LogoutManual;
			if ($clearIdentity) {
				$this->namespaces[$this->currentNamespace]['identity'] = null;
			}
		}
	}


	public function getState(): array
	{
		$ns = $this->namespaces[$this->currentNamespace] ?? null;
		if ($ns === null) {
			return [false, null, null];
		}
		return [$ns['authenticated'], $ns['identity'], $ns['reason']];
	}


	public function setExpiration(?string $expire, bool $clearIdentity): void
	{
	}


	public function setNamespace(string $namespace): self
	{
		$this->currentNamespace = $namespace;
		return $this;
	}


	public function getNamespace(): string
	{
		return $this->currentNamespace;
	}
}


class SimpleAuthenticator implements Nette\Security\Authenticator
{
	public function authenticate(string $username, string $password): IIdentity
	{
		return new SimpleIdentity($username, [$username === 'admin' ? 'admin' : 'user']);
	}
}


test('Different namespaces have independent authentication states', function () {
	$storage = new MockNamespacedStorage;
	$user = new Nette\Security\User($storage);
	$user->setAuthenticator(new SimpleAuthenticator);

	// Login to default namespace
	$user->login('customer', 'xxx');
	Assert::true($user->isLoggedIn());
	Assert::same('customer', $user->getId());
	Assert::same(['user'], $user->getRoles());

	// Switch to 'admin' namespace - should NOT be logged in
	$storage->setNamespace('admin');
	$user->refreshStorage(); // Reload from new namespace
	Assert::false($user->isLoggedIn());
	Assert::null($user->getIdentity());

	// Login different user to admin namespace
	$user->login('admin', 'xxx');
	Assert::true($user->isLoggedIn());
	Assert::same('admin', $user->getId());
	Assert::same(['admin'], $user->getRoles());

	// Switch back to default namespace - customer should still be logged in
	$storage->setNamespace('');
	$user->refreshStorage(); // Reload from new namespace
	Assert::true($user->isLoggedIn());
	Assert::same('customer', $user->getId());
	Assert::same(['user'], $user->getRoles());

	// Switch to admin namespace - admin should still be logged in
	$storage->setNamespace('admin');
	$user->refreshStorage(); // Reload from new namespace
	Assert::true($user->isLoggedIn());
	Assert::same('admin', $user->getId());
	Assert::same(['admin'], $user->getRoles());
});


test('Logout in one namespace does not affect other namespaces', function () {
	$storage = new MockNamespacedStorage;
	$user = new Nette\Security\User($storage);
	$user->setAuthenticator(new SimpleAuthenticator);

	// Login to frontend
	$storage->setNamespace('frontend');
	$user->login('customer', 'xxx');
	Assert::true($user->isLoggedIn());

	// Login to backend
	$storage->setNamespace('backend');
	$user->login('admin', 'xxx');
	Assert::true($user->isLoggedIn());

	// Logout from backend
	$user->logout();
	Assert::false($user->isLoggedIn());

	// Frontend should still be logged in
	$storage->setNamespace('frontend');
	$user->refreshStorage(); // Reload from new namespace
	Assert::true($user->isLoggedIn());
	Assert::same('customer', $user->getId());
});


test('Identity is preserved after logout when not clearing in one namespace', function () {
	$storage = new MockNamespacedStorage;
	$user = new Nette\Security\User($storage);
	$user->setAuthenticator(new SimpleAuthenticator);

	// Login to namespace A
	$storage->setNamespace('A');
	$user->login('john', 'xxx');
	Assert::true($user->isLoggedIn());

	// Logout without clearing identity
	$user->logout(false);
	Assert::false($user->isLoggedIn());
	Assert::same('john', $user->getIdentity()->getId()); // Identity preserved

	// Switch to namespace B - should not have identity
	$storage->setNamespace('B');
	$user->refreshStorage(); // Reload from new namespace
	Assert::false($user->isLoggedIn());
	Assert::null($user->getIdentity());

	// Back to A - identity should still be there
	$storage->setNamespace('A');
	$user->refreshStorage(); // Reload from new namespace
	Assert::false($user->isLoggedIn());
	Assert::same('john', $user->getIdentity()->getId());
});


test('Multiple namespaces can be used simultaneously', function () {
	$storage = new MockNamespacedStorage;
	$user = new Nette\Security\User($storage);
	$user->setAuthenticator(new SimpleAuthenticator);

	// Create 3 different authentication contexts
	$contexts = [
		'frontend' => 'customer1',
		'backend' => 'admin',
		'api' => 'apiuser',
	];

	foreach ($contexts as $namespace => $username) {
		$storage->setNamespace($namespace);
		$user->login($username, 'xxx');
		Assert::true($user->isLoggedIn());
		Assert::same($username, $user->getId());
	}

	// Verify all contexts are still independent
	foreach ($contexts as $namespace => $username) {
		$storage->setNamespace($namespace);
		$user->refreshStorage(); // Reload from new namespace
		Assert::true($user->isLoggedIn());
		Assert::same($username, $user->getId());
	}

	// Logout from one
	$storage->setNamespace('backend');
	$user->refreshStorage(); // Reload from new namespace
	$user->logout();

	// Verify others are unaffected
	$storage->setNamespace('frontend');
	$user->refreshStorage(); // Reload from new namespace
	Assert::true($user->isLoggedIn());
	Assert::same('customer1', $user->getId());

	$storage->setNamespace('api');
	$user->refreshStorage(); // Reload from new namespace
	Assert::true($user->isLoggedIn());
	Assert::same('apiuser', $user->getId());

	$storage->setNamespace('backend');
	$user->refreshStorage(); // Reload from new namespace
	Assert::false($user->isLoggedIn());
});


test('Empty namespace is valid and separate from other namespaces', function () {
	$storage = new MockNamespacedStorage;
	$user = new Nette\Security\User($storage);
	$user->setAuthenticator(new SimpleAuthenticator);

	// Default (empty) namespace
	$storage->setNamespace('');
	$user->login('user1', 'xxx');
	Assert::true($user->isLoggedIn());

	// Named namespace
	$storage->setNamespace('special');
	$user->refreshStorage(); // Reload from new namespace
	Assert::false($user->isLoggedIn());
	$user->login('user2', 'xxx');
	Assert::true($user->isLoggedIn());
	Assert::same('user2', $user->getId());

	// Back to empty namespace
	$storage->setNamespace('');
	$user->refreshStorage(); // Reload from new namespace
	Assert::true($user->isLoggedIn());
	Assert::same('user1', $user->getId());
});


test('Logout event fires only for actual logout, not namespace switch', function () {
	$storage = new MockNamespacedStorage;
	$user = new Nette\Security\User($storage);
	$user->setAuthenticator(new SimpleAuthenticator);

	$logoutCount = 0;
	$user->onLoggedOut[] = function () use (&$logoutCount) {
		$logoutCount++;
	};

	// Login to namespace A
	$storage->setNamespace('A');
	$user->login('john', 'xxx');
	Assert::same(0, $logoutCount);

	// Actual logout in namespace A
	$user->logout();
	Assert::same(1, $logoutCount); // First logout event

	// Login to namespace B
	$storage->setNamespace('B');
	$user->refreshStorage(); // Reload from new namespace
	$user->login('jane', 'xxx');
	Assert::same(1, $logoutCount); // No additional logout

	// Logout from B
	$user->logout();
	Assert::same(2, $logoutCount); // Second logout event

	// Switch to A (nothing logged in there anymore)
	$storage->setNamespace('A');
	$user->refreshStorage(); // Reload from new namespace
	Assert::false($user->isLoggedIn());
	Assert::same(2, $logoutCount); // No logout event for checking status
});
