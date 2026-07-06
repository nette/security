<?php declare(strict_types=1);

/**
 * Test: Nette\Security\User guest identity.
 */

use Nette\Security\IIdentity;
use Nette\Security\SimpleIdentity;
use Nette\Security\User;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';
require __DIR__ . '/MockUserStorage.php';


class GuestAuthenticator implements Nette\Security\Authenticator, Nette\Security\IdentityHandler
{
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
		return new SimpleIdentity('guest', ['guest-role'], ['name' => 'Guest']);
	}
}


class RecordingStorage implements Nette\Security\UserStorage
{
	/** @var list<IIdentity> */
	public array $saved = [];
	private bool $auth = false;
	private ?IIdentity $identity = null;


	public function saveAuthentication(IIdentity $identity): void
	{
		$this->saved[] = $identity;
		$this->auth = true;
		$this->identity = $identity;
	}


	public function clearAuthentication(bool $clearIdentity): void
	{
		$this->auth = false;
		$this->identity = $clearIdentity ? null : $this->identity;
	}


	public function getState(): array
	{
		return [$this->auth, $this->identity, null];
	}


	public function setExpiration(?string $expire, bool $clearIdentity): void
	{
	}
}


test('guest identity is exposed when not logged in', function () {
	$user = new User(new MockUserStorage, new GuestAuthenticator);

	Assert::false($user->isLoggedIn());
	Assert::equal(new SimpleIdentity('guest', ['guest-role'], ['name' => 'Guest']), $user->getIdentity());
	Assert::same('guest', $user->getId());
	Assert::same(['guest-role'], $user->getRoles());
	Assert::true($user->isInRole('guest-role'));
	Assert::false($user->isInRole('admin'));
});


test('login overrides the guest identity', function () {
	$user = new User(new MockUserStorage, new GuestAuthenticator);
	$user->login('john', 'pass');

	Assert::true($user->isLoggedIn());
	Assert::same('john', $user->getId());
	Assert::same(['admin'], $user->getRoles());
});


test('guest identity returns after logout that clears identity', function () {
	$user = new User(new MockUserStorage, new GuestAuthenticator);
	$user->login('john', 'pass');

	$user->logout(clearIdentity: true);

	Assert::false($user->isLoggedIn());
	Assert::same('guest', $user->getId());
	Assert::same(['guest-role'], $user->getRoles());
});


test('retained identity stays for personalization but roles fall back to the guest identity', function () {
	$user = new User(new MockUserStorage, new GuestAuthenticator);
	$user->login('john', 'pass');

	$user->logout(); // persistIdentity is on by default -> identity is retained

	Assert::false($user->isLoggedIn());
	Assert::same('john', $user->getId()); // retained real identity for personalization
	Assert::same(['guest-role'], $user->getRoles()); // but NOT the real ['admin'] roles
});


test('without a guest identity provider the behaviour is unchanged', function () {
	$authenticator = new class implements Nette\Security\Authenticator {
		public function authenticate(string $username, string $password): IIdentity
		{
			return new SimpleIdentity('john', ['admin']);
		}
	};
	$user = new User(new MockUserStorage, $authenticator);

	Assert::false($user->isLoggedIn());
	Assert::null($user->getIdentity());
	Assert::same(['guest'], $user->getRoles());
});


test('guest identity is never written to storage', function () {
	$storage = new RecordingStorage;
	$user = new User($storage, new GuestAuthenticator);

	// acting as a guest must not persist anything
	Assert::same('guest', $user->getId());
	Assert::same(['guest-role'], $user->getRoles());
	Assert::equal(new SimpleIdentity('guest', ['guest-role'], ['name' => 'Guest']), $user->getIdentity());
	Assert::same([], $storage->saved);

	// login/logout cycle, then guest again
	$user->login('john', 'pass');
	$user->logout(clearIdentity: true);
	Assert::same('guest', $user->getId());

	// only the real identity may ever reach the storage
	Assert::same(['john'], array_map(fn(IIdentity $i) => $i->getId(), $storage->saved));
});
