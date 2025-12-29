<?php declare(strict_types=1);

/**
 * Test: Nette\Security\User expiration delegation to UserStorage.
 */

use Nette\Security\IIdentity;
use Nette\Security\User;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


class MockUserStorage implements Nette\Security\UserStorage
{
	public ?string $expireTime = null;
	public bool $expireIdentity = false;
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
		$this->reason = User::LogoutManual;
		if ($clearIdentity) {
			$this->identity = null;
		}
	}


	public function getState(): array
	{
		return [$this->authenticated, $this->identity, $this->reason];
	}


	public function setExpiration(?string $time, bool $clearIdentity = false): void
	{
		$this->expireTime = $time;
		$this->expireIdentity = $clearIdentity;
	}
}


test('User delegates setExpiration to storage', function () {
	$storage = new MockUserStorage;
	$user = new User($storage);

	$user->setExpiration('30 minutes');
	Assert::same('30 minutes', $storage->expireTime);
	Assert::false($storage->expireIdentity);

	$user->setExpiration(null);
	Assert::null($storage->expireTime);
});


test('User delegates setExpiration with clearIdentity flag', function () {
	$storage = new MockUserStorage;
	$user = new User($storage);

	$user->setExpiration('10 minutes', clearIdentity: true);
	Assert::same('10 minutes', $storage->expireTime);
	Assert::true($storage->expireIdentity);
});
