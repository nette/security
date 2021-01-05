<?php

declare(strict_types=1);

class MockUserStorage implements Nette\Security\UserStorage
{
	private $auth = false;

	private $identity;


	public function saveAuthentication(Nette\Security\IIdentity $identity): void
	{
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
