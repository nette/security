<?php

declare(strict_types=1);

class MockUserStorage implements Nette\Security\IUserStorage
{
	private $auth = false;

	private $identity;


	public function setAuthenticated(bool $state)
	{
		$this->auth = $state;
	}


	public function isAuthenticated(): bool
	{
		return $this->auth;
	}


	public function setIdentity(?Nette\Security\IIdentity $identity = null)
	{
		$this->identity = $identity;
	}


	public function getIdentity(): ?Nette\Security\IIdentity
	{
		return $this->identity;
	}


	public function setExpiration(?string $time, int $flags = 0)
	{
	}


	public function getLogoutReason(): ?int
	{
		return null;
	}
}
