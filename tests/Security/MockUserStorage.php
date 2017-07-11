<?php
declare(strict_types=1);

class MockUserStorage implements Nette\Security\IUserStorage
{
	private $auth = FALSE;
	private $identity;


	function setAuthenticated(bool $state)
	{
		$this->auth = $state;
	}


	function isAuthenticated(): bool
	{
		return $this->auth;
	}


	function setIdentity(Nette\Security\IIdentity $identity = NULL)
	{
		$this->identity = $identity;
	}


	function getIdentity(): ?Nette\Security\IIdentity
	{
		return $this->identity;
	}


	function setExpiration($time, int $flags = 0)
	{
	}


	function getLogoutReason(): ?int
	{
	}
}
