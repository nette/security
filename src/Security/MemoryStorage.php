<?php declare(strict_types=1);

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

namespace Nette\Security;


/**
 * Keeps the authentication only for the lifetime of the object, for tests and CLI scripts. Expiration is not supported.
 */
final class MemoryStorage implements UserStorage
{
	private bool $authenticated = false;
	private ?IIdentity $identity = null;
	private ?int $logoutReason = null;


	public function saveAuthentication(IIdentity $identity): void
	{
		$this->authenticated = true;
		$this->identity = $identity;
		$this->logoutReason = null;
	}


	public function clearAuthentication(bool $clearIdentity): void
	{
		$this->authenticated = false;
		$this->identity = $clearIdentity ? null : $this->identity;
		$this->logoutReason = User::LogoutManual;
	}


	public function getState(): array
	{
		return [$this->authenticated, $this->identity, $this->logoutReason];
	}


	public function setExpiration(?string $expire, bool $clearIdentity): void
	{
	}
}
