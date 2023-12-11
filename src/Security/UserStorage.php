<?php

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

declare(strict_types=1);

namespace Nette\Security;


/**
 * Interface for persistent storage for user object data.
 */
interface UserStorage
{
	/** @deprecated use User::LogoutManual */
	public const LOGOUT_MANUAL = 1;

	/** @deprecated use User::LogoutInactivity */
	public const LOGOUT_INACTIVITY = 2;

	/**
	 * Sets the authenticated state of user.
	 */
	function saveAuthentication(IIdentity $identity): void;

	/**
	 * Removed authenticated state of user.
	 */
	function clearAuthentication(bool $clearIdentity): void;

	/**
	 * Returns user authenticated state, identity and logout reason.
	 * @return array{bool, ?IIdentity, ?int}
	 */
	function getState(): array;

	/**
	 * Enables log out from the persistent storage after inactivity (like '20 minutes').
	 */
	function setExpiration(?string $expire, bool $clearIdentity): void;
}
