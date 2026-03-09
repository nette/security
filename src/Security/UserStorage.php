<?php declare(strict_types=1);

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

namespace Nette\Security;


/**
 * Persistent storage for user authentication state and identity.
 */
interface UserStorage
{
	/** @deprecated use User::LogoutManual */
	public const LOGOUT_MANUAL = 1;

	/** @deprecated use User::LogoutInactivity */
	public const LOGOUT_INACTIVITY = 2;

	/**
	 * Saves authenticated identity to storage.
	 */
	function saveAuthentication(IIdentity $identity): void;

	/**
	 * Removes authenticated state from storage.
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
