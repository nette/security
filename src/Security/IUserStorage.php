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
interface IUserStorage
{
	/** Log-out reason {@link IUserStorage::getLogoutReason()} */
	const
		MANUAL = 0b0001,
		INACTIVITY = 0b0010;

	/** Log-out behavior */
	const CLEAR_IDENTITY = 0b1000;

	/**
	 * Sets the authenticated status of this user.
	 * @return static
	 */
	function setAuthenticated(bool $state);

	/**
	 * Is this user authenticated?
	 */
	function isAuthenticated(): bool;

	/**
	 * Sets the user identity.
	 * @return static
	 */
	function setIdentity(?IIdentity $identity);

	/**
	 * Returns current user identity, if any.
	 */
	function getIdentity(): ?IIdentity;

	/**
	 * Enables log out from the persistent storage after inactivity.
	 * @param  string|int|\DateTimeInterface number of seconds or timestamp
	 * @param  int  flag IUserStorage::CLEAR_IDENTITY
	 * @return static
	 */
	function setExpiration($time, int $flags = 0);

	/**
	 * Why was user logged out?
	 */
	function getLogoutReason(): ?int;

}
