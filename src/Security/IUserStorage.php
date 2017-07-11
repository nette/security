<?php

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

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

	/** @deprecated */
	const BROWSER_CLOSED = 0b0100;

	/**
	 * Sets the authenticated status of this user.
	 * @param  bool
	 * @return static
	 */
	function setAuthenticated($state);

	/**
	 * Is this user authenticated?
	 * @return bool
	 */
	function isAuthenticated();

	/**
	 * Sets the user identity.
	 * @return static
	 */
	function setIdentity(IIdentity $identity = null);

	/**
	 * Returns current user identity, if any.
	 * @return IIdentity|null
	 */
	function getIdentity();

	/**
	 * Enables log out from the persistent storage after inactivity.
	 * @param  string|int|\DateTimeInterface number of seconds or timestamp
	 * @param  int  flag IUserStorage::CLEAR_IDENTITY
	 * @return static
	 */
	function setExpiration($time, $flags = 0);

	/**
	 * Why was user logged out?
	 * @return int|null
	 */
	function getLogoutReason();
}
