<?php

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

namespace Nette\Security;

use Nette;


/**
 * Passwords tools.
 */
class Passwords
{
	use Nette\SmartObject;

	/** @deprecated */
	const BCRYPT_COST = 10;


	/**
	 * Computes salted password hash.
	 * @param  string
	 * @param  array with cost (4-31)
	 * @return string  60 chars long
	 */
	public static function hash($password, array $options = [])
	{
		$hash = @password_hash($password, PASSWORD_BCRYPT, $options); // @ is escalated to exception
		if (!$hash) {
			throw new Nette\InvalidStateException('Computed hash is invalid. ' . error_get_last()['message']);
		}
		return $hash;
	}


	/**
	 * Verifies that a password matches a hash.
	 * @return bool
	 */
	public static function verify($password, $hash)
	{
		return password_verify($password, $hash);
	}


	/**
	 * Checks if the given hash matches the options.
	 * @param  string
	 * @param  array with cost (4-31)
	 * @return bool
	 */
	public static function needsRehash($hash, array $options = [])
	{
		return password_needs_rehash($hash, PASSWORD_BCRYPT, $options);
	}
}
