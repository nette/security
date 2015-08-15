<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 */

namespace Nette\Security;

use Nette;


/**
 * Passwords tools.
 */
class Passwords
{
	const BCRYPT_COST = 10;


	/**
	 * Computes salted password hash.
	 * @param  string
	 * @param  array with cost (4-31)
	 * @return string  60 chars long
	 */
	public static function hash($password, array $options = NULL)
	{
		$cost = isset($options['cost']) ? (int) $options['cost'] : self::BCRYPT_COST;
		if ($cost < 4 || $cost > 31) {
			throw new Nette\InvalidArgumentException("Cost must be in range 4-31, $cost given.");
		}

		$salt = Nette\Utils\Random::generate(22, '0-9A-Za-z./');
		$hash = crypt($password, '$2y$' . ($cost < 10 ? 0 : '') . $cost . '$' . $salt);
		if (strlen($hash) < 60) {
			throw new Nette\InvalidStateException('Hash returned by crypt is invalid.');
		}
		return $hash;
	}


	/**
	 * Verifies that a password matches a hash.
	 * @return bool
	 */
	public static function verify($password, $hash)
	{
		return preg_match('#^\$2y\$(?P<cost>\d\d)\$(?P<salt>.{22})#', $hash, $m)
			&& $m['cost'] >= 4 && $m['cost'] <= 31
			&& crypt($password, $hash) === $hash;
	}


	/**
	 * Checks if the given hash matches the options.
	 * @param  string
	 * @param  array with cost (4-31)
	 * @return bool
	 */
	public static function needsRehash($hash, array $options = NULL)
	{
		$cost = isset($options['cost']) ? (int) $options['cost'] : self::BCRYPT_COST;
		return !preg_match('#^\$2y\$(?P<cost>\d\d)\$(?P<salt>.{22})#', $hash, $m)
			|| $m['cost'] < $cost;
	}

}
