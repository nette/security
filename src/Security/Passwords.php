<?php

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

declare(strict_types=1);

namespace Nette\Security;

use Nette;


/**
 * Passwords tools.
 */
class Passwords
{
	use Nette\StaticClass;

	/**
	 * Computes salted password hash. Accepts option 'cost' (4-31)
	 */
	public static function hash(string $password, array $options = []): string
	{
		if (isset($options['cost']) && ($options['cost'] < 4 || $options['cost'] > 31)) {
			throw new Nette\InvalidArgumentException("Cost must be in range 4-31, $options[cost] given.");
		}

		$hash = password_hash($password, PASSWORD_BCRYPT, $options);
		if ($hash === FALSE || strlen($hash) < 60) {
			throw new Nette\InvalidStateException('Hash computed by password_hash is invalid.');
		}
		return $hash;
	}


	/**
	 * Verifies that a password matches a hash.
	 */
	public static function verify(string $password, string $hash): bool
	{
		return password_verify($password, $hash);
	}


	/**
	 * Checks if the given hash matches the options. Accepts option 'cost' (4-31)
	 */
	public static function needsRehash(string $hash, array $options = []): bool
	{
		return password_needs_rehash($hash, PASSWORD_BCRYPT, $options);
	}
}
