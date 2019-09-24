<?php

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

declare(strict_types=1);

namespace Nette\Security;

use Nette;


/**
 * Password Hashing.
 */
class Passwords
{
	use Nette\SmartObject;

	/** @var int|string  string since PHP 7.4 */
	private $algo;

	/** @var array */
	private $options;


	/**
	 * See https://php.net/manual/en/password.constants.php
	 */
	public function __construct($algo = PASSWORD_DEFAULT, array $options = [])
	{
		$this->algo = $algo;
		$this->options = $options;
	}


	/**
	 * Computes salted password hash.
	 */
	public function hash(string $password): string
	{
		$hash = isset($this)
			? @password_hash($password, $this->algo, $this->options) // @ is escalated to exception
			: @password_hash($password, PASSWORD_BCRYPT, func_get_args()[1] ?? []); // back compatibility with v2.x

		if (!$hash) {
			throw new Nette\InvalidStateException('Computed hash is invalid. ' . error_get_last()['message']);
		}
		return $hash;
	}


	/**
	 * Verifies that a password matches a hash.
	 */
	public function verify(string $password, string $hash): bool
	{
		return password_verify($password, $hash);
	}


	/**
	 * Checks if the given hash matches the options.
	 */
	public function needsRehash(string $hash): bool
	{
		return isset($this)
			? password_needs_rehash($hash, $this->algo, $this->options)
			: password_needs_rehash($hash, PASSWORD_BCRYPT, func_get_args()[1] ?? []); // back compatibility with v2.x
	}
}
