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

	private string $algo;
	private array $options;


	/**
	 * Chooses which secure algorithm is used for hashing and how to configure it.
	 * @see https://php.net/manual/en/password.constants.php
	 */
	public function __construct($algo = PASSWORD_DEFAULT, array $options = [])
	{
		$this->algo = $algo;
		$this->options = $options;
	}


	/**
	 * Computes password´s hash. The result contains the algorithm ID and its settings, cryptographical salt and the hash itself.
	 */
	public function hash(
		#[\SensitiveParameter]
		string $password,
	): string
	{
		if ($password === '') {
			throw new Nette\InvalidArgumentException('Password can not be empty.');
		}

		$hash = @password_hash($password, $this->algo, $this->options); // @ is escalated to exception
		if (!$hash) {
			throw new Nette\InvalidStateException('Computed hash is invalid. ' . error_get_last()['message']);
		}

		return $hash;
	}


	/**
	 * Finds out, whether the given password matches the given hash.
	 */
	public function verify(
		#[\SensitiveParameter]
		string $password,
		string $hash,
	): bool
	{
		return password_verify($password, $hash);
	}


	/**
	 * Finds out if the hash matches the options given in constructor.
	 */
	public function needsRehash(string $hash): bool
	{
		return password_needs_rehash($hash, $this->algo, $this->options);
	}
}
