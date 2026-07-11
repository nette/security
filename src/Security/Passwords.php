<?php declare(strict_types=1);

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

namespace Nette\Security;

use Nette;


/**
 * Password hashing and verification.
 */
class Passwords
{
	/**
	 * Configures the hashing algorithm and its options.
	 */
	public function __construct(
		private readonly string $algo = PASSWORD_DEFAULT,
		/** @var array<string, mixed>  algorithm-specific options, see https://php.net/manual/en/password.constants.php */
		private readonly array $options = [],
	) {
	}


	/**
	 * Creates an instance configured for bcrypt hashing. Higher cost means slower and safer hashing;
	 * null falls back to the PHP default.
	 */
	public static function bcrypt(?int $cost = null): self
	{
		return new self(PASSWORD_BCRYPT, $cost === null ? [] : ['cost' => $cost]);
	}


	/**
	 * Creates an instance configured for Argon2id hashing. Null options fall back to PHP defaults.
	 */
	public static function argon2id(?int $memoryCost = null, ?int $timeCost = null, ?int $threads = null): self
	{
		if (!defined('PASSWORD_ARGON2ID')) {
			throw new Nette\NotSupportedException('Argon2 is not supported by this PHP build.');
		}

		return new self(PASSWORD_ARGON2ID, array_filter([
			'memory_cost' => $memoryCost,
			'time_cost' => $timeCost,
			'threads' => $threads,
		], fn($value) => $value !== null));
	}


	/**
	 * Computes a password hash containing the algorithm ID, settings, salt, and the hash itself.
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
			throw new Nette\InvalidStateException('Computed hash is invalid. ' . (error_get_last()['message'] ?? ''));
		}

		return $hash;
	}


	/**
	 * Checks whether the password matches the given hash.
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
	 * Checks whether the hash needs to be rehashed with the current algorithm and options.
	 */
	public function needsRehash(string $hash): bool
	{
		return password_needs_rehash($hash, $this->algo, $this->options);
	}
}
