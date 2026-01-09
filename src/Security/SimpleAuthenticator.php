<?php declare(strict_types=1);

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

namespace Nette\Security;


/**
 * Trivial implementation of Authenticator.
 */
class SimpleAuthenticator implements Authenticator
{
	public function __construct(
		/** @var array<string, string> */
		#[\SensitiveParameter]
		private array $passwords,
		/** @var array<string, string|string[]|null> */
		private array $roles = [],
		/** @var array<string, array<string, mixed>> */
		private array $data = [],
	) {
	}


	/**
	 * Performs an authentication against e.g. database.
	 * and returns IIdentity on success or throws AuthenticationException
	 * @throws AuthenticationException
	 */
	public function authenticate(
		string $username,
		#[\SensitiveParameter]
		string $password,
	): IIdentity
	{
		foreach ($this->passwords as $name => $pass) {
			if (strcasecmp($name, $username) === 0) {
				if ($this->verifyPassword($password, $pass)) {
					return new SimpleIdentity($name, $this->roles[$name] ?? null, $this->data[$name] ?? []);
				} else {
					throw new AuthenticationException('Invalid password.', self::InvalidCredential);
				}
			}
		}

		throw new AuthenticationException("User '$username' not found.", self::IdentityNotFound);
	}


	protected function verifyPassword(string $password, string $passOrHash): bool
	{
		return $password === $passOrHash;
	}
}
