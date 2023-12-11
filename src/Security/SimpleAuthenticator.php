<?php

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

declare(strict_types=1);

namespace Nette\Security;


/**
 * Trivial implementation of Authenticator.
 */
class SimpleAuthenticator implements Authenticator
{
	/**
	 * @param  array  $passwords list of pairs username => password
	 * @param  array  $roles list of pairs username => role[]
	 * @param  array  $data list of pairs username => mixed[]
	 */
	public function __construct(
		#[\SensitiveParameter]
		private array $passwords,
		private array $roles = [],
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
