<?php

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

declare(strict_types=1);

namespace Nette\Security;

use Nette;


/**
 * Trivial implementation of Authenticator.
 */
class SimpleAuthenticator implements Authenticator
{
	use Nette\SmartObject;

	/**
	 * @param  array  $passwords list of pairs username => password
	 * @param  array  $roles list of pairs username => role[]
	 * @param  array  $data list of pairs username => mixed[]
	 */
	public function __construct(
		private array $passwords,
		private array $roles = [],
		private array $data = [],
		private ?Passwords $verifier = null,
	) {
	}


	/**
	 * Performs an authentication against e.g. database.
	 * and returns IIdentity on success or throws AuthenticationException
	 * @throws AuthenticationException
	 */
	public function authenticate(string $username, string $password): IIdentity
	{
		foreach ($this->passwords as $name => $pass) {
			if (strcasecmp($name, $username) === 0) {
				if ($this->verifyPassword($password, $pass)) {
					return new SimpleIdentity($name, $this->roles[$name] ?? null, $this->data[$name] ?? []);
				} else {
					throw new AuthenticationException('Invalid password.', self::INVALID_CREDENTIAL);
				}
			}
		}

		throw new AuthenticationException("User '$username' not found.", self::IDENTITY_NOT_FOUND);
	}


	protected function verifyPassword(string $password, string $passOrHash): bool
	{
		if (preg_match('~\$.{50,}~A', $passOrHash)) {
			return $this->verifier->verify($password, $passOrHash);
		}
		return $password === $passOrHash;
	}
}
