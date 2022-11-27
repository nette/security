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

	/** @var array */
	private $passwords;

	/** @var array */
	private $roles;

	/** @var array */
	private $data;


	/**
	 * @param  array  $passwords list of pairs username => password
	 * @param  array  $roles list of pairs username => role[]
	 * @param  array  $data list of pairs username => mixed[]
	 */
	public function __construct(
		#[\SensitiveParameter]
		array $passwords,
		array $roles = [],
		array $data = []
	) {
		$this->passwords = $passwords;
		$this->roles = $roles;
		$this->data = $data;
	}


	/**
	 * Performs an authentication against e.g. database.
	 * and returns IIdentity on success or throws AuthenticationException
	 * @throws AuthenticationException
	 */
	public function authenticate(
		string $username,
		#[\SensitiveParameter]
		string $password
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
