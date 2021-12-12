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
	private $userlist;

	/** @var array */
	private $usersRoles;

	/** @var array */
	private $usersData;


	/**
	 * @param  array  $userlist list of pairs username => password
	 * @param  array  $usersRoles list of pairs username => role[]
	 * @param  array  $usersData list of pairs username => mixed[]
	 */
	public function __construct(array $userlist, array $usersRoles = [], array $usersData = [])
	{
		$this->userlist = $userlist;
		$this->usersRoles = $usersRoles;
		$this->usersData = $usersData;
	}


	/**
	 * Performs an authentication against e.g. database.
	 * and returns IIdentity on success or throws AuthenticationException
	 * @throws AuthenticationException
	 */
	public function authenticate(string $username, string $password): IIdentity
	{
		foreach ($this->userlist as $name => $pass) {
			if (strcasecmp($name, $username) === 0) {
				if ((string) $pass === $password) {
					return new SimpleIdentity($name, $this->usersRoles[$name] ?? null, $this->usersData[$name] ?? []);
				} else {
					throw new AuthenticationException('Invalid password.', self::INVALID_CREDENTIAL);
				}
			}
		}

		throw new AuthenticationException("User '$username' not found.", self::IDENTITY_NOT_FOUND);
	}
}
