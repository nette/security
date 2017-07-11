<?php

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

namespace Nette\Security;

use Nette;


/**
 * Trivial implementation of IAuthenticator.
 */
class SimpleAuthenticator implements IAuthenticator
{
	use Nette\SmartObject;

	/** @var array */
	private $userlist;

	/** @var array */
	private $usersRoles;


	/**
	 * @param  array  list of pairs username => password
	 * @param  array  list of pairs username => role[]
	 */
	public function __construct(array $userlist, array $usersRoles = [])
	{
		$this->userlist = $userlist;
		$this->usersRoles = $usersRoles;
	}


	/**
	 * Performs an authentication against e.g. database.
	 * and returns IIdentity on success or throws AuthenticationException
	 * @return IIdentity
	 * @throws AuthenticationException
	 */
	public function authenticate(array $credentials)
	{
		list($username, $password) = $credentials;
		foreach ($this->userlist as $name => $pass) {
			if (strcasecmp($name, $username) === 0) {
				if ((string) $pass === (string) $password) {
					return new Identity($name, isset($this->usersRoles[$name]) ? $this->usersRoles[$name] : null);
				} else {
					throw new AuthenticationException('Invalid password.', self::INVALID_CREDENTIAL);
				}
			}
		}
		throw new AuthenticationException("User '$username' not found.", self::IDENTITY_NOT_FOUND);
	}
}
