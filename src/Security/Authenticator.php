<?php

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

declare(strict_types=1);

namespace Nette\Security;


/**
 * Performs authentication.
 */
interface Authenticator extends IAuthenticator
{
	/** Exception error code */
	public const
		IdentityNotFound = 1,
		InvalidCredential = 2,
		Failure = 3,
		NotApproved = 4;

	/**
	 * Performs an authentication.
	 * @throws AuthenticationException
	 */
	function authenticate(string $user, string $password): IIdentity;
}
