<?php

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

declare(strict_types=1);

namespace Nette\Security;


/**
 * @deprecated  update to Nette\Security\Authenticator
 * @method IIdentity authenticate(array $credentials)
 */
interface IAuthenticator
{
	/** Credential key */
	public const
		USERNAME = 0,
		PASSWORD = 1;

	/** Exception error code */
	public const
		IDENTITY_NOT_FOUND = 1,
		INVALID_CREDENTIAL = 2,
		FAILURE = 3,
		NOT_APPROVED = 4;

	/**
	 * Performs an authentication against e.g. database.
	 * and returns IIdentity on success or throws AuthenticationException
	 * @throws AuthenticationException
	 */
	//function authenticate(array $credentials): IIdentity;
}
