<?php

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

declare(strict_types=1);

namespace Nette\Security;


/**
 * Authorizator checks if a given role has authorization
 * to access a given resource.
 */
interface IAuthorizator
{
	/** Set type: all */
	public const ALL = NULL;

	/** Permission type: allow */
	public const ALLOW = TRUE;

	/** Permission type: deny */
	public const DENY = FALSE;

	/**
	 * Performs a role-based authorization.
	 * @param  string|NULL
	 * @param  string|NULL
	 * @param  string|NULL
	 */
	function isAllowed($role, $resource, $privilege): bool;
}
