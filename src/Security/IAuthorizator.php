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
	public const ALL = null;

	/** Permission type: allow */
	public const ALLOW = true;

	/** Permission type: deny */
	public const DENY = false;

	/**
	 * Performs a role-based authorization.
	 * @param  string|null  $role
	 * @param  string|null  $resource
	 * @param  string|null  $privilege
	 */
	function isAllowed($role, $resource, $privilege): bool;
}
