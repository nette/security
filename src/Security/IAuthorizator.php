<?php

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

namespace Nette\Security;


/**
 * Authorizator checks if a given role has authorization
 * to access a given resource.
 */
interface IAuthorizator
{
	/** Set type: all */
	const ALL = null;

	/** Permission type: allow */
	const ALLOW = true;

	/** Permission type: deny */
	const DENY = false;

	/**
	 * Performs a role-based authorization.
	 * @param  string|null
	 * @param  string|null
	 * @param  string|null
	 * @return bool
	 */
	function isAllowed($role, $resource, $privilege);
}
