<?php

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

declare(strict_types=1);

namespace Nette\Security;


/**
 * Represents role, an object that may request access to an IResource.
 */
interface IRole
{
	/**
	 * Returns a string identifier of the Role.
	 */
	function getRoleId(): string;
}
