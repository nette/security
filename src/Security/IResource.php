<?php

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

declare(strict_types=1);

namespace Nette\Security;


/**
 * Represents resource, an object to which access is controlled.
 */
interface IResource
{

	/**
	 * Returns a string identifier of the Resource.
	 */
	function getResourceId(): string;
}
