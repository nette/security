<?php declare(strict_types=1);

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

namespace Nette\Security;


/**
 * Adjusts identity from/to storage.
 */
interface IdentityHandler
{
	function sleepIdentity(IIdentity $identity): IIdentity;

	function wakeupIdentity(IIdentity $identity): ?IIdentity;
}
