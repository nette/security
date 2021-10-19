<?php

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

declare(strict_types=1);

namespace Nette\Security;


/**
 * Adjusts identity from/to storage.
 */
interface IdentityHandler
{
	function sleepIdentity(IIdentity $identity): IIdentity;

	function wakeupIdentity(IIdentity $identity): ?IIdentity;
}
