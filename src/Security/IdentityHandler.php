<?php declare(strict_types=1);

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

namespace Nette\Security;


/**
 * Serializes and restores identity to/from persistent storage.
 */
interface IdentityHandler
{
	/**
	 * Called before identity is written to storage. Typically replaces the full identity with a lightweight token.
	 */
	function sleepIdentity(IIdentity $identity): IIdentity;

	/**
	 * Called after identity is read from storage. Typically refreshes roles or validates the token. Returns null to force logout.
	 */
	function wakeupIdentity(IIdentity $identity): ?IIdentity;
}
