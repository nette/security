<?php

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

declare(strict_types=1);

namespace Nette\Security;


/**
 * Interface for persistent storage for user object data.
 */
interface IMultiUserStorage extends IUserStorage
{

	/**
	 * Add identity to UserStorage.
	 * @param IIdentity $identity
	 * @return static
	 */
	function addIdentity(IIdentity $identity): self;

	/**
	 * Remove specific identity from UserStorage. In case of null remove all identities.
	 * @param IIdentity|null $identity
	 * @return static
	 */
	function removeIdentity(?IIdentity $identity): self;

	/**
	 * Get list of all logged identities in UserStorage.
	 * @return IIdentity[] $identity
	 */
	function getIdentities(): array;
}
