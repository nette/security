<?php declare(strict_types=1);

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

namespace Nette\Security;


/**
 * Represents the user of application.
 * @method array<string, mixed> getData()
 */
interface IIdentity
{
	/**
	 * Returns the ID of user.
	 */
	function getId(): string|int;

	/**
	 * Returns a list of roles that the user is a member of.
	 * @return string[]
	 */
	function getRoles(): array;

	/**
	 * Returns user data.
	 */
	//function getData(): array;
}
