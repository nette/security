<?php declare(strict_types=1);

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

namespace Nette\Security;


/**
 * Decides whether the principal may access a resource. Access is allowed if a voter allows and none forbids.
 */
interface Voter
{
	function vote(Principal $principal, mixed $resource, ?string $privilege): Vote;
}
