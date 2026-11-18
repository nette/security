<?php declare(strict_types=1);

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

namespace Nette\Security;


/**
 * The vote of a voter. A single Forbid overrides any Allow; without an Allow, access is not allowed.
 */
enum Vote
{
	case Allow;
	case Abstain;
	case Forbid;


	/**
	 * Allows if the condition holds, abstains otherwise.
	 */
	public static function allowIf(bool $condition): self
	{
		return $condition ? self::Allow : self::Abstain;
	}
}
