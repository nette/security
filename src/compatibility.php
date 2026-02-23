<?php declare(strict_types=1);

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

namespace Nette\Security;

if (false) {
	/** @deprecated use Nette\Security\SimpleIdentity */
	class Identity extends SimpleIdentity
	{
	}
} elseif (!class_exists(Identity::class)) {
	class_alias(SimpleIdentity::class, Identity::class);
}
