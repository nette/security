<?php

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

declare(strict_types=1);

namespace Nette\Security;

if (false) {
	/** @deprecated use Nette\Security\Authorizator */
	interface IAuthorizator extends Authorizator
	{
	}

	/** @deprecated use Nette\Security\Resource */
	interface IResource extends Resource
	{
	}

	/** @deprecated use Nette\Security\Role */
	interface IRole extends Role
	{
	}
} elseif (!interface_exists(IAuthorizator::class)) {
	class_alias(Authorizator::class, IAuthorizator::class);
	class_alias(Resource::class, IResource::class);
	class_alias(Role::class, IRole::class);
}
