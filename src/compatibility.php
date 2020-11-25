<?php

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

declare(strict_types=1);

namespace Nette\Security;

if (false) {
	/** @deprecated use Nette\Security\Authenticator */
	class IAuthenticator
	{
	}

	/** @deprecated use Nette\Security\Authorizator */
	class IAuthorizator
	{
	}

	/** @deprecated use Nette\Security\Resource */
	class IResource
	{
	}

	/** @deprecated use Nette\Security\Role */
	class IRole
	{
	}

	/** @deprecated use Nette\Security\UserStorage */
	class IUserStorage
	{
	}
} elseif (!interface_exists(IAuthenticator::class)) {
	class_alias(Authenticator::class, IAuthenticator::class);
	class_alias(Authorizator::class, IAuthorizator::class);
	class_alias(Resource::class, IResource::class);
	class_alias(Role::class, IRole::class);
	class_alias(UserStorage::class, IUserStorage::class);
}
