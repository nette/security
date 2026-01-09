<?php declare(strict_types=1);

/**
 * PHPStan type tests.
 */

use Nette\Security\IIdentity;
use Nette\Security\Permission;
use Nette\Security\User;
use function PHPStan\Testing\assertType;


function testPermissionGetRoles(Permission $acl): void
{
	assertType('list<string>', $acl->getRoles());
}


function testPermissionGetRoleParents(Permission $acl): void
{
	$acl->addRole('admin');
	assertType('list<string>', $acl->getRoleParents('admin'));
}


function testPermissionGetResources(Permission $acl): void
{
	assertType('list<string>', $acl->getResources());
}


function testIIdentityGetId(IIdentity $identity): void
{
	assertType('int|string', $identity->getId());
}


function testUserGetId(User $user): void
{
	assertType('int|string|null', $user->getId());
}
