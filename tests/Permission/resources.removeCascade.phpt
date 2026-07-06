<?php declare(strict_types=1);

/**
 * Test: Nette\Security\Permission Ensures that removal of a Resource results in its rules being removed.
 */

use Nette\Security\Permission;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


$acl = new Permission;
$acl->addResource('area');
$acl->allow(null, 'area');
Assert::true($acl->isAllowed(null, 'area'));
$acl->removeResource('area');
Assert::exception(
	fn() => $acl->isAllowed(null, 'area'),
	Nette\InvalidStateException::class,
	"Resource 'area' does not exist.",
);

$acl->addResource('area');
Assert::false($acl->isAllowed(null, 'area'));
