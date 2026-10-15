<?php declare(strict_types=1);

/**
 * Test: Nette\Security\Permission throws when a non-existent Resource is passed to each parameter of inherits().
 */

use Nette\Security\Permission;
use Tester\Assert;

require __DIR__ . '/../bootstrap.php';


$acl = new Permission;
$acl->addResource('area');
Assert::exception(
	fn() => $acl->resourceInheritsFrom('nonexistent', 'area'),
	Nette\InvalidStateException::class,
	"Resource 'nonexistent' does not exist.",
);

Assert::exception(
	fn() => $acl->resourceInheritsFrom('area', 'nonexistent'),
	Nette\InvalidStateException::class,
	"Resource 'nonexistent' does not exist.",
);
