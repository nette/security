<?php

/**
 * Test: Nette\Security\Permission Ensures that an exception is thrown when a non-existent Resource is specified to each parameter of inherits().
 */

declare(strict_types=1);

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
