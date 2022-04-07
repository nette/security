<?php

/**
 * Test: Nette\Security\Permission Ensures that an exception is thrown when a non-existent Role is specified to each parameter of inherits().
 */

declare(strict_types=1);

use Nette\Security\Permission;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


$acl = new Permission;
$acl->addRole('guest');
Assert::exception(
	fn() => $acl->roleInheritsFrom('nonexistent', 'guest'),
	Nette\InvalidStateException::class,
	"Role 'nonexistent' does not exist.",
);

Assert::exception(
	fn() => $acl->roleInheritsFrom('guest', 'nonexistent'),
	Nette\InvalidStateException::class,
	"Role 'nonexistent' does not exist.",
);
