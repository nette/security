<?php declare(strict_types=1);

/**
 * Test: Nette\Security\Permission throws when a non-existent Role is passed to each parameter of inherits().
 */

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
