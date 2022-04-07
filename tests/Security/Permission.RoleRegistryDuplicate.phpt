<?php

/**
 * Test: Nette\Security\Permission Ensures that the same Role cannot be registered more than once to the registry.
 */

declare(strict_types=1);

use Nette\Security\Permission;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


$acl = new Permission;
$acl->addRole('guest');
Assert::exception(
	fn() => $acl->addRole('guest'),
	Nette\InvalidStateException::class,
	"Role 'guest' already exists in the list.",
);
