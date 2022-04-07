<?php

/**
 * Test: Nette\Security\Permission Ensures that the same Resource cannot be added more than once.
 */

declare(strict_types=1);

use Nette\Security\Permission;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


$acl = new Permission;
$acl->addResource('area');
Assert::exception(
	fn() => $acl->addResource('area'),
	Nette\InvalidStateException::class,
	"Resource 'area' already exists in the list.",
);
