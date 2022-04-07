<?php

/**
 * Test: Nette\Security\Permission Ensures that an exception is thrown when a non-existent Role and Resource parameters are specified to isAllowed().
 */

declare(strict_types=1);

use Nette\Security\Permission;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


$acl = new Permission;
Assert::exception(
	fn() => $acl->isAllowed('nonexistent'),
	Nette\InvalidStateException::class,
	"Role 'nonexistent' does not exist.",
);

$acl = new Permission;
Assert::exception(
	fn() => $acl->isAllowed(null, 'nonexistent'),
	Nette\InvalidStateException::class,
	"Resource 'nonexistent' does not exist.",
);
