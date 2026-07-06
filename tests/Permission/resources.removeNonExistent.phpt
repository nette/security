<?php declare(strict_types=1);

/**
 * Test: Nette\Security\Permission Ensures that an exception is thrown when a non-existent Resource is specified for removal.
 */

use Nette\Security\Permission;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


$acl = new Permission;
Assert::exception(
	fn() => $acl->removeResource('nonexistent'),
	Nette\InvalidStateException::class,
	"Resource 'nonexistent' does not exist.",
);
