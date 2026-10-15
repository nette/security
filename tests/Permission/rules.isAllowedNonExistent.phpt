<?php declare(strict_types=1);

/**
 * Test: Nette\Security\Permission throws when a non-existent Role and Resource are passed to isAllowed().
 */

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
