<?php

/**
 * Test: Nette\Security\Permission Ensures that an exception is thrown when a non-existent Role and Resource parameters are specified to isAllowed().
 */

use Nette\Security\Permission;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


Assert::exception(function () {
	$acl = new Permission;
	$acl->isAllowed('nonexistent');
}, Nette\InvalidStateException::class, "Role 'nonexistent' does not exist.");

Assert::exception(function () {
	$acl = new Permission;
	$acl->isAllowed(NULL, 'nonexistent');
}, Nette\InvalidStateException::class, "Resource 'nonexistent' does not exist.");
