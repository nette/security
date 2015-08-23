<?php

/**
 * Test: Nette\Security\Permission Ensures that an exception is thrown when a non-existent Role is specified as a parent upon Role addition.
 */

use Nette\Security\Permission;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


$acl = new Permission;
Assert::exception(function () use ($acl) {
	$acl->addRole('guest', 'nonexistent');
}, Nette\InvalidStateException::class, "Role 'nonexistent' does not exist.");
