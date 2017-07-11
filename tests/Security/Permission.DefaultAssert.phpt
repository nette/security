<?php

/**
 * Test: Nette\Security\Permission Ensures that the default rule obeys its assertion.
 */

declare(strict_types=1);

use Nette\Security\Permission;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


function falseAssertion()
{
	return false;
}


$acl = new Permission;
$acl->deny(null, null, null, 'falseAssertion');
Assert::true($acl->isAllowed(null, null, 'somePrivilege'));
