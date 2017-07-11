<?php

/**
 * Test: Nette\Security\Permission Ensures that removing the default deny rule results in assertion method being removed.
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
Assert::true($acl->isAllowed());
$acl->removeDeny();
Assert::false($acl->isAllowed());
