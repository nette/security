<?php

/**
 * Test: Nette\Security\Permission Ensures that assertions on privileges work properly for a particular Role.
 */

use Nette\Security\Permission;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


function falseAssertion()
{
	return false;
}


function trueAssertion()
{
	return true;
}


$acl = new Permission;
$acl->addRole('guest');
$acl->allow('guest', null, 'somePrivilege', 'trueAssertion');
Assert::true($acl->isAllowed('guest', null, 'somePrivilege'));
$acl->allow('guest', null, 'somePrivilege', 'falseAssertion');
Assert::false($acl->isAllowed('guest', null, 'somePrivilege'));
