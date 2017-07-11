<?php

/**
 * Test: Nette\Security\Permission Ensure that basic rule removal works.
 */

use Nette\Security\Permission;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


$acl = new Permission;
$acl->allow(null, null, ['privilege1', 'privilege2']);
Assert::false($acl->isAllowed());
Assert::true($acl->isAllowed(null, null, 'privilege1'));
Assert::true($acl->isAllowed(null, null, 'privilege2'));
$acl->removeAllow(null, null, 'privilege1');
Assert::false($acl->isAllowed(null, null, 'privilege1'));
Assert::true($acl->isAllowed(null, null, 'privilege2'));
