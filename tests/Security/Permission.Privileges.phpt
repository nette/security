<?php

/**
 * Test: Nette\Security\Permission Ensures that multiple privileges work properly.
 */

use Nette\Security\Permission;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


$acl = new Permission;
$acl->allow(null, null, ['p1', 'p2', 'p3']);
Assert::true($acl->isAllowed(null, null, 'p1'));
Assert::true($acl->isAllowed(null, null, 'p2'));
Assert::true($acl->isAllowed(null, null, 'p3'));
Assert::false($acl->isAllowed(null, null, 'p4'));
$acl->deny(null, null, 'p1');
Assert::false($acl->isAllowed(null, null, 'p1'));
$acl->deny(null, null, ['p2', 'p3']);
Assert::false($acl->isAllowed(null, null, 'p2'));
Assert::false($acl->isAllowed(null, null, 'p3'));
