<?php

/**
 * Test: Nette\Security\Permission Ensures that multiple privileges work properly for a particular Role.
 */

declare(strict_types=1);

use Nette\Security\Permission;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


$acl = new Permission;
$acl->addRole('guest');
$acl->allow('guest', null, ['p1', 'p2', 'p3']);
Assert::true($acl->isAllowed('guest', null, 'p1'));
Assert::true($acl->isAllowed('guest', null, 'p2'));
Assert::true($acl->isAllowed('guest', null, 'p3'));
Assert::false($acl->isAllowed('guest', null, 'p4'));
$acl->deny('guest', null, 'p1');
Assert::false($acl->isAllowed('guest', null, 'p1'));
$acl->deny('guest', null, ['p2', 'p3']);
Assert::false($acl->isAllowed('guest', null, 'p2'));
Assert::false($acl->isAllowed('guest', null, 'p3'));
