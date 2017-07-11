<?php

/**
 * Test: Nette\Security\Permission Ensures that a privilege allowed for a particular Role upon all Resources works properly.
 */

declare(strict_types=1);

use Nette\Security\Permission;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


$acl = new Permission;
$acl->addRole('guest');
$acl->allow('guest', null, 'somePrivilege');
Assert::true($acl->isAllowed('guest', null, 'somePrivilege'));
