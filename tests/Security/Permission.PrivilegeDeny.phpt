<?php

/**
 * Test: Nette\Security\Permission Ensures that a privilege denied for all Roles upon all Resources works properly.
 */

declare(strict_types=1);

use Nette\Security\Permission;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


$acl = new Permission;
$acl->addRole('admin');
$acl->allow('admin');
$acl->allow();
$acl->deny(null, null, 'somePrivilege');
Assert::false($acl->isAllowed(null, null, 'somePrivilege'));
Assert::false($acl->isAllowed('admin', null, 'somePrivilege'));
