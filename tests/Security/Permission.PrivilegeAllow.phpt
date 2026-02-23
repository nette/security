<?php declare(strict_types=1);

/**
 * Test: Nette\Security\Permission Ensures that a privilege allowed for all Roles upon all Resources works properly.
 */

use Nette\Security\Permission;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


$acl = new Permission;
$acl->allow(null, null, 'somePrivilege');
Assert::true($acl->isAllowed(null, null, 'somePrivilege'));
