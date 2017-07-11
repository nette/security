<?php

/**
 * Test: Nette\Security\Permission Ensures that ACL-wide rules (all Roles, Resources, and privileges) work properly.
 */

declare(strict_types=1);

use Nette\Security\Permission;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


$acl = new Permission;
$acl->allow();
Assert::true($acl->isAllowed());
Assert::true($acl->isAllowed(null, null, 'somePrivilege'));

$acl->deny();
Assert::false($acl->isAllowed());
Assert::false($acl->isAllowed(null, null, 'somePrivilege'));
