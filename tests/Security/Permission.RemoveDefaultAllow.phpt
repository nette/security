<?php

/**
 * Test: Nette\Security\Permission Ensures that removing the default allow rule results in default deny rule being assigned.
 */

declare(strict_types=1);

use Nette\Security\Permission;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


$acl = new Permission;
$acl->allow();
Assert::true($acl->isAllowed());
$acl->removeAllow();
Assert::false($acl->isAllowed());
