<?php declare(strict_types=1);

/**
 * Test: Nette\Security\Permission Ensures that removing non-existent default deny rule does nothing.
 */

use Nette\Security\Permission;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


$acl = new Permission;
$acl->allow();
$acl->removeDeny();
Assert::true($acl->isAllowed());
