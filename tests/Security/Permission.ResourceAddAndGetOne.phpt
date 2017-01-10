<?php

/**
 * Test: Nette\Security\Permission Ensures that basic addition and retrieval of a single Resource works.
 */

declare(strict_types=1);

use Nette\Security\Permission;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


$acl = new Permission;
Assert::false($acl->hasResource('area'));

$acl->addResource('area');
Assert::true($acl->hasResource('area'));

$acl->removeResource('area');
Assert::false($acl->hasResource('area'));
