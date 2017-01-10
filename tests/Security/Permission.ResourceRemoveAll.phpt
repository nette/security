<?php

/**
 * Test: Nette\Security\Permission Ensures that removal of all Resources works.
 */

declare(strict_types=1);

use Nette\Security\Permission;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


$acl = new Permission;
$acl->addResource('area');
$acl->removeAllResources();
Assert::false($acl->hasResource('area'));
