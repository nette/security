<?php declare(strict_types=1);

/**
 * Test: Nette\Security\Permission Ensures that removal of all Resources works.
 */

use Nette\Security\Permission;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


$acl = new Permission;
$acl->addResource('area');
$acl->removeAllResources();
Assert::false($acl->hasResource('area'));
