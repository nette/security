<?php

/**
 * Test: Nette\Security\Permission Tests basic Resource inheritance.
 */

declare(strict_types=1);

use Nette\Security\Permission;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


$acl = new Permission;
$acl->addResource('city');
$acl->addResource('building', 'city');
$acl->addResource('room', 'building');

Assert::same(['city', 'building', 'room'], $acl->getResources());
Assert::true($acl->resourceInheritsFrom('building', 'city', onlyParent: true));
Assert::true($acl->resourceInheritsFrom('room', 'building', onlyParent: true));
Assert::true($acl->resourceInheritsFrom('room', 'city'));
Assert::false($acl->resourceInheritsFrom('room', 'city', onlyParent: true));
Assert::false($acl->resourceInheritsFrom('city', 'building'));
Assert::false($acl->resourceInheritsFrom('building', 'room'));
Assert::false($acl->resourceInheritsFrom('city', 'room'));

$acl->removeResource('building');
Assert::false($acl->hasResource('room'));
