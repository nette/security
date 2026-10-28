<?php declare(strict_types=1);

/**
 * Test: Nette\Security\Permission Ensures that a query for all privileges on a Resource honors a deny rule for a specific privilege
 * on its parent Resource, after the rules of the Resource itself have been checked.
 */

use Nette\Security\Permission;
use Tester\Assert;

require __DIR__ . '/../bootstrap.php';


$acl = new Permission;
$acl->addResource('parent');
$acl->addResource('child', 'parent');
$acl->allow(null, 'parent');
$acl->deny(null, 'parent', 'delete');
$acl->allow(null, 'child', 'view');
Assert::false($acl->isAllowed(null, 'child'));
Assert::false($acl->isAllowed(null, 'child', 'delete'));
Assert::true($acl->isAllowed(null, 'child', 'view'));
