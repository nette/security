<?php declare(strict_types=1);

/**
 * Test: Nette\Security\Permission Ensures that a privilege denied for a particular Role upon all Resources works properly.
 */

use Nette\Security\Permission;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


$acl = new Permission;
$acl->addRole('guest');
$acl->allow('guest');
$acl->deny('guest', null, 'somePrivilege');
Assert::false($acl->isAllowed('guest', null, 'somePrivilege'));
