<?php declare(strict_types=1);

/**
 * Test: Nette\Security\Permission Ensures that an example for a content management system is operable.
 */

use Nette\Security\Permission;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


$acl = new Permission;
$acl->addRole('guest');
$acl->addRole('staff', 'guest');  // staff inherits permissions from guest
$acl->addRole('editor', 'staff'); // editor inherits permissions from staff
$acl->addRole('administrator');

// Guest may only view content
$acl->allow('guest', null, 'view');

// Staff inherits view privilege from guest, but also needs additional privileges
$acl->allow('staff', null, ['edit', 'submit', 'revise']);

// Editor inherits view, edit, submit, and revise privileges, but also needs additional privileges
$acl->allow('editor', null, ['publish', 'archive', 'delete']);

// Administrator inherits nothing but is allowed all privileges
$acl->allow('administrator');

// Access control checks based on above permission sets

Assert::true($acl->isAllowed('guest', null, 'view'));
Assert::false($acl->isAllowed('guest', null, 'edit'));
Assert::false($acl->isAllowed('guest', null, 'submit'));
Assert::false($acl->isAllowed('guest', null, 'revise'));
Assert::false($acl->isAllowed('guest', null, 'publish'));
Assert::false($acl->isAllowed('guest', null, 'archive'));
Assert::false($acl->isAllowed('guest', null, 'delete'));
Assert::false($acl->isAllowed('guest', null, 'unknown'));
Assert::false($acl->isAllowed('guest'));

Assert::true($acl->isAllowed('staff', null, 'view'));
Assert::true($acl->isAllowed('staff', null, 'edit'));
Assert::true($acl->isAllowed('staff', null, 'submit'));
Assert::true($acl->isAllowed('staff', null, 'revise'));
Assert::false($acl->isAllowed('staff', null, 'publish'));
Assert::false($acl->isAllowed('staff', null, 'archive'));
Assert::false($acl->isAllowed('staff', null, 'delete'));
Assert::false($acl->isAllowed('staff', null, 'unknown'));
Assert::false($acl->isAllowed('staff'));

Assert::true($acl->isAllowed('editor', null, 'view'));
Assert::true($acl->isAllowed('editor', null, 'edit'));
Assert::true($acl->isAllowed('editor', null, 'submit'));
Assert::true($acl->isAllowed('editor', null, 'revise'));
Assert::true($acl->isAllowed('editor', null, 'publish'));
Assert::true($acl->isAllowed('editor', null, 'archive'));
Assert::true($acl->isAllowed('editor', null, 'delete'));
Assert::false($acl->isAllowed('editor', null, 'unknown'));
Assert::false($acl->isAllowed('editor'));

Assert::true($acl->isAllowed('administrator', null, 'view'));
Assert::true($acl->isAllowed('administrator', null, 'edit'));
Assert::true($acl->isAllowed('administrator', null, 'submit'));
Assert::true($acl->isAllowed('administrator', null, 'revise'));
Assert::true($acl->isAllowed('administrator', null, 'publish'));
Assert::true($acl->isAllowed('administrator', null, 'archive'));
Assert::true($acl->isAllowed('administrator', null, 'delete'));
Assert::true($acl->isAllowed('administrator', null, 'unknown'));
Assert::true($acl->isAllowed('administrator'));

// Some checks on specific areas, which inherit access controls from the root ACL node
$acl->addResource('newsletter');
$acl->addResource('pending', 'newsletter');
$acl->addResource('gallery');
$acl->addResource('profiles', 'gallery');
$acl->addResource('config');
$acl->addResource('hosts', 'config');
Assert::true($acl->isAllowed('guest', 'pending', 'view'));
Assert::true($acl->isAllowed('staff', 'profiles', 'revise'));
Assert::true($acl->isAllowed('staff', 'pending', 'view'));
Assert::true($acl->isAllowed('staff', 'pending', 'edit'));
Assert::false($acl->isAllowed('staff', 'pending', 'publish'));
Assert::false($acl->isAllowed('staff', 'pending'));
Assert::false($acl->isAllowed('editor', 'hosts', 'unknown'));
Assert::true($acl->isAllowed('administrator', 'pending'));

// Add a new group, marketing, which bases its permissions on staff
$acl->addRole('marketing', 'staff');

// Refine the privilege sets for more specific needs

// Allow marketing to publish and archive newsletters
$acl->allow('marketing', 'newsletter', ['publish', 'archive']);

// Allow marketing to publish and archive latest news
$acl->addResource('news');
$acl->addResource('latest', 'news');
$acl->allow('marketing', 'latest', ['publish', 'archive']);

// Deny staff (and marketing, by inheritance) rights to revise latest news
$acl->deny('staff', 'latest', 'revise');

// Deny everyone access to archive news announcements
$acl->addResource('announcement', 'news');
$acl->deny(null, 'announcement', 'archive');

// Access control checks for the above refined permission sets

Assert::true($acl->isAllowed('marketing', null, 'view'));
Assert::true($acl->isAllowed('marketing', null, 'edit'));
Assert::true($acl->isAllowed('marketing', null, 'submit'));
Assert::true($acl->isAllowed('marketing', null, 'revise'));
Assert::false($acl->isAllowed('marketing', null, 'publish'));
Assert::false($acl->isAllowed('marketing', null, 'archive'));
Assert::false($acl->isAllowed('marketing', null, 'delete'));
Assert::false($acl->isAllowed('marketing', null, 'unknown'));
Assert::false($acl->isAllowed('marketing'));

Assert::true($acl->isAllowed('marketing', 'newsletter', 'publish'));
Assert::false($acl->isAllowed('staff', 'pending', 'publish'));
Assert::true($acl->isAllowed('marketing', 'pending', 'publish'));
Assert::true($acl->isAllowed('marketing', 'newsletter', 'archive'));
Assert::false($acl->isAllowed('marketing', 'newsletter', 'delete'));
Assert::false($acl->isAllowed('marketing', 'newsletter'));

Assert::true($acl->isAllowed('marketing', 'latest', 'publish'));
Assert::true($acl->isAllowed('marketing', 'latest', 'archive'));
Assert::false($acl->isAllowed('marketing', 'latest', 'delete'));
Assert::false($acl->isAllowed('marketing', 'latest', 'revise'));
Assert::false($acl->isAllowed('marketing', 'latest'));

Assert::false($acl->isAllowed('marketing', 'announcement', 'archive'));
Assert::false($acl->isAllowed('staff', 'announcement', 'archive'));
Assert::false($acl->isAllowed('administrator', 'announcement', 'archive'));

Assert::false($acl->isAllowed('staff', 'latest', 'publish'));
Assert::false($acl->isAllowed('editor', 'announcement', 'archive'));

// Remove some previous permission specifications

// Marketing can no longer publish and archive newsletters
$acl->removeAllow('marketing', 'newsletter', ['publish', 'archive']);

// Marketing can no longer archive the latest news
$acl->removeAllow('marketing', 'latest', 'archive');

// Now staff (and marketing, by inheritance) may revise latest news
$acl->removeDeny('staff', 'latest', 'revise');

// Access control checks for the above refinements

Assert::false($acl->isAllowed('marketing', 'newsletter', 'publish'));
Assert::false($acl->isAllowed('marketing', 'newsletter', 'archive'));

Assert::false($acl->isAllowed('marketing', 'latest', 'archive'));

Assert::true($acl->isAllowed('staff', 'latest', 'revise'));
Assert::true($acl->isAllowed('marketing', 'latest', 'revise'));

// Grant marketing all permissions on the latest news
$acl->allow('marketing', 'latest');

// Access control checks for the above refinement
Assert::true($acl->isAllowed('marketing', 'latest', 'archive'));
Assert::true($acl->isAllowed('marketing', 'latest', 'publish'));
Assert::true($acl->isAllowed('marketing', 'latest', 'edit'));
Assert::true($acl->isAllowed('marketing', 'latest'));
