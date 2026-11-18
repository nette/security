<?php declare(strict_types=1);

/**
 * Test: Nette\Security\Permission as a voter.
 */

use Nette\Security\{Permission, Principal, Resource, SimpleIdentity, User, Vote, Voter};
use Tester\Assert;

require __DIR__ . '/../bootstrap.php';
require __DIR__ . '/../User/MockUserStorage.php';


class Page implements Resource
{
	public function getResourceId(): string
	{
		return 'page';
	}
}


function createAcl(): Permission
{
	$acl = new Permission;
	$acl->addRole('guest');
	$acl->addRole('editor', 'guest');
	$acl->addRole('admin');
	$acl->addResource('page');
	$acl->addResource('article');
	$acl->addResource('perex', 'article');
	return $acl;
}


function vote(Permission $acl, array $roles, mixed $resource, ?string $privilege = null): Vote
{
	return $acl->vote(new Principal(null, $roles), $resource, $privilege);
}


test('the default deny-all abstains, an allow allows', function () {
	$acl = createAcl();
	Assert::same(Vote::Abstain, vote($acl, ['guest'], 'page', 'view'));
	Assert::same(Vote::Abstain, vote($acl, ['guest'], null));

	$acl->allow('guest', 'page', 'view');
	Assert::same(Vote::Allow, vote($acl, ['guest'], 'page', 'view'));
	Assert::same(Vote::Allow, vote($acl, ['guest'], new Page, 'view'));
	Assert::same(Vote::Abstain, vote($acl, ['guest'], 'page', 'edit'));
});


test('an explicit deny forbids', function () {
	$acl = createAcl();
	$acl->deny('editor', 'article', 'delete');
	Assert::same(Vote::Forbid, vote($acl, ['editor'], 'article', 'delete'));
	Assert::same(Vote::Abstain, vote($acl, ['editor'], 'article', 'edit'));
	Assert::same(Vote::Abstain, vote($acl, ['guest'], 'article', 'delete'));
});


test('a deny of all privileges forbids each of them and the whole resource', function () {
	$acl = createAcl();
	$acl->deny('editor', 'article');
	Assert::same(Vote::Forbid, vote($acl, ['editor'], 'article', 'edit'));
	Assert::same(Vote::Forbid, vote($acl, ['editor'], 'article'));
});


test('a specific privilege wins over all privileges', function () {
	$acl = createAcl();
	$acl->allow('editor', 'article');
	$acl->deny('editor', 'article', 'delete');
	Assert::same(Vote::Allow, vote($acl, ['editor'], 'article', 'view'));
	Assert::same(Vote::Forbid, vote($acl, ['editor'], 'article', 'delete'));
	Assert::same(Vote::Forbid, vote($acl, ['editor'], 'article')); // a whole-resource query is vetoed by any deny

	$acl = createAcl();
	$acl->deny('editor', 'article');
	$acl->allow('editor', 'article', 'view');
	Assert::same(Vote::Allow, vote($acl, ['editor'], 'article', 'view'));
	Assert::same(Vote::Forbid, vote($acl, ['editor'], 'article', 'edit'));
});


test('a deny of a parent role forbids, the own rule of a role wins over it', function () {
	$acl = createAcl();
	$acl->deny('guest', 'article', 'edit');
	Assert::same(Vote::Forbid, vote($acl, ['editor'], 'article', 'edit'));

	$acl->allow('editor', 'article', 'edit');
	Assert::same(Vote::Allow, vote($acl, ['editor'], 'article', 'edit'));
	Assert::same(Vote::Forbid, vote($acl, ['guest'], 'article', 'edit'));
});


test('a deny of a parent resource forbids, the rule of a child resource wins over it', function () {
	$acl = createAcl();
	$acl->deny('editor', 'article', 'edit');
	Assert::same(Vote::Forbid, vote($acl, ['editor'], 'perex', 'edit'));

	$acl->allow('editor', 'perex', 'edit');
	Assert::same(Vote::Allow, vote($acl, ['editor'], 'perex', 'edit'));
	Assert::same(Vote::Forbid, vote($acl, ['editor'], 'article', 'edit'));
});


test('a deny for all roles or of a whole role forbids', function () {
	$acl = createAcl();
	$acl->deny(null, 'article', 'delete');
	Assert::same(Vote::Forbid, vote($acl, ['guest'], 'article', 'delete'));
	Assert::same(Vote::Forbid, vote($acl, ['admin'], 'article', 'delete'));

	$acl = createAcl();
	$acl->deny('guest');
	Assert::same(Vote::Forbid, vote($acl, ['guest'], 'page', 'view'));
	Assert::same(Vote::Forbid, vote($acl, ['editor'], 'page', 'view'));
	Assert::same(Vote::Abstain, vote($acl, ['admin'], 'page', 'view'));
});


test('the default rule abstains when it denies, also when set explicitly', function () {
	$acl = createAcl();
	$acl->allow();
	Assert::same(Vote::Allow, vote($acl, ['guest'], 'page', 'view'));

	$acl->deny();
	Assert::same(Vote::Abstain, vote($acl, ['guest'], 'page', 'view'));
	Assert::false($acl->isAllowed('guest', 'page', 'view'));
});


test('a failed assertion makes the rule not apply', function () {
	$acl = createAcl();
	$acl->deny('editor', 'article', 'edit', fn() => false);
	Assert::same(Vote::Abstain, vote($acl, ['editor'], 'article', 'edit'));

	$acl->deny('editor', 'article', 'edit', fn() => true);
	Assert::same(Vote::Forbid, vote($acl, ['editor'], 'article', 'edit'));

	$acl = createAcl();
	$acl->allow('editor', 'article', 'edit', fn() => false);
	Assert::same(Vote::Abstain, vote($acl, ['editor'], 'article', 'edit'));

	$acl = createAcl();
	$acl->allow(null, null, null, fn() => false); // the default rule inverts a failed assertion to a deny
	Assert::same(Vote::Abstain, vote($acl, ['guest'], 'page', 'view'));
});


test('any role of the principal allows, an explicit deny of another role then does not forbid', function () {
	$acl = createAcl();
	$acl->deny('editor', 'article', 'delete');
	$acl->allow('admin', 'article');
	Assert::same(Vote::Allow, vote($acl, ['editor', 'admin'], 'article', 'delete'));
	Assert::same(Vote::Abstain, vote($acl, ['admin', 'editor'], 'page', 'view'));
	Assert::same(Vote::Forbid, vote($acl, ['guest', 'editor'], 'article', 'delete'));
});


test('unknown roles and resources abstain instead of throwing', function () {
	$acl = createAcl();
	$acl->deny('editor');
	Assert::same(Vote::Abstain, vote($acl, ['member'], 'page', 'view'));
	Assert::same(Vote::Abstain, vote($acl, ['editor'], 'unknown'));
	Assert::same(Vote::Abstain, vote($acl, ['editor'], new stdClass, 'view'));
	Assert::same(Vote::Abstain, vote($acl, ['editor'], stdClass::class, 'create'));
});


test('an explicit deny of the ACL overrides other voters', function () {
	$acl = createAcl();
	$acl->deny('editor', 'article', 'delete');
	$adminVoter = new class implements Voter {
		public function vote(Principal $principal, mixed $resource, ?string $privilege): Vote
		{
			return Vote::allowIf($principal->isInRole('admin'));
		}
	};

	$user = new User(new MockUserStorage, null, $acl, $adminVoter);
	$user->login(new SimpleIdentity(1, ['admin']));
	Assert::true($user->isAllowed('article', 'delete'));

	$user->login(new SimpleIdentity(1, ['admin', 'editor']));
	Assert::false($user->isAllowed('article', 'delete'));
	Assert::true($user->isAllowed('article', 'edit'));
});


test('a Resource object is voted on by its name, also with an explicit deny', function () {
	$acl = createAcl();
	$queried = null;
	$acl->allow('editor', 'page', 'edit', function (Permission $acl) use (&$queried) {
		$queried = $acl->getQueriedResource();
		return true;
	});
	$acl->deny('editor', 'page', 'delete');

	Assert::same(Vote::Allow, vote($acl, ['editor'], new Page, 'edit'));
	Assert::same('page', $queried);
	Assert::same(Vote::Forbid, vote($acl, ['editor'], new Page, 'delete'));
});
