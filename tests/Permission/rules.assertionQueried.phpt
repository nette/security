<?php declare(strict_types=1);

/**
 * Test: Nette\Security\Permission assertions with getQueriedRole() and getQueriedResource().
 */

use Nette\Security\{Permission, Resource, Role};
use Tester\Assert;

require __DIR__ . '/../bootstrap.php';


class ArticleResource implements Resource
{
	public function getResourceId(): string
	{
		return 'article';
	}
}


test('the assertion gets the rule of the match, getQueried*() what was queried', function () {
	$acl = new Permission;
	$acl->addRole('registered');
	$acl->addRole('editor', 'registered');
	$acl->addResource('article');
	$acl->addResource('perex', 'article');

	$log = [];
	$acl->allow('registered', 'article', 'edit', function (Permission $acl, ?string $role, ?string $resource) use (&$log): bool {
		$log[] = [$role, $resource, $acl->getQueriedRole(), $acl->getQueriedResource()];
		return true;
	});

	Assert::true($acl->isAllowed('editor', 'perex', 'edit'));
	Assert::true($acl->isAllowed('registered', 'article', 'edit'));
	Assert::same([
		['registered', 'article', 'editor', 'perex'],
		['registered', 'article', 'registered', 'article'],
	], $log);
});


test('a Resource object is queried by its name', function () {
	$acl = new Permission;
	$acl->addRole('registered');
	$acl->addResource('article');

	$queried = null;
	$acl->allow('registered', 'article', 'edit', function (Permission $acl) use (&$queried): bool {
		$queried = $acl->getQueriedResource();
		return true;
	});

	Assert::true($acl->isAllowed('registered', new ArticleResource, 'edit'));
	Assert::same('article', $queried);
});


test('a Role object is not accepted', function () {
	$acl = new Permission;
	$acl->addRole('registered');
	$role = new class implements Role {
		public function getRoleId(): string
		{
			return 'registered';
		}
	};

	Assert::exception(
		fn() => $acl->isAllowed($role),
		TypeError::class,
	);
});


test('the queried state is restored after a nested query and outside of a query', function () {
	$acl = new Permission;
	$acl->addRole('registered');
	$acl->addResource('article');
	$acl->addResource('comment');
	$acl->allow('registered', 'comment', 'view');

	$log = [];
	$acl->allow('registered', 'article', 'view', function (Permission $acl) use (&$log): bool {
		$allowed = $acl->isAllowed('registered', 'comment', 'view');
		$log[] = [$acl->getQueriedRole(), $acl->getQueriedResource()];
		return $allowed;
	});

	Assert::true($acl->isAllowed('registered', 'article', 'view'));
	Assert::same([['registered', 'article']], $log);
	Assert::null($acl->getQueriedRole());
	Assert::null($acl->getQueriedResource());
});
