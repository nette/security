<?php declare(strict_types=1);

/**
 * Test: Nette\Security\Permission assertions with getQueriedRole() and getQueriedResource().
 */

use Nette\Security\Permission;
use Nette\Security\Resource;
use Nette\Security\Role;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


class UserRole implements Role
{
	public function __construct(
		public string $roleId,
		public int $userId,
	) {
	}


	public function getRoleId(): string
	{
		return $this->roleId;
	}
}


class ArticleResource implements Resource
{
	public function __construct(
		public string $resourceId,
		public int $authorId,
	) {
	}


	public function getResourceId(): string
	{
		return $this->resourceId;
	}
}


test('Assertion can access queried role and resource objects', function () {
	$acl = new Permission;

	$user1 = new UserRole('user1', 123);
	$user2 = new UserRole('user2', 456);

	$article1 = new ArticleResource('article1', 123); // authored by user1
	$article2 = new ArticleResource('article2', 456); // authored by user2

	// addRole() accepts only strings
	$acl->addRole('user1');
	$acl->addRole('user2');
	$acl->addResource('article1');
	$acl->addResource('article2');

	// Assertion: user can edit only their own articles
	$ownerAssertion = function (Permission $acl): bool {
		$role = $acl->getQueriedRole();
		$resource = $acl->getQueriedResource();

		// When isAllowed() is called with objects, getQueried* returns those objects
		// But they might also be strings if called with strings
		if ($role instanceof UserRole && $resource instanceof ArticleResource) {
			return $role->userId === $resource->authorId;
		}

		return false; // Deny if not using objects
	};

	// Allow rules are set using string IDs
	$acl->allow('user1', 'article1', 'edit', $ownerAssertion);
	$acl->allow('user1', 'article2', 'edit', $ownerAssertion);
	$acl->allow('user2', 'article1', 'edit', $ownerAssertion);
	$acl->allow('user2', 'article2', 'edit', $ownerAssertion);

	// user1 can edit article1 (their own)
	Assert::true($acl->isAllowed($user1, $article1, 'edit'));

	// user1 cannot edit article2 (belongs to user2)
	Assert::false($acl->isAllowed($user1, $article2, 'edit'));

	// user2 can edit article2 (their own)
	Assert::true($acl->isAllowed($user2, $article2, 'edit'));

	// user2 cannot edit article1 (belongs to user1)
	Assert::false($acl->isAllowed($user2, $article1, 'edit'));
});


test('getQueriedRole() returns string when queried with string', function () {
	$acl = new Permission;

	$acl->addRole('admin');
	$acl->addResource('article');

	$assertion = function (Permission $acl): bool {
		$role = $acl->getQueriedRole();
		Assert::same('admin', $role);
		Assert::type('string', $role);
		return true;
	};

	$acl->allow('admin', 'article', 'edit', $assertion);

	Assert::true($acl->isAllowed('admin', 'article', 'edit'));
});


test('getQueriedResource() returns string when queried with string', function () {
	$acl = new Permission;

	$acl->addRole('admin');
	$acl->addResource('article');

	$assertion = function (Permission $acl): bool {
		$resource = $acl->getQueriedResource();
		Assert::same('article', $resource);
		Assert::type('string', $resource);
		return true;
	};

	$acl->allow('admin', 'article', 'edit', $assertion);

	Assert::true($acl->isAllowed('admin', 'article', 'edit'));
});


test('Assertion with complex business logic using queried objects', function () {
	$acl = new Permission;

	// Simulate a blog system with posts and comments
	class Post implements Resource
	{
		public function __construct(
			public string $resourceId,
			public int $authorId,
			public bool $published,
			public int $categoryId,
		) {
		}


		public function getResourceId(): string
		{
			return $this->resourceId;
		}
	}

	class Author implements Role
	{
		public function __construct(
			public string $roleId,
			public int $id,
			public bool $isPremium,
			public array $allowedCategories,
		) {
		}


		public function getRoleId(): string
		{
			return $this->roleId;
		}
	}

	$premiumAuthor = new Author('author1', 100, true, [1, 2, 3]);
	$regularAuthor = new Author('author2', 200, false, [1]);

	$post1 = new Post('post1', 100, true, 1);   // by premium author, published, category 1
	$post2 = new Post('post2', 200, false, 2);  // by regular author, draft, category 2
	$post3 = new Post('post3', 999, true, 3);   // by someone else, published, category 3

	// addRole/addResource accept only strings
	$acl->addRole('author1');
	$acl->addRole('author2');
	$acl->addResource('post1');
	$acl->addResource('post2');
	$acl->addResource('post3');

	// Complex assertion: can edit if:
	// 1. Own post, OR
	// 2. Premium user AND post is unpublished AND category allowed
	$editAssertion = function (Permission $acl): bool {
		$author = $acl->getQueriedRole();
		$post = $acl->getQueriedResource();

		// When using objects, assertion receives the actual objects
		if (!($author instanceof Author && $post instanceof Post)) {
			return false;
		}

		// Own post - always allowed
		if ($author->id === $post->authorId) {
			return true;
		}

		// Premium users can edit unpublished posts in their categories
		return $author->isPremium && !$post->published && in_array($post->categoryId, $author->allowedCategories, true);
	};

	$acl->allow('author1', ['post1', 'post2', 'post3'], 'edit', $editAssertion);
	$acl->allow('author2', ['post1', 'post2', 'post3'], 'edit', $editAssertion);

	// premiumAuthor can edit their own post1
	Assert::true($acl->isAllowed($premiumAuthor, $post1, 'edit'));

	// premiumAuthor can edit post2 (unpublished, category 2 allowed)
	Assert::true($acl->isAllowed($premiumAuthor, $post2, 'edit'));

	// premiumAuthor cannot edit post3 (published, even though category allowed)
	Assert::false($acl->isAllowed($premiumAuthor, $post3, 'edit'));

	// regularAuthor can edit their own post2
	Assert::true($acl->isAllowed($regularAuthor, $post2, 'edit'));

	// regularAuthor cannot edit post1 (not their own, premium feature)
	Assert::false($acl->isAllowed($regularAuthor, $post1, 'edit'));
});


test('getQueriedRole() and getQueriedResource() are available inside assertion', function () {
	$acl = new Permission;

	$acl->addRole('user');
	$acl->addResource('article');

	$assertion = function (Permission $acl): bool {
		// Inside assertion - should have values
		Assert::notNull($acl->getQueriedRole());
		Assert::notNull($acl->getQueriedResource());
		return true;
	};

	$acl->allow('user', 'article', 'view', $assertion);

	$acl->isAllowed('user', 'article', 'view');
});


test('Assertion with role inheritance uses actual queried role, not inherited', function () {
	$acl = new Permission;

	$admin = new UserRole('admin', 1);
	$editor = new UserRole('editor', 2);

	$acl->addRole('editor');
	$acl->addRole('admin', 'editor'); // admin inherits from editor

	$acl->addResource('article');

	$capturedRoles = [];

	$assertion = function (Permission $acl) use (&$capturedRoles): bool {
		$queriedRole = $acl->getQueriedRole();
		if ($queriedRole instanceof UserRole) {
			$capturedRoles[] = $queriedRole->getRoleId();
		}
		return true;
	};

	$acl->allow('editor', 'article', 'view', $assertion);

	// Query with admin object - should capture 'admin', not 'editor'
	$acl->isAllowed($admin, 'article', 'view');

	Assert::same(['admin'], $capturedRoles);
});


test('Multiple assertions in hierarchy all receive correct queried objects', function () {
	$acl = new Permission;

	$user = new UserRole('user', 100);
	$article = new ArticleResource('article', 200);

	$acl->addRole('user');
	$acl->addResource('article');

	$assertion1Calls = 0;
	$assertion2Calls = 0;

	$assertion1 = function (Permission $acl) use (&$assertion1Calls, $user, $article): bool {
		$assertion1Calls++;
		Assert::same($user, $acl->getQueriedRole());
		Assert::same($article, $acl->getQueriedResource());
		return true;
	};

	$assertion2 = function (Permission $acl) use (&$assertion2Calls, $user, $article): bool {
		$assertion2Calls++;
		Assert::same($user, $acl->getQueriedRole());
		Assert::same($article, $acl->getQueriedResource());
		return true;
	};

	$acl->allow('user', 'article', 'view', $assertion1);
	$acl->allow('user', 'article', 'edit', $assertion2);

	$acl->isAllowed($user, $article, 'view');
	Assert::same(1, $assertion1Calls);
	Assert::same(0, $assertion2Calls);

	$acl->isAllowed($user, $article, 'edit');
	Assert::same(1, $assertion1Calls);
	Assert::same(1, $assertion2Calls);
});
