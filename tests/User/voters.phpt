<?php declare(strict_types=1);

/**
 * Test: Nette\Security\User authorization by voters.
 */

use Nette\Security\{Principal, SimpleIdentity, User, Vote, Voter};
use Tester\Assert;

require __DIR__ . '/../bootstrap.php';
require __DIR__ . '/MockUserStorage.php';


class Article
{
	public function __construct(
		public ?int $authorId,
	) {
	}
}


class ArticleVoter implements Voter
{
	public function vote(Principal $principal, mixed $resource, ?string $privilege): Vote
	{
		return Vote::allowIf($resource instanceof Article && match ($privilege) {
			'edit' => $principal->hasId($resource->authorId),
			default => false,
		});
	}
}


class AdminVoter implements Voter
{
	public function vote(Principal $principal, mixed $resource, ?string $privilege): Vote
	{
		return Vote::allowIf($principal->isInRole('admin'));
	}
}


class BannedVoter implements Voter
{
	public function vote(Principal $principal, mixed $resource, ?string $privilege): Vote
	{
		return $principal->isInRole('banned') ? Vote::Forbid : Vote::Abstain;
	}
}


test('no voter', function () {
	$user = new User(new MockUserStorage);
	Assert::exception(
		fn() => $user->isAllowed('backend'),
		Nette\InvalidStateException::class,
		'No voter has been added.',
	);
});


test('the voter receives the principal, the resource and the privilege', function () {
	$log = [];
	$voter = new class ($log) implements Voter {
		public function __construct(
			private array &$log,
		) {
		}


		public function vote(Principal $principal, mixed $resource, ?string $privilege): Vote
		{
			$this->log[] = [$principal->getRoles(), $resource, $privilege];
			return Vote::Abstain;
		}
	};
	$user = new User(new MockUserStorage, null, $voter);

	Assert::false($user->isAllowed());
	Assert::false($user->isAllowed('backend', 'view'));
	Assert::same([[['guest'], null, null], [['guest'], 'backend', 'view']], $log);
});


test('a voter allows', function () {
	$article = new Article(authorId: 1);
	$user = new User(new MockUserStorage, null, new ArticleVoter);
	$user->addVoter(new AdminVoter);

	Assert::false($user->isAllowed($article, 'edit'));

	$user->login(new SimpleIdentity(1));
	Assert::true($user->isAllowed($article, 'edit'));
	Assert::false($user->isAllowed($article, 'delete'));

	$user->login(new SimpleIdentity(2, ['admin']));
	Assert::true($user->isAllowed($article, 'edit'));
	Assert::true($user->isAllowed($article, 'delete'));
});


test('a voter forbids whatever the others allow', function () {
	$user = new User(new MockUserStorage, null, new AdminVoter, new BannedVoter, new AdminVoter);

	$user->login(new SimpleIdentity(1, ['admin']));
	Assert::true($user->isAllowed('backend'));

	$user->login(new SimpleIdentity(1, ['admin', 'banned']));
	Assert::false($user->isAllowed('backend'));
});


test('the retained identity is not the principal', function () {
	$article = new Article(authorId: 1);
	$user = new User(new MockUserStorage, null, new ArticleVoter);
	$user->login(new SimpleIdentity(1));
	$user->logout();

	Assert::same(1, $user->getId());
	Assert::null($user->getPrincipal()->getIdentity());
	Assert::same(['guest'], $user->getPrincipal()->getRoles());
	Assert::false($user->isAllowed($article, 'edit'));
});


test('a guest identity gives the principal its roles, not itself', function () {
	$authenticator = new class implements Nette\Security\Authenticator, Nette\Security\IdentityHandler {
		public function authenticate(string $username, string $password): Nette\Security\IIdentity
		{
			throw new LogicException;
		}


		public function sleepIdentity(Nette\Security\IIdentity $identity): Nette\Security\IIdentity
		{
			return $identity;
		}


		public function wakeupIdentity(Nette\Security\IIdentity $identity): ?Nette\Security\IIdentity
		{
			return $identity;
		}


		public function getGuestIdentity(): ?Nette\Security\IIdentity
		{
			return new SimpleIdentity(1, ['admin']);
		}
	};
	$user = new User(new MockUserStorage, $authenticator, new ArticleVoter, new AdminVoter);

	Assert::null($user->getPrincipal()->getIdentity());
	Assert::same(['admin'], $user->getPrincipal()->getRoles());
	Assert::true($user->isAllowed('backend'));
	Assert::true($user->isInRole('admin'));
});


test('a principal for someone else than the current user', function () {
	$article = new Article(authorId: 1);
	$user = new User(new MockUserStorage, null, new ArticleVoter, new AdminVoter);

	Assert::true($user->createPrincipal(new SimpleIdentity(1))->isAllowed($article, 'edit'));
	Assert::false($user->createPrincipal(new SimpleIdentity(2))->isAllowed($article, 'edit'));
	Assert::true($user->createPrincipal(new SimpleIdentity(2, ['admin']))->isAllowed($article, 'edit'));
	Assert::false($user->isLoggedIn());
});


test('a guest owns no record, not even one without an owner', function () {
	$user = new User(new MockUserStorage, null, new ArticleVoter);
	Assert::false($user->isAllowed(new Article(authorId: null), 'edit'));

	$user->login(new SimpleIdentity(1));
	Assert::false($user->isAllowed(new Article(authorId: null), 'edit'));
});


test('a principal for someone else takes the identity as it is, null is a guest', function () {
	$authenticator = new class implements Nette\Security\Authenticator, Nette\Security\IdentityHandler {
		public function authenticate(string $username, string $password): Nette\Security\IIdentity
		{
			throw new LogicException;
		}


		public function sleepIdentity(Nette\Security\IIdentity $identity): Nette\Security\IIdentity
		{
			throw new LogicException;
		}


		public function wakeupIdentity(Nette\Security\IIdentity $identity): ?Nette\Security\IIdentity
		{
			throw new LogicException;
		}


		public function getGuestIdentity(): ?Nette\Security\IIdentity
		{
			return new SimpleIdentity('guest', ['visitor']);
		}
	};
	$user = new User(new MockUserStorage, $authenticator, new ArticleVoter, new AdminVoter);

	$identity = new SimpleIdentity(1, ['member']);
	$principal = $user->createPrincipal($identity);
	Assert::same($identity, $principal->getIdentity());
	Assert::same(['member'], $principal->getRoles());

	$principal = $user->createPrincipal(null);
	Assert::null($principal->getIdentity());
	Assert::same(['visitor'], $principal->getRoles());
	Assert::false($principal->isAllowed(new Article(authorId: null), 'edit'));
	Assert::false($user->isLoggedIn());
});


test('the role-based authorizator is asked for each role', function () {
	$authorizator = new class implements Nette\Security\Authorizator {
		public function isAllowed(?string $role, mixed $resource, ?string $privilege): bool
		{
			return $role === 'editor' && $resource === 'backend';
		}
	};
	$user = new User(new MockUserStorage, null, new ArticleVoter, new BannedVoter);
	@$user->setAuthorizator($authorizator); // @ deprecated

	$user->login(new SimpleIdentity(1, ['member', 'editor']));
	Assert::true($user->isAllowed('backend'));
	Assert::true($user->isAllowed(new Article(authorId: 1), 'edit'));
	Assert::false($user->isAllowed('frontend'));

	$user->login(new SimpleIdentity(1, ['editor', 'banned']));
	Assert::false($user->isAllowed('backend'));
});
