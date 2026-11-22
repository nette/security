<?php declare(strict_types=1);

/**
 * Test: Nette\Security\Principal
 */

use Nette\Security\{Principal, SimpleIdentity, Vote, Voter};
use Tester\Assert;

require __DIR__ . '/../bootstrap.php';


class Comment
{
	public function __construct(
		public string $article,
	) {
	}
}


class ArticleVoter implements Voter
{
	public function vote(Principal $principal, mixed $resource, string|UnitEnum|null $privilege): Vote
	{
		return Vote::allowIf($resource === 'public' && $privilege === 'view');
	}
}


class CommentVoter implements Voter
{
	public function vote(Principal $principal, mixed $resource, string|UnitEnum|null $privilege): Vote
	{
		return Vote::allowIf($resource instanceof Comment && $principal->isAllowed($resource->article, $privilege));
	}
}


enum PostPrivilege: string
{
	case View = 'view';
	case Edit = 'edit';
}


enum ProfilePrivilege: string
{
	case Edit = 'edit';
}


enum BoardPrivilege
{
	case Moderate;
}


enum Level: int
{
	case High = 1;
}


enum Access
{
	case Admin;
	case Reports;
}


class Post
{
	public function __construct(
		public bool $published,
	) {
	}
}


class Board
{
}


class Topic
{
	public function __construct(
		public Board $board,
	) {
	}
}


class PostVoter implements Voter
{
	public function vote(Principal $principal, mixed $resource, string|UnitEnum|null $privilege): Vote
	{
		if (!$resource instanceof Post || !$privilege instanceof PostPrivilege) {
			return Vote::Abstain;
		}

		return Vote::allowIf(match ($privilege) {
			PostPrivilege::View => $resource->published || $principal->isInRole('editor'),
			PostPrivilege::Edit => $principal->isInRole('editor'),
		});
	}
}


class BoardVoter implements Voter
{
	public function vote(Principal $principal, mixed $resource, string|UnitEnum|null $privilege): Vote
	{
		return Vote::allowIf(
			$resource instanceof Board && $privilege === BoardPrivilege::Moderate && $principal->isInRole('moderator'),
		);
	}
}


class TopicVoter implements Voter
{
	public function vote(Principal $principal, mixed $resource, string|UnitEnum|null $privilege): Vote
	{
		return Vote::allowIf($resource instanceof Topic && $principal->isAllowed($resource->board, BoardPrivilege::Moderate));
	}
}


class AccessVoter implements Voter
{
	public function vote(Principal $principal, mixed $resource, string|UnitEnum|null $privilege): Vote
	{
		return Vote::allowIf($resource === Access::Admin && $principal->isInRole('admin'));
	}
}


test('a guest', function () {
	$principal = new Principal(null, ['guest']);
	Assert::null($principal->getIdentity());
	Assert::false($principal->isLoggedIn());
	Assert::null($principal->getGuestIdentity());
	Assert::false($principal->hasId(null));
	Assert::same(['guest'], $principal->getRoles());
	Assert::true($principal->isInRole('guest'));
	Assert::false($principal->isInRole('admin'));
});


test('a guest with a guest identity', function () {
	$guest = new SimpleIdentity(1, ['visitor']);
	$principal = new Principal(null, ['visitor'], [], $guest);
	Assert::same($guest, $principal->getGuestIdentity());
	Assert::null($principal->getIdentity());
	Assert::false($principal->isLoggedIn());
	Assert::false($principal->hasId(1));
});


test('a logged-in user', function () {
	$identity = new SimpleIdentity(1, ['admin']);
	$principal = new Principal($identity, ['admin']);
	Assert::same($identity, $principal->getIdentity());
	Assert::true($principal->isLoggedIn());
	Assert::true($principal->hasId(1));
	Assert::false($principal->hasId('1'));
	Assert::false($principal->hasId(null));
	Assert::true($principal->isInRole('admin'));
});


test('a logged-in user has no guest identity', function () {
	$principal = new Principal(new SimpleIdentity(1), [], [], new SimpleIdentity('guest'));
	Assert::null($principal->getGuestIdentity());
});


test('without roles, those of the identity are used', function () {
	Assert::same(['admin', 'editor'], new Principal(new SimpleIdentity(1, ['admin', 'editor']))->getRoles());
	Assert::same(['visitor'], new Principal(null, guestIdentity: new SimpleIdentity('guest', ['visitor']))->getRoles());
	Assert::same(['guest'], new Principal(null)->getRoles());
	Assert::same([], new Principal(new SimpleIdentity(1, ['admin']), [])->getRoles());
});


test('no voter', function () {
	Assert::exception(
		fn() => new Principal(null, [])->isAllowed('article'),
		Nette\InvalidStateException::class,
		'No voter has been added. Register a service implementing Nette\Security\Voter, or call User::addVoter().',
	);
});


test('a voter delegates to another one', function () {
	$principal = new Principal(null, ['guest'], [new ArticleVoter, new CommentVoter]);
	Assert::true($principal->isAllowed(new Comment('public'), 'view'));
	Assert::false($principal->isAllowed(new Comment('draft'), 'view'));
	Assert::false($principal->isAllowed(new Comment('public'), 'edit'));
});


test('a voter receives the privilege and the resource as they are', function () {
	$log = [];
	$voter = new class ($log) implements Voter {
		public function __construct(
			private array &$log,
		) {
		}


		public function vote(Principal $principal, mixed $resource, string|UnitEnum|null $privilege): Vote
		{
			$this->log[] = [$resource, $privilege];
			return Vote::Abstain;
		}
	};
	$principal = new Principal(null, ['guest'], [$voter]);

	Assert::false($principal->isAllowed('post', PostPrivilege::Edit));
	Assert::false($principal->isAllowed('board', BoardPrivilege::Moderate));
	Assert::false($principal->isAllowed('level', Level::High));
	Assert::false($principal->isAllowed(Access::Admin));
	Assert::false($principal->isAllowed(PostPrivilege::View, 'view'));
	Assert::same([
		['post', PostPrivilege::Edit],
		['board', BoardPrivilege::Moderate],
		['level', Level::High],
		[Access::Admin, null],
		[PostPrivilege::View, 'view'],
	], $log);
});


test('a voter decides by a match over the cases of its enum', function () {
	$principal = new Principal(null, ['editor'], [new PostVoter]);
	Assert::true($principal->isAllowed(new Post(false), PostPrivilege::View));
	Assert::true($principal->isAllowed(new Post(false), PostPrivilege::Edit));

	$principal = new Principal(null, ['guest'], [new PostVoter]);
	Assert::true($principal->isAllowed(new Post(true), PostPrivilege::View));
	Assert::false($principal->isAllowed(new Post(false), PostPrivilege::View));
	Assert::false($principal->isAllowed(new Post(true), PostPrivilege::Edit));
});


test('a voter abstains on a case of another enum and on a name', function () {
	$principal = new Principal(null, ['editor'], [new PostVoter]);
	Assert::false($principal->isAllowed(new Post(true), ProfilePrivilege::Edit));
	Assert::false($principal->isAllowed(new Post(true), BoardPrivilege::Moderate));
	Assert::false($principal->isAllowed(new Post(true), 'edit'));
	Assert::false($principal->isAllowed(new Post(true)));
	Assert::false($principal->isAllowed('post', PostPrivilege::Edit));
});


test('a voter delegates with an enum privilege', function () {
	$topic = new Topic(new Board);
	Assert::true(new Principal(null, ['moderator'], [new BoardVoter, new TopicVoter])->isAllowed($topic));
	Assert::false(new Principal(null, ['guest'], [new BoardVoter, new TopicVoter])->isAllowed($topic));
});


test('a case of an enum is a resource', function () {
	$principal = new Principal(null, ['admin'], [new AccessVoter]);
	Assert::true($principal->isAllowed(Access::Admin));
	Assert::false($principal->isAllowed(Access::Reports));
	Assert::false(new Principal(null, ['guest'], [new AccessVoter])->isAllowed(Access::Admin));
});
