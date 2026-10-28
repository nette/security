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
	public function vote(Principal $principal, mixed $resource, ?string $privilege): Vote
	{
		return Vote::allowIf($resource === 'public' && $privilege === 'view');
	}
}


class CommentVoter implements Voter
{
	public function vote(Principal $principal, mixed $resource, ?string $privilege): Vote
	{
		return Vote::allowIf($resource instanceof Comment && $principal->isAllowed($resource->article, $privilege));
	}
}


test('a guest', function () {
	$principal = new Principal(null, ['guest']);
	Assert::null($principal->getIdentity());
	Assert::false($principal->hasId(null));
	Assert::same(['guest'], $principal->getRoles());
	Assert::true($principal->isInRole('guest'));
	Assert::false($principal->isInRole('admin'));
});


test('a logged-in user', function () {
	$identity = new SimpleIdentity(1, ['admin']);
	$principal = new Principal($identity, ['admin']);
	Assert::same($identity, $principal->getIdentity());
	Assert::true($principal->hasId(1));
	Assert::false($principal->hasId('1'));
	Assert::false($principal->hasId(null));
	Assert::true($principal->isInRole('admin'));
});


test('no voter', function () {
	Assert::exception(
		fn() => (new Principal(null, []))->isAllowed('article'),
		Nette\InvalidStateException::class,
		'No voter has been added.',
	);
});


test('a voter delegates to another one', function () {
	$principal = new Principal(null, ['guest'], [new ArticleVoter, new CommentVoter]);
	Assert::true($principal->isAllowed(new Comment('public'), 'view'));
	Assert::false($principal->isAllowed(new Comment('draft'), 'view'));
	Assert::false($principal->isAllowed(new Comment('public'), 'edit'));
});
