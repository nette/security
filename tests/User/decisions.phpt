<?php declare(strict_types=1);

/**
 * Test: User::$onDecided reports every decision with the votes cast
 */

use Nette\Security\{MemoryStorage, Principal, User, Vote, Voter};
use Tester\Assert;

require __DIR__ . '/../bootstrap.php';


class FixedVoter implements Voter
{
	public function __construct(
		private Vote $vote,
	) {
	}


	public function vote(Principal $principal, mixed $resource, string|UnitEnum|null $privilege): Vote
	{
		return $resource === 'nested' ? Vote::allowIf($principal->isAllowed('inner')) : $this->vote;
	}
}


function decide(array $voters, string $resource): array
{
	$user = new User(new MemoryStorage, null, ...$voters);
	$log = [];
	$user->onDecided[] = function (Principal $principal, mixed $resource, $privilege, array $votes, bool $allowed) use (&$log) {
		$log[] = [$resource, $privilege, array_map(fn($pair) => $pair[1], $votes), $allowed];
	};
	$user->isAllowed($resource, 'edit');
	return $log;
}


test('the votes of all voters and the result', function () {
	$log = decide([new FixedVoter(Vote::Abstain), new FixedVoter(Vote::Allow)], 'article');
	Assert::same([['article', 'edit', [Vote::Abstain, Vote::Allow], true]], $log);
});


test('a forbidding vote ends the decision', function () {
	$log = decide([new FixedVoter(Vote::Allow), new FixedVoter(Vote::Forbid), new FixedVoter(Vote::Allow)], 'article');
	Assert::same([['article', 'edit', [Vote::Allow, Vote::Forbid], false]], $log);
});


test('nobody decided', function () {
	$log = decide([new FixedVoter(Vote::Abstain)], 'article');
	Assert::same([['article', 'edit', [Vote::Abstain], false]], $log);
});


test('a question a voter asks is reported before the one it answers', function () {
	$log = decide([new FixedVoter(Vote::Allow)], 'nested');
	Assert::same([
		['inner', null, [Vote::Allow], true],
		['nested', 'edit', [Vote::Allow], true],
	], $log);
});


test('without a listener, the principal has no observer', function () {
	$user = new User(new MemoryStorage, null, new FixedVoter(Vote::Allow));
	Assert::true($user->isAllowed('article'));
});
