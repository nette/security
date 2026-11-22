<?php declare(strict_types=1);

/**
 * Test: UserPanel lists the decisions made during the request
 */

use Nette\Bridges\SecurityTracy\UserPanel;
use Nette\Security\{MemoryStorage, Principal, User, Vote, Voter};
use Tester\Assert;

require __DIR__ . '/../bootstrap.php';


enum Access
{
	case Reports;
}


class ReportVoter implements Voter
{
	public function vote(Principal $principal, mixed $resource, string|UnitEnum|null $privilege): Vote
	{
		return $resource === Access::Reports ? Vote::Allow : Vote::Abstain;
	}
}


$user = new User(new MemoryStorage, null, new ReportVoter);
$panel = new UserPanel($user);
Assert::null($panel->getPanel()); // no session and nothing decided yet

$user->isAllowed(Access::Reports);
$user->isAllowed(Access::Reports);
$user->isAllowed('artcle', 'view');

$html = (string) $panel->getPanel();
Assert::contains('Access::Reports', $html);
Assert::contains('ReportVoter: Allow', $html);
Assert::match('%A%<td>2</td>%A%', $html);
Assert::contains('&apos;artcle&apos;', $html);
Assert::contains('nobody decided', $html);
Assert::notNull($panel->getTab());
