<?php declare(strict_types=1);

/**
 * Test: Nette\Security\SimpleIdentity is an Identity even if nothing loaded the alias.
 */

use Nette\Security\{Identity, SimpleIdentity};
use Tester\Assert;

require __DIR__ . '/../bootstrap.php';


$identity = new SimpleIdentity(1);
Assert::true($identity instanceof Identity);
Assert::same($identity, (fn(Identity $identity) => $identity)($identity));
