<?php declare(strict_types=1);

/**
 * Test: Nette\Security\TokenIdentity carries only the token.
 */

use Nette\Security\TokenIdentity;
use Tester\Assert;

require __DIR__ . '/../bootstrap.php';


$identity = new TokenIdentity('abcdefghijklmn');
Assert::same('abcdefghijklmn', $identity->getId());

Assert::exception(
	fn() => $identity->getRoles(),
	Nette\NotSupportedException::class,
	'TokenIdentity carries only a token, it has no roles.',
);

Assert::exception(
	fn() => $identity->getData(),
	Nette\NotSupportedException::class,
	'TokenIdentity carries only a token, it has no data.',
);
