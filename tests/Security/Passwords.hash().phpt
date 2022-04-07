<?php

/**
 * Test: Nette\Security\Passwords::hash()
 */

declare(strict_types=1);

use Nette\Security\Passwords;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


Assert::truthy(
	preg_match('#^\$.{50,}\z#', (new Passwords)->hash('my-password')),
);

Assert::truthy(
	preg_match('#^\$2y\$05\$.{53}\z#', (new Passwords(PASSWORD_BCRYPT, ['cost' => 5]))->hash('dg')),
);

$hash = (new Passwords(PASSWORD_BCRYPT))->hash('dg');
Assert::same($hash, crypt('dg', $hash));

Assert::exception(
	fn() => (new Passwords(PASSWORD_BCRYPT, ['cost' => 3]))->hash('dg'),
	ValueError::class,
);

Assert::exception(
	fn() => (new Passwords)->hash(''),
	Nette\InvalidArgumentException::class,
	'Password can not be empty.',
);
