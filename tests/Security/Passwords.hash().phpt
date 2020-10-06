<?php

/**
 * Test: Nette\Security\Passwords::hash()
 */

use Nette\Security\Passwords;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


Assert::truthy(
	preg_match('#^\$2.\$\d\d\$.{53}\z#', Passwords::hash(''))
);

Assert::truthy(
	preg_match('#^\$2y\$05\$.{53}\z#', Passwords::hash('dg', ['cost' => 5]))
);

$hash = Passwords::hash('dg');
Assert::same($hash, crypt('dg', $hash));


Assert::exception(function () {
	Passwords::hash('dg', ['cost' => 3]);
}, PHP_VERSION_ID < 80000 ? Nette\InvalidStateException::class : ValueError::class);

Assert::exception(function () {
	Passwords::hash('dg', ['cost' => 32]);
}, PHP_VERSION_ID < 80000 ? Nette\InvalidStateException::class : ValueError::class);
