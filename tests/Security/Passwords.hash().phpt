<?php

/**
 * Test: Nette\Security\Passwords::hash()
 */

use Nette\Security\Passwords;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


Assert::truthy(
	preg_match('#^\$2.\$\d\d\$.{53}\z#',
	Passwords::hash(''))
);

Assert::truthy(
	preg_match('#^\$2y\$05\$.{53}\z#',
	$h = Passwords::hash('dg', ['cost' => 5]))
);
echo $h;

$hash = Passwords::hash('dg');
Assert::same($hash, crypt('dg', $hash));


Assert::exception(function () {
	Passwords::hash('dg', ['cost' => 3]);
}, Nette\InvalidArgumentException::class, 'Cost must be in range 4-31, 3 given.');

Assert::exception(function () {
	Passwords::hash('dg', ['cost' => 32]);
}, Nette\InvalidArgumentException::class, 'Cost must be in range 4-31, 32 given.');
